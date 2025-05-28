use io_uring::{IoUring, opcode, types};
use ktls::{CorkStream, KtlsStream, config_ktls_server};
use libc::{AT_FDCWD, STATX_SIZE, statx};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::Acceptor;
use rustls::{ServerConfig, ServerConnection};
use std::ffi::CStr;
use std::fs::File;
use std::io::{BufReader, Read, Write, pipe, stdout};
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::{fs, io};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

extern crate libc;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let conf = tls_config();
    let _ = tcp_listener(conf).await;
}

fn tls_config() -> ServerConfig {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter("cert.pem")
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();

    let private_keys = PrivateKeyDer::from_pem_file("key.pem").unwrap();

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_keys)
        .expect("could not create tls config");
    config.enable_secret_extraction = true;
    return config;
}

async fn tcp_listener(config: ServerConfig) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    // let acceptor = Rc::new(acceptor);

    let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();

    loop {
        let (stream, addr) = listener.accept().await?;
        let stream = CorkStream::new(stream);
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            // Perform the TLS handshake asynchronously
            match acceptor.accept(stream).await {
                Ok(mut tls_stream) => {
                    println!("Connection accepted from {:?}", addr);

                    let mut tls_stream = config_ktls_server(tls_stream).await.unwrap();

                    handle_client(&mut tls_stream);

                    // Flush and shutdown TLS session properly
                    if let Err(e) = tls_stream.shutdown().await {
                        eprintln!("Failed to shutdown TLS stream: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("TLS handshake failed: {}", e);
                }
            }
        });
    }
}

fn handle_client(stream: &mut KtlsStream<TcpStream>) -> io::Result<()> {
    let mut ring = IoUring::new(8)?;

    // let fd = fs::File::open("README.md")?;
    http_read_file(c"./README.md", &mut ring, stream);

    Ok(())
}

// let path = c"./README.md";
fn http_read_file(path: &CStr, ring: &mut IoUring, stream: &mut KtlsStream<TcpStream>) {
    let str_path = path.to_str().unwrap();
    let statx: MaybeUninit<statx> = MaybeUninit::uninit();

    let statx_e = opcode::Statx::new(
        types::Fd(AT_FDCWD),
        path.as_ptr(),
        statx.as_ptr().cast_mut().cast(),
    )
    .mask(STATX_SIZE)
    .build()
    .user_data(13);
    unsafe {
        ring.submission()
            .push(&statx_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1).expect("err");

    let cqe = ring.completion().next().expect("completion queue is empty");

    println!("{:?}", cqe);
    unsafe {
        println!("{:?}", statx.assume_init().stx_size);
    }

    // ********************************************
    let content_len = cqe.result();
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
Content-Type: text/plain; charset=UTF-8\r\n\
Content-Length: {length}\r\n\
Content-Disposition: inline; filename=\"{filename}\"\r\n\
Cache-Control: no-cache\r\n\
Server: FastFileServer/1.0\r\n\
\r\n",
        length = content_len,
        filename = str_path,
    );

    let send_e = opcode::Send::new(
        types::Fd(stream.as_raw_fd()),
        response.as_ptr(),
        response.len() as u32,
    )
    .build()
    .user_data(7);
    unsafe {
        ring.submission()
            .push(&send_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1).expect("err");

    let cqe = ring.completion().next().expect("completion queue is empty");

    println!("{:?}", cqe);

    // ********************************************

    let fd = fs::File::open(path.to_str().unwrap()).expect("err");
    let (p_reader, p_writer) = pipe().expect("cound not create pipe");

    let splice_read_e = opcode::Splice::new(
        types::Fd(fd.as_raw_fd()),
        0,
        types::Fd(p_writer.as_raw_fd()),
        -1,
        1024,
    )
    .build()
    .user_data(42);
    unsafe {
        ring.submission()
            .push(&splice_read_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1).expect("err");

    let cqe = ring.completion().next().expect("completion queue is empty");

    println!("{:?}", cqe);

    let splice_write_e = opcode::Splice::new(
        types::Fd(p_reader.as_raw_fd()),
        -1,
        types::Fd(stream.as_raw_fd()),
        -1,
        1024,
    )
    .build()
    .user_data(69);
    unsafe {
        ring.submission()
            .push(&splice_write_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1).expect("err");

    let cqe = ring.completion().next().expect("completion queue is empty");

    println!("{:?}", cqe);
}
