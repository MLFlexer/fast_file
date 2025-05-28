use io_uring::{IoUring, opcode, types};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::Acceptor;
use rustls::{ServerConfig, ServerConnection};
use std::ffi::CStr;
use std::fs::File;
use std::io::{BufReader, Read, Write, pipe, stdout};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::{fs, io};

fn main() -> io::Result<()> {
    let conf = tls_config();
    tcp_listener(conf)
}

fn tls_config() -> ServerConfig {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter("cert.pem")
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();

    let private_keys = PrivateKeyDer::from_pem_file("key.pem").unwrap();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_keys)
        .expect("could not create tls config");
    return config;
}

fn handle_client(stream: &mut TcpStream) -> io::Result<()> {
    let mut ring = IoUring::new(8)?;

    let fd = fs::File::open("README.md")?;
    let (p_reader, p_writer) = pipe().expect("cound not create pipe");

    let splice_read_e = opcode::Splice::new(
        types::Fd(fd.as_raw_fd()),
        0,
        types::Fd(p_writer.as_raw_fd()),
        -1,
        1024,
    )
    .build()
    .user_data(68);
    unsafe {
        ring.submission()
            .push(&splice_read_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1)?;

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
    .user_data(67);
    unsafe {
        ring.submission()
            .push(&splice_write_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1)?;

    let cqe = ring.completion().next().expect("completion queue is empty");

    println!("{:?}", cqe);
    Ok(())
}

fn tcp_listener(config: ServerConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:12345")?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();

            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => continue,
                Err((e, mut alert)) => {
                    alert.write_all(&mut stream).unwrap();
                    panic!("error accepting connection: {e}");
                }
            }
        };
        let mut conn = accepted.into_connection(Arc::new(config.clone())).unwrap();
        println!("conn");
        while conn.is_handshaking() {
            println!("hs");
            conn.complete_io(&mut stream)?;
        }
        println!("end");
        conn.writer().write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello\r\n\r\n",
        )?;
        conn.complete_io(&mut stream)?;
        // handle_client(&mut stream);
        // conn.complete_io(&mut stream)?;

        conn.send_close_notify();
        conn.complete_io(&mut stream)?;

        stream.shutdown(Shutdown::Both)?;
    }
    Ok(())
}
