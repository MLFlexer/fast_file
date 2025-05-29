use io_uring::squeue::Flags;
use io_uring::{IoUring, opcode, types};
use ktls::{CorkStream, KtlsStream, config_ktls_server};
use libc::{AT_FDCWD, O_RDONLY, STATX_SIZE, statx};
use log::{error, info};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::Acceptor;
use rustls::{ServerConfig, ServerConnection};
use simple_logger::SimpleLogger;
use std::any::Any;
use std::cell::OnceCell;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{BufReader, PipeReader, PipeWriter, Read, Write, pipe, stdout};
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::{Arc, OnceLock};
use std::{fs, io};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

extern crate libc;

static PIPE_DEFAULT_SIZE: OnceLock<u32> = OnceLock::new();

fn set_pipe_size(fd: i32) -> u32 {
    let size = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
    if size == -1 {
        panic!("COULD NOT GET SIZE OF PIPE!");
    }
    return size as u32;
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    SimpleLogger::new().init().unwrap();
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
                Ok(tls_stream) => {
                    println!("Connection accepted from {:?}", addr);

                    let mut ktls_stream = config_ktls_server(tls_stream).await.unwrap();

                    handle_client(&mut ktls_stream).await;

                    // Flush and shutdown TLS session properly
                    if let Err(e) = ktls_stream.shutdown().await {
                        error!("Failed to shutdown TLS stream: {}", e);
                    }
                }
                Err(e) => {
                    error!("TLS handshake failed: {}", e);
                }
            }
        });
    }
}

#[derive(Debug)]
enum ContentType {
    Html,
    Css,
    Js,
    Json,
    Png,
    Jpeg,
    Txt,
    OctetStream, // default
}

#[derive(Debug)]
enum FileToServeErr {
    NullByteInPath,
}

#[derive(Debug)]
struct FileToServe {
    content_type: ContentType,
    path: CString,
}

impl FileToServe {
    fn from_str(s: &str) -> Result<Self, FileToServeErr> {
        // TODO: fix this string concat
        let s = [".", s].concat();
        let Ok(path) = CString::new(s.clone()) else {
            return Err(FileToServeErr::NullByteInPath);
        };

        // Get the file extension and determine content type
        let extension = Path::new(&s)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        let content_type = match extension.as_str() {
            "html" => ContentType::Html,
            "css" => ContentType::Css,
            "js" => ContentType::Js,
            "json" => ContentType::Json,
            "png" => ContentType::Png,
            "jpg" | "jpeg" => ContentType::Jpeg,
            "txt" => ContentType::Txt,
            _ => ContentType::OctetStream,
        };

        Ok(FileToServe { content_type, path })
    }

    fn get_http_content_type(&self) -> &str {
        match self.content_type {
            ContentType::Html => "text/html",
            ContentType::Css => "text/css",
            ContentType::Js => "application/javascript",
            ContentType::Json => "application/json",
            ContentType::Png => "image/png",
            ContentType::Jpeg => "image/jpeg",
            ContentType::Txt => "text/plain",
            ContentType::OctetStream => "application/octet-stream",
        }
    }
}

async fn handle_client(stream: &mut KtlsStream<TcpStream>) -> io::Result<()> {
    let mut dst: [u8; 1024] = [0; 1024];
    let n_bytes = stream.read(&mut dst).await.expect("err");
    info!("{:?}", String::from_utf8(dst.to_vec()));
    info!("{}", n_bytes);

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let res = req.parse(&dst).expect("err").unwrap();

    // TODO: should be some fixed size and be able to handle large files.
    let mut ring = IoUring::new(128)?;
    match req.path {
        None => return Ok(()),
        Some("/") => {
            let (mut p_reader, mut p_writer) = pipe().expect("cound not create pipe");
            let file = FileToServe::from_str("/index.html").expect("err");
            let _ = http_read_file(file, &mut ring, stream, &mut p_reader, &mut p_writer);
            if let Err(e) = stream.flush().await {
                error!("Failed to flush TLS stream: {}", e);
            }
        }
        Some(p) => {
            info!("path is: {p}");
            let (mut p_reader, mut p_writer) = pipe().expect("cound not create pipe");
            let file = FileToServe::from_str(p).expect("err");
            info!("{:?}", file);
            let _ = http_read_file(file, &mut ring, stream, &mut p_reader, &mut p_writer);
            if let Err(e) = stream.flush().await {
                error!("Failed to flush TLS stream: {}", e);
            }
        }
    }

    Ok(())
}

// let path = c"./README.md";
fn http_read_file(
    file: FileToServe,
    ring: &mut IoUring,
    stream: &mut KtlsStream<TcpStream>,
    pipe_r: &mut PipeReader,
    pipe_w: &mut PipeWriter,
) -> Result<(), ReadFileErr> {
    open_file(ring, &file.path)?;

    let mut statx: MaybeUninit<statx> = MaybeUninit::uninit();
    let statx_ptr: NonNull<statx> = unsafe { NonNull::new_unchecked(statx.as_mut_ptr()) };
    statx_file(ring, &file.path, statx_ptr)?;

    let (fd, file_size) = get_fd_and_size(ring, statx_ptr)?;
    info!("fd: {:?}, file_size: {}", fd, file_size);

    write_response_and_close(ring, stream, fd, file_size, &file, pipe_r, pipe_w)
}

fn open_file(ring: &mut IoUring, path: &CStr) -> Result<(), ReadFileErr> {
    let openat_e = opcode::OpenAt::new(types::Fd(AT_FDCWD), path.as_ptr())
        .flags(O_RDONLY)
        .build()
        .flags(Flags::IO_LINK);

    if let Err(e) = unsafe { ring.submission().push(&openat_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }
    Ok(())
}

fn statx_file(
    ring: &mut IoUring,
    path: &CStr,
    statx_ptr: NonNull<statx>,
) -> Result<(), ReadFileErr> {
    let statx_e = opcode::Statx::new(
        types::Fd(AT_FDCWD),
        path.as_ptr(),
        statx_ptr.as_ptr().cast(),
    )
    .mask(STATX_SIZE)
    .build();
    // .flags(Flags::IO_LINK);

    if let Err(e) = unsafe { ring.submission().push(&statx_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }
    Ok(())
}

enum ReadFileErr {
    FailedPush,
    OpenAt,
    Statx,
    NoSubmission,
    Submission,
}

type StatxSize = u64;

fn get_fd_and_size(
    ring: &mut IoUring,
    statx_ptr: NonNull<statx>,
) -> Result<(types::Fd, StatxSize), ReadFileErr> {
    if let Err(e) = ring.submit_and_wait(2) {
        return Err(ReadFileErr::Submission);
    };

    let Some(openat_cqe) = ring.completion().next() else {
        return Err(ReadFileErr::NoSubmission);
    };

    let fd = match openat_cqe.result() {
        // TODO: should it advance the submission queue as well???
        err if err < 0 => return Err(ReadFileErr::OpenAt),
        fd => types::Fd(fd),
    };

    let Some(statx_cqe) = ring.completion().next() else {
        return Err(ReadFileErr::NoSubmission);
    };

    if let -1 = statx_cqe.result() {
        return Err(ReadFileErr::Statx);
    };

    let file_size = unsafe { statx_ptr.as_ref().stx_size };

    Ok((fd, file_size))
}

fn write_response_and_close(
    ring: &mut IoUring,
    stream: &mut KtlsStream<TcpStream>,
    fd: types::Fd,
    file_size: StatxSize,
    file: &FileToServe,
    pipe_r: &mut PipeReader,
    pipe_w: &mut PipeWriter,
) -> Result<(), ReadFileErr> {
    let mut n_submissions = 0;
    // TODO: maybe switch to http2 for concurrent requests
    let path = &file.path;
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
Content-Type: {content_type}\r\n\
Content-Length: {length}\r\n\
Content-Disposition: inline; filename=\"{filename}\"\r\n\
Cache-Control: no-cache\r\n\
Connection: keep-alive\r\n\
Server: FastFileServer/1.0\r\n\
\r\n",
        content_type = file.get_http_content_type(),
        length = file_size,
        filename = path.to_str().unwrap(),
    );

    info!("{}", response);

    let send_e = opcode::Send::new(
        types::Fd(stream.as_raw_fd()),
        response.as_ptr(),
        response.len() as u32,
    )
    .build()
    .flags(Flags::IO_LINK);

    if let Err(e) = unsafe { ring.submission().push(&send_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }
    n_submissions += 1;

    // submit enough requests to send the whole file.
    // WARNING: This can overflow the io_uring submission queue.
    for offset in (0..=file_size)
        .step_by(*PIPE_DEFAULT_SIZE.get_or_init(|| set_pipe_size(pipe_w.as_raw_fd())) as usize)
    {
        let remaining = file_size.saturating_sub(offset);
        let len = remaining.min(*PIPE_DEFAULT_SIZE.get().unwrap() as u64) as u32;
        info!("{}", offset);
        let splice_read_e =
            opcode::Splice::new(fd, offset as i64, types::Fd(pipe_w.as_raw_fd()), -1, len)
                .build()
                .flags(Flags::IO_LINK);

        if let Err(e) = unsafe { ring.submission().push(&splice_read_e) } {
            error!("Submission error: {e}");
            return Err(ReadFileErr::FailedPush);
        }
        n_submissions += 1;

        let splice_write_e = opcode::Splice::new(
            types::Fd(pipe_r.as_raw_fd()),
            -1,
            types::Fd(stream.as_raw_fd()),
            -1,
            len,
        )
        .build()
        .flags(Flags::IO_LINK);

        if let Err(e) = unsafe { ring.submission().push(&splice_write_e) } {
            error!("Submission error: {e}");
            return Err(ReadFileErr::FailedPush);
        }
        n_submissions += 1;
    }

    // Closing

    let close_e = opcode::Close::new(fd).build().user_data(420);

    if let Err(e) = unsafe { ring.submission().push(&close_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }
    n_submissions += 1;

    if let Err(e) = ring.submit_and_wait(n_submissions) {
        return Err(ReadFileErr::Submission);
    };

    // TODO: is this correct?
    for _ in 0..n_submissions {
        let Some(cqe) = ring.completion().next() else {
            return Err(ReadFileErr::NoSubmission);
        };
        info!("cqe: {:?}", cqe);
    }
    info!("COMPLETED SEND OF {:?}!", path);

    Ok(())
}
