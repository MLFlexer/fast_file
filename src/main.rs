use io_uring::squeue::Flags;
use io_uring::{IoUring, opcode, types};
use ktls::{CorkStream, KtlsStream, config_ktls_server};
use libc::{AT_FDCWD, O_RDONLY, SPLICE_F_MORE, SPLICE_F_MOVE, STATX_SIZE, statx};
use log::{error, info};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use simple_logger::SimpleLogger;
use std::ffi::{CStr, CString};
use std::io::{PipeReader, PipeWriter, pipe};
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::{Arc, OnceLock};
use std::{io, u64};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

extern crate libc;

static PIPE_DEFAULT_SIZE: OnceLock<u32> = OnceLock::new();

fn set_pipe_size(fd1: i32, fd2: i32) -> u32 {
    let size = unsafe { libc::fcntl(fd1, libc::F_GETPIPE_SZ) };
    let size2 = unsafe { libc::fcntl(fd2, libc::F_GETPIPE_SZ) };
    if size == -1 {
        panic!("COULD NOT GET SIZE OF PIPE!");
    }
    if size2 == -1 {
        panic!("COULD NOT GET SIZE OF PIPE!");
    }
    return (size.min(size2)).min(81920) as u32;
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

    let listener = TcpListener::bind("192.168.0.42:12345").await.unwrap();

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

                    let one: libc::c_int = 1;
                    unsafe {
                        libc::setsockopt(
                            ktls_stream.as_raw_fd(),
                            libc::SOL_TCP,
                            libc::TCP_CORK,
                            &one as *const _ as *const _,
                            std::mem::size_of_val(&one) as _,
                        );
                    }
                    handle_client(&mut ktls_stream).await.expect("ERROR");
                    let one: libc::c_int = 0;
                    unsafe {
                        libc::setsockopt(
                            ktls_stream.as_raw_fd(),
                            libc::SOL_TCP,
                            libc::TCP_CORK,
                            &one as *const _ as *const _,
                            std::mem::size_of_val(&one) as _,
                        );
                    }

                    // Flush and shutdown TLS session properly
                    ktls_stream.flush().await.expect("Could not flush");
                    ktls_stream.shutdown().await.expect("Could not shutdown");
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
    let _res = req.parse(&dst).expect("err").unwrap();

    // TODO: should be some fixed size and be able to handle large files.
    let mut ring = IoUring::new(128)?;
    match req.path {
        None => return Ok(()),
        Some("/") => {
            let (mut p_reader, mut p_writer) = pipe().expect("cound not create pipe");
            let file = FileToServe::from_str("/index.html").expect("err");
            http_read_file(file, &mut ring, stream, &mut p_reader, &mut p_writer).expect("err");
            if let Err(e) = stream.flush().await {
                error!("Failed to flush TLS stream: {}", e);
            }
        }
        Some(p) => {
            info!("path is: {p}");
            let (mut p_reader, mut p_writer) = pipe().expect("cound not create pipe");
            let file = FileToServe::from_str(p).expect("err");
            info!("{:?}", file);
            http_read_file(file, &mut ring, stream, &mut p_reader, &mut p_writer).expect("err");
            if let Err(e) = stream.flush().await {
                error!("Failed to flush TLS stream: {}", e);
            }
        }
    }

    Ok(())
}

fn http_read_file(
    file: FileToServe,
    ring: &mut IoUring,
    stream: &mut KtlsStream<TcpStream>,
    pipe_r: &mut PipeReader,
    pipe_w: &mut PipeWriter,
) -> Result<(), ReadFileErr> {
    if let Err(e) = open_file(ring, &file.path) {
        error!("FAILED TO OPEN FILE!");
        return Err(e);
    };

    let mut statx: MaybeUninit<statx> = MaybeUninit::uninit();
    let statx_ptr: NonNull<statx> = unsafe { NonNull::new_unchecked(statx.as_mut_ptr()) };
    if let Err(e) = statx_file(ring, &file.path, statx_ptr) {
        error!("FAILED TO STATX FILE!");
        return Err(e);
    };

    let Ok((fd, file_size)) = get_fd_and_size(ring, statx_ptr) else {
        error!("FAILED TO WRITE FILE!");
        panic!();
    };
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

    if let Err(e) = unsafe { ring.submission().push(&statx_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }
    Ok(())
}

#[derive(Debug)]
enum ReadFileErr {
    FailedPush,
    OpenAt,
    Statx,
    // NoSubmission,
    Submission,
}

type StatxSize = u64;

fn get_fd_and_size(
    ring: &mut IoUring,
    statx_ptr: NonNull<statx>,
) -> Result<(types::Fd, StatxSize), ReadFileErr> {
    if let Err(_) = ring.submit_and_wait(2) {
        return Err(ReadFileErr::Submission);
    };

    let Some(openat_cqe) = ring.completion().next() else {
        panic!();
    };

    let fd = match openat_cqe.result() {
        // TODO: should it advance the submission queue as well???
        err if err < 0 => return Err(ReadFileErr::OpenAt),
        fd => types::Fd(fd),
    };

    let Some(statx_cqe) = ring.completion().next() else {
        panic!();
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
    let pipe_size = *PIPE_DEFAULT_SIZE
        .get_or_init(|| set_pipe_size(pipe_r.as_raw_fd(), pipe_w.as_raw_fd()))
        as usize;
    let mut total_sub = 0;
    let header_buffer = send_header(ring, types::Fd(stream.as_raw_fd()), file, file_size)?;
    total_sub += 1;

    let mut offsets: Vec<(u32, u32)> = Vec::new();

    for (idx, offset) in (0..file_size).step_by(pipe_size).enumerate() {
        let remaining = file_size.saturating_sub(offset);
        let len = remaining.min(pipe_size as u64) as u32;
        // submit enough requests to send the whole file.
        // WARNING: This can overflow the io_uring submission queue.
        let idx = idx * 2;
        info!("idx: {}", idx);
        let mut flags = SPLICE_F_MOVE | SPLICE_F_MORE;
        if remaining == 0 {
            flags = SPLICE_F_MOVE;
        }

        spliced_read(ring, fd, pipe_w, offset as i64, len, idx as u64, flags)?;
        total_sub += 1;
        offsets.push((offset as u32, len));
        spliced_write(
            ring,
            types::Fd(stream.as_raw_fd()),
            pipe_r,
            len,
            idx as u64 + 1,
            flags,
        )?;
        total_sub += 1;
        offsets.push((offset as u32, len));
    }
    close_file(ring, fd)?;
    total_sub += 1;

    loop {
        info!("starting to wait");
        match ring.submit_and_wait(total_sub) {
            Err(_e) => {
                info!("ERROR WHEN WAITING FOR SUBMISSIONS");
                return Err(ReadFileErr::Submission);
            }
            Ok(i) => {
                info!(
                    "COMPLETED WAITING FOR SUBMISSIONS {i}, {total_sub}, {}",
                    offsets.capacity()
                );
            }
        }

        let prev_total_sub = total_sub;
        total_sub = 0;

        let mut failed_idx = None;
        for _ in 0..prev_total_sub {
            let cqe = ring.completion().next().unwrap();
            info!("{:?}", cqe);

            match cqe.user_data() {
                i if i == u64::MAX => {
                    // open
                }
                i if i == u64::MAX - 1 => {
                    // close
                    if failed_idx.is_some() {
                        close_file(ring, fd)?;
                        total_sub += 1;
                    }
                }
                idx if idx % 2 == 0 => {
                    // read splice
                    if cqe.result() < 0 {
                        let mut flags = SPLICE_F_MOVE | SPLICE_F_MORE;
                        if idx == offsets.len() as u64 - 1 {
                            flags = SPLICE_F_MOVE;
                        }
                        let (offset, len) = offsets[idx as usize];
                        spliced_read(ring, fd, pipe_w, offset as i64, len, idx as u64, flags)?;
                        total_sub += 1;
                    }
                }
                idx if idx % 2 == 1 => {
                    // write splice
                    if cqe.result() < 0 {
                        let (_, len) = offsets[idx as usize];
                        let mut flags = SPLICE_F_MOVE | SPLICE_F_MORE;
                        if idx == offsets.len() as u64 - 1 {
                            flags = SPLICE_F_MOVE;
                        }
                        spliced_write(
                            ring,
                            types::Fd(stream.as_raw_fd()),
                            pipe_r,
                            len,
                            idx as u64,
                            flags,
                        )?;
                        total_sub += 1;

                        if let None = failed_idx {
                            failed_idx = Some(idx);
                        }
                    } else {
                        let (_, len) = offsets[idx as usize];
                        if cqe.result() < len as i32 {
                            let mut flags = SPLICE_F_MOVE | SPLICE_F_MORE;
                            if idx == offsets.len() as u64 - 1 {
                                flags = SPLICE_F_MOVE;
                            }
                            spliced_write(
                                ring,
                                types::Fd(stream.as_raw_fd()),
                                pipe_r,
                                len - cqe.result() as u32,
                                idx as u64,
                                flags,
                            )?;
                            total_sub += 1;

                            if let None = failed_idx {
                                failed_idx = Some(idx);
                            }
                        }
                    }
                }
                _ => todo!(),
            }
        }

        if failed_idx == None {
            break;
        }
    }
    info!("COMPLETED SEND OF {:?}!", file.path);

    drop(header_buffer);
    Ok(())
}

fn spliced_read(
    ring: &mut IoUring,
    fd_read: types::Fd,
    pipe_w: &mut PipeWriter,
    offset: i64,
    len: u32,
    read_id: u64,
    flags: u32,
) -> Result<(), ReadFileErr> {
    let splice_read_e = opcode::Splice::new(
        fd_read,
        offset as i64,
        types::Fd(pipe_w.as_raw_fd()),
        -1,
        len,
    )
    .flags(flags)
    .build()
    .user_data(read_id)
    .flags(Flags::IO_LINK);
    info!("read req: {:?}", splice_read_e);

    if let Err(e) = unsafe { ring.submission().push(&splice_read_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }

    return Ok(());
}

fn spliced_write(
    ring: &mut IoUring,
    fd_write: types::Fd,
    pipe_r: &mut PipeReader,
    len: u32,
    write_id: u64,
    flags: u32,
) -> Result<(), ReadFileErr> {
    let splice_write_e = opcode::Splice::new(types::Fd(pipe_r.as_raw_fd()), -1, fd_write, -1, len)
        .flags(flags)
        .build()
        .user_data(write_id)
        .flags(Flags::IO_LINK);

    info!("write req: {:?}", splice_write_e);

    if let Err(e) = unsafe { ring.submission().push(&splice_write_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }
    return Ok(());
}

fn close_file(ring: &mut IoUring, fd: types::Fd) -> Result<(), ReadFileErr> {
    let close_e = opcode::Close::new(fd).build().user_data(u64::MAX - 1);

    if let Err(e) = unsafe { ring.submission().push(&close_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }
    return Ok(());
}

fn send_header(
    ring: &mut IoUring,
    fd: types::Fd,
    file: &FileToServe,
    length: StatxSize,
) -> Result<String, ReadFileErr> {
    // TODO: maybe switch to http2 for concurrent requests
    let path = &file.path;
    let response_buffer = format!(
        "HTTP/1.1 200 OK\r\n\
Content-Type: {content_type}\r\n\
Content-Length: {length}\r\n\
Content-Disposition: inline; filename=\"{filename}\"\r\n\
Cache-Control: no-cache\r\n\
Server: FastFileServer/1.0\r\n\
\r\n",
        content_type = file.get_http_content_type(),
        length = length,
        filename = path.to_str().unwrap(),
    );

    info!("{}", response_buffer);

    let send_e = opcode::Send::new(fd, response_buffer.as_ptr(), response_buffer.len() as u32)
        .build()
        .user_data(u64::MAX)
        .flags(Flags::IO_LINK);

    if let Err(e) = unsafe { ring.submission().push(&send_e) } {
        error!("Submission error: {e}");
        return Err(ReadFileErr::FailedPush);
    }
    // WARNING: don't drop the buffer before completion of the send
    return Ok(response_buffer);
}
