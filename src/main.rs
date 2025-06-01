use io_uring::squeue::Flags;
use io_uring::{IoUring, opcode, types};
use ktls::{CorkStream, KtlsStream, config_ktls_server};
use libc::{AT_FDCWD, O_RDONLY, SPLICE_F_MORE, SPLICE_F_MOVE, STATX_SIZE, splice, statx};
use log::{error, info};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use simple_logger::SimpleLogger;
use std::ffi::{CStr, CString};
use std::io::{PipeReader, PipeWriter, pipe};
use std::mem::MaybeUninit;
use std::os::fd::IntoRawFd;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr::{NonNull, null_mut};
use std::sync::{Arc, OnceLock};
use std::{env, io, u64};
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
    return (size.min(size2)).min(2_i32.pow(14)) as u32;
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        error!("Usage: {} <address> <port>", args[0]);
        std::process::exit(1);
    }

    let address = &args[1];
    let port = &args[2];

    let conf = tls_config();
    let _ = tcp_listener(conf, address, port).await;
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

async fn tcp_listener(
    config: ServerConfig,
    address: &String,
    port: &String,
) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    // let acceptor = Rc::new(acceptor);

    let full_addr = format!("{}:{}", address, port);
    info!("Listening on: https://{}", full_addr);
    let listener = TcpListener::bind(full_addr.as_str()).await.unwrap();

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

                    let (drained, mut stream) = ktls_stream.into_raw();
                    info!("drained: {:?}", drained);
                    let drained = drained.unwrap_or_default();

                    info!("{} bytes already decoded by rustls", drained.len());

                    // let one: libc::c_int = 1;
                    // unsafe {
                    //     libc::setsockopt(
                    //         ktls_stream.as_raw_fd(),
                    //         libc::SOL_TCP,
                    //         libc::TCP_CORK,
                    //         &one as *const _ as *const _,
                    //         std::mem::size_of_val(&one) as _,
                    //     );
                    // }
                    handle_client(&mut stream, drained.clone())
                        .await
                        .expect("ERROR");

                    info!("READING");
                    // let mut dst: [u8; 1024] = [0; 1024];
                    // let n_bytes = stream.read(&mut dst).await.expect("err");
                    // info!("{:?}", String::from_utf8(dst.to_vec()));
                    // info!("{}", n_bytes);
                    info!("FINISHED SENDING FILE!");
                    let x = stream.flush().await;
                    info!("FINISHED flushing {:?}!", x);

                    let x = stream.shutdown().await;

                    info!("SHUTDOWN!, {:?}", x);
                    drop(drained);
                    // let one: libc::c_int = 0;
                    // unsafe {
                    //     libc::setsockopt(
                    //         ktls_stream.as_raw_fd(),
                    //         libc::SOL_TCP,
                    //         libc::TCP_CORK,
                    //         &one as *const _ as *const _,
                    //         std::mem::size_of_val(&one) as _,
                    //     );
                    // }

                    // Flush and shutdown TLS session properly
                    // ktls_stream.flush().await.expect("Could not flush");
                    // ktls_stream.shutdown().await.expect("Could not shutdown");
                    // let mut retries = 3;
                    // while retries > 0 {
                    //     info!("FLUSHING!");
                    //     match ktls_stream.flush().await {
                    //         Ok(_) => break,
                    //         Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    //             retries -= 1;
                    //             use tokio::time::{Duration, sleep};
                    //             sleep(Duration::from_millis(100)).await;
                    //         }
                    //         Err(e) => {
                    //             eprintln!("Flush failed permanently: {}", e);
                    //             break;
                    //         }
                    //     }
                    // }
                    // let mut retries = 3;
                    // while retries > 0 {
                    //     info!("SHUTDOWN!");
                    //     match ktls_stream.shutdown().await {
                    //         Ok(_) => break,
                    //         Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    //             retries -= 1;
                    //             use tokio::time::{Duration, sleep};
                    //             sleep(Duration::from_millis(100)).await;
                    //         }
                    //         Err(e) => {
                    //             eprintln!("shutdown failed permanently: {}", e);
                    //             break;
                    //         }
                    //     }
                    // }
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

async fn handle_client(stream: &mut TcpStream, drained: Vec<u8>) -> io::Result<()> {
    // let mut dst: [u8; 1024] = [0; 1024];
    // let n_bytes = stream.read(&mut dst).await.expect("err");
    // info!("{:?}", String::from_utf8(dst.to_vec()));
    // info!("{}", n_bytes);
    info!("http raw req: {:?}", String::from_utf8(drained.to_vec()));

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    // let _res = req.parse(&dst).expect("err").unwrap();
    let _res = req.parse(&drained).expect("err").unwrap();

    // TODO: should be some fixed size and be able to handle large files.
    let mut ring = IoUring::new(1024)?;
    match req.path {
        None => return Ok(()),
        Some("/") => {
            let (mut p_reader, mut p_writer) = pipe().expect("cound not create pipe");

            set_nonblocking(p_reader.as_raw_fd())?;
            set_nonblocking(p_writer.as_raw_fd())?;

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

fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        println!("FLAGS: {}", flags);
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn http_read_file(
    file: FileToServe,
    ring: &mut IoUring,
    stream: &mut TcpStream,
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

    // TODO: might already be opened by another thread?
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
    stream: &mut TcpStream,
    fd: types::Fd,
    file_size: StatxSize,
    file: &FileToServe,
    pipe_r: &mut PipeReader,
    pipe_w: &mut PipeWriter,
) -> Result<(), ReadFileErr> {
    let pipe_size = *PIPE_DEFAULT_SIZE
        .get_or_init(|| set_pipe_size(pipe_r.as_raw_fd(), pipe_w.as_raw_fd()))
        as usize;
    let mut num_sqe = 0;
    // send header keep buffer untill it has been confirmed it is sent
    let header_buffer = send_header(ring, types::Fd(stream.as_raw_fd()), file, file_size)?;
    let _res = ring.submit_and_wait(1).expect("err");
    // TODO: should be part of the first uring splice
    let cqe = ring.completion().next().unwrap();
    num_sqe += 1;

    // written to pipe <= written to socket
    // If written to pipe >= pipe_size, then a splice from pipe to socket should occur before the splice from file to pipe.
    let mut written_to_pipe = 0;
    let mut written_to_socket = 0;

    while written_to_socket < file_size as usize {
        info!("socket: {written_to_socket}, file: {written_to_pipe}");
        info!("num_sqe before: {num_sqe}");
        num_sqe += add_splice_sqes(
            ring,
            fd,
            pipe_w,
            types::Fd(stream.as_raw_fd()),
            pipe_r,
            written_to_pipe,
            written_to_socket,
            file_size as usize,
        )?;

        info!("starting to wait for {num_sqe}");
        // let res = ring.submit_and_wait(num_sqe).expect("err");
        // info!("COMPLETED WAITING FOR SUBMISSIONS {res}, {num_sqe}");

        // for cqe in ring.completion() {
        //     info!("{:?}", cqe);

        //     match (cqe.user_data(), cqe.result()) {
        //         (u64::MAX, r) if r < 0 => {
        //             // send header again
        //             todo!();
        //         }
        //         (id, r) if id % 2 == 0 && r > 0 => {
        //             // file -> pipe
        //             written_to_pipe += r as usize;
        //         }
        //         (id, r) if id % 2 == 1 && r > 0 => {
        //             // pipe -> socket
        //             written_to_socket += r as usize;
        //         }
        //         _ => {
        //             continue;
        //         }
        //     }
        // }
        break;
    }
    // TODO: can close while other use it?
    close_file(ring, fd)?;
    let _res = ring.submit_and_wait(1).expect("err");
    drop(header_buffer);
    Ok(())
}

fn write_response_and_close2(
    ring: &mut IoUring,
    stream: &mut TcpStream,
    fd: types::Fd,
    file_size: StatxSize,
    file: &FileToServe,
    pipe_r: &mut PipeReader,
    pipe_w: &mut PipeWriter,
) -> Result<(), ReadFileErr> {
    let pipe_size = *PIPE_DEFAULT_SIZE
        .get_or_init(|| set_pipe_size(pipe_r.as_raw_fd(), pipe_w.as_raw_fd()))
        as usize;
    let mut num_sqe = 0;
    // send header keep buffer untill it has been confirmed it is sent
    let header_buffer = send_header(ring, types::Fd(stream.as_raw_fd()), file, file_size)?;
    num_sqe += 1;

    // written to pipe <= written to socket
    // If written to pipe >= pipe_size, then a splice from pipe to socket should occur before the splice from file to pipe.
    let mut written_to_pipe = 0;
    let mut written_to_socket = 0;

    while written_to_socket < file_size as usize {
        info!("socket: {written_to_socket}, file: {written_to_pipe}");
        info!("num_sqe before: {num_sqe}");
        num_sqe += add_splice_sqes2(
            ring,
            fd,
            pipe_w,
            types::Fd(stream.as_raw_fd()),
            pipe_r,
            written_to_pipe,
            written_to_socket,
            file_size as usize,
        )?;

        info!("starting to wait for {num_sqe}");
        let res = ring.submit_and_wait(num_sqe).expect("err");
        info!("COMPLETED WAITING FOR SUBMISSIONS {res}, {num_sqe}");

        for cqe in ring.completion() {
            info!("{:?}", cqe);

            match (cqe.user_data(), cqe.result()) {
                (u64::MAX, r) if r < 0 => {
                    // send header again
                    todo!();
                }
                (id, r) if id % 2 == 0 && r > 0 => {
                    // file -> pipe
                    written_to_pipe += r as usize;
                }
                (id, r) if id % 2 == 1 && r > 0 => {
                    // pipe -> socket
                    written_to_socket += r as usize;
                }
                _ => {
                    continue;
                }
            }
        }
        num_sqe = 0;
    }
    // TODO: can close while other use it?
    close_file(ring, fd)?;
    let _res = ring.submit_and_wait(1).expect("err");
    drop(header_buffer);
    Ok(())
}

fn add_splice_sqes_working(
    _ring: &mut IoUring, // unused if you're not submitting SQEs
    fd_read: types::Fd,
    pipe_w: &mut PipeWriter,
    fd_write: types::Fd,
    pipe_r: &mut PipeReader,
    written_to_pipe: usize,
    written_to_socket: usize,
    file_size: usize,
) -> Result<usize, ReadFileErr> {
    let pipe_size =
        *PIPE_DEFAULT_SIZE.get_or_init(|| set_pipe_size(pipe_r.as_raw_fd(), pipe_w.as_raw_fd()));
    let mut num_sqe = 0;
    let flags = libc::SPLICE_F_MOVE;

    let mut offset = written_to_socket;
    while offset < file_size {
        let remaining = file_size - offset;
        let chunk_size = pipe_size.min(remaining.try_into().unwrap());

        // Splice from file -> pipe
        let mut spliced_in = 0;
        while spliced_in < chunk_size {
            let len = chunk_size - spliced_in;
            let n = unsafe {
                libc::splice(
                    fd_read.0,
                    std::ptr::null_mut(),
                    pipe_w.as_raw_fd(),
                    std::ptr::null_mut(),
                    len.try_into().unwrap(),
                    flags,
                )
            };
            if n == -1 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EINTR {
                    continue;
                } else {
                    return Err(ReadFileErr::OpenAt);
                }
            }
            spliced_in += n as u32;
        }

        // Splice from pipe -> socket
        let mut spliced_out = 0;
        while spliced_out < spliced_in {
            let len = spliced_in - spliced_out;
            let n = unsafe {
                libc::splice(
                    pipe_r.as_raw_fd(),
                    std::ptr::null_mut(),
                    fd_write.0,
                    std::ptr::null_mut(),
                    len.try_into().unwrap(),
                    flags,
                )
            };
            if n == -1 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EINTR {
                    continue;
                } else {
                    return Err(ReadFileErr::OpenAt);
                }
            }
            spliced_out += n as u32;
        }

        offset += spliced_out as usize;
        num_sqe += 2; // one for read, one for write
    }

    Ok(num_sqe)
}

fn add_splice_sqes(
    ring: &mut IoUring, // unused if you're not submitting SQEs
    fd_read: types::Fd,
    pipe_w: &mut PipeWriter,
    fd_write: types::Fd,
    pipe_r: &mut PipeReader,
    written_to_pipe: usize,
    written_to_socket: usize,
    file_size: usize,
) -> Result<usize, ReadFileErr> {
    let pipe_size =
        *PIPE_DEFAULT_SIZE.get_or_init(|| set_pipe_size(pipe_r.as_raw_fd(), pipe_w.as_raw_fd()));
    let mut num_sqe = 0;
    let flags = libc::SPLICE_F_MOVE;

    let mut offset = written_to_socket;
    while offset < file_size {
        let remaining = file_size - offset;
        info!("remaining: {}", remaining);
        let chunk_size = pipe_size.min(remaining.try_into().unwrap());

        // Splice from file -> pipe
        let mut spliced_in = 0;
        while spliced_in < chunk_size {
            let len = chunk_size - spliced_in;
            // let n = unsafe {
            //     libc::splice(
            //         fd_read.0,
            //         std::ptr::null_mut(),
            //         pipe_w.as_raw_fd(),
            //         std::ptr::null_mut(),
            //         len.try_into().unwrap(),
            //         flags,
            //     )
            // };

            spliced_read(ring, fd_read, pipe_w, len, 0, flags)?;
            // spliced_write(ring, fd_write, pipe_r, len as u32, 0, flags)?;
            let res = ring.submit_and_wait(1).expect("err");
            let cqe = ring.completion().next().unwrap();
            info!("{:?}", cqe);
            let n = cqe.result();
            if n < 0 {
                let e: SpliceError = (-n).into();
                info!("{:?}", e);
                continue;
            }
            spliced_in += n as u32;
        }
        info!("spliced in: {spliced_in}");

        // Splice from pipe -> socket
        let mut spliced_out = 0;
        while spliced_out < spliced_in {
            let len = spliced_in - spliced_out;

            spliced_write(ring, fd_write, pipe_r, len as u32, 0, flags)?;
            let res = ring.submit_and_wait(1).expect("err");
            let cqe = ring.completion().next().unwrap();
            info!("{:?}", cqe);
            let n = cqe.result();
            if n < 0 {
                let e: SpliceError = (-n).into();
                info!("{:?}", e);
                continue;
            }
            spliced_out += n as u32;
        }
        info!("spliced out: {spliced_out}");

        offset += spliced_out as usize;
        num_sqe += 2; // one for read, one for write
        info!("written to socket");
    }

    Ok(num_sqe)
}

#[derive(Debug)]
enum SpliceError {
    EAGAIN,
    EBADF,
    EINVAL,
    ENOMEM,
    ESPIPE,
}

impl From<i32> for SpliceError {
    fn from(value: i32) -> Self {
        match value {
            libc::EAGAIN => SpliceError::EAGAIN,
            libc::EBADF => SpliceError::EBADF,
            libc::EINVAL => SpliceError::EINVAL,
            libc::ENOMEM => SpliceError::ENOMEM,
            libc::ESPIPE => SpliceError::ESPIPE,
            _ => todo!(),
        }
    }
}

fn add_splice_sqes2(
    ring: &mut IoUring,
    fd_read: types::Fd,
    pipe_w: &mut PipeWriter,
    fd_write: types::Fd,
    pipe_r: &mut PipeReader,
    written_to_pipe: usize,
    written_to_socket: usize,
    file_size: usize,
) -> Result<usize, ReadFileErr> {
    let pipe_size =
        *PIPE_DEFAULT_SIZE.get_or_init(|| set_pipe_size(pipe_r.as_raw_fd(), pipe_w.as_raw_fd()));
    let mut id = 0;
    let flags = 0;

    // written to pipe <= written to socket always.
    //
    // If written to pipe >= pipe_size,
    // then a splice from pipe to socket should
    // occur before the splice from file to pipe.
    let in_pipe = written_to_pipe - written_to_socket;
    if in_pipe > 0 {
        // writes are odd numbered
        id += 1;
        spliced_write(ring, fd_write, pipe_r, pipe_size as u32, id, flags)?;
        id += 1;
    }

    for offset in (written_to_pipe..file_size).step_by(pipe_size as usize) {
        let remaining = file_size.saturating_sub(offset);
        let len = remaining.min(pipe_size as usize) as u32;
        // submit enough requests to send the whole file.
        // WARNING: This can overflow the io_uring submission queue.
        let mut flags = SPLICE_F_MOVE | SPLICE_F_MORE;
        if remaining == 0 {
            flags = SPLICE_F_MOVE;
        }

        spliced_read(ring, fd_read, pipe_w, len, id as u64, flags)?;
        id += 1;
        spliced_write(ring, fd_write, pipe_r, pipe_size, id, flags)?;
        id += 1;
    }
    return Ok(id as usize);
}

fn spliced_read(
    ring: &mut IoUring,
    fd_read: types::Fd,
    pipe_w: &mut PipeWriter,
    len: u32,
    read_id: u64,
    flags: u32,
) -> Result<(), ReadFileErr> {
    let splice_read_e = opcode::Splice::new(fd_read, -1, types::Fd(pipe_w.as_raw_fd()), -1, len)
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
