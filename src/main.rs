use io_uring::{IoUring, opcode, types};
use std::ffi::CStr;
use std::io::{Read, pipe, stdout};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::{fs, io};

fn main() -> io::Result<()> {
    tcp_listener()
}

fn handle_client(stream: TcpStream) -> io::Result<()> {
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
        types::Fd(stdout().as_raw_fd()),
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

fn tcp_listener() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:12345")?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        handle_client(stream?);
    }
    Ok(())
}
