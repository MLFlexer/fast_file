use io_uring::{IoUring, opcode, types};
use std::ffi::CStr;
use std::io::{Read, pipe, stdout};
use std::os::unix::io::AsRawFd;
use std::{fs, io};

fn main() -> io::Result<()> {
    let mut ring = IoUring::new(8)?;

    let fd = fs::File::open("README.md")?;
    let mut buf = vec![0; 1024];

    let read_e = opcode::Read::new(types::Fd(fd.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _)
        .build()
        .user_data(0x42);

    // Note that the developer needs to ensure
    // that the entry pushed into submission queue is valid (e.g. fd, buffer).
    unsafe {
        ring.submission()
            .push(&read_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1)?;

    let cqe = ring.completion().next().expect("completion queue is empty");

    assert_eq!(cqe.user_data(), 0x42);
    assert!(cqe.result() >= 0, "read error: {}", cqe.result());
    println!("{:?}", cqe);

    let write_e = opcode::Write::new(types::Fd(stdout().as_raw_fd()), buf.as_ptr(), 1024)
        .build()
        .user_data(69);
    unsafe {
        ring.submission()
            .push(&write_e)
            .expect("submission queue is full");
    }

    ring.submit_and_wait(1)?;

    let cqe = ring.completion().next().expect("completion queue is empty");

    println!("{:?}", cqe);

    let (p_reader, p_writer) = pipe().expect("cound not create pipe");

    let splice_read_e = opcode::Splice::new(
        types::Fd(fd.as_raw_fd()),
        0,
        types::Fd(p_writer.as_raw_fd()),
        -1,
        12,
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
        12,
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
