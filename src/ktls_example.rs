//! This is a simple server using rustls' unbuffered API. Meaning that the application layer must
//! handle the buffers required to receive, process and send TLS data.

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use io_uring::{IoUring, opcode, types};
use ktls::KtlsStream;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, InsufficientSizeError,
    UnbufferedStatus,
};
use tokio::io::AsyncReadExt;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args();
    args.next();
    let cert_file = args.next().expect("missing certificate file argument");
    let private_key_file = args.next().expect("missing private key file argument");

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(cert_file)?, load_private_key(private_key_file)?)?;

    if let Some(max_early_data_size) = MAX_EARLY_DATA_SIZE {
        config.max_early_data_size = max_early_data_size;
    }

    config.max_fragment_size = MAX_FRAGMENT_SIZE;

    let mut config = Arc::new(config);
    Arc::get_mut(&mut config).unwrap().enable_secret_extraction = true;

    let listener = TcpListener::bind(format!("[::]:{PORT}"))?;

    let mut ring = IoUring::new(IO_URING_SIZE)?;
    let mut connection_map: HashMap<i32, ConnectionEntry> = HashMap::new();

    accept_multi(listener.as_raw_fd(), &mut ring);

    if let Err(_) = ring.submit() {
        todo!();
    };
    // if let Err(_) = ring.submit_and_wait(1) {
    //     todo!();
    // };

    // let Some(conn_cqe) = ring.completion().next() else {
    //     todo!();
    // };
    // println!("conn_cqe: {:?}", conn_cqe);
    // let stream = unsafe { TcpStream::from_raw_fd(conn_cqe.result()) };
    handle(&config, &mut connection_map, &mut ring)?;
    // println!("{:?}", listener);

    // for stream in listener.incoming() {
    // TODO: use accept multishot to auto accept connections.
    // handle(stream?, &config, &mut connection_map, &mut ring)?;
    // }

    Ok(())
}

#[derive(Debug)]
enum UserData {
    NewConn,
    Conn(i32),
    SendZC(i32),
    HandshakeRecv(i32),
    Recv(i32),
}

impl From<UserData> for u64 {
    fn from(value: UserData) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl From<u64> for UserData {
    fn from(value: u64) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

struct ConnectionEntry {
    buffer: Vec<u8>,
    out_buffer: Vec<u8>,
    conn: UnbufferedServerConnection,
}

impl ConnectionEntry {
    fn new(config: &Arc<ServerConfig>) -> Self {
        let mut buffer = Vec::with_capacity(INCOMING_TLS_BUFSIZE);
        buffer.resize(INCOMING_TLS_BUFSIZE, 0);
        // unsafe { buffer.set_len(INCOMING_TLS_BUFSIZE) };
        // buffer.fill(0);
        ConnectionEntry {
            buffer: buffer,
            out_buffer: Vec::new(),
            conn: UnbufferedServerConnection::new(config.clone())
                .expect("Error when creating new UnbufferedServerConnection!"),
        }
    }
}

fn handle(
    config: &Arc<ServerConfig>,
    connection_map: &mut HashMap<i32, ConnectionEntry>,
    ring: &mut IoUring,
) -> Result<(), Box<dyn Error>> {
    // TODO: should sometime upgrade connection to: https://docs.rs/rustls/latest/rustls/kernel/index.html
    loop {
        if let Err(_) = ring.submit_and_wait(1) {
            todo!();
        };
        let Some(cqe) = ring.completion().next() else {
            continue;
        };
        println!("{:?}", cqe);
        let user_data: UserData = cqe.user_data().into();
        println!("{:?}", user_data);
        match cqe.user_data().into() {
            UserData::Recv(id) => {
                let Some(ce) = connection_map.remove(&id) else {
                    todo!()
                };

                let (secrets, kernel_conn) = ce.conn.dangerous_into_kernel_connection()?;

                // TODO: make into io uring
                let ulp_name = std::ffi::CString::new("tls").unwrap();
                let ret = unsafe {
                    libc::setsockopt(
                        id,
                        libc::SOL_TCP,
                        libc::TCP_ULP,
                        ulp_name.as_ptr() as *const std::ffi::c_void,
                        ulp_name.as_bytes().len() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    panic!("failed with {ret}, {}", io::Error::last_os_error());
                }
                let tx = ktls::CryptoInfo::from_rustls(
                    kernel_conn.negotiated_cipher_suite(),
                    secrets.tx,
                )?;
                // TODO: make into io uring
                let ret = unsafe {
                    libc::setsockopt(id, libc::SOL_TLS, libc::TLS_TX, tx.as_ptr(), tx.size() as _)
                };
                if ret < 0 {
                    panic!("failed with {ret}, {}", io::Error::last_os_error());
                }

                let rx = ktls::CryptoInfo::from_rustls(
                    kernel_conn.negotiated_cipher_suite(),
                    secrets.rx,
                )?;
                // TODO: make into io uring
                let ret = unsafe {
                    libc::setsockopt(id, libc::SOL_TLS, libc::TLS_RX, rx.as_ptr(), rx.size() as _)
                };
                if ret < 0 {
                    panic!("failed with {ret}, {}", io::Error::last_os_error());
                }
                println!("KERNEL TLS ACTIVATED!");
            }
            UserData::NewConn => {
                let id = cqe.result();
                connection_map.insert(id, ConnectionEntry::new(&config));
                let ce = connection_map.get_mut(&id).unwrap();
                let UnbufferedStatus { mut discard, state } =
                    ce.conn.process_tls_records(&mut ce.buffer[..0]);

                println!("{:?}", state);
                match state.unwrap() {
                    ConnectionState::BlockedHandshake { .. } => {
                        recv_tls_handshake(id, &mut ce.buffer, &mut 0, ring)?;
                    }
                    _ => todo!(),
                }
            }
            UserData::HandshakeRecv(id) => {
                let mut to_write = 0;
                let mut res = cqe.result() as usize;
                for i in 0..30 {
                    let ce = connection_map.get_mut(&id).unwrap();
                    println!("buffer: {:?}", ce.buffer[..res].iter().clone());
                    println!("out buffer: {:?}", ce.out_buffer[..to_write].iter().clone());
                    let UnbufferedStatus { mut discard, state } =
                        ce.conn.process_tls_records(&mut ce.buffer[..res]);

                    println!("{:?}", state);
                    println!("discard: {:?}", discard);
                    println!("written: {:?}", to_write);
                    match state.unwrap() {
                        ConnectionState::EncodeTlsData(mut state) => {
                            try_or_resize_and_retry(
                                |out_buffer| state.encode(out_buffer),
                                |e| {
                                    if let EncodeError::InsufficientSize(is) = &e {
                                        Ok(*is)
                                    } else {
                                        Err(e.into())
                                    }
                                },
                                &mut ce.out_buffer,
                                &mut to_write,
                            )?;
                        }
                        ConnectionState::TransmitTlsData(s) => {
                            send_tls_uring(id, &mut ce.out_buffer, to_write, ring);
                            // TODO: should it be done before
                            s.done();
                            println!("Written tls");
                            break;
                        }
                        ConnectionState::ReadTraffic(mut state) => {
                            while let Some(res) = state.next_record() {
                                let AppDataRecord {
                                    discard: new_discard,
                                    payload,
                                } = res?;
                                discard += new_discard;

                                if payload.starts_with(b"GET") {
                                    let response = core::str::from_utf8(payload)?;
                                    let header = response.lines().next().unwrap_or(response);

                                    println!("{header}");
                                } else {
                                    // println!("(.. continued HTTP request ..)");
                                }
                            }

                            if !ce.conn.is_handshaking() {
                                println!("HANDSHAKE IS DONE!");
                                // let x = ce.conn.dangerous_into_kernel_connection();
                                // match x {
                                //     Ok((secrets, kernel_conn)) => {}
                                //     _ => todo!(),
                                // }
                            } else {
                                todo!()
                            }
                        }

                        _ => todo!(),
                    }

                    // TODO: do we really need to fill the discarded with 0? or can we ignore?
                    // This cannot be done rn
                    if discard != 0 {
                        ce.buffer.copy_within(discard..res, 0);
                        res -= discard;

                        eprintln!("discarded {discard}B from `incoming_tls`");
                    }
                    println!("\nnext {i}");
                }
            }
            UserData::SendZC(id) => {
                if io_uring::cqueue::more(cqe.flags()) {
                    println!("sendzc: cqe with more to come: {:?}", cqe);
                } else {
                    println!("sendzc: {:?}", cqe);

                    let ce = connection_map.get_mut(&id).unwrap();
                    println!("buffer sendzc: {:?}", ce.buffer[..85].iter().clone());
                    // println!("out buffer: {:?}", ce.out_buffer);
                    // ce.out_buffer.fill(0);
                    let UnbufferedStatus { mut discard, state } =
                        ce.conn.process_tls_records(&mut ce.buffer[..0]);

                    println!("{:?}", state);
                    match state.unwrap() {
                        ConnectionState::BlockedHandshake { .. } => {
                            // s.done();
                            recv_tls_handshake(id, &mut ce.buffer, &mut 0, ring)?;
                        }
                        ConnectionState::WriteTraffic(mut state) => {
                            if !ce.conn.is_handshaking() {
                                println!("HANDSHAKE IS DONE DRAINING!");
                                recv_tls(id, &mut ce.buffer, ring)?;
                            } else {
                                todo!();
                            }
                        }
                        a => {
                            println!("not implemented {:?}", a);
                            todo!()
                        }
                    }
                }
            }

            a => {
                println!("not implemented {:?}", a);
                todo!()
            }
        }

        println!("\nnext");
    }
}

fn try_or_resize_and_retry<E>(
    mut f: impl FnMut(&mut [u8]) -> Result<usize, E>,
    map_err: impl FnOnce(E) -> Result<InsufficientSizeError, Box<dyn Error>>,
    outgoing_tls: &mut Vec<u8>,
    outgoing_used: &mut usize,
) -> Result<usize, Box<dyn Error>>
where
    E: Error + 'static,
{
    // println!("resize start");
    let written = match f(&mut outgoing_tls[*outgoing_used..]) {
        Ok(written) => written,

        Err(e) => {
            let InsufficientSizeError { required_size } = map_err(e)?;
            let new_len = *outgoing_used + required_size;
            outgoing_tls.resize(new_len, 0);
            // eprintln!("resized `outgoing_tls` buffer to {new_len}B");

            f(&mut outgoing_tls[*outgoing_used..])?
        }
    };
    // println!("resize end");

    *outgoing_used += written;

    Ok(written)
}

fn try_or_resize_and_retry_new<E>(
    mut f: impl FnMut(&mut [u8]) -> Result<usize, E>,
    map_err: impl FnOnce(E) -> Result<InsufficientSizeError, Box<dyn Error>>,
    outgoing_tls: &mut Vec<u8>,
) -> Result<usize, Box<dyn Error>>
where
    E: Error + 'static,
{
    let written = match f(&mut outgoing_tls[0..]) {
        Ok(written) => written,

        Err(e) => {
            let InsufficientSizeError { required_size } = map_err(e)?;
            let new_len = outgoing_tls.len() + required_size;
            outgoing_tls.resize(new_len, 0);
            eprintln!("resized `outgoing_tls` buffer to {new_len}B");

            let res = f(&mut outgoing_tls[0..])?;
            unsafe { outgoing_tls.set_len(new_len) };
            res
        }
    };

    Ok(written)
}
fn recv_tls(
    sock: i32,
    incoming_tls: &mut Vec<u8>,
    ring: &mut IoUring,
) -> Result<(), Box<dyn Error>> {
    let recv_e = opcode::Recv::new(
        types::Fd(sock.as_raw_fd()),
        incoming_tls.as_mut_ptr(),
        incoming_tls.capacity() as u32,
    )
    .build()
    .user_data(UserData::Recv(sock.as_raw_fd()).into());

    if let Err(e) = unsafe { ring.submission().push(&recv_e) } {
        todo!();
    }
    // TODO: integrate io uring multishot somehow
    Ok(())
}

fn recv_tls_handshake(
    sock: i32,
    incoming_tls: &mut Vec<u8>,
    incoming_used: &mut usize,
    ring: &mut IoUring,
) -> Result<(), Box<dyn Error>> {
    let recv_e = opcode::Recv::new(
        types::Fd(sock.as_raw_fd()),
        incoming_tls.as_mut_ptr(),
        incoming_tls.capacity() as u32,
    )
    .build()
    .user_data(UserData::HandshakeRecv(sock.as_raw_fd()).into());

    if let Err(e) = unsafe { ring.submission().push(&recv_e) } {
        todo!();
    }
    // TODO: integrate io uring multishot somehow
    // println!("read start");
    // let read = sock.read(&mut incoming_tls[*incoming_used..])?;
    // eprintln!("received {read}B of data");
    // println!("read end");
    // *incoming_used += read;
    Ok(())
}

fn send_tls(
    sock: i32,
    outgoing_tls: &mut [u8],
    len: usize,
    ring: &mut IoUring,
) -> Result<(), Box<dyn Error>> {
    let recv_e = opcode::Recv::new(
        types::Fd(sock.as_raw_fd()),
        outgoing_tls.as_mut_ptr(),
        outgoing_tls.len() as u32,
    )
    .build()
    .user_data(UserData::HandshakeRecv(sock.as_raw_fd()).into());

    if let Err(e) = unsafe { ring.submission().push(&recv_e) } {
        todo!();
    }
    // println!("send start");
    // sock.write_all(&outgoing_tls[..*outgoing_used])?;
    // eprintln!("sent {outgoing_used}B of data");
    // println!("send end");
    // *outgoing_used = 0;
    Ok(())
}

fn send_tls_uring(
    sock: i32,
    outgoing_tls: &[u8],
    len: usize,
    ring: &mut IoUring,
) -> Result<(), Box<dyn Error>> {
    let send_zc_e = opcode::SendZc::new(
        types::Fd(sock.as_raw_fd()),
        outgoing_tls.as_ptr(),
        len as u32,
    )
    .build()
    .user_data(UserData::SendZC(sock).into());

    if let Err(e) = unsafe { ring.submission().push(&send_zc_e) } {
        todo!();
    }

    // if let Err(_) = ring.submit_and_wait(1) {
    //     todo!();
    // };

    // let Some(sendzc_cqe_fst) = ring.completion().next() else {
    //     todo!();
    // };

    // println!("{:?}", sendzc_cqe_fst);
    // if io_uring::cqueue::more(sendzc_cqe_fst.flags()) {
    //     if let Err(_) = ring.submit_and_wait(1) {
    //         todo!();
    //     };
    //     let Some(sendzc_cqe_snd) = ring.completion().next() else {
    //         todo!();
    //     };
    //     println!("{:?}", sendzc_cqe_snd);
    // }

    Ok(())
}

fn accept_multi(sock: i32, ring: &mut IoUring) {
    let acc_multi_e = opcode::AcceptMulti::new(types::Fd(sock))
        .build()
        .user_data(UserData::NewConn.into());

    if let Err(e) = unsafe { ring.submission().push(&acc_multi_e) } {
        todo!();
    }
}

fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, io::Error> {
    Ok(CertificateDer::pem_file_iter(path)
        .expect("cannot open certificate file")
        .map(|cert| cert.unwrap())
        .collect())
}

fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, io::Error> {
    Ok(PrivateKeyDer::from_pem_file(path).expect("cannot open private key file"))
}

const KB: usize = 1024;
const INCOMING_TLS_BUFSIZE: usize = 16 * KB;
// const OUTGOING_TLS_INITIAL_BUFSIZE: usize = 0;
const MAX_EARLY_DATA_SIZE: Option<u32> = Some(128);
const MAX_FRAGMENT_SIZE: Option<usize> = None;

const PORT: u16 = 1443;
const MAX_ITERATIONS: usize = 30;

const IO_URING_SIZE: u32 = 1024;
