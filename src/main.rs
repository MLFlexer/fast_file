//! This is a simple server using rustls' unbuffered API. Meaning that the application layer must
//! handle the buffers required to receive, process and send TLS data.

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::CStr;
use std::io::{self};
use std::mem::MaybeUninit;
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use io_uring::squeue::Flags;
use io_uring::{IoUring, opcode, types};
use libc::msghdr;
use log::{info, warn};
use rustls::kernel::KernelConnection;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, InsufficientSizeError, UnbufferedStatus,
};
use rustls::{ExtractedSecrets, ServerConfig};
use simple_logger::SimpleLogger;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args();
    args.next();
    let cert_file = args.next().expect("missing certificate file argument");
    let private_key_file = args.next().expect("missing private key file argument");

    SimpleLogger::new()
        .with_level(log::LevelFilter::Off)
        .init()
        .expect("Failed to initialize logger");

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(cert_file)?, load_private_key(private_key_file)?)?;

    if let Some(max_early_data_size) = MAX_EARLY_DATA_SIZE {
        config.max_early_data_size = max_early_data_size;
    }

    config.max_fragment_size = MAX_FRAGMENT_SIZE;

    let mut config = Arc::new(config);
    Arc::get_mut(&mut config).unwrap().enable_secret_extraction = true;

    setup_close_tls_msg();
    let listener = TcpListener::bind(format!("[::]:{PORT}"))?;

    // let mut ring = IoUring::new(IO_URING_SIZE)?;
    let mut ring = IoUring::builder()
        // .setup_single_issuer()
        // .setup_iopoll()
        .setup_sqpoll(2_000)
        .build(IO_URING_SIZE)?;
    let mut connection_map: HashMap<i32, ConnectionType> = HashMap::new();

    accept_multi(listener.as_raw_fd(), &mut ring);

    if let Err(_) = ring.submit() {
        todo!();
    };
    handle(&config, &mut connection_map, &mut ring)?;

    Ok(())
}

#[derive(Debug)]
enum UserData {
    NewConn,
    SendZC(i32),
    HandshakeRecv(i32),
    Recv(i32),
    SsoUlp(i32),
    SsoTx(i32),
    SsoRx(i32),
    Send(i32),
    SendMsg(i32),
    Close(i32),
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

struct UnbufferedConn {
    buffer: Vec<u8>,
    out_buffer: Vec<u8>,
    conn: UnbufferedServerConnection,
}

struct KTLSConn {
    conn: KernelConnection<ServerConnectionData>,
    rx: Box<MaybeUninit<ktls::CryptoInfo>>,
    tx: Box<MaybeUninit<ktls::CryptoInfo>>,
}

impl KTLSConn {
    fn new(kernel_conn: KernelConnection<ServerConnectionData>) -> Self {
        Self {
            conn: kernel_conn,
            rx: Box::new_uninit(),
            tx: Box::new_uninit(),
        }
    }

    fn set_tx_rx(&mut self, secrets: ExtractedSecrets) -> Result<(), Box<dyn std::error::Error>> {
        self.tx.write(ktls::CryptoInfo::from_rustls(
            self.conn.negotiated_cipher_suite(),
            secrets.tx,
        )?);
        self.rx.write(ktls::CryptoInfo::from_rustls(
            self.conn.negotiated_cipher_suite(),
            secrets.rx,
        )?);
        Ok(())
    }
}

enum ConnectionType {
    Handshake(UnbufferedConn),
    Kernel(KTLSConn),
}

impl ConnectionType {
    fn into_unbuf(&mut self) -> Result<&mut UnbufferedConn, &str> {
        match self {
            ConnectionType::Handshake(conn) => Ok(conn),
            _ => Err("Not a unbuffered connection!"),
        }
    }

    fn into_kernel(&mut self) -> Result<&mut KTLSConn, &str> {
        match self {
            ConnectionType::Kernel(conn) => Ok(conn),
            _ => Err("Not a unbuffered connection!"),
        }
    }

    fn unbuf_to_kernel(self) -> Result<(Self, ExtractedSecrets), Box<dyn std::error::Error>> {
        let unbuf = match self {
            ConnectionType::Handshake(unbuf) => unbuf,
            _ => return Err("Did not contain unbuffered!".into()),
        };
        let (secrets, kernel_conn) = unbuf.conn.dangerous_into_kernel_connection()?;
        let out = ConnectionType::Kernel(KTLSConn::new(kernel_conn));
        Ok((out, secrets))
    }
}

impl UnbufferedConn {
    fn new(config: &Arc<ServerConfig>) -> Self {
        let mut buffer = Vec::with_capacity(INCOMING_TLS_BUFSIZE);
        buffer.resize(INCOMING_TLS_BUFSIZE, 0);
        Self {
            buffer: buffer,
            out_buffer: Vec::new(),
            conn: UnbufferedServerConnection::new(config.clone())
                .expect("Error when creating new UnbufferedServerConnection!"),
        }
    }
}

fn handle(
    config: &Arc<ServerConfig>,
    connection_map: &mut HashMap<i32, ConnectionType>,
    ring: &mut IoUring,
) -> Result<(), Box<dyn Error>> {
    let mut x = 0;
    let mut y = 0;
    loop {
        let cqe = {
            let next = ring.completion().next();
            match next {
                Some(cqe) => {
                    x += 1;
                    if let Err(_) = ring.submit() {
                        todo!();
                    };
                    cqe
                }
                None => {
                    y += 1;
                    if let Err(_) = ring.submit_and_wait(1) {
                        todo!();
                    };
                    ring.completion().next().unwrap()
                }
            }
        };
        if (x + y) % 100 == 0 {
            warn!("submitted without waiting: {x}, waited for: {y}");
        }

        info!("{:?}", cqe);
        let user_data: UserData = cqe.user_data().into();
        info!("{:?}", user_data);
        match cqe.user_data().into() {
            UserData::Recv(id) => {
                let Some(ce) = connection_map.remove(&id) else {
                    todo!()
                };

                let (mut kernel_ce, secrets) = ce.unbuf_to_kernel()?;

                ktls_setsocketopts(id, ring, (secrets, kernel_ce.into_kernel()?))?;
                connection_map.insert(id, kernel_ce);
                info!("KERNEL TLS ACTIVATED!");
            }
            UserData::NewConn => {
                let id = cqe.result();
                connection_map.insert(id, ConnectionType::Handshake(UnbufferedConn::new(&config)));
                info!("STARTED NEW CONN ON {id}");
                info!("CONNECTION MAP: {:?}", connection_map.keys());
                // sleep(Duration::from_secs(1));
                let ce = connection_map.get_mut(&id).unwrap().into_unbuf()?;
                let UnbufferedStatus { discard: _, state } =
                    ce.conn.process_tls_records(&mut ce.buffer[..0]);

                info!("{:?}", state);
                match state.unwrap() {
                    ConnectionState::BlockedHandshake { .. } => {
                        recv_tls_handshake(id, &mut ce.buffer, ring)?;
                    }
                    _ => todo!(),
                }
            }
            UserData::HandshakeRecv(id) => {
                let mut to_write = 0;
                let mut res = cqe.result() as usize;
                for i in 0..MAX_ITERATIONS {
                    let ce = connection_map.get_mut(&id).unwrap().into_unbuf()?;
                    info!("buffer: {:?}", ce.buffer[..res].iter().clone());
                    info!("out buffer: {:?}", ce.out_buffer[..to_write].iter().clone());
                    let UnbufferedStatus { mut discard, state } =
                        ce.conn.process_tls_records(&mut ce.buffer[..res]);

                    info!("{:?}", state);
                    info!("discard: {:?}", discard);
                    info!("written: {:?}", to_write);
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
                            send_tls_uring(id, &mut ce.out_buffer, to_write, ring)?;
                            // TODO: should it be done before???
                            s.done();
                            info!("Written tls");
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

                                    info!("{header}");
                                } else {
                                    info!("(.. continued HTTP request ..)");
                                }
                            }

                            if !ce.conn.is_handshaking() {
                                info!("HANDSHAKE IS DONE!");
                                // todo!();
                                let Some(ce) = connection_map.remove(&id) else {
                                    todo!()
                                };

                                let (mut kernel_ce, secrets) = ce.unbuf_to_kernel()?;

                                ktls_setsocketopts(id, ring, (secrets, kernel_ce.into_kernel()?))?;
                                connection_map.insert(id, kernel_ce);
                                break;
                            } else {
                                todo!()
                            }
                        }
                        ConnectionState::WriteTraffic(_) => {
                            //TODO: is this correct???
                            if !ce.conn.is_handshaking() {
                                info!("HANDSHAKE IS DONE DRAINING!");
                                recv_tls(id, &mut ce.buffer, ring)?;
                                break;
                            } else {
                                todo!();
                            }
                        }

                        a => {
                            // TODO: should not be catch all
                            info!("not implemented {:?}, {:?}", a, cqe);
                            todo!();
                        }
                    }

                    // TODO: do we really need to fill the discarded with 0? or can we ignore?
                    // This cannot be done rn
                    if discard != 0 {
                        ce.buffer.copy_within(discard..res, 0);
                        res -= discard;

                        warn!("discarded {discard}B from `incoming_tls`");
                    }
                    info!("\nnext {i}");
                }
            }
            UserData::SendZC(id) => {
                if io_uring::cqueue::more(cqe.flags()) {
                    info!("sendzc: cqe with more to come: {:?}", cqe);
                    if cqe.result() < 0 {
                        panic!(
                            "sendzc failed with: {}",
                            io::Error::from_raw_os_error(-cqe.result())
                        )
                    }
                } else {
                    info!("sendzc: {:?}", cqe);

                    let ce = connection_map.get_mut(&id).unwrap().into_unbuf()?;
                    info!("buffer sendzc: {:?}", ce.buffer[..85].iter().clone());
                    let UnbufferedStatus { discard: _, state } =
                        ce.conn.process_tls_records(&mut ce.buffer[..0]);

                    info!("{:?}", state);
                    match state.unwrap() {
                        ConnectionState::BlockedHandshake { .. } => {
                            recv_tls_handshake(id, &mut ce.buffer, ring)?;
                        }
                        ConnectionState::WriteTraffic(_) => {
                            if !ce.conn.is_handshaking() {
                                info!("HANDSHAKE IS DONE DRAINING!");
                                recv_tls(id, &mut ce.buffer, ring)?;
                            } else {
                                todo!();
                            }
                        }
                        a => {
                            info!("not implemented {:?}", a);
                            todo!()
                        }
                    }
                }
            }
            UserData::SsoUlp(_id) => {
                if cqe.result() < 0 {
                    // TODO: should retry

                    panic!(
                        "set socket opts failed with: {}",
                        io::Error::from_raw_os_error(-cqe.result())
                    )
                }
            }
            UserData::SsoTx(_id) => {
                if cqe.result() < 0 {
                    // TODO: should retry

                    panic!(
                        "set socket opts failed with: {}",
                        io::Error::from_raw_os_error(-cqe.result())
                    )
                }
            }

            UserData::SsoRx(id) => {
                if cqe.result() < 0 {
                    // TODO: should retry

                    panic!(
                        "set socket opts failed with: {}",
                        io::Error::from_raw_os_error(-cqe.result())
                    )
                }

                static RESPONSE: &CStr =
                    c"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from kTLS server\r\n";
                let send_e = opcode::Send::new(
                    types::Fd(id),
                    RESPONSE.as_ptr().cast(),
                    RESPONSE.count_bytes() as u32,
                )
                .build()
                .user_data(UserData::Send(id).into());

                if let Err(_e) = unsafe { ring.submission().push(&send_e) } {
                    todo!();
                }
            }
            UserData::Send(id) => {
                if cqe.result() < 0 {
                    // TODO: should retry
                    panic!(
                        "Send failed with: {}",
                        io::Error::from_raw_os_error(-cqe.result())
                    )
                }

                // TODO: should shutdown before closing???
                send_close_notify(id, ring)?;
            }
            UserData::SendMsg(_id) => {
                if cqe.result() < 0 {
                    // TODO: should retry
                    panic!(
                        "Send failed with: {}",
                        io::Error::from_raw_os_error(-cqe.result())
                    )
                }
            }
            UserData::Close(id) => {
                if cqe.result() < 0 {
                    // TODO: should retry
                    panic!(
                        "Send failed with: {}",
                        io::Error::from_raw_os_error(-cqe.result())
                    )
                } else {
                    info!("CLOSED: {id}");

                    // sleep(Duration::from_secs(1));
                    connection_map.remove(&id);
                }
            }
            a => {
                info!("not implemented {:?}", a);
                info!("not implemented {:?}", -cqe.result());
                info!("{}", io::Error::from_raw_os_error(-cqe.result()));
                todo!()
            }
        }

        info!("\nnext");
    }
}

// TODO: change this:
use rustls::{
    AlertDescription,
    internal::msgs::{enums::AlertLevel, message::Message},
};
const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const ALERT: u8 = 0x15;

// TODO: change this:
// Yes, really. cmsg components are aligned to [libc::c_long]
#[cfg_attr(target_pointer_width = "32", repr(C, align(4)))]
#[cfg_attr(target_pointer_width = "64", repr(C, align(8)))]
struct Cmsg<const N: usize> {
    hdr: libc::cmsghdr,
    data: [u8; N],
}

impl<const N: usize> Cmsg<N> {
    fn new(level: i32, typ: i32, data: [u8; N]) -> Self {
        Self {
            hdr: libc::cmsghdr {
                // on Linux this is a usize, on macOS this is a u32
                #[allow(clippy::unnecessary_cast)]
                cmsg_len: (memoffset::offset_of!(Self, data) + N) as _,
                cmsg_level: level,
                cmsg_type: typ,
            },
            data,
        }
    }
}

// TODO: change this:
static mut CLOSE_NOTIFY_MSGHDR_PTR: *const msghdr = std::ptr::null();
fn get_close_notify_msg_ptr() -> *const msghdr {
    unsafe { CLOSE_NOTIFY_MSGHDR_PTR }
}

fn setup_close_tls_msg() {
    let mut data = vec![];
    Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify)
        .payload
        .encode(&mut data);
    let data = data.leak();

    let cmsg = Cmsg::new(libc::SOL_TLS, TLS_SET_RECORD_TYPE, [ALERT]);
    let cmsg = Box::leak(Box::new(cmsg));

    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut libc::iovec {
            iov_base: data.as_mut_ptr() as _,
            iov_len: data.len(),
        },
        msg_iovlen: 1,
        msg_control: cmsg as *mut _ as *mut _,
        msg_controllen: cmsg.hdr.cmsg_len,
        msg_flags: 0,
    };

    let msg = Box::leak(Box::new(msg));
    unsafe {
        CLOSE_NOTIFY_MSGHDR_PTR = msg;
    }
}
pub fn send_close_notify(fd: std::os::fd::RawFd, ring: &mut IoUring) -> std::io::Result<()> {
    let send_msg_e = opcode::SendMsg::new(types::Fd(fd), get_close_notify_msg_ptr())
        .flags(0)
        .build()
        .flags(Flags::IO_LINK)
        .user_data(UserData::SendMsg(fd).into());

    let close_e = opcode::Close::new(types::Fd(fd))
        .build()
        .user_data(UserData::Close(fd).into());

    if let Err(_e) = unsafe { ring.submission().push_multiple(&[send_msg_e, close_e]) } {
        todo!();
    }
    Ok(())
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
    let written = match f(&mut outgoing_tls[*outgoing_used..]) {
        Ok(written) => written,

        Err(e) => {
            let InsufficientSizeError { required_size } = map_err(e)?;
            let new_len = *outgoing_used + required_size;
            outgoing_tls.resize(new_len, 0);
            warn!("resized `outgoing_tls` buffer to {new_len}B");

            f(&mut outgoing_tls[*outgoing_used..])?
        }
    };

    *outgoing_used += written;

    Ok(written)
}

fn ktls_setsocketopts(
    sock: i32,
    ring: &mut IoUring,
    (secrets, kernel_conn): (rustls::ExtractedSecrets, &mut KTLSConn),
) -> Result<(), Box<dyn std::error::Error>> {
    static ULP_NAME: &std::ffi::CStr = c"tls";
    let setsockopt_ulp_e = opcode::SetSockOpt::new(
        types::Fd(sock),
        libc::SOL_TCP as u32,
        libc::TCP_ULP as u32,
        ULP_NAME.as_ptr() as *const std::ffi::c_void,
        ULP_NAME.to_bytes().len() as libc::socklen_t,
    )
    .build()
    .flags(Flags::IO_LINK)
    .user_data(UserData::SsoUlp(sock).into());

    kernel_conn.set_tx_rx(secrets)?;

    let tx_ptr = unsafe { kernel_conn.tx.as_mut().assume_init_mut() };
    let setsockopt_tx_e = opcode::SetSockOpt::new(
        types::Fd(sock),
        libc::SOL_TLS as u32,
        libc::TLS_TX as u32,
        tx_ptr.as_ptr(),
        tx_ptr.size() as _,
    )
    .build()
    .flags(Flags::IO_LINK)
    .user_data(UserData::SsoTx(sock).into());

    let rx_ptr = unsafe { kernel_conn.rx.as_mut().assume_init_mut() };
    let setsockopt_rx_e = opcode::SetSockOpt::new(
        types::Fd(sock),
        libc::SOL_TLS as u32,
        libc::TLS_RX as u32,
        rx_ptr.as_ptr(),
        rx_ptr.size() as _,
    )
    .build()
    // Don't link after last
    .user_data(UserData::SsoRx(sock).into());

    if let Err(_e) = unsafe {
        ring.submission()
            .push_multiple(&[setsockopt_ulp_e, setsockopt_tx_e, setsockopt_rx_e])
    } {
        todo!();
    }
    Ok(())
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

    if let Err(_e) = unsafe { ring.submission().push(&recv_e) } {
        todo!();
    }
    // TODO: integrate io uring multishot somehow
    Ok(())
}

fn recv_tls_handshake(
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
    .user_data(UserData::HandshakeRecv(sock.as_raw_fd()).into());

    if let Err(_e) = unsafe { ring.submission().push(&recv_e) } {
        todo!();
    }
    // TODO: integrate io uring multishot somehow
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

    if let Err(_e) = unsafe { ring.submission().push(&send_zc_e) } {
        todo!();
    }

    Ok(())
}

fn accept_multi(sock: i32, ring: &mut IoUring) {
    let acc_multi_e = opcode::AcceptMulti::new(types::Fd(sock))
        .build()
        .user_data(UserData::NewConn.into());

    if let Err(_e) = unsafe { ring.submission().push(&acc_multi_e) } {
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

const IO_URING_SIZE: u32 = 1024 * 16;
