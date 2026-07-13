use clap::{Parser, ValueEnum};
use log::{debug, error, info};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use vsock::{VMADDR_CID_HOST, VMADDR_CID_LOCAL, VsockListener, VsockStream};

/// Vsock Context ID options for binding
///
/// The CID (Context ID) identifies the communication endpoint in the vsock namespace.
/// On the host, only three CID values are valid:
/// - CID=0: Wildcard - binds to all local contexts
/// - CID=1: Local loopback within the same context
/// - CID=2: The host's fixed identity (VMADDR_CID_HOST)
///
/// Guest VMs are assigned CIDs >= 3 by the hypervisor.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum VsockCid
{
    /// Wildcard - binds to all local contexts (CID=0)
    Any,
    /// Local loopback within the same context (CID=1)
    Local,
    /// The host's fixed identity in vsock namespace (CID=2)
    Host,
}

impl From<VsockCid> for u32
{
    fn from(cid: VsockCid) -> u32
    {
        match cid {
            VsockCid::Any => 0,
            VsockCid::Local => VMADDR_CID_LOCAL,
            VsockCid::Host => VMADDR_CID_HOST,
        }
    }
}

impl fmt::Display for VsockCid
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self {
            VsockCid::Any => write!(f, "any (CID=0)"),
            VsockCid::Local => write!(f, "local (CID=1)"),
            VsockCid::Host => write!(f, "host (CID=2)"),
        }
    }
}

/// Default proxy port
const DEFAULT_PORT: u32 = 1337;

/// Default buffer size
const BUFFER_SIZE: usize = 8192;

/// Default TCP connection timeout in seconds
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Check if an IO error is expected during normal connection termination
/// Returns true for errors that indicate the peer closed the connection
fn is_expected_close_error(e: &io::Error) -> bool {
    match e.kind() {
        // Broken pipe - writing to a socket the peer has closed
        io::ErrorKind::BrokenPipe => true,
        // Connection reset - peer forcibly closed the connection
        io::ErrorKind::ConnectionReset => true,
        // Connection aborted - connection was aborted
        io::ErrorKind::ConnectionAborted => true,
        // Unexpected end of file - peer closed during read
        io::ErrorKind::UnexpectedEof => true,
        _ => false,
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args
{
    /// The Context ID of vsock listening socket.
    #[arg(long, default_value_t = VsockCid::Host)]
    vsock_cid: VsockCid,

    /// The port of vsock listening socket
    #[arg(long, default_value_t = DEFAULT_PORT)]
    vsock_port: u32,

    /// The IP address and port of remote provisioning server (addr:port)
    #[arg(long, default_value = "127.0.0.1:1337")]
    server_addr: String,

    /// TCP connection timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout_secs: u64,

    /// Turns on verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() -> io::Result<()>
{
    let args = Args::parse();

    if !args.verbose && std::env::var("RUST_LOG").is_ok() {
        env_logger::init_from_env(env_logger::Env::default());
    } else {
        let log_level = if args.verbose { "debug" } else { "info" };
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();
    }

    info!(
        "Starting provisioning proxy on {}:{}",
        u32::from(args.vsock_cid),
        args.vsock_port
    );

    let listener = VsockListener::bind_with_cid_port(args.vsock_cid.into(), args.vsock_port)
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to bind vsock: {}", e)))?;

    for stream_result in listener.incoming() {
        match stream_result {
            Ok(vsock) => {
                let peer_addr = match vsock.peer_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("Failed to get peer address: {}", e);
                        continue;
                    }
                };

                info!(
                    "New vsock connection from CID:{} port:{}",
                    peer_addr.cid(),
                    peer_addr.port()
                );

                let server_addr = args.server_addr.clone();
                let timeout_secs = args.timeout_secs;

                thread::spawn(move || {
                    if let Err(e) = handle_vsock_connection(vsock, &server_addr, timeout_secs) {
                        error!("Connection handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept vsock connection: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_vsock_connection(vsock: VsockStream, tcp_addr: &str, timeout_secs: u64) -> io::Result<()>
{
    let addr: SocketAddr = tcp_addr.parse().map_err(|e| {
        error!("Failed to parse server address '{}': {}", tcp_addr, e);
        io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid server address: {}", e))
    })?;

    let tcp = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)) {
        Ok(tcp) => tcp,
        Err(e) => {
            error!("Failed to connect to {} within {}s: {}", tcp_addr, timeout_secs, e);
            return Err(e);
        }
    };

    tcp.set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to set TCP read timeout: {}", e)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to set TCP write timeout: {}", e)))?;

    info!("TCP connection established with {}s timeout, starting proxy", timeout_secs);

    if let Err(e) = copy_bidirectional(vsock, tcp) {
        error!("Copy bidirectional error: {}", e);
    }

    Ok(())
}

fn copy_bidirectional(vsock: VsockStream, tcp: TcpStream) -> io::Result<()>
{
    let mut vsock_buf = [0u8; BUFFER_SIZE];
    let mut tcp_buf = [0u8; BUFFER_SIZE];
    let bytes_tx = Arc::new(AtomicU64::new(0));
    let bytes_rx = Arc::new(AtomicU64::new(0));

    // Clone streams and counters for each direction - each thread needs its own owned handle
    let tcp_reader = tcp.try_clone().expect("Failed to clone TCP stream");
    let vsock_writer = vsock.try_clone().expect("Failed to clone vsock");
    let bytes_rx_clone = Arc::clone(&bytes_rx);

    // Handling VSOCK <- TCP stream
    let vsock_write_handle = thread::spawn(move || -> io::Result<()> {
        let mut tcp_read = tcp_reader;
        let mut vsock_write = vsock_writer;
        let result = (|| -> io::Result<()> {
            loop {
                match tcp_read.read(&mut tcp_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        bytes_rx_clone.fetch_add(n as u64, Ordering::SeqCst);
                        vsock_write.write_all(&tcp_buf[..n])?;
                        vsock_write.flush()?;
                        debug!("VSOCK <- TCP RX: {} bytes", n);
                    }
                    Err(e) => {
                        debug!("VSOCK <- TCP RX Error: {}", e);
                        return Err(e);
                    }
                }
            }
            Ok(())
        })();
        debug!("VSOCK <- TCP RX done");
        if let Err(e) = tcp_read.shutdown(std::net::Shutdown::Read) {
            debug!("TCP read shutdown (expected on peer close): {}", e);
        }
        if let Err(e) = vsock_write.shutdown(std::net::Shutdown::Write) {
            debug!("Vsock write shutdown (expected on peer close): {}", e);
        }
        result
    });

    let vsock_reader = vsock.try_clone().expect("Failed to clone vsock");
    let tcp_writer = tcp.try_clone().expect("Failed to clone TCP stream");
    let bytes_tx_clone = Arc::clone(&bytes_tx);

    // Handling VSOCK -> TCP stream
    let vsock_read_result = thread::spawn(move || -> io::Result<()> {
        let mut vsock_read = vsock_reader;
        let mut tcp_write = tcp_writer;
        let result = (|| -> io::Result<()> {
            loop {
                match vsock_read.read(&mut vsock_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        bytes_tx_clone.fetch_add(n as u64, Ordering::SeqCst);
                        tcp_write.write_all(&vsock_buf[..n])?;
                        tcp_write.flush()?;
                        debug!("VSOCK -> TCP TX: {} bytes", n);
                    }
                    Err(e) => {
                        debug!("VSOCK -> TCP TX Error: {}", e);
                        return Err(e);
                    }
                }
            }
            Ok(())
        })();
        debug!("VSOCK -> TCP TX done");
        if let Err(e) = vsock_read.shutdown(Shutdown::Read) {
            debug!("Vsock read shutdown (expected on peer close): {}", e);
        }
        if let Err(e) = tcp_write.shutdown(Shutdown::Write) {
            debug!("TCP write shutdown (expected on peer close): {}", e);
        }
        result
    });

    match vsock_write_handle.join() {
        Ok(thread_result) => {
            if let Err(e) = thread_result {
                if !is_expected_close_error(&e) {
                    error!("VSOCK <- TCP thread error: {}", e);
                }
            }
        }
        Err(_) => error!("VSOCK <- TCP thread panicked"),
    }

    match vsock_read_result.join() {
        Ok(thread_result) => {
            if let Err(e) = thread_result {
                if !is_expected_close_error(&e) {
                    error!("VSOCK -> TCP thread error: {}", e);
                }
            }
        }
        Err(_) => error!("VSOCK -> TCP thread panicked"),
    }

    info!(
        "Connection complete: TX: {} bytes, RX: {} bytes total",
        bytes_tx.load(Ordering::SeqCst),
        bytes_rx.load(Ordering::SeqCst)
    );

    Ok(())
}
