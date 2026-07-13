use clap::{Parser, ValueEnum};
use log::{debug, error, info};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
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

impl VsockCid
{
    fn as_u32(&self) -> u32
    {
        match self {
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

    /// Turns on verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() -> io::Result<()>
{
    let args = Args::parse();
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    info!(
        "Starting provisioning proxy on {}:{}",
        args.vsock_cid.as_u32(),
        args.vsock_port
    );

    let listener = VsockListener::bind_with_cid_port(args.vsock_cid.as_u32(), args.vsock_port)
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

                thread::spawn(move || {
                    if let Err(e) = handle_vsock_connection(vsock, &server_addr) {
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

fn handle_vsock_connection(vsock: VsockStream, tcp_addr: &str) -> io::Result<()>
{
    let tcp = match TcpStream::connect(&tcp_addr) {
        Ok(tcp) => tcp,
        Err(e) => {
            error!("Failed to connect to {}: {}", tcp_addr, e);
            return Err(e);
        }
    };

    info!("TCP connection established, starting TLS passthrough");

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
                        bytes_rx_clone.fetch_add(n as u64, Ordering::Relaxed);
                        vsock_write.write_all(&tcp_buf[..n])?;
                        vsock_write.flush()?;
                        debug!("VSOCK <- TCP RX: {} bytes", n);
                    }
                    Err(e) => {
                        debug!("VSOCK <- TCP RX Error: {:#}", e);
                        return Err(e);
                    }
                }
            }
            Ok(())
        })();
        debug!("VSOCK <- TCP RX done");
        let _ = tcp_read.shutdown(std::net::Shutdown::Read);
        let _ = vsock_write.shutdown(std::net::Shutdown::Write);
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
                        bytes_tx_clone.fetch_add(n as u64, Ordering::Relaxed);
                        tcp_write.write_all(&vsock_buf[..n])?;
                        tcp_write.flush()?;
                        debug!("VSOCK -> TCP TX: {} bytes", n);
                    }
                    Err(e) => {
                        debug!("VSOCK -> TCP TX Error: {:#}", e);
                        return Err(e);
                    }
                }
            }
            Ok(())
        })();
        debug!("VSOCK -> TCP TX done");
        let _ = vsock_read.shutdown(Shutdown::Read);
        let _ = tcp_write.shutdown(Shutdown::Write);
        result
    });

    let _ = vsock_write_handle.join();
    let _ = vsock_read_result.join();

    info!(
        "Connection complete: TX: {} bytes, RX: {} bytes total",
        bytes_tx.load(Ordering::Relaxed),
        bytes_rx.load(Ordering::Relaxed)
    );

    Ok(())
}
