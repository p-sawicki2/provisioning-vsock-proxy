pub mod policy;
pub mod stream_helpers;

use clap::{Parser, ValueEnum};
use log::{error, info};
use std::fmt;
use std::io::{self};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
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

/// Default buffer size (64 KB)
const BUFFER_SIZE: usize = 65536;

/// Default TCP connection timeout in seconds
const DEFAULT_TIMEOUT_SECS: u64 = 60;

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

    /// Path to JSON policy file for server whitelist
    #[arg(long)]
    policy_file: Option<String>,
}

fn main() -> io::Result<()>
{
    let args = Args::parse();

    if !args.verbose && std::env::var("RUST_LOG").is_ok() {
        env_logger::init_from_env(env_logger::Env::default());
    } else {
        let log_level = if args.verbose { "debug" } else { "info" };
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
            .init();
    }

    let policy_manager = if let Some(policy_file) = &args.policy_file {
        let manager = policy::PolicyManager::new();
        manager.load_from_file(policy_file).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to load policy file '{}': {}", policy_file, e),
            )
        })?;
        info!("Successfully loaded policy from '{}'", policy_file);
        manager.log_policy();
        Some(Arc::new(manager))
    } else {
        None
    };

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
                let policy_manager = policy_manager.clone();

                thread::spawn(move || {
                    if let Err(e) = handle_vsock_connection(
                        vsock,
                        &server_addr,
                        timeout_secs,
                        policy_manager.as_deref(),
                    ) {
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

fn handle_vsock_connection(
    vsock: VsockStream,
    tcp_addr: &str,
    timeout_secs: u64,
    policy_manager: Option<&policy::PolicyManager>,
) -> io::Result<()>
{
    let (host_for_policy, port_for_policy) = tcp_addr
        .rsplit_once(':')
        .map(|(host, port)| {
            (
                host.trim_start_matches('[').trim_end_matches(']'),
                port.parse::<u16>(),
            )
        })
        .and_then(|(host, port_result)| port_result.ok().map(|port| (host, port)))
        .ok_or_else(|| {
            error!(
                "Invalid server address format '{}': expected host:port",
                tcp_addr
            );
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid address format, expected host:port",
            )
        })?;

    let tx_limit = if let Some(manager) = policy_manager {
        if !manager.is_allowed(host_for_policy, port_for_policy) {
            error!(
                "Connection to {}:{} is not allowed by policy",
                host_for_policy, port_for_policy
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Connection to {}:{} is not allowed by policy",
                    host_for_policy, port_for_policy
                ),
            ));
        }

        manager.tx_bytes_limit(host_for_policy, port_for_policy)
    } else {
        None
    };

    // Resolve the address (handles both IP addresses and domain names via DNS)
    let addr: SocketAddr = tcp_addr
        .to_socket_addrs()
        .map_err(|e| {
            error!("Failed to resolve server address '{}': {}", tcp_addr, e);
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to resolve address: {}", e),
            )
        })?
        .next()
        .ok_or_else(|| {
            error!("No addresses resolved for '{}'", tcp_addr);
            io::Error::new(io::ErrorKind::InvalidInput, "No addresses resolved")
        })?;

    info!(
        "Resolved '{}' to {}, establishing TCP connection",
        tcp_addr, addr
    );

    let tcp = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)) {
        Ok(tcp) => tcp,
        Err(e) => {
            error!(
                "Failed to connect to {} within {}s: {}",
                tcp_addr, timeout_secs, e
            );
            return Err(e);
        }
    };

    if tx_limit.is_some() {
        info!(
            "TCP connection established with {}s timeout, TX limit: {:?}, starting proxy",
            timeout_secs, tx_limit
        );
    } else {
        info!(
            "TCP connection established with {}s timeout, starting proxy",
            timeout_secs
        );
    }

    if let Err(e) = stream_helpers::copy_bidirectional(vsock, tcp, tx_limit) {
        error!("Copy bidirectional error: {}", e);
    }

    Ok(())
}
