pub mod conproto;
pub mod policy;
pub mod stream_helpers;

use clap::{Parser, ValueEnum};
use log::{debug, error, info};
use std::fmt;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use vsock::{VsockListener, VsockStream, VMADDR_CID_HOST, VMADDR_CID_LOCAL};
use conproto::{read_connect_request, send_connect_response};

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

/// The timeout for read/write operations on TCP socket
const TCP_READ_WRITE_TIMEOUT: u64 = 60;

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

    /// Use connection protocol to select the server (ratls-get should also run with that option)
    #[arg(short, long, default_value_t = false)]
    conproto: bool,

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

    if args.conproto {
        info!("Connection protocol is enabled.");
    }

    let listener = VsockListener::bind_with_cid_port(args.vsock_cid.into(), args.vsock_port)
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to bind vsock: {}", e)))?;

    for stream_result in listener.incoming() {
        match stream_result {
            Ok(mut vsock) => {
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

                let server_addr = if args.conproto {
                    match read_connect_request(&mut vsock) {
                        Ok(request) => request.server_addr,
                        Err(e) => {
                            error!("Failed to read connection request: {}", e);
                            continue;
                        }
                    }
                } else {
                    args.server_addr.clone()
                };

                // This is intentional. We don't handle connection in a thread because
                // we want handle them synchronously i.e. one connection at a time.
                if let Err(e) = handle_vsock_connection(
                    vsock,
                    &server_addr,
                    args.timeout_secs,
                    args.conproto,
                    &policy_manager,
                ) {
                    error!("Connection handler error: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to accept vsock connection: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_vsock_connection(
    mut vsock: VsockStream,
    tcp_addr: &str,
    timeout_secs: u64,
    conproto: bool,
    policy_manager: &Option<Arc<policy::PolicyManager>>,
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

    // Check if connection is allowed by policy
    if let Some(manager) = policy_manager {
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
    }

    // Resolve the address and try to connect to each resolved address (fallback support)
    let (tcp, connected_addr) = tcp_addr
        .to_socket_addrs()
        .map_err(|e| {
            error!("Failed to resolve server address '{}': {}", tcp_addr, e);
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to resolve address: {}", e),
            )
        })?
        .find_map(|addr| {
            debug!("Attempting TCP connection to {}", addr);
            TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs))
                .map_err(|e| {
                    error!("Failed to connect to {}: {}", addr, e);
                    e
                })
                .ok()
                .map(|tcp| (tcp, addr))
        })
        .ok_or_else(|| {
            error!(
                "Failed to connect to any resolved address for '{}'",
                tcp_addr
            );
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Failed to connect to any resolved address",
            )
        })?;

    tcp.set_read_timeout(Some(Duration::from_secs(TCP_READ_WRITE_TIMEOUT)))
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to set TCP read timeout: {}", e)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(TCP_READ_WRITE_TIMEOUT)))
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to set TCP write timeout: {}", e)))?;

    info!(
        "TCP connection established to {} (resolved from '{}'), starting proxy",
        connected_addr, tcp_addr
    );

    if conproto {
        send_connect_response(
            &mut vsock,
            true,
            &format!("Connection established to {}", connected_addr),
        )?;
    }

    // Pass policy manager and server info to copy_bidirectional for per-server byte tracking
    // Clone Arc and convert &str to String for thread-safe ownership
    let policy_manager_clone = policy_manager.clone();
    if let Err(e) = stream_helpers::copy_bidirectional(
        vsock,
        tcp,
        policy_manager_clone,
        host_for_policy.to_string(),
        port_for_policy,
    ) {
        error!("Copy bidirectional error: {}", e);
    }

    Ok(())
}
