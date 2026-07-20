use log::{debug, info};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use vsock::VsockStream;

use crate::policy::PolicyManager;
use crate::BUFFER_SIZE;

const BUFFER_SIZE_VSOCK: usize = BUFFER_SIZE;

/// Copies data bidirectionally between vsock and TCP streams
/// Enforces a cumulative TX bytes limit per server (address:port) stored in PolicyManager
pub fn copy_bidirectional(
    vsock: VsockStream,
    tcp: TcpStream,
    policy_manager: Option<Arc<PolicyManager>>,
    server_addr: String,
    server_port: u16,
) -> io::Result<()>
{
    let mut tcp_buf = [0u8; BUFFER_SIZE];
    let bytes_rx = Arc::new(AtomicU64::new(0));
    let bytes_tx = Arc::new(AtomicU64::new(0));

    let tcp_reader = tcp
        .try_clone()
        .map_err(|e| io::Error::new(e.kind(), "Failed to clone TCP reader stream"))?;
    let vsock_writer = vsock
        .try_clone()
        .map_err(|e| io::Error::new(e.kind(), "Failed to clone VSOCK writer stream"))?;
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
        if let Err(e) = tcp_read.shutdown(Shutdown::Read) {
            debug!("TCP read shutdown (expected on peer close): {}", e);
        }
        if let Err(e) = vsock_write.shutdown(Shutdown::Write) {
            debug!("Vsock write shutdown (expected on peer close): {}", e);
        }
        result
    });

    // Handling VSOCK -> TCP stream
    let vsock_reader = vsock
        .try_clone()
        .map_err(|e| io::Error::new(e.kind(), "Failed to clone VSOCK reader stream"))?;
    let tcp_writer = tcp
        .try_clone()
        .map_err(|e| io::Error::new(e.kind(), "Failed to clone TCP writer stream"))?;

    let policy_manager_clone = policy_manager.clone();
    let server_addr_clone = server_addr.clone();
    let bytes_tx_clone = Arc::clone(&bytes_tx);

    let vsock_read_handle = thread::spawn(move || -> io::Result<()> {
        let mut vsock_read = vsock_reader;
        let mut tcp_write = tcp_writer;
        let mut vsock_buf = [0u8; BUFFER_SIZE_VSOCK];

        let result = (|| -> io::Result<()> {
            loop {
                match vsock_read.read(&mut vsock_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Some(manager) = &policy_manager_clone {
                            manager.check_and_add_tx_bytes(
                                &server_addr_clone,
                                server_port,
                                n as u64,
                            )?;
                        } else {
                            bytes_tx_clone.fetch_add(n as u64, Ordering::SeqCst);
                        }

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
        // If we detect an error (due to tx byte limit check) we use shutdown(Shutdown::Both) to force
        // VSOCK <- TCP stream handling thread to close sockets. It shutdowns connections immediately
        // preventing from keeping half-open connections.
        let vsock_read_shutdown = if result.is_err() {
            Shutdown::Both
        } else {
            Shutdown::Read
        };
        let tcp_write_shutdown = if result.is_err() {
            Shutdown::Both
        } else {
            Shutdown::Write
        };
        if let Err(e) = vsock_read.shutdown(vsock_read_shutdown) {
            debug!("Vsock read shutdown (expected on peer close): {}", e);
        }
        if let Err(e) = tcp_write.shutdown(tcp_write_shutdown) {
            debug!("TCP write shutdown (expected on peer close): {}", e);
        }
        result
    });

    // Wait for both threads and handle errors
    match vsock_write_handle.join() {
        Ok(thread_result) => {
            if let Err(e) = thread_result {
                if !is_expected_close_error(&e) {
                    debug!("VSOCK <- TCP thread error: {}", e);
                }
            }
        }
        Err(_) => debug!("VSOCK <- TCP thread panicked"),
    }

    match vsock_read_handle.join() {
        Ok(thread_result) => {
            if let Err(e) = thread_result {
                if !is_expected_close_error(&e) {
                    debug!("VSOCK -> TCP thread error: {}", e);
                }
            }
        }
        Err(_) => debug!("VSOCK -> TCP thread panicked"),
    }

    info!("Connection complete");
    // Log connection completion using PolicyManager's encapsulated method
    if let Some(manager) = &policy_manager {
        manager.log_connection_complete(&server_addr, server_port);
    } else {
        info!("  TX: {} bytes", bytes_tx.load(Ordering::SeqCst));
    }
    info!("  RX: {} bytes", bytes_rx.load(Ordering::SeqCst));

    Ok(())
}

/// Check if an IO error is expected during normal connection termination
fn is_expected_close_error(e: &io::Error) -> bool
{
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
