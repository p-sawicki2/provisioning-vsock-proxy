use log::{debug, warn};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use vsock::VsockStream;

use crate::BUFFER_SIZE;

trait TxLimitChecker
{
    fn check(&self, current_tx: u64) -> io::Result<()>;
}

/// Checker that uses a hard limit for transmitted bytes
struct WithLimit
{
    limit: u64,
}

impl TxLimitChecker for WithLimit
{
    fn check(&self, current_tx: u64) -> io::Result<()>
    {
        if current_tx > self.limit {
            warn!("TX bytes limit exceeded: {} > {}", current_tx, self.limit);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("TX bytes limit exceeded: {} > {}", current_tx, self.limit),
            ));
        }
        Ok(())
    }
}

/// Checker that always succeeds
struct NoLimit;

impl TxLimitChecker for NoLimit
{
    fn check(&self, _current_tx: u64) -> io::Result<()>
    {
        Ok(())
    }
}

fn copy_vsock_to_tcp(
    vsock_reader: VsockStream,
    tcp_writer: TcpStream,
    bytes_tx_clone: Arc<AtomicU64>,
    tx_bytes_limit: Option<u64>,
) -> thread::JoinHandle<io::Result<()>>
{

    fn copy_loop<C: TxLimitChecker + Send + 'static>(
        vsock_reader: VsockStream,
        tcp_writer: TcpStream,
        bytes_tx_clone: Arc<AtomicU64>,
        checker: C,
    ) -> thread::JoinHandle<io::Result<()>>
    {
        thread::spawn(move || -> io::Result<()> {
            let mut vsock_read = vsock_reader;
            let mut tcp_write = tcp_writer;
            let mut vsock_buf = [0u8; 8192];

            let result = (|| -> io::Result<()> {
                loop {
                    match vsock_read.read(&mut vsock_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let current_tx =
                                bytes_tx_clone.fetch_add(n as u64, Ordering::SeqCst) + n as u64;

                            checker.check(current_tx)?;

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
        })
    }

    match tx_bytes_limit {
        Some(limit) => copy_loop(
            vsock_reader,
            tcp_writer,
            bytes_tx_clone,
            WithLimit { limit },
        ),
        None => copy_loop(vsock_reader, tcp_writer, bytes_tx_clone, NoLimit),
    }
}

/// Copies data bidirectionally between vsock and TCP streams
/// Optionally enforces a hard TX bytes limit on the VSOCK -> TCP direction
pub fn copy_bidirectional(
    vsock: VsockStream,
    tcp: TcpStream,
    tx_bytes_limit: Option<u64>,
) -> io::Result<()>
{
    let mut tcp_buf = [0u8; BUFFER_SIZE];
    let bytes_tx = Arc::new(AtomicU64::new(0));
    let bytes_rx = Arc::new(AtomicU64::new(0));

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
        if let Err(e) = tcp_read.shutdown(Shutdown::Read) {
            debug!("TCP read shutdown (expected on peer close): {}", e);
        }
        if let Err(e) = vsock_write.shutdown(Shutdown::Write) {
            debug!("Vsock write shutdown (expected on peer close): {}", e);
        }
        result
    });

    let vsock_reader = vsock.try_clone().expect("Failed to clone vsock");
    let tcp_writer = tcp.try_clone().expect("Failed to clone TCP stream");
    let bytes_tx_clone = Arc::clone(&bytes_tx);

    // Handling VSOCK -> TCP stream
    let vsock_read_result =
        copy_vsock_to_tcp(vsock_reader, tcp_writer, bytes_tx_clone, tx_bytes_limit);

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

    match vsock_read_result.join() {
        Ok(thread_result) => {
            if let Err(e) = thread_result {
                if !is_expected_close_error(&e) {
                    debug!("VSOCK -> TCP thread error: {}", e);
                }
            }
        }
        Err(_) => debug!("VSOCK -> TCP thread panicked"),
    }

    debug!(
        "Connection complete: TX: {} bytes, RX: {} bytes total",
        bytes_tx.load(Ordering::SeqCst),
        bytes_rx.load(Ordering::SeqCst)
    );

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
