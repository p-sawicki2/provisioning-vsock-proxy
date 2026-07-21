use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Protocol message sent by ratls-get to request TCP connection
#[derive(Serialize, Deserialize, Debug)]
pub struct ProxyRequest
{
    pub command: String,
    pub server_addr: String,
}

/// Protocol response sent by proxy to ratls-get
#[derive(Serialize, Deserialize, Debug)]
pub struct ProxyResponse
{
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub fn read_connect_request<R: Read>(reader: &mut R) -> io::Result<ProxyRequest>
{
    let mut request_str = String::new();
    let mut buf = [0u8; 1024];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection closed before request",
            ));
        }

        if let Some(pos) = buf[..n].iter().position(|&b| b == b'\n') {
            request_str.push_str(std::str::from_utf8(&buf[..pos]).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("Invalid UTF-8: {}", e))
            })?);
            break;
        }

        request_str.push_str(std::str::from_utf8(&buf[..n]).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Invalid UTF-8: {}", e))
        })?);
    }

    let request: ProxyRequest = serde_json::from_str(&request_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e)))?;

    if request.command != "CONNECT" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid command: {}", request.command),
        ));
    }

    Ok(request)
}

pub fn send_connect_response<W: Write>(writer: &mut W, success: bool, message: &str) -> io::Result<()>
{
    let response = ProxyResponse {
        status: if success {
            "SUCCESS".to_string()
        } else {
            "FAILURE".to_string()
        },
        reason: if success {
            None
        } else {
            Some(message.to_string())
        },
    };

    let mut json = serde_json::to_string(&response).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON serialization error: {}", e),
        )
    })?;

    // ratls-get expects JSON followed by newline
    json.push('\n');
    writer.write_all(json.as_bytes())?;
    writer.flush()?;
    Ok(())
}
