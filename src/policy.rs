use log::debug;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::RwLock;

/// Rule defining access policy for a specific server
#[derive(Debug, Clone, Deserialize)]
pub struct ServerRule
{
    /// Server address - can be a domain name or IPv4/IPv6 address
    pub address: String,
    /// Server port number
    pub port: u16,
    /// Maximum number of bytes that can be sent to this server
    pub tx_bytes_limit: u64,
}

/// Whitelist of allowed servers
pub type ServerWhitelist = Vec<ServerRule>;

/// A polocy manager maintaining the whitelist of servers
pub struct PolicyManager
{
    whitelist: RwLock<ServerWhitelist>,
}

impl PolicyManager
{
    /// Creates a new PolicyManager with an empty whitelist
    pub fn new() -> Self
    {
        PolicyManager {
            whitelist: RwLock::new(ServerWhitelist::new()),
        }
    }

    /// Loads the whitelist from a JSON file
    ///
    /// # Arguments
    /// * `filename` - Path to the JSON file containing server rules
    ///
    /// # Returns
    /// * `Ok(())` if the file was successfully loaded and parsed
    /// * `Err(String)` if there was an error reading or parsing the file, or if duplicate rules are detected
    pub fn load_from_file(&self, filename: &str) -> Result<(), String>
    {
        let content = fs::read_to_string(filename)
            .map_err(|e| format!("Failed to read file '{}': {}", filename, e))?;

        let whitelist: ServerWhitelist = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON from '{}': {}", filename, e))?;

        // Check for duplicate (address, port) pairs
        let mut seen_rules: HashSet<(String, u16)> = HashSet::new();
        for rule in &whitelist {
            let key = (rule.address.to_lowercase(), rule.port);
            if !seen_rules.insert(key.clone()) {
                return Err(format!(
                    "Duplicate rule detected in '{}': address='{}', port={}",
                    filename, rule.address, rule.port
                ));
            }
        }

        let mut guard = self
            .whitelist
            .write()
            .map_err(|e| format!("Failed to acquire write lock: {}", e))?;

        *guard = whitelist;

        Ok(())
    }

    /// Checks if a connection to the specified server is allowed
    ///
    /// # Arguments
    /// * `address` - Server address (domain name or IP address)
    /// * `port` - Server port number
    ///
    /// # Returns
    /// * `true` if the server is in the whitelist
    /// * `false` if the server is not in the whitelist
    pub fn is_allowed(&self, address: &str, port: u16) -> bool
    {
        let guard = self.whitelist.read().expect("Failed to acquire read lock");

        for rule in guard.iter() {
            if rule.port == port && self.addresses_match(&rule.address, address) {
                return true;
            }
        }

        false
    }

    /// Gets the TX bytes limit for a specific server
    ///
    /// # Arguments
    /// * `address` - Server address (domain name or IP address)
    /// * `port` - Server port number
    ///
    /// # Returns
    /// * `Some(u64)` with the byte limit if the server is in the whitelist
    /// * `None` if the server is not in the whitelist
    pub fn tx_bytes_limit(&self, address: &str, port: u16) -> Option<u64>
    {
        let guard = self.whitelist.read().expect("Failed to acquire read lock");

        for rule in guard.iter() {
            if rule.port == port && self.addresses_match(&rule.address, address) {
                return Some(rule.tx_bytes_limit);
            }
        }

        None
    }

    /// Compares two addresses, handling both domain names and IP addresses
    fn addresses_match(&self, rule_addr: &str, check_addr: &str) -> bool
    {
        // First try exact string match (for domain names or when both are the same format)
        if rule_addr.to_lowercase() == check_addr.to_lowercase() {
            return true;
        }

        // Try to parse both as IP addresses and compare
        if let (Ok(rule_ip), Ok(check_ip)) = (
            rule_addr.parse::<Ipv4Addr>(),
            check_addr.parse::<Ipv4Addr>(),
        ) {
            return rule_ip == check_ip;
        }

        false
    }

    /// Logs the loaded from JSON file policy rules to debug output
    pub fn log_policy(&self)
    {
        let guard = self.whitelist.read().expect("Failed to acquire read lock");
        debug!("Loaded policy with {} rules:", guard.len());
        for rule in guard.iter() {
            debug!(
                "  - address: {}, port: {}, tx_bytes_limit: {}",
                rule.address, rule.port, rule.tx_bytes_limit
            );
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_load_from_file()
    {
        let manager = PolicyManager::new();

        // Create a temporary test file
        let test_content = r#"[
            {"address": "example.com", "port": 443, "tx_bytes_limit": 1024},
            {"address": "192.168.1.1", "port": 8080, "tx_bytes_limit": 2048}
        ]"#;

        let test_file = "/tmp/test_policy.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        assert!(manager.load_from_file(test_file).is_ok());

        // Clean up
        fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_is_allowed()
    {
        let manager = PolicyManager::new();

        let test_content = r#"[
            {"address": "example.com", "port": 443, "tx_bytes_limit": 1024}
        ]"#;

        let test_file = "/tmp/test_policy2.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        manager.load_from_file(test_file).unwrap();

        assert!(manager.is_allowed("example.com", 443));
        assert!(!manager.is_allowed("example.com", 80));
        assert!(!manager.is_allowed("other.com", 443));

        fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_tx_bytes_limit()
    {
        let manager = PolicyManager::new();

        let test_content = r#"[
            {"address": "example.com", "port": 443, "tx_bytes_limit": 1024}
        ]"#;

        let test_file = "/tmp/test_policy3.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        manager.load_from_file(test_file).unwrap();

        assert_eq!(manager.tx_bytes_limit("example.com", 443), Some(1024));
        assert_eq!(manager.tx_bytes_limit("example.com", 80), None);

        fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_duplicate_detection()
    {
        let manager = PolicyManager::new();

        // Test duplicate address and port
        let test_content = r#"[
            {"address": "example.com", "port": 443, "tx_bytes_limit": 1024},
            {"address": "example.com", "port": 443, "tx_bytes_limit": 2048}
        ]"#;

        let test_file = "/tmp/test_policy_dup.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        // Should fail due to duplicate
        assert!(manager.load_from_file(test_file).is_err());

        // Test case-insensitive duplicate detection
        let test_content = r#"[
            {"address": "Example.com", "port": 443, "tx_bytes_limit": 1024},
            {"address": "EXAMPLE.COM", "port": 443, "tx_bytes_limit": 2048}
        ]"#;

        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        // Should fail due to case-insensitive duplicate
        assert!(manager.load_from_file(test_file).is_err());

        // Clean up
        fs::remove_file(test_file).ok();
    }
}
