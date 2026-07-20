use log::{debug, info};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};

/// Rule defining access policy for a specific server
/// This struct contains only configuration data from the JSON policy file
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

/// Key for identifying a server in the stats map
type ServerKey = (String, u16);

/// Runtime statistics for servers, tracking cumulative TX bytes used
pub struct ServerStatsHashMap
{
    stats: HashMap<ServerKey, Arc<AtomicU64>>,
}

impl ServerStatsHashMap {
    pub fn new() -> Self {
        ServerStatsHashMap {
            stats: HashMap::new(),
        }
    }

    /// Gets or creates a counter for the given server
    pub fn get_or_create_counter(&mut self, address: &str, port: u16) -> Arc<AtomicU64> {
        let key = (address.to_lowercase(), port);
        self.stats
            .entry(key)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone()
    }
}

impl Default for ServerStatsHashMap {
    fn default() -> Self {
        Self::new()
    }
}

/// A policy manager maintaining the whitelist of servers and runtime statistics
pub struct PolicyManager
{
    whitelist: RwLock<ServerWhitelist>,
    stats: RwLock<ServerStatsHashMap>,
}

impl PolicyManager
{
    pub fn new() -> Self
    {
        PolicyManager {
            whitelist: RwLock::new(ServerWhitelist::new()),
            stats: RwLock::new(ServerStatsHashMap::new()),
        }
    }

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

    /// Gets the current TX bytes used for a specific server
    /// Creates a counter if one doesn't exist yet
    pub fn tx_bytes_used(&self, address: &str, port: u16) -> u64
    {
        let mut stats_guard = self.stats.write().expect("Failed to acquire stats write lock");
        let counter = stats_guard.get_or_create_counter(address, port);
        counter.load(Ordering::SeqCst)
    }

    /// Checks if adding the specified bytes would exceed the limit for the server,
    /// and if not, atomically adds the bytes to the counter.
    pub fn check_and_add_tx_bytes(&self, address: &str, port: u16, bytes_to_add: u64) -> Result<(), std::io::Error>
    {
        // First check if the server is in the whitelist and get its limit
        let whitelist_guard = self.whitelist.read().expect("Failed to acquire read lock");
        let tx_bytes_limit = whitelist_guard
            .iter()
            .find(|rule| rule.port == port && self.addresses_match(&rule.address, address))
            .map(|rule| rule.tx_bytes_limit)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("Server {}:{} not found in whitelist", address, port),
                )
            })?;

        drop(whitelist_guard);

        // Get or create the counter in stats map
        let mut stats_guard = self.stats.write().expect("Failed to acquire stats write lock");
        let counter = stats_guard.get_or_create_counter(address, port);

        // Check and add atomically using compare-exchange loop
        loop {
            let current = counter.load(Ordering::SeqCst);

            // Check if adding bytes_to_add would exceed the limit
            if current.saturating_add(bytes_to_add) > tx_bytes_limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "TX bytes limit exceeded for {}:{}: {} + {} > {}",
                        address, port, current, bytes_to_add, tx_bytes_limit
                    ),
                ));
            }

            // Try to atomically add the bytes
            match counter.compare_exchange(current, current + bytes_to_add, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Ok(()),
                Err(_new_current) => {
                    // Another thread modified the counter, retry with new value
                    continue;
                }
            }
        }
    }


    /// Compares two addresses, handling both domain names and IP addresses
    fn addresses_match(&self, rule_addr: &str, check_addr: &str) -> bool
    {
        // First try exact string match (for domain names or when both are the same format)
        if rule_addr.to_lowercase() == check_addr.to_lowercase() {
            return true;
        }

        // Try to parse both as IPv4/IPv6 addresses and compare
        if let (Ok(rule_ip), Ok(check_ip)) = (
            rule_addr.parse::<Ipv4Addr>(),
            check_addr.parse::<Ipv4Addr>(),
        ) {
            return rule_ip == check_ip;
        }

        if let (Ok(rule_ip), Ok(check_ip)) = (
            rule_addr.parse::<Ipv6Addr>(),
            check_addr.parse::<Ipv6Addr>()
        ) {
            return rule_ip == check_ip;
        }

        false
    }

    pub fn log_policy(&self)
    {
        let whitelist_guard = self.whitelist.read().expect("Failed to acquire read lock");
        debug!("Loaded policy with {} rules:", whitelist_guard.len());
        for rule in whitelist_guard.iter() {
            debug!(
                "  - address: {}, port: {}, tx_bytes_limit: {}",
                rule.address, rule.port, rule.tx_bytes_limit
            );
        }
    }

    /// Logs connection completion with cumulative TX bytes used for the server
    pub fn log_connection_complete(&self, address: &str, port: u16, bytes_rx: u64)
    {
        let used = self.tx_bytes_used(address, port);
        if let Some(limit) = self.tx_bytes_limit(address, port) {
            info!(
                "Connection complete: Server {}:{} used {} / {} bytes (cumulative)",
                address, port, used, limit
            );
        } else {
            info!("Connection complete: RX: {} bytes", bytes_rx);
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

    #[test]
    fn test_tx_bytes_used_initial()
    {
        let manager = PolicyManager::new();

        let test_content = r#"[
            {"address": "example.com", "port": 443, "tx_bytes_limit": 1024}
        ]"#;

        let test_file = "/tmp/test_policy_bytes.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        manager.load_from_file(test_file).unwrap();

        // Initially, tx_bytes_used returns 0 (counter created on first call)
        assert_eq!(manager.tx_bytes_used("example.com", 443), 0);

        // After first transmission, counter is updated
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 100).is_ok());
        assert_eq!(manager.tx_bytes_used("example.com", 443), 100);

        fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_check_and_add_tx_bytes()
    {
        let manager = PolicyManager::new();

        let test_content = r#"[
            {"address": "example.com", "port": 443, "tx_bytes_limit": 1000}
        ]"#;

        let test_file = "/tmp/test_policy_check_add.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        manager.load_from_file(test_file).unwrap();

        // First addition should succeed
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 100).is_ok());
        assert_eq!(manager.tx_bytes_used("example.com", 443), 100);

        // Second addition should succeed
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 200).is_ok());
        assert_eq!(manager.tx_bytes_used("example.com", 443), 300);

        // Third addition that would exceed limit should fail
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 800).is_err());
        // Counter should remain unchanged after failed addition
        assert_eq!(manager.tx_bytes_used("example.com", 443), 300);

        // Addition that brings exactly to limit should succeed
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 700).is_ok());
        assert_eq!(manager.tx_bytes_used("example.com", 443), 1000);

        // Any further addition should fail
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 1).is_err());

        fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_check_and_add_tx_bytes_unknown_server()
    {
        let manager = PolicyManager::new();

        let test_content = r#"[
            {"address": "example.com", "port": 443, "tx_bytes_limit": 1000}
        ]"#;

        let test_file = "/tmp/test_policy_unknown.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        manager.load_from_file(test_file).unwrap();

        // Adding bytes to unknown server should fail
        let result = manager.check_and_add_tx_bytes("unknown.com", 443, 100);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);

        // Adding bytes to known server but unknown port should fail
        let result = manager.check_and_add_tx_bytes("example.com", 80, 100);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);

        fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_tx_bytes_used_cumulative()
    {
        let manager = PolicyManager::new();

        let test_content = r#"[
            {"address": "example.com", "port": 443, "tx_bytes_limit": 10000}
        ]"#;

        let test_file = "/tmp/test_policy_cumulative.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        manager.load_from_file(test_file).unwrap();

        // Simulate multiple sessions adding bytes
        for i in 1..=10 {
            assert!(manager.check_and_add_tx_bytes("example.com", 443, 100).is_ok());
            assert_eq!(manager.tx_bytes_used("example.com", 443), i * 100);
        }

        fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_tx_bytes_used_multiple_servers()
    {
        let manager = PolicyManager::new();

        let test_content = r#"[
            {"address": "server1.com", "port": 443, "tx_bytes_limit": 1000},
            {"address": "server2.com", "port": 443, "tx_bytes_limit": 2000}
        ]"#;

        let test_file = "/tmp/test_policy_multi.json";
        let mut file = File::create(test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        manager.load_from_file(test_file).unwrap();

        // Initially, counters return 0
        assert_eq!(manager.tx_bytes_used("server1.com", 443), 0);
        assert_eq!(manager.tx_bytes_used("server2.com", 443), 0);

        // Add bytes to server1
        assert!(manager.check_and_add_tx_bytes("server1.com", 443, 500).is_ok());
        assert_eq!(manager.tx_bytes_used("server1.com", 443), 500);
        assert_eq!(manager.tx_bytes_used("server2.com", 443), 0);

        // Add bytes to server2
        assert!(manager.check_and_add_tx_bytes("server2.com", 443, 1500).is_ok());
        assert_eq!(manager.tx_bytes_used("server1.com", 443), 500);
        assert_eq!(manager.tx_bytes_used("server2.com", 443), 1500);

        // server1 should still have room for 500 more
        assert!(manager.check_and_add_tx_bytes("server1.com", 443, 500).is_ok());
        assert_eq!(manager.tx_bytes_used("server1.com", 443), 1000);

        // server1 is now at limit
        assert!(manager.check_and_add_tx_bytes("server1.com", 443, 1).is_err());

        // server2 should still have room for 500 more
        assert!(manager.check_and_add_tx_bytes("server2.com", 443, 500).is_ok());
        assert_eq!(manager.tx_bytes_used("server2.com", 443), 2000);

        fs::remove_file(test_file).ok();
    }
}
