use log::debug;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};

/// Rule defining access policy for a specific server
#[derive(Debug)]
pub struct ServerRule
{
    /// Server address - can be a domain name or IPv4/IPv6 address
    pub address: String,
    /// Server port number
    pub port: u16,
    /// Maximum number of bytes that can be sent to this server
    pub tx_bytes_limit: u64,
    /// Atomic counter tracking cumulative bytes sent to this server (not serialized)
    pub tx_bytes_used: Arc<AtomicU64>,
}

/// Custom deserialization to initialize tx_bytes_used
impl<'de> Deserialize<'de> for ServerRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ServerRuleHelper {
            pub address: String,
            pub port: u16,
            pub tx_bytes_limit: u64,
        }

        let helper = ServerRuleHelper::deserialize(deserializer)?;
        Ok(ServerRule {
            address: helper.address,
            port: helper.port,
            tx_bytes_limit: helper.tx_bytes_limit,
            tx_bytes_used: Arc::new(AtomicU64::new(0)),
        })
    }
}

/// Clone implementation for ServerRule that shares the tx_bytes_used counter
impl Clone for ServerRule {
    fn clone(&self) -> Self {
        ServerRule {
            address: self.address.clone(),
            port: self.port,
            tx_bytes_limit: self.tx_bytes_limit,
            tx_bytes_used: Arc::clone(&self.tx_bytes_used),
        }
    }
}

/// Whitelist of allowed servers
pub type ServerWhitelist = Vec<ServerRule>;

/// A policy manager maintaining the whitelist of servers
pub struct PolicyManager
{
    whitelist: RwLock<ServerWhitelist>,
}

impl PolicyManager
{
    pub fn new() -> Self
    {
        PolicyManager {
            whitelist: RwLock::new(ServerWhitelist::new()),
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

    pub fn tx_bytes_used(&self, address: &str, port: u16) -> Option<u64>
    {
        let guard = self.whitelist.read().expect("Failed to acquire read lock");

        for rule in guard.iter() {
            if rule.port == port && self.addresses_match(&rule.address, address) {
                return Some(rule.tx_bytes_used.load(Ordering::SeqCst));
            }
        }

        None
    }

    pub fn check_and_add_tx_bytes(&self, address: &str, port: u16, bytes_to_add: u64) -> Result<(), std::io::Error>
    {
        let guard = self.whitelist.read().expect("Failed to acquire read lock");

        for rule in guard.iter() {
            if rule.port == port && self.addresses_match(&rule.address, address) {
                let current = rule.tx_bytes_used.load(Ordering::SeqCst);

                // Check if adding bytes_to_add would exceed the limit
                if current.saturating_add(bytes_to_add) > rule.tx_bytes_limit {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "TX bytes limit exceeded for {}:{}: {} + {} > {}",
                            rule.address, rule.port, current, bytes_to_add, rule.tx_bytes_limit
                        ),
                    ));
                }

                rule.tx_bytes_used.fetch_add(bytes_to_add, Ordering::SeqCst);

                return Ok(());
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Server {}:{} not found in whitelist", address, port),
        ))
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
        let guard = self.whitelist.read().expect("Failed to acquire read lock");
        debug!("Loaded policy with {} rules:", guard.len());
        for rule in guard.iter() {
            debug!(
                "  - address: {}, port: {}, tx_bytes_limit: {}, tx_bytes_used: {}",
                rule.address, rule.port, rule.tx_bytes_limit, rule.tx_bytes_used.load(Ordering::SeqCst)
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

        // Initially, tx_bytes_used should be 0
        assert_eq!(manager.tx_bytes_used("example.com", 443), Some(0));

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
        assert_eq!(manager.tx_bytes_used("example.com", 443), Some(100));

        // Second addition should succeed
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 200).is_ok());
        assert_eq!(manager.tx_bytes_used("example.com", 443), Some(300));

        // Third addition that would exceed limit should fail
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 800).is_err());
        // Counter should remain unchanged after failed addition
        assert_eq!(manager.tx_bytes_used("example.com", 443), Some(300));

        // Addition that brings exactly to limit should succeed
        assert!(manager.check_and_add_tx_bytes("example.com", 443, 700).is_ok());
        assert_eq!(manager.tx_bytes_used("example.com", 443), Some(1000));

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
            assert_eq!(manager.tx_bytes_used("example.com", 443), Some(i * 100));
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

        // Add bytes to server1
        assert!(manager.check_and_add_tx_bytes("server1.com", 443, 500).is_ok());
        assert_eq!(manager.tx_bytes_used("server1.com", 443), Some(500));
        assert_eq!(manager.tx_bytes_used("server2.com", 443), Some(0));

        // Add bytes to server2
        assert!(manager.check_and_add_tx_bytes("server2.com", 443, 1500).is_ok());
        assert_eq!(manager.tx_bytes_used("server1.com", 443), Some(500));
        assert_eq!(manager.tx_bytes_used("server2.com", 443), Some(1500));

        // server1 should still have room for 500 more
        assert!(manager.check_and_add_tx_bytes("server1.com", 443, 500).is_ok());
        assert_eq!(manager.tx_bytes_used("server1.com", 443), Some(1000));

        // server1 is now at limit
        assert!(manager.check_and_add_tx_bytes("server1.com", 443, 1).is_err());

        // server2 should still have room for 500 more
        assert!(manager.check_and_add_tx_bytes("server2.com", 443, 500).is_ok());
        assert_eq!(manager.tx_bytes_used("server2.com", 443), Some(2000));

        fs::remove_file(test_file).ok();
    }
}
