use rust_cli_wallet::wallet::{Wallet, WalletAddress, Utxo, UtxoStatus};
use std::path::PathBuf;
use std::fs;

/// Common test utilities for the wallet tests
pub struct TestUtils;

impl TestUtils {
    /// Creates a test wallet with a known mnemonic
    pub fn create_test_wallet() -> Wallet {
        Wallet {
            addresses: Vec::new(),
            next_index: 0,
            mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        }
    }

    /// Creates a test UTXO with specified parameters
    pub fn create_test_utxo(txid: &str, vout: u32, value: u64) -> Utxo {
        Utxo {
            txid: txid.to_string(),
            vout,
            value,
            status: UtxoStatus {
                confirmed: true,
                block_height: Some(1000),
                block_hash: Some("test_block_hash".to_string()),
                block_time: Some(1234567890),
            },
        }
    }

    /// Creates a test address with specified parameters
    pub fn create_test_address(address: &str, private_key: &str, balance: u64) -> WalletAddress {
        let utxos = if balance > 0 {
            vec![Self::create_test_utxo("test_txid", 0, balance)]
        } else {
            Vec::new()
        };

        WalletAddress {
            address: address.to_string(),
            private_key: private_key.to_string(),
            public_key: "test_public_key".to_string(),
            utxos,
            derivation_path: "m/44'/1'/0'/0/0".to_string(),
        }
    }

    /// Creates a test wallet with multiple addresses and UTXOs
    pub fn create_populated_test_wallet() -> Wallet {
        let mut wallet = Self::create_test_wallet();
        
        // Add addresses with different UTXO configurations
        wallet.addresses.push(Self::create_test_address("addr1", "key1", 1000));
        wallet.addresses.push(Self::create_test_address("addr2", "key2", 2000));
        wallet.addresses.push(Self::create_test_address("addr3", "key3", 0)); // Empty address
        
        wallet
    }

    /// Creates a temporary test file path
    pub fn create_temp_file_path(prefix: &str) -> PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        
        PathBuf::from(format!("test_{}_{}.json", prefix, timestamp))
    }

    /// Cleans up test files
    pub fn cleanup_test_file(path: &PathBuf) {
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }

    /// Validates wallet data integrity
    pub fn validate_wallet_integrity(wallet: &Wallet) -> bool {
        // Check that all addresses have valid data
        for addr in &wallet.addresses {
            if addr.address.is_empty() || addr.private_key.is_empty() {
                return false;
            }
            
            // Check that UTXOs have valid data
            for utxo in &addr.utxos {
                if utxo.txid.is_empty() {
                    return false;
                }
            }
        }
        
        true
    }

    /// Calculates total wallet balance
    pub fn calculate_total_balance(wallet: &Wallet) -> u64 {
        wallet.addresses.iter()
            .flat_map(|addr| &addr.utxos)
            .map(|utxo| utxo.value)
            .sum()
    }

    /// Validates that a wallet can be serialized and deserialized correctly
    pub fn test_serialization_roundtrip(wallet: &Wallet) -> bool {
        match serde_json::to_string(wallet) {
            Ok(json) => {
                match serde_json::from_str::<Wallet>(&json) {
                    Ok(deserialized) => {
                        deserialized.address_count() == wallet.address_count() &&
                        deserialized.next_index == wallet.next_index &&
                        deserialized.mnemonic == wallet.mnemonic
                    }
                    Err(_) => false
                }
            }
            Err(_) => false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_utils_creation() {
        let wallet = TestUtils::create_test_wallet();
        assert_eq!(wallet.address_count(), 0);
        assert!(wallet.mnemonic.is_some());

        let utxo = TestUtils::create_test_utxo("test_tx", 0, 1000);
        assert_eq!(utxo.txid, "test_tx");
        assert_eq!(utxo.value, 1000);

        let address = TestUtils::create_test_address("test_addr", "test_key", 500);
        assert_eq!(address.address, "test_addr");
        assert_eq!(address.utxos.len(), 1);
    }

    #[test]
    fn test_populated_wallet() {
        let wallet = TestUtils::create_populated_test_wallet();
        assert_eq!(wallet.address_count(), 3);
        
        let balance = TestUtils::calculate_total_balance(&wallet);
        assert_eq!(balance, 3000); // 1000 + 2000 + 0
    }

    #[test]
    fn test_wallet_integrity() {
        let wallet = TestUtils::create_populated_test_wallet();
        assert!(TestUtils::validate_wallet_integrity(&wallet));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let wallet = TestUtils::create_populated_test_wallet();
        assert!(TestUtils::test_serialization_roundtrip(&wallet));
    }

    #[test]
    fn test_temp_file_path() {
        let path = TestUtils::create_temp_file_path("test");
        assert!(path.to_string_lossy().contains("test_"));
        assert!(path.to_string_lossy().ends_with(".json"));
    }
} 