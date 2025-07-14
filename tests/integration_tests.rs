use rust_cli_wallet::wallet::{Wallet, WalletAddress, Utxo, UtxoStatus};

#[tokio::test]
async fn test_wallet_creation_and_persistence() {
    let mut wallet = Wallet {
        addresses: Vec::new(),
        next_index: 0,
        mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
    };
    
    // Test wallet creation
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    wallet.initialize_with_seed(mnemonic).await.unwrap();
    assert!(wallet.address_count() > 0);
    
    // Test save/load
    let test_path = std::path::PathBuf::from("test_wallet.json");
    wallet.save_to_file(&test_path).unwrap();
    let loaded = Wallet::load_from_file(&test_path).unwrap();
    assert_eq!(loaded.address_count(), wallet.address_count());
    
    // Cleanup
    let _ = std::fs::remove_file(&test_path);
}

#[test]
fn test_wallet_operations() {
    let mut wallet = Wallet {
        addresses: Vec::new(),
        next_index: 0,
        mnemonic: None,
    };
    
    // Test address operations
    wallet.addresses.push(WalletAddress {
        address: "addr1".to_string(),
        private_key: "key1".to_string(),
        public_key: "pubkey1".to_string(),
        utxos: vec![Utxo {
            txid: "tx1".to_string(),
            vout: 0,
            value: 1000,
            status: UtxoStatus {
                confirmed: true,
                block_height: Some(1000),
                block_hash: Some("hash1".to_string()),
                block_time: Some(1234567890),
            },
        }],
        derivation_path: "m/44'/1'/0'/0/0".to_string(),
    });
    assert_eq!(wallet.address_count(), 1);
    
    // Test UTXO operations
    let utxos = wallet.get_utxos_from_address("addr1");
    assert!(utxos.is_ok());
    assert_eq!(utxos.unwrap().len(), 1);
}

#[test]
fn test_error_handling() {
    let wallet = Wallet {
        addresses: Vec::new(),
        next_index: 0,
        mnemonic: None,
    };
    
    // Test invalid operations
    assert!(wallet.get_address(999).is_none());
    assert!(wallet.get_utxos_from_address("nonexistent").is_err());
}

#[test]
fn test_wallet_serialization() {
    let wallet = Wallet {
        addresses: vec![WalletAddress {
            address: "addr1".to_string(),
            private_key: "key1".to_string(),
            public_key: "pubkey1".to_string(),
            utxos: vec![Utxo {
                txid: "tx1".to_string(),
                vout: 0,
                value: 1000,
                status: UtxoStatus {
                    confirmed: true,
                    block_height: Some(1000),
                    block_hash: Some("hash1".to_string()),
                    block_time: Some(1234567890),
                },
            }],
            derivation_path: "m/44'/1'/0'/0/0".to_string(),
        }],
        next_index: 1,
        mnemonic: Some("test mnemonic".to_string()),
    };
    
    // Test JSON roundtrip
    let json = serde_json::to_string(&wallet).unwrap();
    let deserialized: Wallet = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.address_count(), wallet.address_count());
} 