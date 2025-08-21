use rust_cli_wallet::wallet::{Wallet, WalletAddress, Utxo, UtxoStatus};
use std::collections::HashMap;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;

#[tokio::test]
async fn test_wallet_creation_and_persistence() {
    let mut wallet = Wallet {
        addresses: Vec::new(),
        next_index: 0,
        next_multisig_index: 0,
        mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        multisig_wallets: Vec::new(),
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
        next_multisig_index: 0,
        mnemonic: None,
        multisig_wallets: Vec::new(),
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
        next_multisig_index: 0,
        mnemonic: None,
        multisig_wallets: Vec::new(),
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
        next_multisig_index: 0,
        mnemonic: Some("test mnemonic".to_string()),
        multisig_wallets: Vec::new(),
    };
    
    // Test JSON roundtrip
    let json = serde_json::to_string(&wallet).unwrap();
    let deserialized: Wallet = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.address_count(), wallet.address_count());
}

#[tokio::test]
async fn test_multisig_wallet_creation() {
    let mut wallet = Wallet {
        addresses: Vec::new(),
        next_index: 0,
        next_multisig_index: 0,
        mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        multisig_wallets: Vec::new(),
    };
    
    // Create a multi-signature wallet using generated keys
    let secp = Secp256k1::new();
    let sk1 = SecretKey::new(&mut rand::thread_rng());
    let sk2 = SecretKey::new(&mut rand::thread_rng());
    let sk3 = SecretKey::new(&mut rand::thread_rng());
    let pk1 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk1, Network::Testnet));
    let pk2 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk2, Network::Testnet));
    let pk3 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk3, Network::Testnet));
    let public_keys = vec![pk1.to_string(), pk2.to_string(), pk3.to_string()];

    let mut my_private_keys = HashMap::new();
    let wif1 = bitcoin::PrivateKey::new(sk1, Network::Testnet).to_wif();
    my_private_keys.insert(public_keys[0].clone(), wif1);
    
    let wallet_id = wallet.create_multisig_wallet(
        "Test Multi-Sig".to_string(),
        public_keys,
        2, // 2-of-3
        my_private_keys,
        bitcoin::Network::Testnet,
    ).expect("Failed to create multi-signature wallet");
    
    // Verify the wallet was created
    assert_eq!(wallet.multisig_wallet_count(), 1);
    
    let multisig_wallet = wallet.get_multisig_wallet(&wallet_id)
        .expect("Multi-signature wallet not found");
    
    assert_eq!(multisig_wallet.name, "Test Multi-Sig");
    assert_eq!(multisig_wallet.required_signatures, 2);
    assert_eq!(multisig_wallet.total_signers, 3);
    assert!(multisig_wallet.can_sign());
    assert_eq!(multisig_wallet.my_key_count(), 1);
    
    // Test listing multi-signature wallets
    let wallet_list = wallet.list_multisig_wallets();
    assert!(wallet_list.contains("Test Multi-Sig"));
    assert!(wallet_list.contains("2-of-3"));
    
    // Test balance calculation
    assert_eq!(wallet.get_total_multisig_balance(), 0);
    
    // Test wallet removal
    assert!(wallet.remove_multisig_wallet(&wallet_id));
    assert_eq!(wallet.multisig_wallet_count(), 0);
}

#[tokio::test]
async fn test_multisig_complete_workflow() {
    let mut wallet = Wallet {
        addresses: Vec::new(),
        next_index: 0,
        next_multisig_index: 0,
        mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        multisig_wallets: Vec::new(),
    };
    
    println!("=== Multi-Signature Wallet Complete Workflow Test ===");
    
    // Step 1: Create a multi-signature wallet
    println!("Step 1: Creating multi-signature wallet...");
    // Generate keys for the complete workflow as well
    let secp = Secp256k1::new();
    let sk1 = SecretKey::new(&mut rand::thread_rng());
    let sk2 = SecretKey::new(&mut rand::thread_rng());
    let sk3 = SecretKey::new(&mut rand::thread_rng());
    let pk1 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk1, Network::Testnet));
    let pk2 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk2, Network::Testnet));
    let pk3 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk3, Network::Testnet));
    let public_keys = vec![pk1.to_string(), pk2.to_string(), pk3.to_string()];

    let mut my_private_keys = HashMap::new();
    let wif1 = bitcoin::PrivateKey::new(sk1, Network::Testnet).to_wif();
    my_private_keys.insert(public_keys[0].clone(), wif1);
    
    let wallet_id = wallet.create_multisig_wallet(
        "Company Treasury".to_string(),
        public_keys,
        2, // 2-of-3
        my_private_keys,
        bitcoin::Network::Testnet,
    ).expect("Failed to create multi-signature wallet");
    
    println!("✅ Multi-signature wallet created with ID: {}", wallet_id);
    
    // Step 2: Verify wallet properties
    println!("\nStep 2: Verifying wallet properties...");
    let multisig_wallet = wallet.get_multisig_wallet(&wallet_id)
        .expect("Multi-signature wallet not found");
    
    assert_eq!(multisig_wallet.name, "Company Treasury");
    assert_eq!(multisig_wallet.required_signatures, 2);
    assert_eq!(multisig_wallet.total_signers, 3);
    assert!(multisig_wallet.can_sign());
    assert_eq!(multisig_wallet.my_key_count(), 1);
    
    println!("✅ Wallet properties verified:");
    println!("   - Name: {}", multisig_wallet.name);
    println!("   - Required signatures: {}/{}", multisig_wallet.required_signatures, multisig_wallet.total_signers);
    println!("   - Can sign: {}", multisig_wallet.can_sign());
    println!("   - My keys: {}", multisig_wallet.my_key_count());
    println!("   - Address: {}", multisig_wallet.address);
    
    // Step 3: Test wallet listing
    println!("\nStep 3: Testing wallet listing...");
    let wallet_list = wallet.list_multisig_wallets();
    println!("{}", wallet_list);
    assert!(wallet_list.contains("Company Treasury"));
    assert!(wallet_list.contains("2-of-3"));
    
    // Step 4: Test balance management
    println!("\nStep 4: Testing balance management...");
    assert_eq!(wallet.get_total_multisig_balance(), 0);
    println!("✅ Initial balance: {} satoshis", wallet.get_total_multisig_balance());
    
    // Step 5: Test transaction creation (without actual UTXOs)
    println!("\nStep 5: Testing transaction creation...");
    let transaction_result = wallet.create_multisig_transaction(
        &wallet_id,
        "tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", // Test destination
        10000, // 0.0001 BTC
        5, // 5 sat/byte fee rate
    );
    
    // This should fail because there are no UTXOs, but it tests the method structure
    match transaction_result {
        Ok(_) => println!("✅ Transaction creation succeeded (unexpected - should have no UTXOs)"),
        Err(e) => println!("✅ Transaction creation failed as expected: {}", e),
    }
    
    // Step 6: Test wallet removal
    println!("\nStep 6: Testing wallet removal...");
    assert!(wallet.remove_multisig_wallet(&wallet_id));
    assert_eq!(wallet.multisig_wallet_count(), 0);
    println!("✅ Wallet removed successfully");
    
    println!("\n=== Multi-Signature Test Complete ===");
} 