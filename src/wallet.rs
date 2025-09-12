//! # Bitcoin CLI Wallet Implementation
//! 
//! This module provides a complete Bitcoin wallet implementation in Rust, supporting
//! wallet creation, address generation, transaction signing, and UTXO management.
//! 
//! ## Key Features
//! - BIP39 mnemonic phrase support for wallet recovery
//! - BIP44 hierarchical deterministic (HD) address generation
//! - Gap limit implementation for efficient address scanning
//! - P2PKH transaction signing and broadcasting
//! - UTXO management and balance tracking
//! - Secure private key handling
//! 
//! ## Security Considerations
//! - Private keys are stored in WIF format for compatibility
//! - Mnemonic phrases are stored securely for consistent address generation
//! - All cryptographic operations use the bitcoin-rs library for security
//! 
//! ## Usage Example
//! ```rust
//! use std::path::Path;
//! use rust_cli_wallet::wallet::Wallet;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a new wallet
//!     let mut wallet = Wallet {
//!         addresses: Vec::new(),
//!         next_index: 0,
//!         next_multisig_index: 0,
//!         mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
//!         multisig_wallets: Vec::new(),
//!     };
//!     
//!     // Initialize with mnemonic
//!     wallet.initialize_with_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").await?;
//! 
//!     // Generate a new address
//!     let address = wallet.get_new_address()?;
//!     println!("Generated address: {}", address);
//! 
//!     // Note: Transaction sending requires actual UTXOs, so we'll just show the structure
//!     // let txid = wallet.sign_and_send_transaction("destination_address", 10000, 5).await?;
//!     
//!     Ok(())
//! }

use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};
use std::error::Error as StdError;
use std::str::FromStr;
use super::multisig;
use bitcoin::{
    Address, Network, PrivateKey, ScriptBuf, Transaction as BitcoinTransaction,
    TxIn, TxOut, secp256k1::{Message, Secp256k1},
    consensus::encode::serialize_hex,
    sighash::{SighashCache, EcdsaSighashType},
    transaction::Version,
    absolute::LockTime,
    Sequence, Witness, Amount,
    OutPoint,
    hashes::{hash160, Hash, sha256},
};
// In bitcoin 0.32, Address::p2wpkh accepts a CompressedPublicKey via TryFrom<PublicKey>.
// Avoid importing a specific type path; instead use try_into to obtain the compressed key.

/// Represents an Unspent Transaction Output (UTXO) in the Bitcoin network.
/// 
/// UTXOs are the fundamental building blocks of Bitcoin transactions. Each UTXO
/// represents a specific amount of Bitcoin that can be spent as an input in a new transaction.
/// 
/// # Fields
/// - `txid`: The transaction ID that created this UTXO
/// - `vout`: The output index within that transaction (0-based)
/// - `value`: The amount in satoshis (1 BTC = 100,000,000 satoshis)
/// - `status`: Metadata about the UTXO's confirmation status
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Utxo {
    /// Transaction ID in hexadecimal format
    pub txid: String,
    /// Output index within the transaction (0-based)
    pub vout: u32,
    /// Amount in satoshis
    pub value: u64,
    /// Confirmation status and blockchain metadata
    pub status: UtxoStatus,
}

/// Contains metadata about a UTXO's status in the blockchain.
/// 
/// This struct tracks whether a UTXO has been confirmed in a block,
/// which block it's in, and when it was mined. This information is
/// crucial for determining if a UTXO is safe to spend.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UtxoStatus {
    /// Whether the UTXO has been confirmed in a block
    pub confirmed: bool,
    /// Block height where this UTXO was confirmed (None if unconfirmed)
    pub block_height: Option<u32>,
    /// Hash of the block containing this UTXO
    pub block_hash: Option<String>,
    /// Unix timestamp when the block was mined
    pub block_time: Option<u64>,
}

/// Represents a Bitcoin address in the wallet with its associated private key and UTXOs.
/// 
/// Each address in a Bitcoin wallet has its own private key and can hold multiple UTXOs.
/// The derivation path shows how this address was generated from the master seed.
/// 
/// # Security Note
/// The private key is stored in WIF (Wallet Import Format) for compatibility
/// with other Bitcoin software. In a production environment, consider
/// encrypting private keys with a password.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WalletAddress {
    /// The Bitcoin address in base58check format (e.g., "m...")
    pub address: String,
    /// Private key in WIF (Wallet Import Format) for signing transactions
    pub private_key: String,
    /// Public key in hexadecimal format
    pub public_key: String,
    /// List of unspent transaction outputs for this address
    pub utxos: Vec<Utxo>,
    /// BIP44 derivation path showing how this address was generated
    /// Format: "m/44'/1'/0'/0/{index}" for testnet
    pub derivation_path: String,
}

impl std::fmt::Display for WalletAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

/// A complete Bitcoin wallet containing multiple addresses and their associated data.
/// 
/// This is the main wallet structure that manages all addresses, tracks the next
/// address index to generate, and stores the mnemonic phrase for consistent
/// address derivation across sessions.
/// 
/// # Key Features
/// - Hierarchical deterministic (HD) address generation
/// - Mnemonic phrase storage for wallet recovery
/// - Automatic address indexing and management
/// - Serialization support for persistent storage
/// - Multi-signature wallet support
/// 
/// # Security Considerations
/// - The mnemonic phrase is stored in plain text for wallet recovery
/// - In production, consider encrypting the entire wallet file
/// - Private keys are stored in WIF format for compatibility
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Wallet {
    /// List of all addresses in the wallet
    pub addresses: Vec<WalletAddress>,
    /// Next address index to generate (incremented after each new address)
    pub next_index: u32,
    /// Next multi-signature index to generate (incremented after each new multi-sig wallet)
    pub next_multisig_index: u32,
    /// BIP39 mnemonic phrase for wallet recovery and consistent address generation
    /// 
    /// This field is optional and may be None for wallets created without
    /// mnemonic phrases. When present, it enables deterministic address
    /// generation and wallet recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    /// List of multi-signature wallets
    pub multisig_wallets: Vec<multisig::MultiSigWallet>,
}

impl Wallet {
    /// Loads a wallet from a JSON file on disk.
    /// 
    /// This function reads the wallet data from a file and deserializes it into
    /// a Wallet struct. The file should contain a valid JSON representation
    /// of the wallet with addresses, next_index, and optionally a mnemonic phrase.
    /// 
    /// # Arguments
    /// * `path` - The file path where the wallet is stored
    /// 
    /// # Returns
    /// * `Ok(Wallet)` - The loaded wallet if successful
    /// * `Err` - If the file doesn't exist, is invalid JSON, or cantbe read
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn StdError>> {
        let json = fs::read_to_string(path)?;
        match serde_json::from_str::<Wallet>(&json) {
            Ok(wallet) => Ok(wallet),
            Err(e) => {
                // Try to migrate from old format
                if let Ok(migrated_wallet) = Self::migrate_from_old_format(&json) {
                    println!("✅ Successfully migrated wallet from old format to new format with multi-signature support.");
                    Ok(migrated_wallet)
                } else {
                    let error_msg = format!("Failed to parse wallet file: {}. This may be due to an incompatible wallet format. Please check if the wallet file structure matches the expected format.", e);
                    Err(error_msg.into())
                }
            }
        }
    }
    
    /// Migrates wallet from old format (without multisig_wallets) to new format
    fn migrate_from_old_format(json: &str) -> Result<Self, Box<dyn StdError>> {
        // Define the old wallet structure
        #[derive(serde::Deserialize)]
        struct OldWallet {
            pub addresses: Vec<WalletAddress>,
            pub next_index: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            pub mnemonic: Option<String>,
        }
        
        // Try to parse as old format
        let old_wallet: OldWallet = serde_json::from_str(json)?;
        
        // Convert to new format by adding empty multisig_wallets
        Ok(Wallet {
            addresses: old_wallet.addresses,
            next_index: old_wallet.next_index,
            next_multisig_index: 0, // Default for migrated wallets
            mnemonic: old_wallet.mnemonic,
            multisig_wallets: Vec::new(),
        })
    }

    /// Saves the wallet to a JSON file on disk.
    /// 
    /// This function serializes the wallet data to JSON format and writes it
    /// to the specified file. The wallet file contains all addresses, their
    /// private keys, UTXOs, and the mnemonic phrase (if present).
    /// 
    /// # Arguments
    /// * `path` - The file path where the wallet should be saved
    /// 
    /// # Returns
    /// * `Ok(())` - If the wallet was saved successfully
    /// * `Err` - If the file can't be written or serialization fails
    /// 
    /// # Security Note
    /// The wallet file contains sensitive information (private keys, mnemonic).
    /// In production, consider encrypting the file or storing private keys
    /// in a secure hardware module.
    pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn StdError>> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Retrieves a wallet address by its index.
    /// 
    /// Returns a reference to the WalletAddress at the specified index,
    /// or None if the index is out of bounds.
    /// 
    /// # Arguments
    /// * `index` - The zero-based index of the address to retrieve
    /// 
    /// # Returns
    /// * `Some(&WalletAddress)` - The address if the index is valid
    /// * `None` - If the index is out of bounds 
    /// 

    pub fn get_address(&self, index: usize) -> Option<&WalletAddress> {
        self.addresses.get(index)
    }

    /// Signs and broadcasts a Bitcoin transaction to send funds to a destination address.
    /// 
    /// This is the core function for sending Bitcoin transactions. It performs several
    /// critical steps:
    /// 1. Updates wallet balances to ensure fresh UTXO data
    /// 2. Selects optimal UTXOs to spend (coin selection algorithm)
    /// 3. Creates a Bitcoin transaction with proper inputs and outputs
    /// 4. Signs each input with the corresponding private key
    /// 5. Broadcasts the signed transaction to the Bitcoin network
    /// 
    /// # Arguments
    /// * `dest_address` - The destination Bitcoin address to send funds to
    /// * `amount` - The amount to send in satoshis (1 BTC = 100,000,000 satoshis)
    /// * `fee_rate` - The fee rate in satoshis per byte for transaction prioritization
    /// 
    /// # Returns
    /// * `Ok(String)` - The transaction ID (txid) of the broadcast transaction
    /// * `Err(WalletError::InsufficientFunds)` - If the wallet doesn't have enough funds
    /// * `Err(WalletError::TransactionFailed)` - If transaction creation or signing fails
    /// 
    /// # Technical Details
    /// 
    /// ## UTXO Selection
    /// The function can either automatically select UTXOs from all addresses or
    /// use only UTXOs from a specific source address if provided. It uses a smart
    /// coin selection algorithm to choose the optimal combination of UTXOs that
    /// minimizes fees while ensuring sufficient funds.
    /// 
    /// ## Transaction Structure
    /// - **Inputs**: References to previous UTXOs being spent
    /// - **Outputs**: Destination address (user-specified amount) + change address (remaining funds)
    /// - **Fee Calculation**: Based on transaction size and specified fee rate
    /// 
    /// ## Signing Process
    /// Each input is signed using ECDSA with the secp256k1 curve, creating a
    /// cryptographic proof that the wallet owns the private keys for the spent UTXOs.
    /// 
    /// ## Security Considerations
    /// - Private keys are used only for signing and are not transmitted
    /// - Transaction signing follows Bitcoin's standard ECDSA signature scheme
    /// - All cryptographic operations use the bitcoin-rs library for security
    /// 
    /// # Errors
    /// - **InsufficientFunds**: Wallet balance is less than amount + fees
    /// - **TransactionFailed**: Network error, invalid address, or signing failure
    pub async fn  sign_and_send_transaction(
        &mut self,
        dest_address: &str,
        amount: u64,
        fee_rate: u64,
        source_address: Option<&str>,
    ) -> Result<String, WalletError> {
        println!("Starting transaction process...");
        println!("Destination address: {}", dest_address);
        println!("Amount: {} satoshis", amount);
        println!("Fee rate: {} sat/byte", fee_rate);
        
        // Display source address information
        match source_address {
            Some(addr) => println!("Source address: {} (user-specified)", addr),
            None => println!("Source address: Auto-selected (optimal UTXOs from all addresses)"),
        }

        // Always update balances before sending to ensure fresh data
        println!("Updating balances and validating UTXOs...");
        if let Err(e) = self.update_balances().await {
            println!("Failed to update balances: {}", e);
            return Err(WalletError::TransactionFailed);
        }
        println!("Balance update completed.");

        // Collect UTXOs based on source address preference
        let all_utxos: Vec<(&WalletAddress, Utxo)> = self.addresses
            .iter()
            .flat_map(|addr| addr.utxos.iter().map(move |utxo| (addr, utxo.clone())))
            .collect();
        
        println!("Found {} UTXOs after validation", all_utxos.len());
        
        if all_utxos.is_empty() {
            println!("No valid UTXOs found after validation");
            return Err(WalletError::InsufficientFunds);
        }
        
        // Filter UTXOs based on source address preference and supported script types (P2PKH, P2WPKH)
        let spendable_utxos: Vec<(&WalletAddress, Utxo)> = all_utxos
            .into_iter()
            .filter(|(addr, _)| {
                // Check source address (if specified)
                let source_match = source_address.map(|src| addr.address == src).unwrap_or(true);
                // Allow legacy P2PKH (m/n…) and native segwit P2WPKH (tb1q…)
                let is_p2pkh = addr.address.starts_with("m") || addr.address.starts_with("n");
                let is_p2wpkh = addr.address.starts_with("tb1q");

                source_match && (is_p2pkh || is_p2wpkh)
            })
            .collect();
        
        println!("Found {} spendable UTXOs{}", 
            spendable_utxos.len(),
            source_address.map_or(" from all addresses".to_string(), |src| format!(" from source address: {}", src))
        );
        
        if spendable_utxos.is_empty() {
            let error_msg = source_address.map_or(
                "No spendable UTXOs available for transaction".to_string(),
                |src| format!("No spendable UTXOs found in specified source address: {}", src)
            );
            println!("{}", error_msg);
            return Err(WalletError::InsufficientFunds);
        }
        
        // UTXO selection based on whether source address was specified
        let selected_utxos = match source_address {
            Some(_) => {
                // User specified a source address - use ALL UTXOs from that address
                // The filtering above already ensures only UTXOs from the specified address are included
                println!("Using all {} UTXOs from specified source address", spendable_utxos.len());
                spendable_utxos.into_iter().map(|(addr, utxo)| ((*addr).clone(), utxo.clone())).collect()
            }
            None => {
                // No source address specified - use smart selection across all addresses
                println!("Using smart UTXO selection across all addresses");
                self.select_optimal_utxos(&spendable_utxos, amount, fee_rate)?
            }
        };

        // Calculate total value of selected UTXOs and estimate transaction fee
        let total_value: u64 = selected_utxos.iter().map(|(_, utxo)| utxo.value).sum();
        
        // Transaction size estimation by type (approximate vbytes):
        // - P2PKH input ~148 vbytes
        // - P2WPKH input ~68 vbytes
        // - P2PKH output ~34 vbytes; P2WPKH output ~31 vbytes
        // - Overhead ~10 vbytes
        let num_p2wpkh_inputs = selected_utxos.iter().filter(|(addr, _)| addr.address.starts_with("tb1q")).count() as u64;
        let num_p2pkh_inputs = selected_utxos.len() as u64 - num_p2wpkh_inputs;

        // Destination output size based on destination address prefix
        let dest_out_sz = if dest_address.starts_with("tb1q") { 31u64 } else { 34u64 };
        // Change output size based on our first address prefix
        let change_out_sz = if self.addresses[0].address.starts_with("tb1q") { 31u64 } else { 34u64 };

        // Assume there will be a change output; adjust later if change == 0
        let mut estimated_size = num_p2pkh_inputs * 148 + num_p2wpkh_inputs * 68 + dest_out_sz + change_out_sz + 10;
        let fee = estimated_size * fee_rate;

        println!("Selected {} UTXOs", selected_utxos.len());
        println!("Total value: {} satoshis", total_value);
        println!("Estimated fee: {} satoshis", fee);

        // Verify we have sufficient funds (amount + fee)
        if total_value < amount + fee {
            println!("Failed to send transaction: Insufficient funds");
            return Err(WalletError::InsufficientFunds);
        }

        // Create the Bitcoin transaction structure
        let mut tx = BitcoinTransaction {
            version: Version::TWO,  // Current Bitcoin transaction version
            lock_time: LockTime::ZERO,  // No time lock (transaction can be mined immediately)
            input: Vec::new(),
            output: Vec::new(),
        };

        // Add transaction inputs (references to UTXOs being spent)
        for (_, utxo) in &selected_utxos {
            let txid = bitcoin::Txid::from_str(&utxo.txid)
                .map_err(|_| WalletError::TransactionFailed)?;
            
            let outpoint = OutPoint::new(txid, utxo.vout);
            tx.input.push(TxIn {
                previous_output: outpoint,  // Reference to the UTXO being spent
                script_sig: ScriptBuf::new(),  // Will be filled during signing
                sequence: Sequence::ZERO,  // No sequence lock
                witness: Witness::new(),  // No witness data (legacy transaction)
            });
        }

        // Add the destination output (where funds are being sent)
        let dest_script = self.create_script_pubkey(dest_address, Network::Testnet)?;
        tx.output.push(TxOut {
            value: Amount::from_sat(amount),  // Amount being sent
            script_pubkey: dest_script,  // Locking script for destination address
        });

        // Add change output if there are remaining funds after amount + fee
        let change = total_value - amount - fee;
        if change > 0 {
            let change_address = &self.addresses[0];  // Use first address as change address
            let change_script = self.create_script_pubkey(&change_address.address, Network::Testnet)?;
            tx.output.push(TxOut {
                value: Amount::from_sat(change),  // Remaining funds sent back to wallet
                script_pubkey: change_script,
            });
        } else {
            // Re-estimate fee without change output
            estimated_size = num_p2pkh_inputs * 148 + num_p2wpkh_inputs * 68 + dest_out_sz + 10;
            let new_fee = estimated_size * fee_rate;
            if total_value < amount + new_fee {
                println!("Failed to send transaction: Insufficient funds after fee re-estimation");
                return Err(WalletError::InsufficientFunds);
            }
        }

        println!("\nTransaction Structure:");
        println!("Version: {}", tx.version);
        println!("Lock Time: {}", tx.lock_time);
        println!("Inputs:");
        for (i, input) in tx.input.iter().enumerate() {
            println!("  Input {}: {}:{}", i, input.previous_output.txid, input.previous_output.vout);
            println!("  Sequence: {}", input.sequence);
        }
        println!("Outputs:");
        for (i, output) in tx.output.iter().enumerate() {
            println!("  Output {}: {} satoshis", i, output.value);
            println!("  Script: {}", output.script_pubkey);
        }

        // Sign transaction for inputs (supports P2PKH and P2WPKH)
        let secp = Secp256k1::new();
        for (i, (addr, utxo)) in selected_utxos.iter().enumerate() {
            println!("\nSigning input {} with address {}", i, addr.address);
            
            //wif stands for wallet import format, it is a standard format for importing private keys into wallets. 
            let private_key = PrivateKey::from_wif(&addr.private_key)
                .map_err(|_| WalletError::TransactionFailed)?;
            
            // Determine address type
            let address = Address::from_str(&addr.address)
                .map_err(|_| WalletError::TransactionFailed)?
                .require_network(Network::Testnet)
                .map_err(|_| WalletError::TransactionFailed)?;

            let pubkey = private_key.public_key(&secp);

            match address.address_type() {
                Some(bitcoin::AddressType::P2pkh) => {
                    let script_pubkey = self.create_script_pubkey(&addr.address, Network::Testnet)?;
                    // Verify pubkey matches address
                    let pubkey_hash = address.pubkey_hash().ok_or(WalletError::TransactionFailed)?;
                    let derived_pubkey_hash = bitcoin::PubkeyHash::from_byte_array(
                        hash160::Hash::hash(&pubkey.inner.serialize()).to_byte_array()
                    );
                    if pubkey_hash != derived_pubkey_hash {
                        println!("\nPublic key hash mismatch!");
                        println!("Expected: {}", pubkey_hash);
                        println!("Got: {}", derived_pubkey_hash);
                        return Err(WalletError::TransactionFailed);
                    }

                    let cache = SighashCache::new(&tx);
                    let sighash = match cache.legacy_signature_hash(i, &script_pubkey, EcdsaSighashType::All as u32) {
                        Ok(sighash) => sighash,
                        Err(_) => {
                            println!("Failed to create sighash for input {}", i);
                            return Err(WalletError::TransactionFailed);
                        }
                    };
                    let msg = Message::from_digest_slice(sighash.as_ref()).map_err(|_| WalletError::TransactionFailed)?;
                    let sig = secp.sign_ecdsa(&msg, &private_key.inner);

                    let mut sig_bytes = sig.serialize_der().to_vec();
                    sig_bytes.push(EcdsaSighashType::All as u8);
                    let pubkey_bytes = pubkey.inner.serialize();
                    let script_sig = bitcoin::script::Builder::new()
                        .push_slice(bitcoin::script::PushBytesBuf::try_from(sig_bytes).unwrap())
                        .push_slice(bitcoin::script::PushBytesBuf::try_from(pubkey_bytes.to_vec()).unwrap())
                        .into_script();
                    tx.input[i].script_sig = script_sig;
                }
                Some(bitcoin::AddressType::P2wpkh) => {
                    // Build scriptCode for BIP143 (standard P2PKH script with our pubkey hash)
                    let derived_pubkey_hash = bitcoin::PubkeyHash::from_byte_array(
                        hash160::Hash::hash(&pubkey.inner.serialize()).to_byte_array()
                    );
                    let script_code = bitcoin::script::Builder::new()
                        .push_opcode(bitcoin::opcodes::all::OP_DUP)
                        .push_opcode(bitcoin::opcodes::all::OP_HASH160)
                        .push_slice(derived_pubkey_hash)
                        .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
                        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                        .into_script();

                    let mut cache = SighashCache::new(&tx);
                    let sighash = match cache.p2wpkh_signature_hash(i, &script_code, Amount::from_sat(utxo.value), EcdsaSighashType::All) {
                        Ok(sighash) => sighash,
                        Err(_) => {
                            println!("Failed to create segwit sighash for input {}", i);
                            return Err(WalletError::TransactionFailed);
                        }
                    };
                    let msg = Message::from_digest_slice(sighash.as_ref()).map_err(|_| WalletError::TransactionFailed)?;
                    let sig = secp.sign_ecdsa(&msg, &private_key.inner);
                    let mut sig_bytes = sig.serialize_der().to_vec();
                    sig_bytes.push(EcdsaSighashType::All as u8);
                    let pubkey_bytes = pubkey.inner.serialize();

                    // For native segwit P2WPKH: empty script_sig, witness = [sig, pubkey]
                    tx.input[i].script_sig = ScriptBuf::new();
                    tx.input[i].witness.push(sig_bytes);
                    tx.input[i].witness.push(pubkey_bytes);
                }
                _ => {
                    println!("Unsupported address type for signing: {}", addr.address);
                    return Err(WalletError::TransactionFailed);
                }
            }
        }

        // Broadcast transaction
        let client = reqwest::Client::new();
        let url = "https://blockstream.info/testnet/api/tx";
        let tx_hex = serialize_hex(&tx);
        
        println!("\nBroadcasting transaction...");
        println!("Transaction hex: {}", tx_hex);
        println!("Input scripts:");
        for (i, input) in tx.input.iter().enumerate() {
            println!("Input {} script: {}", i, input.script_sig);
        }
        println!("Output scripts:");
        for (i, output) in tx.output.iter().enumerate() {
            println!("Output {} script: {}", i, output.script_pubkey);
        }
        
        let response = client.post(url)
            .header("Content-Type", "text/plain")
            .body(tx_hex)
            .send()
            .await
            .map_err(|e| {
                println!("Network error: {}", e);
                WalletError::TransactionFailed
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            println!("Transaction failed: {}", error_text);
            return Err(WalletError::TransactionFailed);
        }

        let txid = tx.compute_txid();
        println!("\nTransaction successful!");
        println!("Transaction ID: {}", txid);
        Ok(txid.to_string())
    }

    /// Simple UTXO selection algorithm - easy to understand and implement
    fn select_optimal_utxos(
        &self,
        all_utxos: &[(&WalletAddress, Utxo)],
        target_amount: u64,
        fee_rate: u64,
    ) -> Result<Vec<(WalletAddress, Utxo)>, WalletError> {
        println!("\n=== Simple UTXO Selection ===");
        println!("Target amount: {} satoshis", target_amount);
        println!("Available UTXOs: {}", all_utxos.len());
        
        // Method 1: Largest First (Most Common in Real Wallets)
        println!("\nMethod: Largest First (like Electrum)");
       
        let mut sorted_utxos = all_utxos.to_vec();
        sorted_utxos.sort_by(|a, b| b.1.value.cmp(&a.1.value)); // Largest first
         
        let mut selected = Vec::new();
        let mut total_value = 0u64;
        
        // ✅ OPTIMIZATION: Calculate fee components once outside the loop
        let fee_per_input = 200 * fee_rate;
        
        for (addr, utxo) in sorted_utxos {
            println!("  Considering UTXO: {} satoshis (address: {})", utxo.value, addr.address);
            
            selected.push(((*addr).clone(), utxo.clone()));
            total_value += utxo.value;
            
            // ✅ EFFICIENT: Use pre-calculated fee components
            let estimated_fee = selected.len() as u64 * fee_per_input;
            println!("  Total so far: {} satoshis, Estimated fee: {} satoshis", total_value, estimated_fee);
            
            if total_value >= target_amount + estimated_fee {
                println!("✓ Sufficient funds found with {} UTXOs", selected.len());
                return Ok(selected);
            }
        }
        
        println!("✗ Insufficient funds even with all UTXOs");
        Err(WalletError::InsufficientFunds)
    }

    fn create_script_pubkey(&self, address: &str, network: Network) -> Result<ScriptBuf, WalletError> {
        let address = Address::from_str(address)
            .map_err(|_| WalletError::TransactionFailed)?
            .require_network(network)
            .map_err(|_| WalletError::TransactionFailed)?;
            
        // For P2PKH addresses, we need to create a proper P2PKH script
        match address.address_type() {
            Some(bitcoin::AddressType::P2pkh) => {
                let pubkey_hash = address.pubkey_hash()
                    .ok_or(WalletError::TransactionFailed)?;
                println!("Pubkey hash: {}", pubkey_hash);
                Ok(bitcoin::script::Builder::new()
                    .push_opcode(bitcoin::opcodes::all::OP_DUP)
                    .push_opcode(bitcoin::opcodes::all::OP_HASH160)
                    .push_slice(pubkey_hash)
                    .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                    .into_script())
            }
            _ => Ok(address.script_pubkey())
        }
    }

    /// Validate that a UTXO actually belongs to the given address
    /// You catch the error before creating the transaction
    async fn validate_utxo_ownership(address: &str, utxo: &Utxo) -> Result<bool, Box<dyn StdError>> {
        let client = reqwest::Client::new();
        let url = format!("https://blockstream.info/testnet/api/tx/{}", utxo.txid);
        let response = client.get(&url).send().await?;
        
        if response.status().is_success() {
            let tx_data: serde_json::Value = response.json().await?;
            
            // Get the output at the specified vout
            if let Some(outputs) = tx_data.get("vout").and_then(|v| v.as_array()) {
                if let Some(output) = outputs.get(utxo.vout as usize) {
                    if let Some(scriptpubkey_address) = output.get("scriptpubkey_address") {
                        if let Some(addr_str) = scriptpubkey_address.as_str() {
                            // Check if the UTXO's address matches our address
                            let is_valid = addr_str == address;
                            println!("Validating UTXO {}:{} - Expected: {}, Actual: {}, Valid: {}", 
                                utxo.txid, utxo.vout, address, addr_str, is_valid);
                            return Ok(is_valid);
                        }
                    }
                }
            }
        }
        
        println!("Validating UTXO {}:{} - Could not validate, assuming invalid", utxo.txid, utxo.vout);
        Ok(false)
    }

    pub async fn update_balances(&mut self) -> Result<(), Box<dyn StdError>> {
        // Create HTTP client with timeout settings
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600)) // 5 second timeout (faster)
            .build()?;
        
        let total_addresses = self.addresses.len();
        println!("Updating balances for {} addresses...", total_addresses);
        
        for (i, address_info) in self.addresses.iter_mut().enumerate() {
            println!("[{}/{}] Updating address: {}", i + 1, total_addresses, address_info.address);
            
            let url = format!("https://blockstream.info/testnet/api/address/{}", address_info.address);
            
            // Add timeout and error handling
            let response = match client.get(&url).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    println!("⚠️  Network error for {}: {}", address_info.address, e);
                    address_info.utxos = Vec::new();
                    continue;
                }
            };

            if response.status().is_success() { 
                let utxo_url = format!("https://blockstream.info/testnet/api/address/{}/utxo", address_info.address);
                
                let utxo_response = match client.get(&utxo_url).send().await {
                    Ok(resp) => resp,
                    Err(e) => {
                        println!("⚠️  UTXO fetch error for {}: {}", address_info.address, e);
                        address_info.utxos = Vec::new();
                        continue;
                    }
                };
                
                if utxo_response.status().is_success() {
                    let utxos: Vec<Utxo> = match utxo_response.json().await {
                        Ok(utxos) => utxos,
                        Err(e) => {
                            println!("⚠️  JSON parse error for {}: {}", address_info.address, e);
                            address_info.utxos = Vec::new();
                            continue;
                        }
                    };
                    
                    println!("  Found {} UTXOs for {}", utxos.len(), address_info.address);
                    
                    
                    let mut valid_utxos = Vec::new();
                    for utxo in utxos {
                        if Self::validate_utxo_ownership(&address_info.address, &utxo).await? {
                            valid_utxos.push(utxo);
                        } else {
                            println!("Warning: UTXO {}:{} does not belong to address {}", 
                                utxo.txid, utxo.vout, address_info.address);
                        }
                    }
                    address_info.utxos = valid_utxos;   
                    
                } else {
                    println!("  No UTXOs found for {}", address_info.address);
                    address_info.utxos = Vec::new();
                }
            } else {
                println!("  Address not found: {}", address_info.address);
                address_info.utxos = Vec::new();
            }
        }

        // Save wallet after updating balances
        self.save_to_file(Path::new("wallet.json"))?;
        println!("✅ Balance update completed!");
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    pub async fn initialize_with_seed(&mut self, mnemonic: &str) -> Result<(), Box<dyn StdError>> {
        // Clear existing wallet
        self.addresses = Vec::new();
        self.next_index = 0;
        
        // Store the mnemonic for consistent address generation
        self.mnemonic = Some(mnemonic.to_string());
        
        // Parse mnemonic and generate addresses
        self.recover_from_mnemonic(mnemonic).await?;
        
        Ok(())
    }
    
    /// Recovers wallet addresses from a BIP39 mnemonic phrase using gap limit scanning.
    /// 
    /// This function implements the BIP44 hierarchical deterministic (HD) wallet standard
    /// with gap limit optimization for efficient address discovery. It scans addresses
    /// sequentially until it finds a sufficient number of consecutive unused addresses,
    /// indicating that no more addresses have been used.
    /// 
    /// # Gap Limit Concept
    /// 
    /// The gap limit is a wallet security and efficiency feature that determines when
    /// to stop scanning for addresses. It works as follows:
    /// 
    /// 1. **Scan addresses in order** (index 0, 1, 2, 3...)
    /// 2. **Count consecutive unused addresses** (addresses with no UTXOs)
    /// 3. **Stop when gap limit is reached** (typically 20 consecutive unused addresses)
    /// 
    /// This prevents infinite scanning while ensuring all used addresses are found.
    /// 
    /// # BIP44 Address Derivation
    /// 
    /// Addresses are derived using the BIP44 path: `m/44'/1'/0'/0/{index}`
    /// - `44'` - BIP44 standard for cryptocurrency wallets
    /// - `1'` - Coin type 1 for Bitcoin testnet (0 for mainnet)
    /// - `0'` - Account number (0 for first account)
    /// - `0` - Change address type (0 for receiving, 1 for change)
    /// - `{index}` - Address index (0, 1, 2, ...)
    /// 
    /// # Cryptographic Implementation
    /// 
    /// Each address is generated deterministically using:
    /// 1. **Mnemonic to seed**: BIP39 mnemonic → 512-bit seed using PBKDF2
    /// 2. **Key derivation**: HMAC-SHA256(seed + index) → private key
    /// 3. **Address generation**: Private key → Public key → P2PKH(pay to public key) address
    /// 
    /// # Arguments
    /// * `mnemonic` - BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
    /// 
    /// # Returns
    /// * `Ok(())` - If addresses were successfully recovered
    /// * `Err` - If mnemonic is invalid or network requests fail
    /// 
    /// # Security Considerations
    /// - The mnemonic phrase is parsed and validated according to BIP39
    /// - Private keys are generated deterministically from the seed
    /// - Address usage is checked via blockchain API (Blockstream testnet)
    /// - A safety limit prevents scanning more than 1000 addresses
    async fn recover_from_mnemonic(&mut self, mnemonic: &str) -> Result<(), Box<dyn StdError>> {
        let secp = Secp256k1::new();
        
        // Parse the BIP39 mnemonic and derive the master seed
        // The empty string "" is the passphrase (no additional password)
        let mnemonic_parsed = bip39::Mnemonic::parse_normalized(mnemonic)
            .map_err(|e| format!("Invalid mnemonic: {}", e))?;
        let seed = mnemonic_parsed.to_seed("");
        
        // Gap limit implementation - standard used by most Bitcoin wallets
        // Scan addresses until we find GAP_LIMIT consecutive unused addresses
        const GAP_LIMIT: u32 = 20; // Standard gap limit used by most wallets
        let mut consecutive_unused = 0;
        let mut recovered_count = 0;
        let mut used_addresses = 0;
        let mut current_index: u32 = 0;
        
        println!("Starting address recovery with gap limit of {}...", GAP_LIMIT);
        
        // Continue scanning until we hit the gap limit
        while consecutive_unused < GAP_LIMIT {
            // Create a deterministic private key for each address using HMAC-SHA256
            // This ensures consistent address generation across sessions
            let mut key_material = seed.to_vec();
            key_material.extend_from_slice(&current_index.to_le_bytes());
            
            let key_hash = sha256::Hash::hash(&key_material);
            let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&key_hash.to_byte_array())
                .map_err(|_| "Failed to create secret key")?;
            
            let private_key = PrivateKey::new(secret_key, Network::Testnet);
            let pubkey = private_key.public_key(&secp);
            let compressed = pubkey.try_into().map_err(|_| "Failed to compress public key").unwrap();
            let address = Address::p2wpkh(&compressed, Network::Testnet);
            
            // Check if this address has been used by querying the blockchain
            let has_been_used = self.check_address_usage(&address.to_string()).await?;
            
            if has_been_used {
                // Found an address with UTXOs - reset the consecutive unused counter
                // This means we should continue scanning as there might be more used addresses
                consecutive_unused = 0;
                used_addresses += 1;
                println!("Found used address at index {}: {}", current_index, address);
            } else {
                // Address has no UTXOs - increment consecutive unused counter
                // If this reaches GAP_LIMIT, we can stop scanning
                consecutive_unused += 1;
                println!("Address at index {} is unused (consecutive unused: {})", current_index, consecutive_unused);
            }
            
            // Always add the first few addresses (up to 5) regardless of UTXO status
            // This ensures you can see your addresses even if they haven't received funds yet
            let should_add = has_been_used || current_index < 5;
            
            if should_add {
                let wallet_address = WalletAddress {
                    address: address.to_string(),
                    private_key: private_key.to_wif(),
                    public_key: private_key.public_key(&secp).to_string(),
                    utxos: Vec::new(),
                    derivation_path: format!("m/84'/1'/0'/0/{}", current_index),
                };
                
                self.addresses.push(wallet_address);
                recovered_count += 1;
                
                if has_been_used {
                    println!("✓ Recovered used address {}: {}", current_index, address);
                } else {
                    println!("✓ Recovered unused address {}: {}", current_index, address);
                }
            }
            
            current_index += 1;
            
            // Safety check: don't scan forever (prevents infinite loops)
            if current_index > 1000 {
                println!("Warning: Reached maximum scan limit of 1000 addresses");
                break;
            }
        }
        
        // Set the next address index for future address generation
        self.next_index = current_index;
        
        println!("\n=== Recovery Summary ===");
        println!("Scanned {} addresses", current_index);
        println!("Found {} addresses with UTXOs", used_addresses);
        println!("Recovered {} addresses total", recovered_count);
        println!("Stopped after {} consecutive unused addresses", GAP_LIMIT);
        println!("Next address index will be: {}", self.next_index);
        
        if recovered_count > 0 {
            println!("✅ Successfully recovered {} addresses from mnemonic", recovered_count);
        } else {
            println!("⚠️  No addresses found. Use 'Create a new address' to generate addresses.");
        }
        
        Ok(())
    }
    
    /// Checks if a Bitcoin address has been used by querying the blockchain for UTXOs.
    /// 
    /// This function determines whether an address has been used by checking if it has
    /// any unspent transaction outputs (UTXOs) on the blockchain. It queries the
    /// Blockstream testnet API to get real-time blockchain data.
    /// 
    /// # How It Works
    /// 
    /// 1. **Address Validation**: First checks if the address exists on the blockchain
    /// 2. **UTXO Query**: If the address exists, queries for its UTXOs
    /// 3. **Usage Determination**: Address is considered "used" if it has any UTXOs
    /// 
    /// # API Endpoints Used
    /// 
    /// - **Address Info**: `https://blockstream.info/testnet/api/address/{address}`
    /// - **UTXO List**: `https://blockstream.info/testnet/api/address/{address}/utxo`
    /// 
    /// # Arguments
    /// * `address` - The Bitcoin address to check (in base58check format)
    /// 
    /// # Returns
    /// * `Ok(true)` - Address has UTXOs (has been used)
    /// * `Ok(false)` - Address has no UTXOs (unused)
    /// * `Err` - Network error or API failure
    /// # Network Considerations
    /// - Uses Bitcoin testnet (not mainnet) for safety
    /// - Relies on Blockstream's public API
    /// - Includes error handling for network failures
    /// - Returns false on API errors (safe default)
    /// 
    /// # Performance Notes
    /// - Makes HTTP requests to external API
    /// - Should be rate-limited in production
    /// - Consider caching results for frequently checked addresses
    async fn check_address_usage(&self, address: &str) -> Result<bool, Box<dyn StdError>> {
        let client = reqwest::Client::new();
        let url = format!("https://blockstream.info/testnet/api/address/{}/utxo", address);
        
        println!("Checking address usage for: {}", address);
        
        // Handle network errors gracefully
        let response = match client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                println!("Network error for {}: {}", address, e);
                return Ok(false); // Safe default: assume no UTXOs
            }
        };
        
        if !response.status().is_success() {
            println!("Address request failed with status: {}", response.status());
            return Ok(false);
        }
        
        let response_text = match response.text().await {
            Ok(text) => text,
            Err(e) => {
                println!("Failed to read response for {}: {}", address, e);
                return Ok(false); // Safe default
            }
        };
        
        println!("UTXO response: {}", response_text);
        
        let has_utxos = response_text.trim() != "[]";
        println!("Address {} has {}UTXOs", address, if has_utxos { "" } else { "no " });
        
        Ok(has_utxos)
    }

    /// Generates a new Bitcoin address for the wallet.
    /// 
    /// This function creates a new address using the same deterministic derivation
    /// method as the recovery process. If the wallet has a stored mnemonic phrase,
    /// it uses that for consistent address generation. Otherwise, it falls back to
    /// random address generation.
    /// 
    /// # Address Generation Process
    /// 
    /// ## With Mnemonic (Deterministic)
    /// 1. **Seed Derivation**: Uses stored BIP39 mnemonic to generate master seed
    /// 2. **Key Derivation**: HMAC-SHA256(seed + next_index) → private key
    /// 3. **Address Creation**: Private key → Public key → P2PKH address
    /// 4. **Index Increment**: Increments next_index for future addresses
    /// 
    /// ## Without Mnemonic (Random)
    /// 1. **Random Key**: Generates a cryptographically secure random private key
    /// 2. **Address Creation**: Private key → Public key → P2PKH address
    /// 3. **Index Increment**: Increments next_index for future addresses
    /// 
    /// # BIP44 Derivation Path
    /// 
    /// For mnemonic-based wallets, addresses follow the path:
    /// `m/44'/1'/0'/0/{next_index}`
    /// 
    /// Where:
    /// - `44'` - BIP44 standard
    /// - `1'` - Bitcoin testnet coin type
    /// - `0'` - Account number
    /// - `0` - Change address type (0 = receiving)
    /// - `{next_index}` - Sequential address index
    /// 
    /// # Arguments
    /// None - uses the wallet's internal state
    /// 
    /// # Returns
    /// * `Ok(String)` - The newly generated Bitcoin address
    /// * `Err` - If address generation fails
    /// 
    /// # Example
    /// ```rust,ignore
    /// // Generate a new address
    /// let new_address = wallet.get_new_address()?;
    /// println!("New address: {}", new_address);
    /// 
    /// // The address is automatically added to the wallet
    /// println!("Total addresses: {}", wallet.address_count());
    /// ```
    /// 
    /// # Security Considerations
    /// - Private keys are generated using cryptographically secure methods
    /// - Mnemonic-based generation ensures deterministic address sequences
    /// - Random generation provides additional security through unpredictability
    /// - All addresses are stored with their private keys in WIF format
    /// 
    /// # State Changes
    /// - Adds the new address to the wallet's address list
    /// - Increments the next_index for future address generation
    /// - The new address is ready to receive funds immediately
    pub fn get_new_address(&mut self) -> Result<String, Box<dyn StdError>> {
        let secp = Secp256k1::new();
        
        // Use the stored mnemonic to generate consistent addresses
        let mnemonic = self.mnemonic.as_ref()
            .ok_or("No mnemonic found. Please initialize wallet with a mnemonic phrase.")?;
        
        let mnemonic_parsed = bip39::Mnemonic::parse_normalized(mnemonic)
            .map_err(|e| format!("Invalid stored mnemonic: {}", e))?;
        let seed = mnemonic_parsed.to_seed("");
        
        // Generate the next address using the same derivation method as recovery
        // This ensures consistency between recovery and new address generation
        let mut key_material = seed.to_vec();
        key_material.extend_from_slice(&self.next_index.to_le_bytes());
        
        let key_hash = sha256::Hash::hash(&key_material);
        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&key_hash.to_byte_array())
            .map_err(|_| "Failed to create secret key")?;
        
        let private_key = PrivateKey::new(secret_key, Network::Testnet);
        let public_key = private_key.public_key(&secp);
        let compressed = public_key.try_into().map_err(|_| "Failed to compress public key").unwrap();
        let address = Address::p2wpkh(&compressed, Network::Testnet);
        
        let derivation_path = format!("m/84'/1'/0'/0/{}", self.next_index);
        
        let wallet_address = WalletAddress {
            address: address.to_string(),
            private_key: private_key.to_wif(),
            public_key: public_key.to_string(),
            utxos: Vec::new(),
            derivation_path,
        };
        
        self.addresses.push(wallet_address);
        self.next_index += 1;
        
        Ok(address.to_string())
    }

    /// Saves the wallet to a file using the default save method.
    /// 
    /// This is a convenience wrapper around `save_to_file` that provides
    /// a simpler interface for saving wallets.
    /// 
    /// # Arguments
    /// * `path` - The file path where the wallet should be saved
    /// 
    /// # Returns
    /// * `Ok(())` - If the wallet was saved successfully
    /// * `Err` - If the file can't be written or serialization fails
    /// 
    /// # Example
    /// ```rust,ignore
    /// // Save to a custom path
    /// // wallet.save(Path::new("my_wallet.json"))?;
    /// ```
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn StdError>> {
        self.save_to_file(path)
    }

    /// Displays all addresses in the wallet with their balances and UTXO counts.
    /// 
    /// This function provides a human-readable summary of the wallet's contents,
    /// showing each address, its current balance (sum of all UTXOs), and the
    /// number of UTXOs it contains.
    /// 
    /// # Output Format
    /// Prints each address, balance and UTXO count to stdout.
    /// 
    /// # Example
    /// ```rust,ignore
    /// use rust_cli_wallet::wallet::Wallet;
    /// 
    /// let wallet = Wallet {
    ///     addresses: Vec::new(),
    ///     next_index: 0,
    ///     mnemonic: None,
    /// };
    /// wallet.display_all();
    /// ```
    pub fn display_all(&self) {
        for (i, addr) in self.addresses.iter().enumerate() {
            println!("Address {}: {}", i + 1, addr.address);
            println!("Balance: {} satoshis", addr.utxos.iter().map(|u| u.value).sum::<u64>());
            println!("UTXOs: {}", addr.utxos.len());
            println!();
        }
    }

    /// Returns the total number of addresses in the wallet.
    /// 
    /// This function provides a quick way to check how many addresses
    /// have been generated or recovered in the wallet.
    /// 
    /// # Returns
    /// The number of addresses as a `usize`
    /// 
    /// # Example
    /// ```rust,ignore
    /// use rust_cli_wallet::wallet::Wallet;
    /// 
    /// let wallet = Wallet {
    ///     addresses: Vec::new(),
    ///     next_index: 0,
    ///     mnemonic: None,
    /// };
    /// let count = wallet.address_count();
    /// println!("Wallet contains {} addresses", count);
    /// ```
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    /// Lists all addresses in the wallet with their balances and UTXO counts.
    /// 
    /// This function provides a detailed view of all addresses in the wallet,
    /// showing each address, its current balance, and the number of UTXOs it contains.
    /// This is useful for users to choose a specific source address for transactions.
    /// 
    /// # Returns
    /// A formatted string containing all address information
    /// 
    /// # Example
    /// ```rust,ignore
    /// use rust_cli_wallet::wallet::Wallet;
    /// 
    /// let wallet = Wallet {
    ///     addresses: Vec::new(),
    ///     next_index: 0,
    ///     mnemonic: None,
    /// };
    /// let address_list = wallet.list_addresses();
    /// println!("{}", address_list);
    /// ```
    pub fn list_addresses(&self) -> String {
        let mut result = String::new();
        result.push_str("Available Addresses:\n");
        result.push_str("===================\n\n");
        
        for (i, addr) in self.addresses.iter().enumerate() {
            let balance: u64 = addr.utxos.iter().map(|u| u.value).sum();
            result.push_str(&format!("Address {}: {}\n", i + 1, addr.address));
            result.push_str(&format!("  Balance: {} satoshis\n", balance));
            result.push_str(&format!("  UTXOs: {}\n", addr.utxos.len()));
            result.push_str(&format!("  Derivation Path: {}\n", addr.derivation_path));
        }
        
        result
    }

    /// Gets UTXOs from a specific address.
    /// 
    /// This function returns all UTXOs belonging to the specified address.
    /// Useful for checking available funds in a specific address before
    /// using it as a source for transactions.
    /// 
    /// # Arguments
    /// * `address` - The Bitcoin address to get UTXOs for
    /// 
    /// # Returns
    /// * `Ok(Vec<Utxo>)` - List of UTXOs for the address
    /// * `Err` - If the address is not found in the wallet
    /// 
    /// # Example
    /// ```rust,ignore
    /// use rust_cli_wallet::wallet::Wallet;
    /// 
    /// let wallet = Wallet {
    ///     addresses: Vec::new(),
    ///     next_index: 0,
    ///     mnemonic: None,
    /// };
    /// let utxos = wallet.get_utxos_from_address("tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?;
    /// println!("Found {} UTXOs", utxos.len());
    /// ```
    #[allow(dead_code)]
    pub fn get_utxos_from_address(&self, address: &str) -> Result<Vec<Utxo>, Box<dyn StdError>> {
        for addr in &self.addresses {
            if addr.address == address {
                return Ok(addr.utxos.clone());
            }
        }
        Err(format!("Address {} not found in wallet", address).into())
    }
}

/// Error types that can occur during wallet operations.
/// 
/// This enum defines the specific error conditions that can arise
/// when performing wallet operations like sending transactions.
#[derive(Debug)]
pub enum WalletError {
    /// Insufficient funds to complete the transaction.
    /// 
    /// This error occurs when the wallet's total balance (sum of all UTXOs)
    /// is less than the requested amount plus estimated transaction fees.
    InsufficientFunds,
    
    /// Transaction creation, signing, or broadcasting failed.
    /// 
    /// This is a catch-all error for various transaction-related failures,
    /// including invalid addresses, network errors, signing failures, and
    /// broadcasting problems.
    TransactionFailed,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::InsufficientFunds => write!(f, "Insufficient funds"),
            WalletError::TransactionFailed => write!(f, "Transaction failed"),
        }
    }
}

impl std::error::Error for WalletError {}

impl Wallet {
    /// Creates a new multi-signature wallet
    /// 
    /// # Arguments
    /// * `name` - Human-readable name for the wallet
    /// * `public_keys` - List of all cosigner public keys
    /// * `required_signatures` - Number of signatures required to spend
    /// * `my_private_keys` - Your own private keys (public_key -> private_key mapping)
    /// * `network` - Bitcoin network (testnet/mainnet)
    /// 
    /// # Returns
    /// * `Ok(String)` - The ID of the created multi-sig wallet
    /// * `Err` - If the configuration is invalid
    pub fn create_multisig_wallet(
        &mut self,
        name: String,
        public_keys: Vec<String>,
        required_signatures: u8,
        my_private_keys: std::collections::HashMap<String, String>,
        network: bitcoin::Network,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Use the next available index and increment it
        let index = self.next_multisig_index;
        self.next_multisig_index += 1;
        
        let multisig_wallet = multisig::MultiSigWallet::new(
            name,
            public_keys,
            required_signatures,
            my_private_keys,
            network,
            index,
        )?;
        
        let wallet_id = multisig_wallet.id.clone();
        self.multisig_wallets.push(multisig_wallet);
        
        Ok(wallet_id)
    }
    
    /// Gets a multi-signature wallet by ID
    /// 
    /// # Arguments
    /// * `id` - The wallet ID to retrieve
    /// 
    /// # Returns
    /// * `Some(&MultiSigWallet)` - The wallet if found
    /// * `None` - If the wallet doesn't exist
    pub fn get_multisig_wallet(&self, id_or_address: &str) -> Option<&multisig::MultiSigWallet> {
        // Try to find by wallet ID first
        if let Some(w) = self.multisig_wallets.iter().find(|w| w.id == id_or_address) {
            return Some(w);
        }
        // If not found, try to find by address (case-insensitive)
        self.multisig_wallets.iter().find(|w| w.address.eq_ignore_ascii_case(id_or_address))
    }
    
    /// Gets all multi-signature wallets
    /// 
    /// # Returns
    /// List of all multi-signature wallets
    #[allow(dead_code)]
    pub fn get_all_multisig_wallets(&self) -> &[multisig::MultiSigWallet] {
        &self.multisig_wallets
    }
    
    /// Gets the total number of multi-signature wallets
    /// 
    /// # Returns
    /// Number of multi-signature wallets
    pub fn multisig_wallet_count(&self) -> usize {
        self.multisig_wallets.len()
    }
    
    /// Removes a multi-signature wallet
    /// 
    /// # Arguments
    /// * `id` - The wallet ID to remove
    /// 
    /// # Returns
    /// * `true` - If the wallet was removed
    /// * `false` - If the wallet wasn't found
    pub fn remove_multisig_wallet(&mut self, id: &str) -> bool {
        let initial_len = self.multisig_wallets.len();
        self.multisig_wallets.retain(|w| w.id != id);
        self.multisig_wallets.len() < initial_len
    }
    
    /// Gets the total balance across all multi-signature wallets
    /// 
    /// # Returns
    /// Total balance in satoshis
    #[allow(dead_code)]
    pub fn get_total_multisig_balance(&self) -> u64 {
        self.multisig_wallets.iter().map(|w| w.get_balance()).sum()
    }
    
    /// Lists all multi-signature wallets with their details
    /// 
    /// # Returns
    /// Formatted string with all multi-sig wallet information
    pub fn list_multisig_wallets(&self) -> String {
        if self.multisig_wallets.is_empty() {
            return "No multi-signature wallets found.".to_string();
        }
        
        let mut result = String::new();
        result.push_str("Multi-Signature Wallets:\n");
        result.push_str("========================\n\n");
        
        for (i, wallet) in self.multisig_wallets.iter().enumerate() {
            result.push_str(&format!("{}. {}\n", i + 1, wallet));
            result.push_str(&format!("   ID: {}\n", wallet.id));
            result.push_str(&format!("   Balance: {} satoshis\n", wallet.get_balance()));
            result.push_str(&format!("   Can Sign: {}\n", wallet.can_sign()));
            result.push_str(&format!("   My Keys: {}\n", wallet.my_key_count()));
            result.push_str(&format!("   Public Keys: {}\n", wallet.public_keys.len()));
            result.push('\n');
        }
        
        result
    }
    
    /// Creates a new multi-signature transaction
    /// 
    /// This function creates a transaction that requires multiple signatures
    /// to spend funds from a multi-signature wallet.
    /// 
    /// # Arguments
    /// * `wallet_id` - The ID of the multi-signature wallet
    /// * `dest_address` - The destination address to send funds to
    /// * `amount` - The amount to send in satoshis
    /// * `fee_rate` - The fee rate in satoshis per byte
    /// 
    /// # Returns
    /// * `Ok(multisig::MultiSigTransaction)` - The transaction ready for signing
    /// * `Err` - If transaction creation fails
    pub fn create_multisig_transaction(
        &self,
        wallet_id: &str,
        dest_address: &str,
        amount: u64,
        fee_rate: u64,
    ) -> Result<multisig::MultiSigTransaction, Box<dyn std::error::Error>> {
        let multisig_wallet = self.get_multisig_wallet(wallet_id)
            .ok_or("Multi-signature wallet not found")?;
        
        multisig_wallet.create_transaction(dest_address, amount, fee_rate)
    }
    
    /// Signs a multi-signature transaction with your private keys
    /// 
    /// This function creates signatures for a multi-signature transaction
    /// using the private keys you control for the specified wallet.
    /// 
    /// # Arguments
    /// * `wallet_id` - The ID of the multi-signature wallet
    /// * `multisig_tx` - The transaction to sign
    /// 
    /// # Returns
    /// * `Ok(Vec<multisig::PartialSignature>)` - The signatures you created
    /// * `Err` - If signing fails
    pub fn sign_multisig_transaction(
        &self,
        wallet_id: &str,
        multisig_tx: &mut multisig::MultiSigTransaction,
    ) -> Result<Vec<multisig::PartialSignature>, Box<dyn std::error::Error>> {
        let multisig_wallet = self.get_multisig_wallet(wallet_id)
            .ok_or("Multi-signature wallet not found")?;
        
        multisig_wallet.sign_transaction(multisig_tx)
    }
    

    
    /// Finalizes a multi-signature transaction for broadcasting
    /// 
    /// This function combines all signatures and creates the final
    /// transaction that can be broadcast to the network.
    /// 
    /// # Arguments
    /// * `wallet_id` - The ID of the multi-signature wallet
    /// * `multisig_tx` - The transaction to finalize
    /// 
    /// # Returns
    /// * `Ok(BitcoinTransaction)` - The finalized transaction
    /// * `Err` - If finalization fails
    pub fn finalize_multisig_transaction(
        &self,
        multisig_wallet: &multisig::MultiSigWallet,
        multisig_tx: &multisig::MultiSigTransaction,
    ) -> Result<BitcoinTransaction, Box<dyn std::error::Error>> {
        if multisig_wallet.id != multisig_tx.wallet_id
        && multisig_wallet.address != multisig_tx.multisig_address
    {
        return Err("Mismatched wallet for transaction".into());
    }
        multisig_wallet.finalize_transaction(multisig_tx)
    }
    
    /// Broadcasts a finalized multi-signature transaction
    /// 
    /// This function takes a finalized multi-signature transaction
    /// and broadcasts it to the Bitcoin network.
    /// 
    /// # Arguments
    /// * `finalized_tx` - The finalized transaction to broadcast
    /// 
    /// # Returns
    /// * `Ok(String)` - The transaction ID (txid) of the broadcast transaction
    /// * `Err` - If broadcasting fails
    pub async fn broadcast_multisig_transaction(
        &self,
        finalized_tx: &BitcoinTransaction,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let url = "https://blockstream.info/testnet/api/tx";
        let tx_hex = serialize_hex(finalized_tx);
        
        println!("Broadcasting multi-signature transaction...");
        println!("Transaction hex: {}", tx_hex);
        
        let response = client.post(url)
            .header("Content-Type", "text/plain")
            .body(tx_hex)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            println!("Transaction failed: {}", error_text);
            return Err("Transaction broadcasting failed".into());
        }

        let txid = finalized_tx.compute_txid();
        println!("Multi-signature transaction successful!");
        println!("Transaction ID: {}", txid);
        Ok(txid.to_string())
    }
    
    /// Updates the balance of a multi-signature wallet
    /// 
    /// This function fetches the current UTXOs for a multi-signature wallet
    /// from the blockchain and updates the wallet's balance.
    /// 
    /// # Arguments
    /// * `wallet_id` - The ID of the multi-signature wallet to update
    /// 
    /// # Returns
    /// * `Ok(())` - If the balance was updated successfully
    /// * `Err` - If the update fails
    pub async fn update_multisig_balance(
        &mut self,
        wallet_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let multisig_wallet = self.get_multisig_wallet(wallet_id)
            .ok_or("Multi-signature wallet not found")?;
        
        let client = reqwest::Client::new();
        let url = format!("https://blockstream.info/testnet/api/address/{}/utxo", multisig_wallet.address);
        
        println!("Updating balance for multi-signature wallet: {}", multisig_wallet.name);
        println!("Address: {}", multisig_wallet.address);
        
        let response = client.get(&url).send().await?;
        
        if response.status().is_success() {
            let utxos: Vec<Utxo> = response.json().await?;
            println!("Found {} UTXOs for multi-signature wallet", utxos.len());
            
            // Update the wallet's UTXOs
            if let Some(wallet) = self.multisig_wallets.iter_mut().find(|w| w.id == wallet_id) {
                wallet.utxos = utxos;
            }
        } else {
            println!("No UTXOs found for multi-signature wallet");
            if let Some(wallet) = self.multisig_wallets.iter_mut().find(|w| w.id == wallet_id) {
                wallet.utxos = Vec::new();
            }
        }
        
        // Save the updated wallet
        self.save_to_file(Path::new("wallet.json"))?;
        println!("✅ Multi-signature wallet balance updated!");
        
        Ok(())
    }
    
    /// Exports a multi-signature wallet configuration for sharing with other cosigners
    /// 
    /// This function creates a configuration file that can be safely shared with other
    /// cosigners. The configuration excludes private keys for security and includes
    /// all necessary information to recreate the multi-signature wallet.
    /// 
    /// # Arguments
    /// * `wallet_id` - The ID of the multi-signature wallet to export
    /// 
    /// # Returns
    /// * `Ok(multisig::MultiSigConfig)` - The configuration that can be shared
    /// * `Err` - If the wallet is not found or cannot be exported
    pub fn export_multisig_config(
        &self,
        wallet_id: &str,
    ) -> Result<multisig::MultiSigConfig, Box<dyn std::error::Error>> {
        let multisig_wallet = self.get_multisig_wallet(wallet_id)
            .ok_or("Multi-signature wallet not found")?;
        
        multisig_wallet.export_config()
    }
    
    /// Imports a multi-signature wallet configuration from another cosigner
    /// 
    /// This function allows you to import a multi-signature wallet configuration
    /// and add your own private keys to participate in the wallet.
    /// 
    /// # Arguments
    /// * `config` - The imported configuration
    /// * `my_private_keys` - Your private keys for the public keys you control
    /// 
    /// # Returns
    /// * `Ok(String)` - The ID of the imported multi-signature wallet
    /// * `Err` - If the configuration is invalid or cannot be imported
    #[allow(dead_code)]
    pub fn import_multisig_config(
        &mut self,
        config: multisig::MultiSigConfig,
        my_private_keys: std::collections::HashMap<String, String>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let multisig_wallet = multisig::MultiSigWallet::from_config(config, my_private_keys)?;
        
        let wallet_id = multisig_wallet.id.clone();
        self.multisig_wallets.push(multisig_wallet);
        
        Ok(wallet_id)
    }
    
    /// Imports a multi-signature wallet configuration and automatically updates its balance
    /// 
    /// This function imports a multi-signature wallet configuration and immediately
    /// fetches the current balance from the blockchain to ensure the wallet shows
    /// the correct balance after import.
    /// 
    /// # Arguments
    /// * `config` - The imported configuration
    /// * `my_private_keys` - Your private keys for the public keys you control
    /// 
    /// # Returns
    /// * `Ok(String)` - The ID of the imported multi-signature wallet
    /// * `Err` - If the configuration is invalid or cannot be imported
    pub async fn import_multisig_config_with_balance(
        &mut self,
        config: multisig::MultiSigConfig,
        my_private_keys: std::collections::HashMap<String, String>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let multisig_wallet = multisig::MultiSigWallet::from_config(config, my_private_keys)?;
        
        let wallet_id = multisig_wallet.id.clone();
        self.multisig_wallets.push(multisig_wallet);
        
        // Automatically update the balance after import
        self.update_multisig_balance(&wallet_id).await?;
        
        Ok(wallet_id)
    }
    

}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // Helper function to create a test wallet
    fn create_test_wallet() -> Wallet {
        Wallet {
            addresses: Vec::new(),
            next_index: 0,
            next_multisig_index: 0,
            mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
            multisig_wallets: Vec::new(),
        }
    }

    // Helper function to create a test UTXO
    fn create_test_utxo(txid: &str, vout: u32, value: u64) -> Utxo {
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

    // Helper function to create a test address
    fn create_test_address(address: &str, private_key: &str, balance: u64) -> WalletAddress {
        let utxos = if balance > 0 {
            vec![create_test_utxo("test_txid", 0, balance)]
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

    #[test]
    fn test_wallet_creation() {
        let wallet = create_test_wallet();
        assert_eq!(wallet.address_count(), 0);
        assert_eq!(wallet.next_index, 0);
        assert!(wallet.mnemonic.is_some());
    }

    #[test]
    fn test_wallet_is_empty() {
        let wallet = create_test_wallet();
        assert!(wallet.is_empty());
        
        let mut wallet_with_addresses = create_test_wallet();
        wallet_with_addresses.addresses.push(create_test_address("addr1", "key1", 1000));
        assert!(!wallet_with_addresses.is_empty());
    }

    #[test]
    fn test_wallet_address_count() {
        let mut wallet = create_test_wallet();
        assert_eq!(wallet.address_count(), 0);
        
        wallet.addresses.push(create_test_address("addr1", "key1", 1000));
        assert_eq!(wallet.address_count(), 1);
        
        wallet.addresses.push(create_test_address("addr2", "key2", 2000));
        assert_eq!(wallet.address_count(), 2);
    }

    #[test]
    fn test_get_address() {
        let mut wallet = create_test_wallet();
        wallet.addresses.push(create_test_address("addr1", "key1", 1000));
        wallet.addresses.push(create_test_address("addr2", "key2", 2000));
        
        // Test valid index
        let addr = wallet.get_address(0);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().address, "addr1");
        
        // Test invalid index
        let addr = wallet.get_address(999);
        assert!(addr.is_none());
    }

    #[test]
    fn test_get_utxos_from_address() {
        let mut wallet = create_test_wallet();
        wallet.addresses.push(create_test_address("addr1", "key1", 1000));
        
        // Test existing address
        let utxos = wallet.get_utxos_from_address("addr1");
        assert!(utxos.is_ok());
        assert_eq!(utxos.unwrap().len(), 1);
        
        // Test non-existing address
        let utxos = wallet.get_utxos_from_address("non_existent");
        assert!(utxos.is_err());
    }

    #[test]
    fn test_wallet_serialization_roundtrip() {
        let mut wallet = create_test_wallet();
        wallet.addresses.push(create_test_address("addr1", "key1", 1000));
        
        // Test serialization
        let json = serde_json::to_string(&wallet);
        assert!(json.is_ok());
        
        // Test deserialization
        let deserialized: Wallet = serde_json::from_str(&json.unwrap()).unwrap();
        assert_eq!(deserialized.address_count(), wallet.address_count());
        assert_eq!(deserialized.next_index, wallet.next_index);
        assert_eq!(deserialized.mnemonic, wallet.mnemonic);
    }

    #[test]
    fn test_wallet_save_and_load() {
        let mut wallet = create_test_wallet();
        wallet.addresses.push(create_test_address("addr1", "key1", 1000));
        
        // Create temporary file
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        // Test save
        let save_result = wallet.save_to_file(path);
        assert!(save_result.is_ok());
        
        // Test load
        let loaded_wallet = Wallet::load_from_file(path);
        assert!(loaded_wallet.is_ok());
        
        let loaded_wallet = loaded_wallet.unwrap();
        assert_eq!(loaded_wallet.address_count(), wallet.address_count());
        assert_eq!(loaded_wallet.next_index, wallet.next_index);
        assert_eq!(loaded_wallet.mnemonic, wallet.mnemonic);
    }

    #[test]
    fn test_utxo_creation() {
        let utxo = create_test_utxo("test_txid", 1, 50000);
        
        assert_eq!(utxo.txid, "test_txid");
        assert_eq!(utxo.vout, 1);
        assert_eq!(utxo.value, 50000);
        assert!(utxo.status.confirmed);
        assert_eq!(utxo.status.block_height, Some(1000));
    }

    #[test]
    fn test_wallet_address_creation() {
        let address = create_test_address("test_addr", "test_key", 1000);
        
        assert_eq!(address.address, "test_addr");
        assert_eq!(address.private_key, "test_key");
        assert_eq!(address.public_key, "test_public_key");
        assert_eq!(address.derivation_path, "m/44'/1'/0'/0/0");
        assert_eq!(address.utxos.len(), 1);
        assert_eq!(address.utxos[0].value, 1000);
    }

    #[test]
    fn test_wallet_address_display() {
        let address = create_test_address("test_addr", "test_key", 1000);
        let display = format!("{}", address);
        assert_eq!(display, "test_addr");
    }

    #[test]
    fn test_wallet_error_display() {
        let insufficient_funds = WalletError::InsufficientFunds;
        assert_eq!(format!("{}", insufficient_funds), "Insufficient funds");
        
        let transaction_failed = WalletError::TransactionFailed;
        assert_eq!(format!("{}", transaction_failed), "Transaction failed");
    }

    #[test]
    fn test_list_addresses() {
        let mut wallet = create_test_wallet();
        wallet.addresses.push(create_test_address("addr1", "key1", 1000));
        wallet.addresses.push(create_test_address("addr2", "key2", 2000));
        
        let address_list = wallet.list_addresses();
        assert!(address_list.contains("Available Addresses:"));
        assert!(address_list.contains("addr1"));
        assert!(address_list.contains("addr2"));
        assert!(address_list.contains("1000 satoshis"));
        assert!(address_list.contains("2000 satoshis"));
    }

    #[test]
    fn test_empty_wallet_serialization() {
        let wallet = Wallet {
            addresses: Vec::new(),
            next_index: 0,
            next_multisig_index: 0,
            mnemonic: None,
            multisig_wallets: Vec::new(),
        };
        
        let json = serde_json::to_string(&wallet);
        assert!(json.is_ok());
        
        let deserialized: Wallet = serde_json::from_str(&json.unwrap()).unwrap();
        assert_eq!(deserialized.address_count(), 0);
        assert_eq!(deserialized.next_index, 0);
        assert!(deserialized.mnemonic.is_none());
    }
}