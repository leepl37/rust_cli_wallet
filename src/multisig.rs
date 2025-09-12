use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::ser::SerializeStruct;
use serde::de::{self, Visitor, MapAccess};
use std::fmt;
use bitcoin::{PublicKey, Address, Network, ScriptBuf, Transaction as BitcoinTransaction, TxIn, TxOut, secp256k1::{Message, Secp256k1}, sighash::{SighashCache, EcdsaSighashType}, transaction::Version, absolute::LockTime, Sequence, Witness, Amount, OutPoint};
use std::collections::HashMap;
use std::str::FromStr;

/// Represents a partial signature for a multi-signature transaction
/// 
/// This struct contains a signature created by one of the cosigners
/// and the information needed to combine it with other signatures.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PartialSignature {
    /// The public key that created this signature
    pub public_key: String,
    /// The DER-encoded signature with hash type
    pub signature: Vec<u8>,
    /// The input index this signature is for
    pub input_index: usize,
}

/// Represents a multi-signature transaction that's being created
/// 
/// This struct contains all the information needed to create and sign
/// a multi-signature transaction, including the transaction data and
/// collected signatures.
#[derive(Debug, Clone)]
pub struct MultiSigTransaction {
    /// The transaction being created
    pub transaction: BitcoinTransaction,
    /// The redeem script for this multi-sig wallet
    pub redeem_script: ScriptBuf,
    /// Partial signatures collected so far
    pub partial_signatures: Vec<PartialSignature>,
    /// The multi-signature wallet this transaction is for
    pub wallet_id: String,
    /// The multi-signature address (P2SH format)
    pub multisig_address: String,
    /// Whether the transaction is fully signed and ready to broadcast
    pub is_complete: bool,
}

impl Serialize for MultiSigTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MultiSigTransaction", 6)?;
        state.serialize_field("transaction", &bitcoin::consensus::encode::serialize_hex(&self.transaction))?;
        state.serialize_field("redeem_script", &self.redeem_script.to_bytes())?;
        state.serialize_field("partial_signatures", &self.partial_signatures)?;
        state.serialize_field("wallet_id", &self.wallet_id)?;
        state.serialize_field("multisig_address", &self.multisig_address)?;
        state.serialize_field("is_complete", &self.is_complete)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MultiSigTransaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Removed unused Field enum to avoid dead_code warning
        struct MultiSigTransactionVisitor;
        impl<'de> Visitor<'de> for MultiSigTransactionVisitor {
            type Value = MultiSigTransaction;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct MultiSigTransaction")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut transaction = None;
                let mut redeem_script = None;
                let mut partial_signatures = None;
                let mut wallet_id = None;
                let mut multisig_address = None;
                let mut is_complete = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "transaction" => {
                            let tx_hex: String = map.next_value()?;
                            let tx_bytes = hex::decode(&tx_hex).map_err(de::Error::custom)?;
                            let tx: BitcoinTransaction = bitcoin::consensus::encode::deserialize(&tx_bytes).map_err(de::Error::custom)?;
                            transaction = Some(tx);
                        },
                        "redeem_script" => {
                            let script_bytes: Vec<u8> = map.next_value()?;
                            let script = ScriptBuf::from_bytes(script_bytes);
                            redeem_script = Some(script);
                        },
                        "partial_signatures" => {
                            partial_signatures = Some(map.next_value()?);
                        },
                        "wallet_id" => {
                            wallet_id = Some(map.next_value()?);
                        },
                        "multisig_address" => {
                            multisig_address = Some(map.next_value()?);
                        },
                        "is_complete" => {
                            is_complete = Some(map.next_value()?);
                        },
                        _ => { let _: serde::de::IgnoredAny = map.next_value()?; },
                    }
                }
                Ok(MultiSigTransaction {
                    transaction: transaction.ok_or_else(|| de::Error::missing_field("transaction"))?,
                    redeem_script: redeem_script.ok_or_else(|| de::Error::missing_field("redeem_script"))?,
                    partial_signatures: partial_signatures.ok_or_else(|| de::Error::missing_field("partial_signatures"))?,
                    wallet_id: wallet_id.ok_or_else(|| de::Error::missing_field("wallet_id"))?,
                    multisig_address: multisig_address.ok_or_else(|| de::Error::missing_field("multisig_address"))?,
                    is_complete: is_complete.ok_or_else(|| de::Error::missing_field("is_complete"))?,
                })
            }
        }
        deserializer.deserialize_struct("MultiSigTransaction", &["transaction", "redeem_script", "partial_signatures", "wallet_id", "multisig_address", "is_complete"], MultiSigTransactionVisitor)
    }
}

impl MultiSigTransaction {
    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let tx = serde_json::from_str(&json)?;
        Ok(tx)
    }
}

/// Configuration for a multi-signature wallet that can be exported and imported
/// 
/// This struct contains all the information needed to recreate a multi-signature
/// wallet, excluding private keys for security. It can be safely shared between
/// cosigners to ensure they all have the same multi-signature wallet setup.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MultiSigConfig {
    /// Human-readable name for the wallet
    pub name: String,
    /// List of all cosigner public keys (in order)
    pub public_keys: Vec<String>,
    /// Number of signatures required to spend (e.g., 2 for 2-of-3)
    pub required_signatures: u8,
    /// Total number of cosigners
    pub total_signers: u8,
    /// The multi-signature address (P2SH format)
    pub address: String,
    /// Derivation path for this multi-sig wallet
    pub derivation_path: String,
    /// Network (testnet/mainnet)
    pub network: String,
    /// Redeem script for this multi-signature wallet
    pub redeem_script: String,
    /// Version of the configuration format
    pub version: String,
    /// Creation timestamp
    pub created_at: u64,
}

/// Represents a multi-signature wallet configuration
/// 
/// This struct contains all the information needed to create and manage
/// a multi-signature wallet, including the public keys of all cosigners,
/// the required number of signatures, and the generated address.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MultiSigWallet {
    /// Unique identifier for this multi-sig wallet
    pub id: String,
    /// Human-readable name for the wallet
    pub name: String,
    /// List of all cosigner public keys (in order)
    pub public_keys: Vec<String>,
    /// Number of signatures required to spend (e.g., 2 for 2-of-3)
    pub required_signatures: u8,
    /// Total number of cosigners
    pub total_signers: u8,
    /// The multi-signature address (P2SH format)
    pub address: String,
    /// Your own private keys (for signing transactions)
    /// Key: public_key, Value: private_key
    pub my_private_keys: HashMap<String, String>,
    /// Derivation path for this multi-sig wallet
    pub derivation_path: String,
    /// Network (testnet/mainnet) - stored as string for serialization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// List of unspent transaction outputs for this address
    pub utxos: Vec<crate::wallet::Utxo>,
}


impl MultiSigWallet {
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
    /// * `Ok(MultiSigWallet)` - The created multi-sig wallet
    /// * `Err` - If the configuration is invalid
    pub fn new(
        name: String,
        public_keys: Vec<String>,
        required_signatures: u8,
        my_private_keys: HashMap<String, String>,
        network: Network,
        index: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let total_signers = public_keys.len() as u8;
        
        // Validate the configuration
        if required_signatures > total_signers {
            return Err("Required signatures cannot exceed total signers".into());
        }
        
        if required_signatures == 0 {
            return Err("At least one signature is required".into());
        }
        
        if public_keys.is_empty() {
            return Err("At least one public key is required".into());
        }
        
        // Generate the multi-sig address (default to native SegWit P2WSH)
        let address = Self::generate_multisig_address(&public_keys, required_signatures, network)?;
        
        // Generate unique ID
        let id = format!("multisig_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        
        // Create derivation path using the provided index
        let derivation_path = format!("m/45/0/{}'", index);
        
        Ok(MultiSigWallet {
            id,
            name,
            public_keys,
            required_signatures,
            total_signers,
            address,
            my_private_keys,
            derivation_path,
            network: Some(network.to_string()),
            utxos: Vec::new(),
        })
    }
    
    /// Generates a multi-signature address from public keys
    /// 
    /// By default, this creates a native SegWit P2WSH address from the
    /// multisig witness script. Public keys are sorted per BIP67.
    /// 
    /// # Arguments
    /// * `public_keys` - List of public keys (will be sorted by BIP67)
    /// * `required_signatures` - Number of signatures required
    /// * `network` - Bitcoin network
    /// 
    /// # Returns
    /// * `Ok(String)` - The multi-signature address
    /// * `Err` - If address generation fails
    fn generate_multisig_address(
        public_keys: &[String],
        required_signatures: u8,
        network: Network,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Sort public keys according to BIP67 (lexicographic order)
        let mut sorted_keys = public_keys.to_vec();
        sorted_keys.sort();
        
        // Convert string public keys to bitcoin::PublicKey
        let mut bitcoin_pubkeys = Vec::new();
        for key_str in &sorted_keys {
            let pubkey = PublicKey::from_str(key_str)?;
            bitcoin_pubkeys.push(pubkey);
        }
        
        // Create the witness script for multi-signature (same script body)
        let witness_script = Self::create_redeem_script(&bitcoin_pubkeys, required_signatures)?;
        
        // Generate native SegWit P2WSH address from the witness script
        let address = Address::p2wsh(&witness_script, network);
        
        Ok(address.to_string())
    }


    
    /// Creates a redeem script for multi-signature
    /// 
    /// The redeem script follows the format: <required> <pubkey1> <pubkey2> ... <total> OP_CHECKMULTISIG
    /// 
    /// # Arguments
    /// * `public_keys` - List of public keys (already sorted)
    /// * `required_signatures` - Number of signatures required
    /// 
    /// # Returns
    /// * `Ok(ScriptBuf)` - The redeem script
    /// * `Err` - If script creation fails
    fn create_redeem_script(
        public_keys: &[PublicKey],
        required_signatures: u8,
    ) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
        let total_signers = public_keys.len() as u8;
        
        let mut builder = bitcoin::script::Builder::new();
        
        // Push the required number of signatures
        builder = builder.push_int(required_signatures as i64);
        
        // Push all public keys
        for pubkey in public_keys {
            builder = builder.push_key(pubkey);
        }
        
        // Push the total number of signers
        builder = builder.push_int(total_signers as i64);
        
        // Add OP_CHECKMULTISIG
        builder = builder.push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG);
        
        Ok(builder.into_script())
    }
    
    /// Gets the balance of this multi-signature wallet
    /// 
    /// # Returns
    /// The total balance in satoshis
    pub fn get_balance(&self) -> u64 {
        self.utxos.iter().map(|utxo| utxo.value).sum()
    }
    
    /// Checks if you can sign transactions for this wallet
    /// 
    /// # Returns
    /// * `true` - If you have at least one private key for this wallet
    /// * `false` - If you don't have any private keys
    pub fn can_sign(&self) -> bool {
        !self.my_private_keys.is_empty()
    }
    
    /// Gets the number of private keys you control
    /// 
    /// # Returns
    /// Number of private keys you have for this wallet
    pub fn my_key_count(&self) -> usize {
        self.my_private_keys.len()
    }
    

    
    /// Exports the multi-signature wallet configuration for sharing with other cosigners
    /// 
    /// This function creates a configuration file that can be safely shared with other
    /// cosigners. The configuration excludes private keys for security and includes
    /// all necessary information to recreate the multi-signature wallet.
    /// 
    /// # Returns
    /// * `Ok(MultiSigConfig)` - The configuration that can be shared
    /// * `Err` - If the configuration cannot be exported
    pub fn export_config(&self) -> Result<MultiSigConfig, Box<dyn std::error::Error>> {
        // Create the redeem script for this wallet
        let redeem_script = self.create_redeem_script_for_signing()?;
        
        let config = MultiSigConfig {
            name: self.name.clone(),
            public_keys: self.public_keys.clone(),
            required_signatures: self.required_signatures,
            total_signers: self.total_signers,
            address: self.address.clone(),
            derivation_path: self.derivation_path.clone(),
            network: self.network.clone().unwrap_or_else(|| "testnet".to_string()),
            redeem_script: redeem_script.to_string(),
            version: "1.0".to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        Ok(config)
    }
    
    /// Creates a multi-signature wallet from an imported configuration
    /// 
    /// This function allows other cosigners to import a multi-signature wallet
    /// configuration and add their own private keys to participate in the wallet.
    /// 
    /// # Arguments
    /// * `config` - The imported configuration
    /// * `my_private_keys` - Your private keys for the public keys you control
    /// 
    /// # Returns
    /// * `Ok(MultiSigWallet)` - The imported multi-signature wallet
    /// * `Err` - If the configuration is invalid or cannot be imported
    pub fn from_config(
        config: MultiSigConfig,
        my_private_keys: HashMap<String, String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate the configuration
        if config.required_signatures > config.total_signers {
            return Err("Required signatures cannot exceed total signers".into());
        }
        
        if config.required_signatures == 0 {
            return Err("At least one signature is required".into());
        }
        
        if config.public_keys.is_empty() {
            return Err("At least one public key is required".into());
        }
        
        // Verify that the address matches the configuration
        let network = match config.network.as_str() {
            "testnet" => Network::Testnet,
            "mainnet" => Network::Bitcoin,
            _ => return Err("Invalid network".into()),
        };
        
        let expected_address = Self::generate_multisig_address(
            &config.public_keys,
            config.required_signatures,
            network,
        )?;
        
        if expected_address != config.address {
            return Err("Address in configuration does not match expected address".into());
        }
        
        // Generate unique ID for this instance
        let id = format!("multisig_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        
        Ok(MultiSigWallet {
            id,
            name: config.name,
            public_keys: config.public_keys,
            required_signatures: config.required_signatures,
            total_signers: config.total_signers,
            address: config.address,
            my_private_keys,
            derivation_path: config.derivation_path,
            network: Some(config.network),
            utxos: Vec::new(),
        })
    }

    /// Creates a new multi-signature transaction
    /// 
    /// This function creates a transaction structure that can be signed
    /// by multiple parties. It selects UTXOs, creates the transaction,
    /// and prepares it for signing.
    /// 
    /// # Arguments
    /// * `dest_address` - The destination address to send funds to
    /// * `amount` - The amount to send in satoshis
    /// * `fee_rate` - The fee rate in satoshis per byte
    /// 
    /// # Returns
    /// * `Ok(MultiSigTransaction)` - The transaction ready for signing
    /// * `Err` - If transaction creation fails
    pub fn create_transaction(
        &self,
        dest_address: &str,
        amount: u64,
        fee_rate: u64,
    ) -> Result<MultiSigTransaction, Box<dyn std::error::Error>> {
        // Validate we have enough funds
        let total_balance = self.get_balance();
        if total_balance < amount {
            return Err("Insufficient funds".into());
        }
        
        // Select UTXOs to spend
        let selected_utxos = self.select_utxos(amount, fee_rate)?;
        let total_value: u64 = selected_utxos.iter().map(|utxo| utxo.value).sum();
        
        // Estimate transaction fee
        let estimated_size = (selected_utxos.len() as u64) * 200 + 100; // Rough estimate
        let fee = estimated_size * fee_rate;
        
        if total_value < amount + fee {
            return Err("Insufficient funds including fees".into());
        }
        
        // Create the transaction
        let mut tx = BitcoinTransaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        
        // Add inputs
        for utxo in &selected_utxos {
            let txid = bitcoin::Txid::from_str(&utxo.txid)?;
            let outpoint = OutPoint::new(txid, utxo.vout);
            
            tx.input.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(), // Will be filled during signing
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            });
        }
        
        // Add destination output
        let dest_script = self.create_script_pubkey(dest_address)?;
        tx.output.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: dest_script,
        });
        
        // Add change output if needed
        let change = total_value - amount - fee;
        if change > 0 {
            let change_script = self.create_script_pubkey(&self.address)?;
            tx.output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_script,
            });
        }
        
        // Create redeem script
        let redeem_script = self.create_redeem_script_for_signing()?;
        
        Ok(MultiSigTransaction {
            transaction: tx,
            redeem_script,
            partial_signatures: Vec::new(),
            wallet_id: self.id.clone(),
            multisig_address: self.address.clone(),
            is_complete: false,
        })
    }
    
    /// Signs a multi-signature transaction with your private keys
    /// 
    /// This function creates signatures for all inputs using your private keys.
    /// Each signature is stored as a PartialSignature that can be combined
    /// with signatures from other cosigners.
    /// 
    /// # Arguments
    /// * `multisig_tx` - The transaction to sign
    /// 
    /// # Returns
    /// * `Ok(Vec<PartialSignature>)` - The signatures you created
    /// * `Err` - If signing fails
    pub fn sign_transaction(
        &self,
        multisig_tx: &mut MultiSigTransaction,
    ) -> Result<Vec<PartialSignature>, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let mut new_signatures = Vec::new();
        
        // Sign each input
        for input_index in 0..multisig_tx.transaction.input.len() {
            // Create sighash for this input
            let cache = SighashCache::new(&multisig_tx.transaction);
            let sighash = cache.legacy_signature_hash(
                input_index,
                &multisig_tx.redeem_script,
                EcdsaSighashType::All as u32,
            )?;
            
            let msg = Message::from_digest_slice(sighash.as_ref())?;
            
        // Sign with each of your private keys
        for (pubkey_str, privkey_str) in &self.my_private_keys {
            let private_key = bitcoin::PrivateKey::from_wif(privkey_str)?;
            
            // Verify this public key is in our wallet
            if !self.public_keys.contains(pubkey_str) {
                continue;
            }
            
            // Check if we've already signed this input with this public key
            let already_signed = multisig_tx.partial_signatures.iter().any(|existing_sig| {
                existing_sig.public_key == *pubkey_str && existing_sig.input_index == input_index
            });
            
            if already_signed {
                println!("Already signed input {} with public key {}", input_index, pubkey_str);
                continue;
            }
            
            // Create signature
            let sig = secp.sign_ecdsa(&msg, &private_key.inner);
            
            // Convert to DER format with hash type
            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(EcdsaSighashType::All as u8);
            
            // Create partial signature
            let partial_sig = PartialSignature {
                public_key: pubkey_str.clone(),
                signature: sig_bytes,
                input_index,
            };
            
            new_signatures.push(partial_sig);
        }
        }
        
        // Add new signatures to the transaction
        multisig_tx.partial_signatures.extend(new_signatures.clone());
        
        // Check if we have enough signatures
        self.check_completion(multisig_tx);
        
        if new_signatures.is_empty() {
            println!("✅ No new signatures needed - you have already signed all inputs you can sign for this transaction");
            println!("   Current signature count: {} total signatures", multisig_tx.partial_signatures.len());
        } else {
            println!("✅ Added {} new signatures to the transaction", new_signatures.len());
            println!("   Total signatures now: {} signatures", multisig_tx.partial_signatures.len());
        }
        
        // Show completion status
        if multisig_tx.is_complete {
            println!("🎉 Transaction is now complete and ready for finalization!");
        } else {
            println!("⏳ Transaction still needs more signatures to be complete");
        }
        
        Ok(new_signatures)
    }
    

    
    /// Finalizes a multi-signature transaction for broadcasting
    /// 
    /// This function combines all signatures and creates the final
    /// transaction that can be broadcast to the network.
    /// 
    /// # Arguments
    /// * `multisig_tx` - The transaction to finalize
    /// 
    /// # Returns
    /// * `Ok(BitcoinTransaction)` - The finalized transaction
    /// * `Err` - If finalization fails
    pub fn finalize_transaction(
        &self,
        multisig_tx: &MultiSigTransaction,
    ) -> Result<BitcoinTransaction, Box<dyn std::error::Error>> {
        if !multisig_tx.is_complete {
            return Err("Transaction is not fully signed".into());
        }
        
        let mut final_tx = multisig_tx.transaction.clone();
        
        // Group signatures by input
        let mut signatures_by_input: HashMap<usize, Vec<PartialSignature>> = HashMap::new();
        for sig in &multisig_tx.partial_signatures {
            signatures_by_input.entry(sig.input_index).or_default().push(sig.clone());
        }
        
        // Create unlocking data for each input
        for (input_index, input) in final_tx.input.iter_mut().enumerate() {
            if let Some(signatures) = signatures_by_input.get(&input_index) {
                // Sort signatures by public key order (BIP67)
                let mut sorted_sigs = signatures.clone();
                sorted_sigs.sort_by(|a, b| a.public_key.cmp(&b.public_key));

                // Build witness stack for P2WSH: [sig1, sig2, ..., witness_script]
                // Also support wrapped P2SH-P2WSH by placing the witness program in script_sig
                // Detect by script form: if redeem_script is a multisig and address is P2WSH,
                // we prefer witness path. Fallback to legacy P2SH if needed.

                // Construct the program for P2WSH
                let witness_script_bytes = multisig_tx.redeem_script.as_bytes().to_vec();

                // Default: use witness (native P2WSH)
                input.script_sig = ScriptBuf::new();
                input.witness.push(vec![]); // OP_0 dummy for CHECKMULTISIG
                for sig in &sorted_sigs {
                    input.witness.push(sig.signature.clone());
                }
                input.witness.push(witness_script_bytes);
            }
        }
        
        Ok(final_tx)
    }
    
    /// Checks if the transaction has enough signatures to be complete
    /// 
    /// # Arguments
    /// * `multisig_tx` - The transaction to check
    fn check_completion(&self, multisig_tx: &mut MultiSigTransaction) {
        // Count unique signers
        let mut unique_signers = std::collections::HashSet::new();
        for sig in &multisig_tx.partial_signatures {
            unique_signers.insert(&sig.public_key);
        }
        
        multisig_tx.is_complete = unique_signers.len() >= self.required_signatures as usize;
    }
    
    /// Selects UTXOs to spend for a transaction
    /// 
    /// # Arguments
    /// * `amount` - The amount to spend
    /// * `fee_rate` - The fee rate
    /// 
    /// # Returns
    /// * `Ok(Vec<crate::wallet::Utxo>)` - Selected UTXOs
    /// * `Err` - If insufficient funds
    fn select_utxos(
        &self,
        amount: u64,
        fee_rate: u64,
    ) -> Result<Vec<crate::wallet::Utxo>, Box<dyn std::error::Error>> {
        let mut selected = Vec::new();
        let mut total_value = 0u64;
        
        // Simple largest-first selection
        let mut sorted_utxos = self.utxos.clone();
        sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));
        
        for utxo in sorted_utxos {
            selected.push(utxo.clone());
            total_value += utxo.value;
            
            let estimated_fee = selected.len() as u64 * 200 * fee_rate;
            if total_value >= amount + estimated_fee {
                return Ok(selected);
            }
        }
        
        Err("Insufficient funds".into())
    }
    
    /// Creates a script pubkey for an address
    /// 
    /// # Arguments
    /// * `address` - The address to create script for
    /// 
    /// # Returns
    /// * `Ok(ScriptBuf)` - The script pubkey
    /// * `Err` - If script creation fails
    fn create_script_pubkey(&self, address: &str) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
        let network = self.network.as_ref()
            .ok_or("Network not set")?
            .parse::<Network>()?;
        let address = Address::from_str(address)?.require_network(network)?;
        
        match address.address_type() {
            Some(bitcoin::AddressType::P2pkh) => {
                let pubkey_hash = address.pubkey_hash()
                    .ok_or("Invalid P2PKH address")?;
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
    
    /// Creates the redeem script for signing
    /// 
    /// # Returns
    /// * `Ok(ScriptBuf)` - The redeem script
    /// * `Err` - If script creation fails
    fn create_redeem_script_for_signing(&self) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
        // Sort public keys according to BIP67
        let mut sorted_keys = self.public_keys.clone();
        sorted_keys.sort();
        
        // Convert to bitcoin::PublicKey
        let mut bitcoin_pubkeys = Vec::new();
        for key_str in &sorted_keys {
            let pubkey = PublicKey::from_str(key_str)?;
            bitcoin_pubkeys.push(pubkey);
        }
        
        Self::create_redeem_script(&bitcoin_pubkeys, self.required_signatures)
    }
}

impl std::fmt::Display for MultiSigWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}-of-{}) - {}",
            self.name,
            self.required_signatures,
            self.total_signers,
            self.address
        )
    }
} 

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_multisig_wallet_creation() {
        // Generate three valid compressed public keys
        let secp = Secp256k1::new();
        let sk1 = SecretKey::new(&mut rand::thread_rng());
        let sk2 = SecretKey::new(&mut rand::thread_rng());
        let sk3 = SecretKey::new(&mut rand::thread_rng());

        let pk1 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk1, Network::Testnet));
        let pk2 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk2, Network::Testnet));
        let pk3 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk3, Network::Testnet));

        let public_keys = vec![pk1.to_string(), pk2.to_string(), pk3.to_string()];
        
        let mut my_private_keys = HashMap::new();
        // Provide WIF for the first key to allow can_sign() to be true
        let wif1 = bitcoin::PrivateKey::new(sk1, Network::Testnet).to_wif();
        my_private_keys.insert(public_keys[0].clone(), wif1);
        
        let wallet = MultiSigWallet::new(
            "Test Multi-Sig".to_string(),
            public_keys,
            2, // 2-of-3
            my_private_keys,
            Network::Testnet,
            0, // index
        );
        
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();
        assert_eq!(wallet.name, "Test Multi-Sig");
        assert_eq!(wallet.required_signatures, 2);
        assert_eq!(wallet.total_signers, 3);
        assert!(wallet.can_sign());
        assert_eq!(wallet.my_key_count(), 1);
    }

    #[test]
    fn test_multisig_wallet_validation() {
        // Single valid key but require 2 signatures -> invalid
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey::new(sk, Network::Testnet));
        let public_keys = vec![pk.to_string()];
        
        let my_private_keys = HashMap::new();
        
        let wallet = MultiSigWallet::new(
            "Test Multi-Sig".to_string(),
            public_keys,
            2, // 2-of-1 (invalid)
            my_private_keys,
            Network::Testnet,
            0, // index
        );
        
        assert!(wallet.is_err());
    }
} 