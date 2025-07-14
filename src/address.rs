use bitcoin::Network;
use serde::{Serialize, Deserialize};

// Custom serialization for Network enum since bitcoin crate doesn't implement Serialize/Deserialize
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl From<Network> for NetworkType {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => NetworkType::Bitcoin,
            Network::Testnet => NetworkType::Testnet,
            Network::Signet => NetworkType::Signet,
            Network::Regtest => NetworkType::Regtest,
            _ => NetworkType::Bitcoin, // Default to Bitcoin for any future variants
        }
    }
}

impl From<NetworkType> for Network {
    fn from(network: NetworkType) -> Self {
        match network {
            NetworkType::Bitcoin => Network::Bitcoin,
            NetworkType::Testnet => Network::Testnet,
            NetworkType::Signet => Network::Signet,
            NetworkType::Regtest => Network::Regtest,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BitcoinAddress {
    pub private_key: String,  // WIF format private key
    pub public_key: String,   // Hex-encoded public key
    pub address: String,      // Base58-encoded Bitcoin address
    
    /// Network type (mainnet/testnet) with custom serialization
    /// 
    /// # Why Custom Serialization?
    /// 
    /// The bitcoin crate's Network enum doesn't implement Serialize/Deserialize traits
    /// due to dependency conflicts and version compatibility issues. External libraries
    /// often avoid including serialization dependencies to prevent:
    /// 
    /// 1. **Version Conflicts**: If bitcoin crate used serde 1.0 but our project uses serde 2.0
    /// 2. **Unnecessary Dependencies**: Not all users need JSON serialization
    /// 3. **Library Bloat**: Keeping external libraries lightweight
    /// 
    /// # Our Solution
    /// 
    /// We create a custom serialization module (network_serde) that:
    /// - Converts Network → NetworkType for JSON serialization
    /// - Converts NetworkType → Network for JSON deserialization
    /// - Uses #[serde(with = "network_serde")] to override default behavior
    /// 
    /// # How It Works
    /// 
    /// When saving to JSON:
    /// Network::Testnet → NetworkType::Testnet → "testnet"
    /// 
    /// When loading from JSON:
    /// "testnet" → NetworkType::Testnet → Network::Testnet
    /// 
    /// This pattern allows us to persist Bitcoin addresses with their network
    /// information while maintaining compatibility with the bitcoin crate.
    #[serde(with = "network_serde")]
    pub network: Network,     // Network type (mainnet/testnet)
}

// Custom serialization module for Network
// 
// This module provides custom serialization/deserialization for the bitcoin::Network enum
// because the bitcoin crate doesn't implement Serialize/Deserialize traits.
// 
// # Technical Background
// 
// External libraries like bitcoin crate often don't implement serialization traits
// to avoid dependency conflicts and keep the library lightweight. This creates a
// common pattern in Rust where we need to create wrapper types or custom
// serialization for external types.
// 
// # Implementation Details
// 
// - serialize(): Converts bitcoin::Network → NetworkType → JSON string
// - deserialize(): Converts JSON string → NetworkType → bitcoin::Network
// - Uses the From trait implementations for clean conversion
// 
// # Usage
// 
// This module is used via #[serde(with = "network_serde")] attribute on
// fields of type bitcoin::Network, allowing seamless JSON persistence.
mod network_serde {
    use super::*;
    use serde::{Serializer, Deserializer};

    /// Custom serializer for bitcoin::Network
    /// 
    /// Converts Network → NetworkType → JSON string
    /// This allows bitcoin::Network to be serialized to JSON even though
    /// the bitcoin crate doesn't implement Serialize.
    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert bitcoin::Network to our NetworkType wrapper
        let network_type = NetworkType::from(*network);
        // Serialize the wrapper (which implements Serialize)
        network_type.serialize(serializer)
    }

    /// Custom deserializer for bitcoin::Network
    /// 
    /// Converts JSON string → NetworkType → Network
    /// This allows bitcoin::Network to be deserialized from JSON even though
    /// the bitcoin crate doesn't implement Deserialize.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize to our NetworkType wrapper
        let network_type: NetworkType = NetworkType::deserialize(deserializer)?;
        // Convert wrapper back to bitcoin::Network
        Ok(Network::from(network_type))
    }
} 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_conversion() {
        let testnet = Network::Testnet;
        let network_type = NetworkType::from(testnet);
        assert!(matches!(network_type, NetworkType::Testnet));
        
        let converted_back = Network::from(network_type);
        assert!(matches!(converted_back, Network::Testnet));
    }

    #[test]
    fn test_bitcoin_address_creation() {
        let address = BitcoinAddress {
            private_key: "test_key".to_string(),
            public_key: "test_pubkey".to_string(),
            address: "test_address".to_string(),
            network: Network::Testnet,
        };
        
        assert_eq!(address.private_key, "test_key");
        assert_eq!(address.network, Network::Testnet);
    }
} 