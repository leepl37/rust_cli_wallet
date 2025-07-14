use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UtxoStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u32>,
    #[serde(default)]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_creation() {
        let utxo = Utxo {
            txid: "test_txid".to_string(),
            vout: 1,
            value: 50000,
            status: UtxoStatus {
                confirmed: true,
                block_height: Some(1000),
                block_hash: Some("test_hash".to_string()),
                block_time: Some(1234567890),
            },
        };
        
        assert_eq!(utxo.txid, "test_txid");
        assert_eq!(utxo.value, 50000);
        assert!(utxo.status.confirmed);
    }

    #[test]
    fn test_utxo_status_defaults() {
        let status = UtxoStatus {
            confirmed: false,
            block_height: None,
            block_hash: None,
            block_time: None,
        };
        
        assert!(!status.confirmed);
        assert!(status.block_height.is_none());
    }
}

