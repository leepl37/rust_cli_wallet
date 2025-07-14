use serde::{Serialize, Deserialize};

/// Represents a transaction input (UTXO to spend)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    /// The transaction ID of the UTXO
    pub txid: String,
    /// The output index of the UTXO
    pub vout: u32,
    /// The amount of the UTXO in satoshis
    pub amount: u64,
}

/// Represents a transaction output (where to send funds)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    /// The destination address
    pub address: String,
    /// The amount to send in satoshis
    pub amount: u64,
}

/// Represents a complete Bitcoin transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// List of inputs to spend
    pub inputs: Vec<TxInput>,
    /// List of outputs to send to
    pub outputs: Vec<TxOutput>,
    /// Transaction fee in satoshis
    pub fee: u64,
    /// Network (mainnet/testnet) for the transaction
    pub network: String,
} 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction {
            inputs: vec![TxInput {
                txid: "input_txid".to_string(),
                vout: 0,
                amount: 1000,
            }],
            outputs: vec![TxOutput {
                address: "dest_address".to_string(),
                amount: 900,
            }],
            fee: 100,
            network: "testnet".to_string(),
        };
        
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.fee, 100);
    }

    #[test]
    fn test_tx_input_output() {
        let input = TxInput {
            txid: "test_tx".to_string(),
            vout: 1,
            amount: 5000,
        };
        
        let output = TxOutput {
            address: "test_addr".to_string(),
            amount: 4500,
        };
        
        assert_eq!(input.amount, 5000);
        assert_eq!(output.amount, 4500);
    }
} 