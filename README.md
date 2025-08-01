# Bitcoin CLI Wallet in Rust

A secure, feature-rich Bitcoin wallet implementation in Rust with support for wallet creation, address generation, transaction signing, and UTXO management.

## 🚀 Features

- **BIP39 Mnemonic Support**: Create and recover wallets using standard mnemonic phrases
- **BIP44 HD Wallet**: Hierarchical deterministic address generation
- **Gap Limit Implementation**: Efficient address scanning with configurable gap limits
- **P2PKH Transaction Signing**: Secure ECDSA signing for legacy Bitcoin addresses
- **Multi-signature Wallets**: Create and manage 2-of-3, 3-of-5, etc. multi-signature wallets
- **Multi-signature Transaction Signing**: Sign transactions with multiple cosigners and duplicate detection
- **Transaction Broadcasting**: Finalize and broadcast multi-signature transactions to the network
- **UTXO Management**: Real-time balance tracking and UTXO validation
- **Blockchain Integration**: Direct integration with Bitcoin testnet via Blockstream API
- **Secure Key Management**: Private keys stored in WIF format with proper cryptographic handling

## 🛠️ Technical Highlights

- **Cryptographic Security**: Uses bitcoin-rs library for all cryptographic operations
- **Memory Safety**: Leverages Rust's ownership system for secure memory management
- **Async/Await**: Non-blocking blockchain API calls for better performance
- **Error Handling**: Comprehensive error handling with custom error types
- **Serialization**: JSON-based wallet persistence with serde

## 📋 Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Internet connection for blockchain API access
- Bitcoin testnet for safe testing

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/rust_cli_wallet.git
   cd rust_cli_wallet
   ```

2. **Build the project**:
   ```bash
   cargo build --release
   ```

3. **Run the wallet**:
   ```bash
   cargo run
   ```

## 🏗️ Architecture

### Core Components

1. **Wallet**: Main wallet structure managing addresses and state
2. **WalletAddress**: Individual address with private key and UTXOs
3. **UTXO**: Unspent transaction output representation
4. **Transaction Signing**: ECDSA signing with secp256k1 curve

### Key Algorithms

#### Gap Limit Scanning
The wallet implements BIP44 gap limit scanning to efficiently discover used addresses:

```
1. Scan addresses sequentially (index 0, 1, 2...)
2. Count consecutive unused addresses
3. Stop when gap limit (20) is reached
4. This prevents infinite scanning while finding all used addresses
```

#### Address Derivation
Addresses are derived using BIP44 path: `m/44'/1'/0'/0/{index}`

- `44'` - BIP44 standard
- `1'` - Bitcoin testnet coin type
- `0'` - Account number
- `0` - Change address type (receiving)
- `{index}` - Sequential address index

#### Transaction Creation
1. **UTXO Selection**: Smart coin selection algorithm
2. **Fee Calculation**: Based on transaction size and fee rate
3. **Input Creation**: References to spent UTXOs
4. **Output Creation**: Destination + change addresses
5. **Signing**: ECDSA signatures for each input

## 🔒 Security Considerations

### Private Key Management
- Private keys stored in WIF (Wallet Import Format)
- Mnemonic phrases enable deterministic key generation
- All cryptographic operations use bitcoin-rs library

### Network Security
- Uses Bitcoin testnet for safe testing
- Validates all blockchain data before use
- Implements proper error handling for network failures

### Memory Safety
- Leverages Rust's ownership system
- No unsafe code blocks
- Automatic memory management prevents common vulnerabilities

## 🧪 Testing

Run the test suite:

```bash
cargo test
```

Run with verbose output:

```bash
cargo test -- --nocapture
```

## 🔧 Configuration

### Network Selection
Currently supports Bitcoin testnet. To switch to mainnet:

1. Change `Network::Testnet` to `Network::Bitcoin`
2. Update BIP44 coin type from `1'` to `0'`
3. Use mainnet blockchain APIs

### Gap Limit Configuration
The gap limit is set to 20 by default. To modify:

```rust
const GAP_LIMIT: u32 = 20; // Change this value
```

## 🚀 Future Enhancements

- [ ] SegWit support (P2SH-P2WPKH, P2WPKH)
- [ ] Hardware wallet integration
- [ ] Lightning Network support
- [ ] Advanced multi-signature features (time-locks, threshold signatures)


## 📝 Recent Updates

### v1.2.0 - Multi-signature Feature (Latest)
- ✅ **Multi-signature Wallet Creation**: Create 2-of-3, 3-of-5, etc. multi-signature wallets
- ✅ **Transaction Signing**: Sign transactions with multiple cosigners and duplicate detection
- ✅ **CLI Interface**: Complete menu system for multi-signature operations
- ✅ **Transaction Broadcasting**: Finalize and broadcast multi-signature transactions
- ✅ **File Management**: Save/load transaction files for sharing between cosigners
- ✅ **Enhanced Error Handling**: Clear user feedback and validation

### v1.1.0 - Basic Wallet Features
- ✅ Basic wallet creation and address generation
- ✅ Transaction sending and receiving
- ✅ UTXO management and balance tracking
- ✅ BIP39 mnemonic support

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This is educational software. Use at your own risk. Never use this wallet for storing significant amounts of Bitcoin without thorough testing and security review.

## 🙏 Acknowledgments

- [bitcoin-rs](https://github.com/rust-bitcoin/rust-bitcoin) for the Bitcoin library
- [BIP39](https://github.com/maciejhirsz/tiny-bip39) for mnemonic phrase support
- [Blockstream](https://blockstream.info/) for the blockchain API

## 📞 Support

For questions or issues:
- Open an issue on GitHub
- Check the documentation
- Review the test cases for usage examples 