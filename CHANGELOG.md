# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2024-01-15

### Added
- Multi-signature wallet creation and management
- Support for 2-of-3, 3-of-5, and other multi-signature configurations
- Transaction signing with duplicate signature detection
- CLI menu system for multi-signature wallet operations
- Transaction file loading, signing, and broadcasting
- Signature completion checking and validation
- Import/export functionality for multi-signature wallet configurations
- Real-time balance tracking for multi-signature wallets

### Changed
- Enhanced error handling and user feedback throughout the application
- Improved transaction signing logic with better validation
- Updated CLI interface to include multi-signature options

### Fixed
- Prevented duplicate signatures when re-signing transactions
- Added proper validation for multi-signature wallet configurations
- Improved error messages for better user experience

## [1.1.0] - 2024-01-10

### Added
- Basic Bitcoin wallet functionality
- BIP39 mnemonic phrase support
- BIP44 hierarchical deterministic address generation
- P2PKH transaction signing
- UTXO management and balance tracking
- Blockchain integration via Blockstream API
- Secure private key management in WIF format
- Gap limit implementation for efficient address scanning

### Technical Features
- Rust-based implementation with memory safety
- Async/await for non-blocking blockchain API calls
- Comprehensive error handling with custom error types
- JSON-based wallet persistence with serde
- Cryptographic operations using bitcoin-rs library

## [1.0.0] - 2024-01-01

### Added
- Initial project setup
- Basic project structure
- Core wallet functionality foundation 