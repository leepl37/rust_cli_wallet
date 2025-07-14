use std::path::Path;
use std::io::{self, Write};
use std::error::Error;
use crate::wallet::Wallet;

mod address;
mod wallet;
mod utxo;
mod transaction;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    run_interactive_mode().await
}

async fn run_interactive_mode() -> Result<(), Box<dyn std::error::Error>> {
    // Load or create wallet
    let wallet_path = Path::new("wallet.json");
    let mut wallet = match Wallet::load_from_file(wallet_path) {
        Ok(wallet) => wallet,
        Err(_) => {
            // File doesn't exist, create empty wallet
            println!("No wallet file found. Creating new wallet...");
            Wallet {
                addresses: Vec::new(),
                next_index: 0,
                mnemonic: None,
            }
        }
    };
    
    // If wallet is empty, ask user if they want to create a new one or import
    if wallet.is_empty() {
        println!("No wallet found. Would you like to:");
        println!("1. Create a new wallet");
        println!("2. Import an existing wallet with a mnemonic phrase");
        print!("Enter your choice (1-2): ");
        io::stdout().flush()?;
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        match choice.trim() {
            "1" => {
                // Create a new wallet with random mnemonic
                println!("Creating a new wallet with a random mnemonic...");
                
                // Generate a new 12-word mnemonic
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let mut entropy = [0u8; 16]; // 16 bytes = 128 bits = 12 words
                rng.fill(&mut entropy);
                let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
                    .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;
                
                let mnemonic_phrase = mnemonic.to_string();
                
                println!("\n=== IMPORTANT: BACKUP YOUR MNEMONIC ===");
                println!("Your wallet recovery phrase:");
                println!("{}", mnemonic_phrase);
                println!("\n⚠️  WARNING: Write this down and keep it safe!");
                println!("⚠️  Anyone with this phrase can access your funds!");
                println!("⚠️  Never share it with anyone!");
                println!("⚠️  Store it offline in a secure location!");
                println!("==========================================\n");
                
                // Confirm user has written it down
                print!("Type 'YES' to confirm you have written down your mnemonic: ");
                io::stdout().flush()?;
                
                let mut confirmation = String::new();
                io::stdin().read_line(&mut confirmation)?;
                
                if confirmation.trim() != "YES" && confirmation.trim() != "yes" {
                    println!("Please write down your mnemonic and try again.");
                    return Ok(());
                }
                
                // Initialize wallet with the generated mnemonic
                wallet.initialize_with_seed(&mnemonic_phrase).await?;
                wallet.save(wallet_path)?;
                
                println!("Wallet created successfully!");
                println!("Generated {} addresses", wallet.address_count());
                if let Some(first_addr) = wallet.get_address(0) {
                    println!("First address: {}", first_addr.address);
                }
                println!("You can now recover this wallet anytime using your mnemonic phrase.");
            },
            "2" => {
                // Import wallet with mnemonic
                print!("Enter your mnemonic phrase (12 or 24 words): ");
                io::stdout().flush()?;
                
                let mut mnemonic = String::new();
                io::stdin().read_line(&mut mnemonic)?;
                let mnemonic = mnemonic.trim();
                
                // Validate mnemonic using bip39
                let _mnemonic_parsed = match bip39::Mnemonic::parse_normalized(mnemonic) {
                    Ok(m) => m,
                    Err(e) => {
                        println!("Invalid mnemonic: {}", e);
                        println!("Please enter a valid 12 or 24 word mnemonic phrase.");
                        return Ok(());
                    }
                };
                
                println!("Initializing wallet with your mnemonic...");
                wallet.initialize_with_seed(mnemonic).await?;
                wallet.save(wallet_path)?;
                
                println!("Wallet imported successfully!");
                println!("Recovered {} addresses from mnemonic", wallet.address_count());
                if let Some(first_addr) = wallet.get_address(0) {
                    println!("First address: {}", first_addr.address);
                }
            },
            _ => {
                println!("Invalid choice. Exiting.");
                return Ok(());
            }
        }
    }

    // Update balances for all addresses (with timeout)
    println!("Updating balances for all addresses...");
    println!("(This may take a moment due to network requests)");
    
    match tokio::time::timeout(std::time::Duration::from_secs(600), wallet.update_balances()).await {
        Ok(result) => {
            if let Err(e) = result {
                println!("⚠️  Balance update failed: {}. Continuing with cached data...", e);
            } else { 
                println!("✅ Balance update completed successfully!");
            }
        }
        Err(_) => {
            println!("⚠️  Balance update timed out after 30 seconds. Continuing with cached data...");
        }
    }

    // Display all addresses and their balances
    wallet.display_all();

    // Interactive menu for managing addresses
    loop {
        println!("\n=== Bitcoin Wallet Menu ===");
        println!("1. Create a new address");
        println!("2. Send Bitcoin to another address in this wallet");
        println!("3. Send Bitcoin to an external address");
        println!("4. Display all addresses and balances");
        println!("5. List addresses with detailed information");
        println!("6. Exit");
        print!("Enter your choice (1-6): ");
        io::stdout().flush()?;
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        match choice.trim() {
            "1" => {
                // Create a new address
                let new_address = wallet.get_new_address()?;
                wallet.save(wallet_path)?;
                
                // Update balances
                wallet.update_balances().await?;
                
                println!("\nCreated new address: {}", new_address);
            },
            // become - we need to look though this. how to debug and make sure the code is working and break points 

            "2" => {
                // Send Bitcoin to another address in this wallet
                if wallet.address_count() < 2 {
                    println!("You need at least two addresses to send Bitcoin. Create another address first.");
                    continue;
                }
                
                // Display available addresses
                println!("\nAvailable addresses:");
                wallet.display_all();
                
                // Get source address
                print!("Enter the number of the source address (1-{}), or press Enter to auto-select: ", wallet.address_count());
                io::stdout().flush()?;
                let mut source_idx = String::new();
                io::stdin().read_line(&mut source_idx)?;
                
                // Check if user pressed Enter (empty input) for auto-selection
                println!("DEBUG: User input: '{}'", source_idx.trim());
                let idx: Option<usize> = if source_idx.trim().is_empty() {
                    println!("DEBUG: Auto-selecting source address...");
                    None
                } else {
                    let parsed = source_idx.trim().parse().unwrap_or(0);
                    println!("DEBUG: Parsed user input: {}", parsed);
                    if parsed < 1 || parsed > wallet.address_count() {
                        println!("Invalid source address number.");
                        continue;
                    }
                    Some(parsed)
                };
                
                let source_address_option = if let Some(i) = idx {
                    let addr = wallet.get_address(i - 1).ok_or("Invalid source address")?;
                    println!("Selected source address: {}", addr.address);
                    Some(addr.address.clone())
                } else {
                    println!("Will auto-select source address from available UTXOs");
                    None
                };
                
                // Get destination address
                print!("Enter the number of the destination address (1-{}): ", wallet.address_count());
                io::stdout().flush()?;
                let mut dest_idx = String::new();
                io::stdin().read_line(&mut dest_idx)?;
                let dest_idx: usize = dest_idx.trim().parse().unwrap_or(0);
                
                if dest_idx < 1 || dest_idx > wallet.address_count() || idx == Some(dest_idx) {
                    println!("Invalid destination address number.");
                    continue;
                }
                
                // Get amount
                print!("Enter the amount to send (in satoshis, 1 BTC = 100,000,000 satoshis): ");
                io::stdout().flush()?;
                let mut amount_str = String::new();
                io::stdin().read_line(&mut amount_str)?;
                let amount = amount_str.trim().parse().unwrap_or_else(|_| {
                    println!("Invalid amount. you typed : {}, using 0", amount_str);
                    0
                });
                
                if amount == 0 {
                    println!("Invalid amount.");
                    continue;
                }
                
                // Get fee
                print!("Enter the transaction fee (in satoshis): ");
                io::stdout().flush()?;
                let mut fee_str = String::new();
                io::stdin().read_line(&mut fee_str)?;
                let fee: u64 = fee_str.trim().parse().unwrap_or(0);
                
                if fee == 0 {
                    println!("Invalid fee.");
                    continue;
                }
                
                // Get addresses before mutable borrow
                let dest_addr = wallet.get_address(dest_idx - 1)
                    .ok_or("Invalid destination address")?;
                
                let dest_addr_string = dest_addr.to_string();
                
                // Display source information
                match &source_address_option {
                    Some(addr) => println!("\nSending {} satoshis from {} to {}", 
                        amount, addr, dest_addr_string),
                    None => println!("\nSending {} satoshis (auto-select source) to {}", 
                        amount, dest_addr_string),
                }
                
                // Debug: Print what we're sending to the function
                println!("DEBUG: Calling sign_and_send_transaction with:");
                println!("  - destination: {}", dest_addr_string);
                println!("  - amount: {} satoshis", amount);
                println!("  - fee: {} satoshis", fee);
                println!("  - source_address: {:?}", source_address_option.as_deref());
                
                match wallet.sign_and_send_transaction(
                    &dest_addr_string,
                    amount,
                    fee,
                    source_address_option.as_deref()
                ).await {
                    Ok(txid) => println!("Transaction sent successfully! TXID: {}", txid),
                    Err(e) => println!("Failed to send transaction: {}", e),
                }
                
                // Update balances
                wallet.update_balances().await?;
            },
            "3" => {
                // Send Bitcoin to an external address
                if wallet.address_count() < 1 {
                    println!("You need at least one address with funds to send Bitcoin. Create an address first.");
                    continue;
                }
                
                // Display available addresses
                println!("\nAvailable addresses:");
                wallet.display_all();
                
                // Get source address
                print!("Enter the number of the source address (1-{}), or press Enter to auto-select: ", wallet.address_count());
                io::stdout().flush()?;
                let mut source_idx = String::new();
                io::stdin().read_line(&mut source_idx)?;
                
                // Check if user pressed Enter (empty input) for auto-selection
                let idx: Option<usize> = if source_idx.trim().is_empty() {
                    println!("Auto-selecting source address...");
                    None
                } else {
                    let parsed = source_idx.trim().parse().unwrap_or(0);
                    if parsed < 1 || parsed > wallet.address_count() {
                        println!("Invalid source address number.");
                        continue;
                    }
                    Some(parsed)
                };
                
                let source_address_option = if let Some(i) = idx {
                    let addr = wallet.get_address(i - 1).ok_or("Invalid source address")?;
                    println!("Selected source address: {}", addr.address);
                    Some(addr.address.clone())
                } else {
                    println!("Will auto-select source address from available UTXOs");
                    None
                };
                
                // Get external destination address
                print!("Enter the external destination address: ");
                io::stdout().flush()?;
                let mut dest_address = String::new();
                io::stdin().read_line(&mut dest_address)?;
                let dest_address = dest_address.trim();
                
                // Validate the address format
                if !dest_address.starts_with("m") && !dest_address.starts_with("n") && !dest_address.starts_with("2") && !dest_address.starts_with("tb1") {
                    println!("Invalid Bitcoin testnet address format. Address should start with m, n, 2, or tb1.");
                    continue;
                }
                
                // Get amount
                print!("Enter the amount to send (in satoshis, 1 BTC = 100,000,000 satoshis): ");
                io::stdout().flush()?;
                let mut amount_str = String::new();
                io::stdin().read_line(&mut amount_str)?;
                let amount = amount_str.trim().parse().unwrap_or_else(|_| {
                    println!("Invalid amount. you typed : {}, using 0", amount_str);
                    0
                });
                
                if amount == 0 {
                    println!("Invalid amount.");
                    continue;
                }
                
                // Get fee
                print!("Enter the transaction fee (in satoshis): ");
                io::stdout().flush()?;
                let mut fee_str = String::new();
                io::stdin().read_line(&mut fee_str)?;
                let fee: u64 = fee_str.trim().parse().unwrap_or(0);
                
                if fee == 0 {
                    println!("Invalid fee.");
                    continue;
                }
                
                // Display source information
                match &source_address_option {
                    Some(addr) => println!("\nSending {} satoshis from {} to external address: {}", 
                        amount, addr, dest_address),
                    None => println!("\nSending {} satoshis (auto-select source) to external address: {}", 
                        amount, dest_address),
                }
                
                // Debug: Print what we're sending to the function
                println!("DEBUG: Calling sign_and_send_transaction with:");
                println!("  - destination: {}", dest_address);
                println!("  - amount: {} satoshis", amount);
                println!("  - fee: {} satoshis", fee);
                println!("  - source_address: {:?}", source_address_option.as_deref());
                
                match wallet.sign_and_send_transaction(
                    dest_address,
                    amount,
                    fee,
                    source_address_option.as_deref()
                ).await {
                    Ok(txid) => println!("Transaction sent successfully! TXID: {}", txid),
                    Err(e) => println!("Failed to send transaction: {}", e),
                }
                
                // Update balances
                wallet.update_balances().await?;
            },
            "4" => {
                // Display all addresses and balances
                wallet.update_balances().await?;
                wallet.display_all();
            },
            "5" => {
                // List addresses with detailed information
                wallet.update_balances().await?;
                println!("{}", wallet.list_addresses());
            },
            "6" => {
                // Exit
                println!("Goodbye!");
                break;
            },
            _ => {
                println!("Invalid choice. Please try again.");
            }
        }
    }
    
    Ok(())
}
