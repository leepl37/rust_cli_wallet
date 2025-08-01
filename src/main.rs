use std::error::Error;

mod address;
mod wallet;
mod utxo;
mod transaction;
mod multisig;
mod cli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    cli::run_interactive_mode().await
}
