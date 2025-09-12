use std::io::{self, Write};
use std::str::FromStr;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use ldk_node::{Builder, Node};
use bitcoin::Network;
use std::time::Duration;
use std::thread;
use serde_json::Value;

pub struct LdkNodeQuickstartMenu {
    node: Option<Node>,
    recent_invoices: Vec<String>,
    recent_sent: Vec<(String, u64)>, // (invoice, amount_msat)
}

impl LdkNodeQuickstartMenu {
    pub fn show() -> Result<(), Box<dyn std::error::Error>> {
        let mut menu = LdkNodeQuickstartMenu { node: None, recent_invoices: Vec::new(), recent_sent: Vec::new() };
        loop {
            println!("\n⚡ LDK Node Quickstart (Testnet)");
            println!("===============================");
            println!("1. Start node (testnet) and print Node ID");
            println!("2. Show new on-chain funding address");
            println!("3. Open channel to peer (pubkey + ip:port)");
            println!("4. Create invoice (amount in sats)");
            println!("5. Pay BOLT11 invoice");
            println!("6. Wait until a channel is ready (poll)");
            println!("7. List channels and capacities");
            println!("8. Show on-chain balance (mempool.space)");
            println!("9. Show recent session events");
            println!("10. Back");
            print!("Enter your choice: ");
            io::stdout().flush()?;

            let mut choice = String::new();
            io::stdin().read_line(&mut choice)?;

            match choice.trim() {
                "1" => menu.start_node()?,
                "2" => menu.show_funding_address()?,
                "3" => menu.open_channel_prompt()?,
                "4" => menu.create_invoice_prompt()?,
                "5" => menu.pay_invoice_prompt()?,
                "6" => menu.wait_until_channel_ready()?,
                "7" => menu.list_channels_prompt()?,
                "8" => menu.show_onchain_balance_prompt()?,
                "9" => menu.show_recent_session_events()?,
                "10" => {
                    menu.stop_if_running()?;
                    break;
                },
                _ => println!("Invalid choice"),
            }
        }
        Ok(())
    }

    fn start_node(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.node.is_some() {
            let node = self.node.as_ref().unwrap();
            println!("Node already running. Node ID: {}", node.node_id());
            return Ok(());
        }

        let mut builder = Builder::new();
        builder.set_network(Network::Testnet);
        builder.set_storage_dir_path("./ldk_data".to_string());
        // builder.set_chain_source_esplora("https://blockstream.info/testnet/api".to_string(), None);
        builder.set_chain_source_esplora("https://mempool.space/testnet/api".to_string(), None);
        builder.set_listening_addresses(vec![SocketAddress::TcpIpV4 { addr: [0,0,0,0], port: 9735 }])?;
        // Optional: accelerate gossip sync
        // builder.set_gossip_source_rgs("https://rapidsync.lightningdevkit.org/testnet/snapshot".to_string());

        let node = builder.build()?;
        node.start()?;
        println!("Node ID: {}", node.node_id());
        println!("✅ Node is running. Leave this menu open to keep it running.");
        self.node = Some(node);
        Ok(())
    }

    fn ensure_node(&mut self) -> Result<&Node, Box<dyn std::error::Error>> {
        if self.node.is_none() {
            self.start_node()?;
        }
        Ok(self.node.as_ref().unwrap())
    }

    fn show_funding_address(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let node = self.ensure_node()?;
        let addr = node.onchain_payment().new_address()?;
        println!("Send testnet BTC to: {}", addr);
        Ok(())
    }

    fn open_channel_prompt(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let node = self.ensure_node()?;

        print!("Enter peer node pubkey (hex): ");
        io::stdout().flush()?;
        let mut pk = String::new();
        io::stdin().read_line(&mut pk)?;
        let pk = pk.trim();

        print!("Enter peer address (ip:port): ");
        io::stdout().flush()?;
        let mut addr = String::new();
        io::stdin().read_line(&mut addr)?;
        let addr = addr.trim();

        print!("Enter channel amount in sats (e.g., 100000): ");
        io::stdout().flush()?;
        let mut amt = String::new();
        io::stdin().read_line(&mut amt)?;
        let amt_sats: u64 = amt.trim().parse()?;

        let node_id = match PublicKey::from_str(pk) {
            Ok(pk) => pk,
            Err(e) => {
                println!("Invalid pubkey: {}", e);
                return Ok(());
            }
        };
        let node_addr = match SocketAddress::from_str(addr) {
            Ok(a) => a,
            Err(_e) => {
                println!("Invalid address. Expected format ip:port (e.g., 1.2.3.4:9735)");
                return Ok(());
            }
        };

        println!("Opening channel... this requires on-chain funds and confirmations.");
        node.open_channel(node_id, node_addr, amt_sats, None, None)?;
        println!("Channel open initiated. Monitor events/confirmations.");
        Ok(())
    }

    fn create_invoice_prompt(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let node = self.ensure_node()?;

        print!("Enter amount in sats: ");
        io::stdout().flush()?;
        let mut amt = String::new();
        io::stdin().read_line(&mut amt)?;
        let amt_sats: u64 = match amt.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                println!("Invalid amount");
                return Ok(());
            }
        };

        print!("Enter description (optional): ");
        io::stdout().flush()?;
        let mut desc = String::new();
        io::stdin().read_line(&mut desc)?;
        let desc = desc.trim();
        let desc = if desc.is_empty() { "invoice" } else { desc };

        let amount_msat = amt_sats.saturating_mul(1000);
        let expiry_secs: u32 = 3600;
        let description = Description::new(desc.to_string())?;
        let invoice = node
            .bolt11_payment()
            .receive(amount_msat as u64, &Bolt11InvoiceDescription::Direct(description), expiry_secs)?;

        let invoice_str = invoice.to_string();
        println!("Invoice: {}", invoice_str);
        self.recent_invoices.push(invoice_str);
        Ok(())
    }

    fn list_channels_prompt(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let node = self.ensure_node()?;
        let channels = node.list_channels();
        if channels.is_empty() {
            println!("No channels found.");
            return Ok(());
        }

        println!("\nChannels:");
        for (i, ch) in channels.iter().enumerate() {
            // Avoid hex encoding dependency; show SCID if present and peer id short form
            let scid = ch.short_channel_id.map(|v| v.to_string()).unwrap_or("pending".to_string());
            let peer = format!("{:?}", ch.counterparty_node_id);
            let peer_short = if peer.len() > 18 { &peer[..18] } else { &peer };
            println!(
                "{}. scid={} usable={} outbound={} msat inbound={} msat peer={}",
                i + 1,
                scid,
                ch.is_usable,
                ch.outbound_capacity_msat,
                ch.inbound_capacity_msat,
                peer_short,
            );
        }

        Ok(())
    }

    fn wait_until_channel_ready(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let node = self.ensure_node()?;
        println!("Waiting for any channel to become usable (up to 120s)...");
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            let channels = node.list_channels();
            if channels.iter().any(|c| c.is_usable) {
                println!("✅ A channel is usable.");
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                println!("⏱️  Timed out waiting for a usable channel.");
                return Ok(());
            }
            thread::sleep(Duration::from_secs(2));
        }
    }

    fn pay_invoice_prompt(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let node = self.ensure_node()?;

        print!("Paste BOLT11 invoice: ");
        io::stdout().flush()?;
        let mut inv = String::new();
        io::stdin().read_line(&mut inv)?;
        let inv = inv.trim();

        let invoice: Bolt11Invoice = match Bolt11Invoice::from_str(inv) {
            Ok(i) => i,
            Err(e) => {
                println!("Invalid invoice: {}", e);
                return Ok(());
            }
        };

        let amount_msat = invoice.amount_milli_satoshis().unwrap_or(0);
        match node.bolt11_payment().send(&invoice, None) {
            Ok(_pid) => {
                println!("Payment sent (pending). Use menu 7 to ensure a usable channel; the receiver should see the payment.");
                self.recent_sent.push((inv.to_string(), amount_msat));
            },
            Err(e) => println!("Failed to send: {}", e),
        }
        Ok(())
    }

    fn show_onchain_balance_prompt(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _node = self.ensure_node()?; // ensure running
        print!("Enter testnet address to query (tb1.../m.../n...): ");
        io::stdout().flush()?;
        let mut addr = String::new();
        io::stdin().read_line(&mut addr)?;
        let addr = addr.trim();
        if addr.is_empty() {
            println!("No address entered.");
            return Ok(());
        }

        // Query mempool.space for UTXOs
        let url = format!("https://mempool.space/testnet/api/address/{}/utxo", addr);
        let output = std::process::Command::new("curl")
            .arg("-s")
            .arg(url)
            .output();
        match output {
            Ok(out) => {
                if !out.status.success() {
                    println!("Failed to query mempool.space (curl exited with error)." );
                    return Ok(());
                }
                let body = String::from_utf8_lossy(&out.stdout);
                match serde_json::from_str::<Value>(&body) {
                    Ok(Value::Array(arr)) => {
                        let count = arr.len();
                        let mut total: u64 = 0;
                        for utxo in arr.iter() {
                            if let Some(v) = utxo.get("value").and_then(|v| v.as_u64()) {
                                total = total.saturating_add(v);
                            }
                        }
                        println!("On-chain balance for {}: {} sats ({} UTXOs)", addr, total, count);
                    }
                    Ok(_) => {
                        println!("Unexpected JSON format: {}", body);
                    }
                    Err(_) => {
                        println!("Non-JSON response: {}", body);
                    }
                }
            }
            Err(e) => println!("Failed to execute curl: {}", e),
        }
        Ok(())
    }

    fn show_recent_session_events(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _node = self.ensure_node()?;
        println!("\nRecent session events:");
        if self.recent_invoices.is_empty() && self.recent_sent.is_empty() {
            println!("(none)");
            return Ok(());
        }
        if !self.recent_invoices.is_empty() {
            println!("- Invoices created:");
            for inv in &self.recent_invoices {
                println!("  {}", inv);
            }
        }
        if !self.recent_sent.is_empty() {
            println!("- Payments sent (this session):");
            for (inv, amt) in &self.recent_sent {
                println!("  {} ({} msat)", inv, amt);
            }
        }
        Ok(())
    }

    fn stop_if_running(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(node) = self.node.take() {
            node.stop()?;
        }
        Ok(())
    }
}
