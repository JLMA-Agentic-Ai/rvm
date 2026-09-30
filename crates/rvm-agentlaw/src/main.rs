//! Binary entry point for the AgentLaw Compliance Appliance.

use rvm_agentlaw::run_server;

fn main() {
    let port = match std::env::var("AGENTLAW_PORT") {
        Err(_) => 8090,
        Ok(p) => match p.parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("AgentLaw: AGENTLAW_PORT '{p}' is not a valid port");
                std::process::exit(2);
            }
        },
    };

    println!("============================================================");
    println!("  AGENTLAW: Hardware-Enforced EU AI Act Compliance Engine   ");
    println!("  Standard: Regulation (EU) 2024/1689 • Articles 12, 14, 15  ");
    println!("  Attestation: SOFTWARE Ed25519 key - not hardware-backed    ");
    println!("============================================================");

    if let Err(e) = run_server(port) {
        eprintln!("AgentLaw: refusing to start (fail-closed): {e}");
        std::process::exit(1);
    }
}
