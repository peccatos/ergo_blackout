use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "ergo_blackout")]
#[command(about = "Verifiable network isolation tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enable network isolation mode.
    Blackout,
    /// Show current network isolation status.
    Status,
    /// Restore the system from a saved pre-blackout snapshot.
    Restore,
    /// Show the planned isolation actions without applying them.
    DryRun,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Blackout => handle_blackout(),
        Command::Status => handle_status(),
        Command::Restore => handle_restore(),
        Command::DryRun => handle_dry_run(),
    }
}

fn handle_blackout() -> Result<()> {
    println!("blackout: real network isolation is not implemented yet.");
    println!("Run `cargo run -- dry-run` to inspect the planned Linux-first isolation flow.");

    Ok(())
}

fn handle_status() -> Result<()> {
    println!("status: no active isolation state is tracked yet.");
    println!("Next backend step: inspect sockets, routes, DNS, and firewall tool availability.");

    Ok(())
}

fn handle_restore() -> Result<()> {
    println!("restore: no saved snapshot exists yet.");
    println!("Nothing was changed by this CLI skeleton, so there is nothing to restore.");

    Ok(())
}

fn handle_dry_run() -> Result<()> {
    println!("dry-run: planned Linux-first isolation checklist");
    println!("1. Inspect listening sockets.");
    println!("2. Inspect active routes.");
    println!("3. Inspect DNS configuration.");
    println!("4. Detect available firewall backend: nft, iptables, or ufw.");
    println!("5. Prepare a pre-change snapshot for restore.");
    println!("6. Prepare deny-by-default network rules.");
    println!("7. Report the plan without applying any system changes.");

    Ok(())
}
