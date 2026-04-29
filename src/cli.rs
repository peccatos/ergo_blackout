use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "ergo_blackout")]
#[command(about = "Verifiable network isolation tool")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Debug, Subcommand)]
pub enum CliCommand {
    /// Enable network isolation mode.
    Blackout {
        /// Apply nftables changes. Without this flag, only the plan is printed.
        #[arg(long)]
        apply: bool,
    },
    /// Show current network isolation status.
    Status,
    /// Restore the system by removing Ergo Blackout nftables rules.
    Restore {
        /// Apply nftables restore changes. Without this flag, only the plan is printed.
        #[arg(long)]
        apply: bool,
    },
    /// Show the planned isolation actions without applying them.
    DryRun,
}
