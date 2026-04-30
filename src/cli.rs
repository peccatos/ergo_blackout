use clap::{Parser, Subcommand};

use crate::plan::BlackoutMode;

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
        /// Blackout mode: soft, hard, or allowlist.
        #[arg(long, default_value_t = BlackoutMode::Soft)]
        mode: BlackoutMode,
        /// TCP port to allow in allowlist mode. Can be repeated.
        #[arg(long = "allow-tcp")]
        allow_tcp: Vec<u16>,
        /// UDP port to allow in allowlist mode. Can be repeated.
        #[arg(long = "allow-udp")]
        allow_udp: Vec<u16>,
        /// Required to apply hard mode because it can terminate SSH access.
        #[arg(long = "i-understand-this-may-cut-ssh")]
        i_understand_this_may_cut_ssh: bool,
    },
    /// Show current network isolation status.
    Status,
    /// Verify Ergo Blackout nftables rules in detail.
    Verify,
    /// Inspect the current system and network state.
    Inspect,
    /// Restore the system by removing Ergo Blackout nftables rules.
    Restore {
        /// Apply nftables restore changes. Without this flag, only the plan is printed.
        #[arg(long)]
        apply: bool,
    },
    /// Show the planned isolation actions without applying them.
    DryRun,
}
