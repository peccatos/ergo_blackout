use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};

use crate::{
    plan::{BlackoutPlan, RestorePlan},
    probe::command_exists,
};

use super::{BackendStatus, BlackoutBackend};

const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "ergo_blackout";

#[derive(Debug, Default)]
pub struct LinuxNftBackend;

impl LinuxNftBackend {
    pub fn new() -> Self {
        Self
    }
}

impl BlackoutBackend for LinuxNftBackend {
    fn name(&self) -> &'static str {
        "linux-nftables"
    }

    fn ensure_supported(&self) -> Result<()> {
        if std::env::consts::OS != "linux" {
            bail!("nftables backend is only supported on Linux");
        }

        if !command_exists("nft") {
            bail!("nftables backend requires `nft` in PATH");
        }

        Ok(())
    }

    fn status(&self) -> Result<BackendStatus> {
        if std::env::consts::OS != "linux" {
            return Ok(BackendStatus {
                supported: false,
                active: false,
                detail: "not running on Linux".to_string(),
            });
        }

        if !command_exists("nft") {
            return Ok(BackendStatus {
                supported: false,
                active: false,
                detail: "`nft` not found in PATH".to_string(),
            });
        }

        let output = Command::new("nft")
            .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .context("failed to run `nft list table inet ergo_blackout`")?;

        if output.status.success() {
            return Ok(BackendStatus {
                supported: true,
                active: true,
                detail: "dedicated nftables table exists".to_string(),
            });
        }

        Ok(BackendStatus {
            supported: true,
            active: false,
            detail: "dedicated nftables table is not active".to_string(),
        })
    }

    fn blackout_plan(&self) -> BlackoutPlan {
        BlackoutPlan {
            steps: vec![
                "Create dedicated nftables table `inet ergo_blackout`.".to_string(),
                "Create input/output chains owned by Ergo Blackout.".to_string(),
                "Allow loopback traffic.".to_string(),
                "Allow established and related traffic.".to_string(),
                "Drop all other inbound and outbound traffic by default.".to_string(),
                "Do not flush or modify unrelated nftables tables.".to_string(),
            ],
            nft_ruleset: blackout_ruleset(),
        }
    }

    fn apply_blackout(&self, plan: &BlackoutPlan) -> Result<()> {
        self.ensure_supported()?;
        delete_owned_table_if_exists();
        run_nft_script(&plan.nft_ruleset)
    }

    fn restore_plan(&self) -> RestorePlan {
        RestorePlan {
            steps: vec![
                "Delete only the dedicated nftables table `inet ergo_blackout`.".to_string(),
                "Leave all unrelated nftables tables untouched.".to_string(),
            ],
            nft_command: vec![
                "nft".to_string(),
                "delete".to_string(),
                "table".to_string(),
                TABLE_FAMILY.to_string(),
                TABLE_NAME.to_string(),
            ],
        }
    }

    fn restore(&self, plan: &RestorePlan) -> Result<()> {
        self.ensure_supported()?;

        let output = Command::new(&plan.nft_command[0])
            .args(&plan.nft_command[1..])
            .output()
            .context("failed to run nft restore command")?;

        if !output.status.success() && !stderr_mentions_missing_table(&output.stderr) {
            bail!("nft restore command failed with status {}", output.status);
        }

        Ok(())
    }
}

fn blackout_ruleset() -> String {
    format!(
        r#"table {TABLE_FAMILY} {TABLE_NAME} {{
    chain input {{
        type filter hook input priority -300; policy drop;
        iif "lo" accept
        ct state established,related accept
    }}

    chain output {{
        type filter hook output priority -300; policy drop;
        oif "lo" accept
        ct state established,related accept
    }}
}}
"#
    )
}

fn delete_owned_table_if_exists() {
    let _ = Command::new("nft")
        .args(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        .status();
}

fn run_nft_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to start `nft -f -`")?;

    child
        .stdin
        .as_mut()
        .context("failed to open nft stdin")?
        .write_all(script.as_bytes())
        .context("failed to write nft ruleset")?;

    let status = child.wait().context("failed to wait for nft")?;
    if !status.success() {
        bail!("nft apply command failed with status {status}");
    }

    Ok(())
}

fn stderr_mentions_missing_table(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).contains("No such file or directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackout_ruleset_uses_only_ergo_blackout_table() {
        let ruleset = blackout_ruleset();

        assert!(ruleset.contains("table inet ergo_blackout"));
        assert!(!ruleset.contains("flush ruleset"));
    }

    #[test]
    fn blackout_ruleset_allows_loopback_and_drops_by_default() {
        let ruleset = blackout_ruleset();

        assert!(ruleset.contains("iif \"lo\" accept"));
        assert!(ruleset.contains("oif \"lo\" accept"));
        assert!(ruleset.contains("policy drop"));
    }

    #[test]
    fn restore_plan_targets_only_ergo_blackout_table() {
        let backend = LinuxNftBackend::new();
        let plan = backend.restore_plan();

        assert_eq!(
            plan.nft_command,
            ["nft", "delete", "table", "inet", "ergo_blackout"]
        );
    }
}
