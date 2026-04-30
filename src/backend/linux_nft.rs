use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};

use crate::{
    plan::{BlackoutMode, BlackoutPlan, BlackoutSpec, RestorePlan},
    probe::command_exists,
    status::{BlackoutStatus, VerificationCheck, VerificationReport},
};

use super::BlackoutBackend;

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

    fn verify(&self, spec: &BlackoutSpec) -> Result<VerificationReport> {
        if std::env::consts::OS != "linux" {
            return Ok(VerificationReport {
                status: BlackoutStatus::Unknown("not running on Linux".to_string()),
                checks: Vec::new(),
            });
        }

        if !command_exists("nft") {
            return Ok(VerificationReport {
                status: BlackoutStatus::Unknown("`nft` not found in PATH".to_string()),
                checks: Vec::new(),
            });
        }

        let output = Command::new("nft")
            .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .context("failed to run `nft list table inet ergo_blackout`")?;

        if !output.status.success() {
            return Ok(VerificationReport {
                status: BlackoutStatus::Inactive,
                checks: vec![VerificationCheck {
                    name: "table_exists",
                    ok: false,
                    detail: "dedicated nftables table is absent".to_string(),
                }],
            });
        }

        let ruleset = String::from_utf8_lossy(&output.stdout);
        let checks = verification_checks(&ruleset, spec);
        let failed: Vec<&VerificationCheck> = checks.iter().filter(|check| !check.ok).collect();
        let status = if failed.is_empty() {
            BlackoutStatus::ActiveVerified
        } else {
            BlackoutStatus::ActiveDrifted(
                failed
                    .iter()
                    .map(|check| check.name)
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        };

        Ok(VerificationReport { status, checks })
    }

    fn blackout_plan(&self, spec: BlackoutSpec) -> BlackoutPlan {
        BlackoutPlan {
            spec: spec.clone(),
            steps: vec![
                "Create dedicated nftables table `inet ergo_blackout`.".to_string(),
                "Create input/output chains owned by Ergo Blackout.".to_string(),
                "Allow loopback traffic.".to_string(),
                mode_step(spec.mode),
                allowlist_step(&spec),
                "Drop all other inbound and outbound traffic by default.".to_string(),
                "Do not flush or modify unrelated nftables tables.".to_string(),
            ],
            nft_ruleset: blackout_ruleset(&spec),
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

fn blackout_ruleset(spec: &BlackoutSpec) -> String {
    let mut input_rules = vec![r#"        iif "lo" accept"#.to_string()];
    let mut output_rules = vec![r#"        oif "lo" accept"#.to_string()];

    if spec.mode == BlackoutMode::Soft {
        input_rules.push("        ct state established,related accept".to_string());
        output_rules.push("        ct state established,related accept".to_string());
    }

    if spec.mode == BlackoutMode::Allowlist {
        for port in &spec.allowlist.tcp_ports {
            input_rules.push(format!("        tcp dport {port} accept"));
            output_rules.push(format!("        tcp dport {port} accept"));
            input_rules.push(format!("        tcp sport {port} accept"));
            output_rules.push(format!("        tcp sport {port} accept"));
        }

        for port in &spec.allowlist.udp_ports {
            input_rules.push(format!("        udp dport {port} accept"));
            output_rules.push(format!("        udp dport {port} accept"));
            input_rules.push(format!("        udp sport {port} accept"));
            output_rules.push(format!("        udp sport {port} accept"));
        }
    }

    format!(
        r#"table {TABLE_FAMILY} {TABLE_NAME} {{
    chain input {{
        type filter hook input priority -300; policy drop;
{input_rules}
    }}

    chain output {{
        type filter hook output priority -300; policy drop;
{output_rules}
    }}
}}
"#,
        input_rules = input_rules.join("\n"),
        output_rules = output_rules.join("\n")
    )
}

fn mode_step(mode: BlackoutMode) -> String {
    match mode {
        BlackoutMode::Soft => "Allow established and related traffic.".to_string(),
        BlackoutMode::Hard => {
            "Do not allow established traffic; only loopback remains.".to_string()
        }
        BlackoutMode::Allowlist => "Allow only explicitly configured ports.".to_string(),
    }
}

fn allowlist_step(spec: &BlackoutSpec) -> String {
    if spec.mode != BlackoutMode::Allowlist {
        return "No allowlist ports are used in this mode.".to_string();
    }

    format!(
        "Allowlisted ports: tcp={:?}, udp={:?}.",
        spec.allowlist.tcp_ports, spec.allowlist.udp_ports
    )
}

fn verification_checks(ruleset: &str, spec: &BlackoutSpec) -> Vec<VerificationCheck> {
    let mut checks = vec![
        check("table_exists", ruleset.contains("table inet ergo_blackout")),
        check("input_chain_exists", ruleset.contains("chain input")),
        check("output_chain_exists", ruleset.contains("chain output")),
        check(
            "input_policy_drop",
            ruleset.contains("hook input") && ruleset.contains("policy drop"),
        ),
        check(
            "output_policy_drop",
            ruleset.contains("hook output") && ruleset.contains("policy drop"),
        ),
        check(
            "loopback_input_allowed",
            ruleset.contains(r#"iif "lo" accept"#),
        ),
        check(
            "loopback_output_allowed",
            ruleset.contains(r#"oif "lo" accept"#),
        ),
    ];

    match spec.mode {
        BlackoutMode::Soft => {
            checks.push(check(
                "established_related_allowed",
                ruleset.contains("ct state established,related accept"),
            ));
        }
        BlackoutMode::Hard => {
            checks.push(check(
                "established_related_absent",
                !ruleset.contains("ct state established,related accept"),
            ));
        }
        BlackoutMode::Allowlist => {
            for port in &spec.allowlist.tcp_ports {
                checks.push(check(
                    "allowlist_tcp_port",
                    ruleset.contains(&format!("tcp dport {port} accept"))
                        && ruleset.contains(&format!("tcp sport {port} accept")),
                ));
            }
            for port in &spec.allowlist.udp_ports {
                checks.push(check(
                    "allowlist_udp_port",
                    ruleset.contains(&format!("udp dport {port} accept"))
                        && ruleset.contains(&format!("udp sport {port} accept")),
                ));
            }
        }
    }

    checks
}

fn check(name: &'static str, ok: bool) -> VerificationCheck {
    VerificationCheck {
        name,
        ok,
        detail: if ok { "ok" } else { "missing or drifted" }.to_string(),
    }
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
        let ruleset = blackout_ruleset(&BlackoutSpec::default());

        assert!(ruleset.contains("table inet ergo_blackout"));
        assert!(!ruleset.contains("flush ruleset"));
    }

    #[test]
    fn blackout_ruleset_allows_loopback_and_drops_by_default() {
        let ruleset = blackout_ruleset(&BlackoutSpec::default());

        assert!(ruleset.contains("iif \"lo\" accept"));
        assert!(ruleset.contains("oif \"lo\" accept"));
        assert!(ruleset.contains("policy drop"));
    }

    #[test]
    fn hard_mode_does_not_allow_established_connections() {
        let ruleset = blackout_ruleset(&BlackoutSpec {
            mode: BlackoutMode::Hard,
            allowlist: Default::default(),
        });

        assert!(!ruleset.contains("ct state established,related accept"));
    }

    #[test]
    fn allowlist_mode_adds_requested_ports() {
        let ruleset = blackout_ruleset(&BlackoutSpec {
            mode: BlackoutMode::Allowlist,
            allowlist: crate::plan::Allowlist {
                tcp_ports: vec![22],
                udp_ports: vec![53],
            },
        });

        assert!(ruleset.contains("tcp dport 22 accept"));
        assert!(ruleset.contains("udp dport 53 accept"));
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
