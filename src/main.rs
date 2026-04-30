mod backend;
mod classify;
mod cli;
mod inspect;
mod plan;
mod probe;
mod status;

use anyhow::{bail, Result};
use backend::{linux_nft::LinuxNftBackend, BlackoutBackend};
use clap::Parser;
use cli::{Cli, CliCommand};
use inspect::{inspect_system, InspectReport};
use plan::{Allowlist, BlackoutMode, BlackoutPlan, BlackoutSpec, RestorePlan};
use probe::SystemProbe;
use status::VerificationReport;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Blackout {
            apply,
            mode,
            allow_tcp,
            allow_udp,
            i_understand_this_may_cut_ssh,
        } => handle_blackout(
            apply,
            BlackoutSpec {
                mode,
                allowlist: Allowlist {
                    tcp_ports: allow_tcp,
                    udp_ports: allow_udp,
                },
            },
            i_understand_this_may_cut_ssh,
        ),
        CliCommand::Status => handle_status(),
        CliCommand::Verify => handle_verify(),
        CliCommand::Inspect => handle_inspect(),
        CliCommand::Restore { apply } => handle_restore(apply),
        CliCommand::DryRun => handle_dry_run(),
    }
}

fn handle_blackout(apply: bool, spec: BlackoutSpec, hard_confirmed: bool) -> Result<()> {
    validate_blackout_spec(&spec, apply, hard_confirmed)?;

    let backend = LinuxNftBackend::new();
    let outcome = run_blackout(&backend, spec, apply)?;

    print_blackout_plan(backend.name(), &outcome.plan);

    if !outcome.applied {
        println!();
        println!("blackout: not applied. Re-run with `--apply` to mutate nftables.");
        return Ok(());
    }

    println!();
    println!("blackout: applied via {}.", backend.name());

    Ok(())
}

fn handle_status() -> Result<()> {
    let probe = SystemProbe::current();
    let backend = LinuxNftBackend::new();
    let report = backend.verify(&BlackoutSpec::default())?;

    print_probe(&probe);
    println!();
    println!("ergo blackout backend:");
    println!("- backend: {}", backend.name());
    println!("- status: {}", report.status);

    Ok(())
}

fn handle_verify() -> Result<()> {
    let backend = LinuxNftBackend::new();
    let report = backend.verify(&BlackoutSpec::default())?;

    print_verification_report(&report);

    Ok(())
}

fn handle_inspect() -> Result<()> {
    let report = inspect_system()?;

    print_inspect_report(&report);

    Ok(())
}

fn handle_restore(apply: bool) -> Result<()> {
    let backend = LinuxNftBackend::new();
    let outcome = run_restore(&backend, apply)?;

    println!("restore plan via {}", backend.name());
    for step in &outcome.plan.steps {
        println!("- {step}");
    }

    if !outcome.applied {
        println!();
        println!("restore: not applied. Re-run with `--apply` to remove Ergo Blackout rules.");
        return Ok(());
    }

    println!();
    println!("restore: applied via {}.", backend.name());

    Ok(())
}

fn handle_dry_run() -> Result<()> {
    let backend = LinuxNftBackend::new();
    let outcome = run_blackout(&backend, BlackoutSpec::default(), false)?;

    print_blackout_plan(backend.name(), &outcome.plan);
    println!();
    println!("dry-run: no system changes were applied.");

    Ok(())
}

#[derive(Debug)]
struct BlackoutOutcome {
    plan: BlackoutPlan,
    applied: bool,
}

#[derive(Debug)]
struct RestoreOutcome {
    plan: RestorePlan,
    applied: bool,
}

fn run_blackout(
    backend: &impl BlackoutBackend,
    spec: BlackoutSpec,
    apply: bool,
) -> Result<BlackoutOutcome> {
    let plan = backend.blackout_plan(spec);

    if apply {
        backend.ensure_supported()?;
        backend.apply_blackout(&plan)?;
    }

    Ok(BlackoutOutcome {
        plan,
        applied: apply,
    })
}

fn run_restore(backend: &impl BlackoutBackend, apply: bool) -> Result<RestoreOutcome> {
    let plan = backend.restore_plan();

    if apply {
        backend.ensure_supported()?;
        backend.restore(&plan)?;
    }

    Ok(RestoreOutcome {
        plan,
        applied: apply,
    })
}

fn print_blackout_plan(backend_name: &str, plan: &plan::BlackoutPlan) {
    println!("blackout plan via {backend_name}");
    println!("mode: {}", plan.spec.mode);
    for step in &plan.steps {
        println!("- {step}");
    }
    println!();
    println!("nft ruleset:");
    println!("{}", plan.nft_ruleset);
}

fn print_verification_report(report: &VerificationReport) {
    println!("verify: {}", report.status);
    for check in &report.checks {
        println!(
            "- {}: {} ({})",
            check.name,
            if check.ok { "ok" } else { "failed" },
            check.detail
        );
    }
}

fn print_inspect_report(report: &InspectReport) {
    println!("System:");
    println!("  OS: {}", report.system.os);
    println!("  Kernel: {}", report.system.kernel);
    println!(
        "  User: {}",
        if report.system.is_root {
            "root"
        } else {
            "no-root"
        }
    );
    println!("  nft: {}", availability(report.system.probe.has_nft));
    println!(
        "  iptables: {}",
        availability(report.system.probe.has_iptables)
    );
    println!("  ufw: {}", availability(report.system.probe.has_ufw));
    println!();
    println!("Network:");
    println!("  Interfaces:");
    for interface in &report.network.interfaces {
        println!("    {interface}");
    }
    println!("  Routes:");
    for route in report.routes.lines() {
        println!("    {route}");
    }
    println!();
    println!("Listening:");
    for row in &report.listening {
        println!(
            "  {} {} -> {}    {}    {}",
            row.protocol, row.local, row.remote, row.class, row.process
        );
    }
    println!();
    println!("Active connections:");
    for row in &report.active_connections {
        println!(
            "  {} {} -> {}    {}    {}",
            row.protocol, row.local, row.remote, row.class, row.process
        );
    }
}

fn validate_blackout_spec(spec: &BlackoutSpec, apply: bool, hard_confirmed: bool) -> Result<()> {
    if spec.mode == BlackoutMode::Hard && apply && !hard_confirmed {
        bail!("hard mode with --apply requires --i-understand-this-may-cut-ssh");
    }

    if spec.mode == BlackoutMode::Allowlist
        && spec.allowlist.tcp_ports.is_empty()
        && spec.allowlist.udp_ports.is_empty()
    {
        bail!("allowlist mode requires at least one --allow-tcp or --allow-udp port");
    }

    Ok(())
}

fn availability(value: bool) -> &'static str {
    if value {
        "available"
    } else {
        "missing"
    }
}

fn print_probe(probe: &SystemProbe) {
    println!("status: read-only system probe");
    println!("target OS: {}", probe.target_os);
    println!();
    println!("available firewall tools:");
    print_tool_status("nft", probe.has_nft);
    print_tool_status("iptables", probe.has_iptables);
    print_tool_status("ufw", probe.has_ufw);
    println!();
    println!("available inspection tools:");
    print_tool_status("ss", probe.has_ss);
    print_tool_status("ip", probe.has_ip);
    print_tool_status("resolvectl", probe.has_resolvectl);
    println!();
    println!("dns config file: {}", yes_no(probe.has_resolv_conf));
    println!(
        "preferred firewall backend: {}",
        probe.preferred_firewall_backend()
    );
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn print_tool_status(name: &str, available: bool) {
    let status = if available { "found" } else { "missing" };
    println!("- {name}: {status}");
}

#[cfg(test)]
mod tests {
    use crate::backend::fake::RecordingBackend;

    use super::*;

    #[test]
    fn blackout_without_apply_does_not_mutate_backend() {
        let backend = RecordingBackend::default();
        let outcome = run_blackout(&backend, BlackoutSpec::default(), false).unwrap();

        assert!(!outcome.applied);
        assert_eq!(backend.calls(), ["blackout_plan"]);
    }

    #[test]
    fn blackout_with_apply_calls_backend_mutation() {
        let backend = RecordingBackend::default();
        let outcome = run_blackout(&backend, BlackoutSpec::default(), true).unwrap();

        assert!(outcome.applied);
        assert_eq!(
            backend.calls(),
            ["blackout_plan", "ensure_supported", "apply_blackout"]
        );
    }

    #[test]
    fn restore_without_apply_does_not_mutate_backend() {
        let backend = RecordingBackend::default();
        let outcome = run_restore(&backend, false).unwrap();

        assert!(!outcome.applied);
        assert_eq!(backend.calls(), ["restore_plan"]);
    }

    #[test]
    fn restore_with_apply_calls_backend_mutation() {
        let backend = RecordingBackend::default();
        let outcome = run_restore(&backend, true).unwrap();

        assert!(outcome.applied);
        assert_eq!(
            backend.calls(),
            ["restore_plan", "ensure_supported", "restore"]
        );
    }

    #[test]
    fn hard_apply_requires_confirmation() {
        let spec = BlackoutSpec {
            mode: BlackoutMode::Hard,
            allowlist: Allowlist::default(),
        };

        assert!(validate_blackout_spec(&spec, true, false).is_err());
        assert!(validate_blackout_spec(&spec, true, true).is_ok());
    }

    #[test]
    fn allowlist_requires_at_least_one_port() {
        let spec = BlackoutSpec {
            mode: BlackoutMode::Allowlist,
            allowlist: Allowlist::default(),
        };

        assert!(validate_blackout_spec(&spec, false, false).is_err());
    }
}
