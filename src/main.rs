mod backend;
mod cli;
mod plan;
mod probe;

use anyhow::Result;
use backend::{linux_nft::LinuxNftBackend, BlackoutBackend};
use clap::Parser;
use cli::{Cli, CliCommand};
use plan::{BlackoutPlan, RestorePlan};
use probe::SystemProbe;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Blackout { apply } => handle_blackout(apply),
        CliCommand::Status => handle_status(),
        CliCommand::Restore { apply } => handle_restore(apply),
        CliCommand::DryRun => handle_dry_run(),
    }
}

fn handle_blackout(apply: bool) -> Result<()> {
    let backend = LinuxNftBackend::new();
    let outcome = run_blackout(&backend, apply)?;

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
    let backend_status = backend.status()?;

    print_probe(&probe);
    println!();
    println!("ergo blackout backend:");
    println!("- backend: {}", backend.name());
    println!("- supported: {}", yes_no(backend_status.supported));
    println!("- active table: {}", yes_no(backend_status.active));
    println!("- detail: {}", backend_status.detail);

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
    let outcome = run_blackout(&backend, false)?;

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

fn run_blackout(backend: &impl BlackoutBackend, apply: bool) -> Result<BlackoutOutcome> {
    let plan = backend.blackout_plan();

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
    for step in &plan.steps {
        println!("- {step}");
    }
    println!();
    println!("nft ruleset:");
    println!("{}", plan.nft_ruleset);
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
        let outcome = run_blackout(&backend, false).unwrap();

        assert!(!outcome.applied);
        assert_eq!(backend.calls(), ["blackout_plan"]);
    }

    #[test]
    fn blackout_with_apply_calls_backend_mutation() {
        let backend = RecordingBackend::default();
        let outcome = run_blackout(&backend, true).unwrap();

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
}
