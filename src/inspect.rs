use std::process::Command;

use anyhow::{Context, Result};

use crate::{classify::classify_connection, probe::SystemProbe};

#[derive(Debug)]
pub struct InspectReport {
    pub system: SystemSection,
    pub network: NetworkSection,
    pub listening: Vec<SocketRow>,
    pub active_connections: Vec<SocketRow>,
    pub routes: String,
}

#[derive(Debug)]
pub struct SystemSection {
    pub os: &'static str,
    pub kernel: String,
    pub is_root: bool,
    pub probe: SystemProbe,
}

#[derive(Debug)]
pub struct NetworkSection {
    pub interfaces: Vec<String>,
}

#[derive(Debug)]
pub struct SocketRow {
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub process: String,
    pub class: &'static str,
}

pub fn inspect_system() -> Result<InspectReport> {
    let probe = SystemProbe::current();
    let kernel = command_stdout("uname", &["-r"]).unwrap_or_else(|_| "unknown".to_string());
    let is_root = command_stdout("id", &["-u"])
        .map(|uid| uid.trim() == "0")
        .unwrap_or(false);
    let interfaces = command_stdout("ip", &["-o", "link", "show"])
        .map(|out| parse_interfaces(&out))
        .unwrap_or_else(|err| vec![format!("unavailable: {err}")]);
    let listening = command_stdout("ss", &["-ltnup"])
        .map(|out| parse_ss_rows(&out))
        .unwrap_or_default();
    let active_connections = command_stdout("ss", &["-tunap"])
        .map(|out| parse_ss_rows(&out))
        .unwrap_or_default();
    let routes =
        command_stdout("ip", &["route"]).unwrap_or_else(|err| format!("unavailable: {err}"));

    Ok(InspectReport {
        system: SystemSection {
            os: probe.target_os,
            kernel,
            is_root,
            probe,
        },
        network: NetworkSection { interfaces },
        listening,
        active_connections,
        routes,
    })
}

fn command_stdout(command: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .with_context(|| format!("failed to run `{command}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!("`{command}` exited with {}; {stderr}", output.status);
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn parse_interfaces(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(": ");
            parts.next()?;
            parts
                .next()
                .map(|name| name.split('@').next().unwrap_or(name).to_string())
        })
        .collect()
}

fn parse_ss_rows(output: &str) -> Vec<SocketRow> {
    output.lines().skip(1).filter_map(parse_ss_row).collect()
}

fn parse_ss_row(line: &str) -> Option<SocketRow> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 5 {
        return None;
    }

    let protocol = cols[0].to_string();
    let local = cols[4].to_string();
    let remote = cols.get(5).copied().unwrap_or("*:*").to_string();
    let process = cols.get(6..).map(|rest| rest.join(" ")).unwrap_or_default();
    let local_port = endpoint_port(&local);
    let remote_port = endpoint_port(&remote);
    let class = classify_connection(local_port, remote_port);

    Some(SocketRow {
        protocol,
        local,
        remote,
        process,
        class,
    })
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    let clean = endpoint.trim_matches(|ch| ch == '[' || ch == ']');
    let port = clean.rsplit_once(':')?.1.trim_matches('*');
    port.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_interface_names() {
        let output = "1: lo: <LOOPBACK>\n2: eth0@if3: <BROADCAST>";
        assert_eq!(parse_interfaces(output), ["lo", "eth0"]);
    }

    #[test]
    fn parses_ss_row_and_classifies_port() {
        let row = parse_ss_row("tcp ESTAB 0 0 192.168.1.10:55122 142.250.1.1:443 users:(\"curl\")")
            .unwrap();

        assert_eq!(row.protocol, "tcp");
        assert_eq!(row.class, "https");
    }
}
