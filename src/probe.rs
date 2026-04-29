use std::{env, path::Path};

#[derive(Debug)]
pub struct SystemProbe {
    pub target_os: &'static str,
    pub has_nft: bool,
    pub has_iptables: bool,
    pub has_ufw: bool,
    pub has_ss: bool,
    pub has_ip: bool,
    pub has_resolvectl: bool,
    pub has_resolv_conf: bool,
}

impl SystemProbe {
    pub fn current() -> Self {
        Self {
            target_os: env::consts::OS,
            has_nft: command_exists("nft"),
            has_iptables: command_exists("iptables"),
            has_ufw: command_exists("ufw"),
            has_ss: command_exists("ss"),
            has_ip: command_exists("ip"),
            has_resolvectl: command_exists("resolvectl"),
            has_resolv_conf: Path::new("/etc/resolv.conf").exists(),
        }
    }

    pub fn preferred_firewall_backend(&self) -> &'static str {
        if self.has_nft {
            "nft"
        } else if self.has_iptables {
            "iptables"
        } else if self.has_ufw {
            "ufw"
        } else {
            "none detected"
        }
    }
}

pub fn command_exists(name: &str) -> bool {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .any(|path| path.join(name).is_file())
}
