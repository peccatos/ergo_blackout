use std::{fmt, str::FromStr};

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlackoutMode {
    Soft,
    Hard,
    Allowlist,
}

impl Default for BlackoutMode {
    fn default() -> Self {
        Self::Soft
    }
}

impl fmt::Display for BlackoutMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Soft => write!(f, "soft"),
            Self::Hard => write!(f, "hard"),
            Self::Allowlist => write!(f, "allowlist"),
        }
    }
}

impl FromStr for BlackoutMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "soft" => Ok(Self::Soft),
            "hard" => Ok(Self::Hard),
            "allowlist" => Ok(Self::Allowlist),
            _ => bail!("unsupported blackout mode `{value}`; expected soft, hard, or allowlist"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowlist {
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackoutSpec {
    pub mode: BlackoutMode,
    pub allowlist: Allowlist,
}

impl Default for BlackoutSpec {
    fn default() -> Self {
        Self {
            mode: BlackoutMode::Soft,
            allowlist: Allowlist::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackoutPlan {
    pub spec: BlackoutSpec,
    pub steps: Vec<String>,
    pub nft_ruleset: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan {
    pub steps: Vec<String>,
    pub nft_command: Vec<String>,
}
