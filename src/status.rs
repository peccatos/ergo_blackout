use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlackoutStatus {
    Inactive,
    ActiveVerified,
    ActiveDrifted(String),
    Unknown(String),
}

impl fmt::Display for BlackoutStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inactive => write!(f, "inactive"),
            Self::ActiveVerified => write!(f, "verified"),
            Self::ActiveDrifted(reason) => write!(f, "drifted: {reason}"),
            Self::Unknown(reason) => write!(f, "unknown: {reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub status: BlackoutStatus,
    pub checks: Vec<VerificationCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}
