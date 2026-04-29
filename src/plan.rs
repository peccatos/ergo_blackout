#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackoutPlan {
    pub steps: Vec<String>,
    pub nft_ruleset: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan {
    pub steps: Vec<String>,
    pub nft_command: Vec<String>,
}
