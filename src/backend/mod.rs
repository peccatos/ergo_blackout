use anyhow::Result;

use crate::plan::{BlackoutPlan, RestorePlan};

pub mod linux_nft;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendStatus {
    pub supported: bool,
    pub active: bool,
    pub detail: String,
}

pub trait BlackoutBackend {
    fn name(&self) -> &'static str;
    fn ensure_supported(&self) -> Result<()>;
    fn status(&self) -> Result<BackendStatus>;
    fn blackout_plan(&self) -> BlackoutPlan;
    fn apply_blackout(&self, plan: &BlackoutPlan) -> Result<()>;
    fn restore_plan(&self) -> RestorePlan;
    fn restore(&self, plan: &RestorePlan) -> Result<()>;
}

#[cfg(test)]
pub mod fake {
    use std::cell::RefCell;

    use anyhow::Result;

    use crate::plan::{BlackoutPlan, RestorePlan};

    use super::{BackendStatus, BlackoutBackend};

    #[derive(Debug, Default)]
    pub struct RecordingBackend {
        calls: RefCell<Vec<&'static str>>,
    }

    impl RecordingBackend {
        pub fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl BlackoutBackend for RecordingBackend {
        fn name(&self) -> &'static str {
            "recording"
        }

        fn ensure_supported(&self) -> Result<()> {
            self.calls.borrow_mut().push("ensure_supported");
            Ok(())
        }

        fn status(&self) -> Result<BackendStatus> {
            self.calls.borrow_mut().push("status");
            Ok(BackendStatus {
                supported: true,
                active: false,
                detail: "fake backend".to_string(),
            })
        }

        fn blackout_plan(&self) -> BlackoutPlan {
            self.calls.borrow_mut().push("blackout_plan");
            BlackoutPlan {
                steps: vec!["fake blackout plan".to_string()],
                nft_ruleset: "table inet ergo_blackout {}".to_string(),
            }
        }

        fn apply_blackout(&self, _plan: &BlackoutPlan) -> Result<()> {
            self.calls.borrow_mut().push("apply_blackout");
            Ok(())
        }

        fn restore_plan(&self) -> RestorePlan {
            self.calls.borrow_mut().push("restore_plan");
            RestorePlan {
                steps: vec!["fake restore plan".to_string()],
                nft_command: vec![
                    "nft".to_string(),
                    "delete".to_string(),
                    "table".to_string(),
                    "inet".to_string(),
                    "ergo_blackout".to_string(),
                ],
            }
        }

        fn restore(&self, _plan: &RestorePlan) -> Result<()> {
            self.calls.borrow_mut().push("restore");
            Ok(())
        }
    }
}
