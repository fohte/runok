#![allow(
    dead_code,
    reason = "shared test helper: not all variants are used in every test binary"
)]

use runok::rules::rule_engine::Action;

/// Test-only enum for parameterizing expected actions in `#[case]` attributes.
#[derive(Debug)]
pub enum ExpectedAction {
    Allow,
    Deny,
    Ask,
    Default,
}

impl ExpectedAction {
    pub fn assert_matches(&self, actual: &Action) {
        match self {
            ExpectedAction::Allow => {
                assert_eq!(*actual, Action::Allow, "expected Allow, got {:?}", actual)
            }
            ExpectedAction::Deny => assert!(
                matches!(actual, Action::Deny(_)),
                "expected Deny, got {:?}",
                actual
            ),
            ExpectedAction::Ask => assert!(
                matches!(actual, Action::Ask(_)),
                "expected Ask, got {:?}",
                actual
            ),
            ExpectedAction::Default => assert_eq!(
                *actual,
                Action::Default,
                "expected Default, got {:?}",
                actual
            ),
        }
    }
}
