mod compound_command_evaluation;
mod config_to_rule_evaluation;
mod optional_notation_and_path_ref;
mod when_clause_rules;
mod wrapper_recursive_evaluation;

use std::collections::HashMap;
use std::path::PathBuf;

use rstest::fixture;
use runok::rules::rule_engine::{Action, EvalContext};

#[fixture]
fn empty_context() -> EvalContext {
    EvalContext {
        env: HashMap::new(),
        cwd: PathBuf::from("/tmp"),
    }
}

type ActionAssertion = fn(&Action);

fn assert_allow(actual: &Action) {
    assert_eq!(*actual, Action::Allow, "expected Allow, got {:?}", actual);
}

fn assert_deny(actual: &Action) {
    assert!(
        matches!(actual, Action::Deny(_)),
        "expected Deny, got {:?}",
        actual
    );
}

fn assert_ask(actual: &Action) {
    assert!(
        matches!(actual, Action::Ask(_)),
        "expected Ask, got {:?}",
        actual
    );
}

fn assert_default(actual: &Action) {
    assert_eq!(
        *actual,
        Action::Default,
        "expected Default, got {:?}",
        actual
    );
}
