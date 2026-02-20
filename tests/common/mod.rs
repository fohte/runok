use runok::rules::rule_engine::Action;

/// Function pointer type for asserting expected actions in `#[case]` attributes.
pub type ActionAssertion = fn(&Action);

pub fn assert_allow(actual: &Action) {
    assert_eq!(*actual, Action::Allow, "expected Allow, got {:?}", actual);
}

pub fn assert_deny(actual: &Action) {
    assert!(
        matches!(actual, Action::Deny(_)),
        "expected Deny, got {:?}",
        actual
    );
}

pub fn assert_ask(actual: &Action) {
    assert!(
        matches!(actual, Action::Ask(_)),
        "expected Ask, got {:?}",
        actual
    );
}

pub fn assert_default(actual: &Action) {
    assert_eq!(
        *actual,
        Action::Default,
        "expected Default, got {:?}",
        actual
    );
}
