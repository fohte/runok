use super::*;
use rstest::rstest;

// ========================================
// FlagWithValue matching (order-independent)
// ========================================

#[rstest]
#[case::flag_before_arg("curl -X|--request POST *", "curl -X POST https://example.com", true)]
#[case::flag_after_arg("curl -X|--request POST *", "curl https://example.com -X POST", true)]
#[case::long_alias(
    "curl -X|--request POST *",
    "curl --request POST https://example.com",
    true
)]
#[case::wrong_value("curl -X|--request POST *", "curl -X GET https://example.com", false)]
#[case::missing_flag("curl -X|--request POST *", "curl https://example.com", false)]
#[case::wildcard_value("curl -X|--request * *", "curl -X DELETE https://example.com", true)]
#[case::bare_flag_before_arg("gh api -X GET *", "gh api -X GET repos/fohte/runok", true)]
#[case::bare_flag_after_arg("gh api -X GET *", "gh api repos/fohte/runok -X GET", true)]
#[case::bare_flag_wrong_value("gh api -X GET *", "gh api -X POST repos/fohte/runok", false)]
#[case::bare_flag_missing("gh api -X GET *", "gh api repos/fohte/runok", false)]
fn flag_with_value_matching(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected
    );
}

// ========================================
// <flag:name> matching at the matcher level
// ========================================

/// Build a Definitions whose only flag group is the field-flag set used by
/// the matcher-level `<flag:name>` tests below.
fn field_flag_defs() -> Definitions {
    let mut defs = Definitions {
        flag_groups: Some(HashMap::from([(
            "field-flag".to_string(),
            "-f|-F|--field|--raw-field *".to_string(),
        )])),
        ..Definitions::default()
    };
    defs.resolve_flag_groups();
    defs
}

#[rstest]
#[case::short_space(
    "gh api graphql <flag:field-flag> *",
    "gh api graphql -f query=hello",
    true
)]
#[case::long_space(
    "gh api graphql <flag:field-flag> *",
    "gh api graphql --raw-field query=hello",
    true
)]
#[case::long_equals(
    "gh api graphql <flag:field-flag> *",
    "gh api graphql --raw-field=query=hello",
    true
)]
#[case::no_field_flag(
    "gh api graphql <flag:field-flag> *",
    "gh api graphql query=hello",
    false
)]
fn flag_group_ref_matching(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
) {
    // Without the test helper learning about FlagGroupRef, the schema would
    // miss `-f`/`-F`/`--field`/`--raw-field` and `parse_command` would
    // mis-parse `-f query=hello` as a boolean flag plus a positional
    // argument, breaking these cases. This test would have failed before
    // the helper was taught about FlagGroupRef.
    assert_eq!(
        check_match(pattern_str, command_str, &field_flag_defs()),
        expected
    );
}
