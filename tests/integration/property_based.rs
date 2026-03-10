use super::*;

use proptest::prelude::*;
use runok::config::parse_config;
use runok::rules::rule_engine::{Action, evaluate_command, evaluate_compound};

// ========================================
// Basic part strategies
// ========================================

fn arb_cmd_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("git".to_string()),
        Just("rm".to_string()),
        Just("curl".to_string()),
        Just("echo".to_string()),
        Just("npm".to_string()),
        Just("ls".to_string()),
    ]
}

fn arb_flag() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("--force".to_string()),
        Just("-f".to_string()),
        Just("--recursive".to_string()),
        Just("-r".to_string()),
        Just("--sort".to_string()),
        Just("-X".to_string()),
        Just("--output".to_string()),
        Just("-v".to_string()),
        Just("--verbose".to_string()),
        Just("--help".to_string()),
        "[a-z]{1,6}".prop_map(|s| format!("--{s}")),
    ]
}

fn arb_positional() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("foo".to_string()),
        Just("bar".to_string()),
        Just("origin".to_string()),
        Just("main".to_string()),
        Just("/tmp/data".to_string()),
        Just(".".to_string()),
        Just("https://example.com".to_string()),
        "[a-zA-Z0-9._/-]{1,15}",
    ]
}

/// Positional values that never start with `-` (safe for =joined flag values)
fn arb_safe_positional() -> impl Strategy<Value = String> {
    arb_positional().prop_filter("must not start with -", |s| !s.starts_with('-'))
}

fn arb_flag_value() -> impl Strategy<Value = String> {
    prop_oneof![arb_positional(), arb_flag(),]
}

// ========================================
// Glob pattern strategy
// ========================================

/// Generates a (glob_pattern, matching_token, non_matching_token) triple.
/// Segments are randomly ordered literals and `*`, allowing patterns like
/// `*suffix`, `pre**suf`, `*mid*`, `lit*lit*`, etc.
fn arb_glob_pattern_and_match() -> impl Strategy<Value = (String, String, String)> {
    // Each segment is either a literal [a-z] chunk or a `*`.
    // We generate a random sequence, requiring at least one `*` and one literal.
    // The literal requirement ensures we can construct a non-matching token by
    // injecting a digit into one literal position (digits never appear in [a-z]).
    proptest::collection::vec(
        prop_oneof![
            // literal segment: (pattern_part, match_part, is_literal)
            "[a-z]{2,4}".prop_map(|s| (s.clone(), s, true)),
            // glob segment: * matches random filler
            "[a-z]{0,3}".prop_map(|filler| ("*".to_string(), filler, false)),
        ],
        2..=6,
    )
    .prop_filter("need at least one * and one literal", |segs| {
        segs.iter().any(|(_, _, is_lit)| *is_lit) && segs.iter().any(|(_, _, is_lit)| !*is_lit)
    })
    .prop_map(|segments| {
        let pattern: String = segments.iter().map(|(p, _, _)| p.as_str()).collect();
        let matching: String = segments.iter().map(|(_, m, _)| m.as_str()).collect();

        // Non-matching: replace ALL characters in ALL literal segments with '0'.
        // Since literals use [a-z] and '0' never appears in [a-z], no literal
        // from the pattern can match anywhere in the non-matching token, even
        // when `*` segments shift the matching window.
        let non_matching: String = segments
            .iter()
            .map(|(_, m, is_lit)| {
                if *is_lit {
                    "0".repeat(m.len())
                } else {
                    m.clone()
                }
            })
            .collect();

        (pattern, matching, non_matching)
    })
    .prop_filter("matching and non-matching must differ", |(_, m, nm)| {
        m != nm
    })
}

// ========================================
// Command generation strategies
// ========================================

fn arb_simple_command() -> impl Strategy<Value = String> {
    (
        arb_cmd_name(),
        proptest::collection::vec(arb_flag_value(), 0..=4),
    )
        .prop_map(|(name, tokens)| build_command(&name, &tokens))
}

fn arb_compound_command() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec(arb_simple_command(), 2..=4),
        proptest::collection::vec(arb_operator(), 1..=3),
    )
        .prop_map(|(cmds, ops)| {
            let mut result = cmds[0].clone();
            for (i, cmd) in cmds.iter().enumerate().skip(1) {
                let op = &ops[i % ops.len()];
                result = format!("{result} {op} {cmd}");
            }
            result
        })
}

/// Generate a random pattern string containing various syntax elements.
/// Used by Property E to exercise the parser with diverse patterns.
fn arb_rich_pattern() -> impl Strategy<Value = String> {
    (
        arb_cmd_name(),
        proptest::collection::vec(
            prop_oneof![
                // Wildcard
                Just("*".to_string()),
                // Positional literal
                arb_positional(),
                // Flag (becomes Alternation in parser)
                arb_flag(),
                // Glob literal (random structure from arb_glob_pattern_and_match)
                arb_glob_pattern_and_match().prop_map(|(pat, _, _)| pat),
                // Negation
                arb_positional().prop_map(|s| format!("!{s}")),
                // Flag negation
                arb_flag().prop_map(|f| format!("!{f}")),
                // Optional
                arb_flag().prop_map(|f| format!("[{f}]")),
                // Alternation
                (arb_positional(), arb_positional()).prop_map(|(a, b)| format!("{a}|{b}")),
                // QuotedLiteral
                arb_positional().prop_map(|s| format!("\"{s}\"")),
            ],
            0..=4,
        ),
    )
        .prop_map(|(cmd, tokens)| {
            if tokens.is_empty() {
                cmd
            } else {
                format!("{cmd} {}", tokens.join(" "))
            }
        })
}

// ========================================
// Helper functions
// ========================================

/// Build a command string from tokens using shlex for proper quoting
fn build_command(cmd_name: &str, tokens: &[String]) -> String {
    let mut parts = vec![cmd_name.to_string()];
    parts.extend(tokens.iter().cloned());
    shlex::try_join(parts.iter().map(|s| s.as_str())).unwrap_or_else(|_| parts.join(" "))
}

/// Build a YAML config with a single rule
fn build_yaml_config(action: &str, pattern: &str) -> String {
    let escaped = pattern.replace('\'', "''");
    indoc::formatdoc! {"
        rules:
          - {action}: '{escaped}'
    "}
}

fn arb_operator() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("&&".to_string()),
        Just("||".to_string()),
        Just("|".to_string()),
        Just(";".to_string()),
    ]
}

/// Extract a comparable action variant string, ignoring internal details
fn action_variant(action: &Action) -> &'static str {
    match action {
        Action::Allow => "Allow",
        Action::Deny(_) => "Deny",
        Action::Ask(_) => "Ask",
    }
}

// ========================================
// Property A1: Wildcard subsumption
// `{cmd} *` matches any command with the same name, regardless of arguments
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_wildcard_subsumes_any_args(
        cmd_name in arb_cmd_name(),
        tokens in proptest::collection::vec(arb_flag_value(), 0..=5),
    ) {
        let pattern = format!("{cmd_name} *");
        let command = build_command(&cmd_name, &tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        let msg = format!("'{cmd_name} *' should match any args: command={command:?}");
        prop_assert_eq!(result.action, Action::Allow, "{}", msg);
    }

    #[test]
    fn prop_wildcard_does_not_match_different_command(
        cmd_name in arb_cmd_name(),
        other_cmd in arb_cmd_name(),
        tokens in proptest::collection::vec(arb_flag_value(), 0..=3),
    ) {
        prop_assume!(cmd_name != other_cmd);
        let pattern = format!("{cmd_name} *");
        let command = build_command(&other_cmd, &tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        let msg = format!("'{cmd_name} *' should NOT match '{other_cmd}' command: command={command:?}");
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "{}", msg
        );
    }
}

// ========================================
// Property A2: Literal strictness
// `{cmd} {literal}` matches exactly and rejects different literals
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_literal_exact_match(
        cmd_name in arb_cmd_name(),
        literal in arb_positional(),
    ) {
        let pattern = format!("{cmd_name} {literal}");
        let command = build_command(&cmd_name, std::slice::from_ref(&literal));
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "exact literal should match: pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_literal_rejects_different(
        cmd_name in arb_cmd_name(),
        literal in arb_positional(),
        other_literal in arb_positional(),
    ) {
        prop_assume!(literal != other_literal);
        let pattern = format!("{cmd_name} {literal}");
        let command = build_command(&cmd_name, std::slice::from_ref(&other_literal));
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "literal should reject different value: pattern={:?} command={:?}",
            pattern, command
        );
    }
}

// ========================================
// Property A3: Flag negation correctness
// `{cmd} !{flag} *` rejects when flag present, allows when absent
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_flag_negation_rejects_when_present(
        cmd_name in arb_cmd_name(),
        negated_flag in arb_flag(),
        positionals in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} !{negated_flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Command with the negated flag present
        let mut tokens = positionals;
        tokens.push(negated_flag.clone());
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "flag negation should reject when flag present: pattern={:?} command={:?}",
            pattern, command
        );
    }

    #[test]
    fn prop_flag_negation_allows_when_absent(
        cmd_name in arb_cmd_name(),
        negated_flag in arb_flag(),
        positionals in proptest::collection::vec(arb_safe_positional(), 0..=3),
    ) {
        let pattern = format!("{cmd_name} !{negated_flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Command without the negated flag (positionals only, no flags)
        let command = build_command(&cmd_name, &positionals);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "flag negation should allow when flag absent: pattern={:?} command={:?}",
            pattern, command);
    }
}

// ========================================
// Property A4: Value negation correctness (position-dependent)
// `{cmd} !{value} *` rejects when first token matches, allows otherwise
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_value_negation_rejects_matching_head(
        cmd_name in arb_cmd_name(),
        negated in arb_safe_positional(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} !{negated} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Command with the negated value at head position
        let mut tokens = vec![negated.clone()];
        tokens.extend(suffix);
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "value negation should reject matching head: pattern={:?} command={:?}",
            pattern, command
        );
    }

    #[test]
    fn prop_value_negation_allows_different_head(
        cmd_name in arb_cmd_name(),
        negated in arb_safe_positional(),
        different in arb_safe_positional(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        prop_assume!(negated != different);
        let pattern = format!("{cmd_name} !{negated} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Command with a different value at head position
        let mut tokens = vec![different.clone()];
        tokens.extend(suffix);
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "value negation should allow different head: pattern={:?} command={:?}",
            pattern, command);
    }
}

// ========================================
// Property A5: Alternation correctness
// `{cmd} {a|b|c} *` matches when head is in set, rejects otherwise
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_alternation_matches_member(
        cmd_name in arb_cmd_name(),
        alternatives in proptest::collection::vec(arb_safe_positional(), 2..=4),
        chosen_idx in 0..4usize,
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let idx = chosen_idx % alternatives.len();
        let chosen = &alternatives[idx];
        let pattern = format!("{cmd_name} {} *", alternatives.join("|"));
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens = vec![chosen.clone()];
        tokens.extend(suffix);
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "alternation should match member: pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_alternation_rejects_non_member(
        cmd_name in arb_cmd_name(),
        alternatives in proptest::collection::vec(arb_safe_positional(), 2..=4),
        outsider in arb_safe_positional(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        prop_assume!(!alternatives.contains(&outsider));
        let pattern = format!("{cmd_name} {} *", alternatives.join("|"));
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens = vec![outsider.clone()];
        tokens.extend(suffix);
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "alternation should reject non-member: pattern={:?} command={:?}",
            pattern, command
        );
    }
}

// ========================================
// Property A6: Optional correctness
// `{cmd} [{flag}] *` matches with or without the flag
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_optional_matches_with_flag(
        cmd_name in arb_cmd_name(),
        opt_flag in arb_flag(),
        suffix in proptest::collection::vec(arb_positional(), 0..=3),
    ) {
        let pattern = format!("{cmd_name} [{opt_flag}] *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens = vec![opt_flag.clone()];
        tokens.extend(suffix);
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "optional should match with flag: pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_optional_matches_without_flag(
        cmd_name in arb_cmd_name(),
        opt_flag in arb_flag(),
        suffix in proptest::collection::vec(arb_positional(), 0..=3),
    ) {
        let pattern = format!("{cmd_name} [{opt_flag}] *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Command without the optional flag
        let command = build_command(&cmd_name, &suffix);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "optional should match without flag: pattern={:?} command={:?}", pattern, command);
    }
}

// ========================================
// Property A7: Glob literal correctness
// `{cmd} {glob}` matches tokens fitting the glob, rejects others
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_glob_literal_matches(
        cmd_name in arb_cmd_name(),
        (glob_pat, matching_tok, _non_matching) in arb_glob_pattern_and_match(),
    ) {
        let pattern = format!("{cmd_name} {glob_pat}");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let command = build_command(&cmd_name, std::slice::from_ref(&matching_tok));
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "glob should match: pattern={:?} token={:?}", glob_pat, matching_tok);
    }

    #[test]
    fn prop_glob_literal_rejects_non_match(
        cmd_name in arb_cmd_name(),
        (glob_pat, _matching, non_matching) in arb_glob_pattern_and_match(),
    ) {
        let pattern = format!("{cmd_name} {glob_pat}");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let command = build_command(&cmd_name, std::slice::from_ref(&non_matching));
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "glob should reject non-match: pattern={:?} token={:?}", glob_pat, non_matching
        );
    }
}

// ========================================
// Property A8: QuotedLiteral correctness
// Quoted patterns suppress glob expansion
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_quoted_literal_exact_match(
        cmd_name in arb_cmd_name(),
        value in arb_positional(),
    ) {
        // "value" in pattern matches the exact string
        let pattern = format!("{cmd_name} \"{value}\"");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let command = build_command(&cmd_name, std::slice::from_ref(&value));
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "quoted literal should match exactly: pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_quoted_literal_suppresses_glob(
        cmd_name in arb_cmd_name(),
        base in arb_safe_positional(),
        extra in arb_safe_positional(),
    ) {
        // "base*" must NOT match "base<extra>" (glob suppressed)
        let quoted_val = format!("{base}*");
        let pattern = format!("{cmd_name} \"{quoted_val}\"");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let non_matching_val = format!("{base}{extra}");
        prop_assume!(non_matching_val != quoted_val);
        let command = build_command(&cmd_name, &[non_matching_val]);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "quoted literal should NOT glob-expand: pattern={:?} command={:?}",
            pattern, command
        );
    }
}

// ========================================
// Property B: Flag token position independence
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_flag_position_independence(
        cmd_name in arb_cmd_name(),
        flag in arb_flag(),
        prefix in proptest::collection::vec(arb_positional(), 0..=2),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // flag at start
        let mut tokens_start = vec![flag.clone()];
        tokens_start.extend(prefix.iter().cloned());
        tokens_start.extend(suffix.iter().cloned());
        let cmd_start = build_command(&cmd_name, &tokens_start);
        let result_start = evaluate_command(&config, &cmd_start, &ctx).unwrap();

        // flag at end
        let mut tokens_end = prefix.clone();
        tokens_end.extend(suffix.iter().cloned());
        tokens_end.push(flag.clone());
        let cmd_end = build_command(&cmd_name, &tokens_end);
        let result_end = evaluate_command(&config, &cmd_end, &ctx).unwrap();

        // flag in middle
        let mut tokens_mid = prefix;
        tokens_mid.push(flag.clone());
        tokens_mid.extend(suffix);
        let cmd_mid = build_command(&cmd_name, &tokens_mid);
        let result_mid = evaluate_command(&config, &cmd_mid, &ctx).unwrap();

        prop_assert_eq!(&result_start.action, &result_end.action,
            "flag position should not matter: start={:?} end={:?} flag={:?}",
            cmd_start, cmd_end, flag);
        prop_assert_eq!(&result_start.action, &result_mid.action,
            "flag position should not matter: start={:?} mid={:?} flag={:?}",
            cmd_start, cmd_mid, flag);
    }

    #[test]
    fn prop_flag_with_value_position_independence(
        cmd_name in arb_cmd_name(),
        flag in arb_flag(),
        value in arb_positional(),
        prefix in proptest::collection::vec(arb_positional(), 0..=2),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {flag} * *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // flag+value at start
        let mut tokens_start = vec![flag.clone(), value.clone()];
        tokens_start.extend(prefix.iter().cloned());
        tokens_start.extend(suffix.iter().cloned());
        let cmd_start = build_command(&cmd_name, &tokens_start);
        let result_start = evaluate_command(&config, &cmd_start, &ctx).unwrap();

        // flag+value at end
        let mut tokens_end = prefix.clone();
        tokens_end.extend(suffix.iter().cloned());
        tokens_end.push(flag.clone());
        tokens_end.push(value.clone());
        let cmd_end = build_command(&cmd_name, &tokens_end);
        let result_end = evaluate_command(&config, &cmd_end, &ctx).unwrap();

        // flag+value in middle
        let mut tokens_mid = prefix;
        tokens_mid.push(flag.clone());
        tokens_mid.push(value.clone());
        tokens_mid.extend(suffix);
        let cmd_mid = build_command(&cmd_name, &tokens_mid);
        let result_mid = evaluate_command(&config, &cmd_mid, &ctx).unwrap();

        prop_assert_eq!(&result_start.action, &result_end.action,
            "FlagWithValue position should not matter: start={:?} end={:?}",
            cmd_start, cmd_end);
        prop_assert_eq!(&result_start.action, &result_mid.action,
            "FlagWithValue position should not matter: start={:?} mid={:?}",
            cmd_start, cmd_mid);
    }

    #[test]
    fn prop_flag_negation_position_independence(
        cmd_name in arb_cmd_name(),
        negated_flag in arb_flag(),
        other_flag in arb_flag(),
        positionals in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        prop_assume!(negated_flag != other_flag);

        let pattern = format!("{cmd_name} !{negated_flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // With the negated flag at start
        let mut tokens_start = vec![negated_flag.clone()];
        tokens_start.extend(positionals.iter().cloned());
        let cmd_start = build_command(&cmd_name, &tokens_start);
        let result_start = evaluate_command(&config, &cmd_start, &ctx).unwrap();

        // With the negated flag at end
        let mut tokens_end = positionals.clone();
        tokens_end.push(negated_flag.clone());
        let cmd_end = build_command(&cmd_name, &tokens_end);
        let result_end = evaluate_command(&config, &cmd_end, &ctx).unwrap();

        prop_assert_eq!(&result_start.action, &result_end.action,
            "flag negation position should not matter: start={:?} end={:?}",
            cmd_start, cmd_end);
    }

    /// FlagWithValue with a glob value pattern: position should not matter.
    #[test]
    fn prop_flag_with_glob_value_position_independence(
        cmd_name in arb_cmd_name(),
        flag in arb_flag(),
        (glob_pat, matching_tok, _) in arb_glob_pattern_and_match(),
        prefix in proptest::collection::vec(arb_safe_positional(), 0..=2),
        suffix in proptest::collection::vec(arb_safe_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {flag} {glob_pat} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // flag+value at start
        let mut tokens_start = vec![flag.clone(), matching_tok.clone()];
        tokens_start.extend(prefix.iter().cloned());
        tokens_start.extend(suffix.iter().cloned());
        let cmd_start = build_command(&cmd_name, &tokens_start);
        let result_start = evaluate_command(&config, &cmd_start, &ctx).unwrap();

        // flag+value at end
        let mut tokens_end = prefix.clone();
        tokens_end.extend(suffix.iter().cloned());
        tokens_end.push(flag.clone());
        tokens_end.push(matching_tok.clone());
        let cmd_end = build_command(&cmd_name, &tokens_end);
        let result_end = evaluate_command(&config, &cmd_end, &ctx).unwrap();

        prop_assert_eq!(&result_start.action, &result_end.action,
            "FlagWithValue glob position should not matter: start={:?} end={:?}",
            cmd_start, cmd_end);
    }
}

// ========================================
// Property C: Equals-sign equivalence
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_equals_equivalence_flag_with_wildcard_value(
        cmd_name in arb_cmd_name(),
        flag in arb_flag(),
        value in arb_positional(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {flag} * *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens_space = vec![flag.clone(), value.clone()];
        tokens_space.extend(suffix.iter().cloned());
        let cmd_space = build_command(&cmd_name, &tokens_space);
        let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

        let mut tokens_eq = vec![format!("{flag}={value}")];
        tokens_eq.extend(suffix);
        let cmd_eq = build_command(&cmd_name, &tokens_eq);
        let result_eq = evaluate_command(&config, &cmd_eq, &ctx).unwrap();

        prop_assert_eq!(&result_space.action, &result_eq.action,
            "equals equivalence failed: space={:?} eq={:?}", cmd_space, cmd_eq);
    }

    #[test]
    fn prop_equals_equivalence_flag_with_fixed_value(
        cmd_name in arb_cmd_name(),
        flag in arb_flag(),
        value in arb_safe_positional(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {flag} {value} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens_space = vec![flag.clone(), value.clone()];
        tokens_space.extend(suffix.iter().cloned());
        let cmd_space = build_command(&cmd_name, &tokens_space);
        let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

        let mut tokens_eq = vec![format!("{flag}={value}")];
        tokens_eq.extend(suffix);
        let cmd_eq = build_command(&cmd_name, &tokens_eq);
        let result_eq = evaluate_command(&config, &cmd_eq, &ctx).unwrap();

        prop_assert_eq!(&result_space.action, &result_eq.action,
            "fixed value equals equivalence failed: space={:?} eq={:?}", cmd_space, cmd_eq);
    }

    #[test]
    fn prop_equals_equivalence_optional_flag_with_value(
        cmd_name in arb_cmd_name(),
        flag in arb_flag(),
        value in arb_positional(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} [{flag} {value}] *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens_space = vec![flag.clone(), value.clone()];
        tokens_space.extend(suffix.iter().cloned());
        let cmd_space = build_command(&cmd_name, &tokens_space);
        let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

        let mut tokens_eq = vec![format!("{flag}={value}")];
        tokens_eq.extend(suffix);
        let cmd_eq = build_command(&cmd_name, &tokens_eq);
        let result_eq = evaluate_command(&config, &cmd_eq, &ctx).unwrap();

        prop_assert_eq!(&result_space.action, &result_eq.action,
            "optional FlagWithValue equals equivalence failed: space={:?} eq={:?}",
            cmd_space, cmd_eq);
    }

    #[test]
    fn prop_equals_equivalence_flag_negation(
        cmd_name in arb_cmd_name(),
        negated_flag in arb_flag(),
        value in arb_positional(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} !{negated_flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens_space = vec![negated_flag.clone(), value.clone()];
        tokens_space.extend(suffix.iter().cloned());
        let cmd_space = build_command(&cmd_name, &tokens_space);
        let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

        let mut tokens_eq = vec![format!("{negated_flag}={value}")];
        tokens_eq.extend(suffix);
        let cmd_eq = build_command(&cmd_name, &tokens_eq);
        let result_eq = evaluate_command(&config, &cmd_eq, &ctx).unwrap();

        prop_assert_eq!(&result_space.action, &result_eq.action,
            "equals negation equivalence failed: space={:?} eq={:?}", cmd_space, cmd_eq);
    }

    #[test]
    fn prop_equals_equivalence_with_glob_value(
        cmd_name in arb_cmd_name(),
        flag in arb_flag(),
        (glob_pat, matching_tok, _) in arb_glob_pattern_and_match(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        // FlagWithValue with glob in value position: --flag glob_pattern
        let pattern = format!("{cmd_name} {flag} {glob_pat} *");
        let yaml = build_yaml_config("allow", &pattern);
        if let Ok(config) = parse_config(&yaml) {
            let ctx = empty_context();

            let mut tokens_space = vec![flag.clone(), matching_tok.clone()];
            tokens_space.extend(suffix.iter().cloned());
            let cmd_space = build_command(&cmd_name, &tokens_space);
            let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

            let mut tokens_eq = vec![format!("{flag}={matching_tok}")];
            tokens_eq.extend(suffix);
            let cmd_eq = build_command(&cmd_name, &tokens_eq);
            let result_eq = evaluate_command(&config, &cmd_eq, &ctx).unwrap();

            prop_assert_eq!(&result_space.action, &result_eq.action,
                "glob value equals equivalence failed: space={:?} eq={:?}", cmd_space, cmd_eq);
        }
    }
}

// ========================================
// Property D: Deny propagation in compound commands
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_deny_propagation_compound(
        allowed_cmd in arb_cmd_name(),
        denied_cmd in arb_cmd_name(),
        operator in arb_operator(),
        deny_first in proptest::bool::ANY,
    ) {
        prop_assume!(allowed_cmd != denied_cmd);

        let yaml = indoc::formatdoc! {"
            rules:
              - allow: '{allowed_cmd} *'
              - deny: '{denied_cmd} *'
        "};
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let allowed = format!("{allowed_cmd} arg");
        let denied = format!("{denied_cmd} arg");

        let compound = if deny_first {
            format!("{denied} {operator} {allowed}")
        } else {
            format!("{allowed} {operator} {denied}")
        };

        let result = evaluate_compound(&config, &compound, &ctx).unwrap();
        prop_assert!(
            matches!(result.action, Action::Deny(_)),
            "deny should propagate in compound: command={:?} result={:?}",
            compound, result.action
        );
    }

    #[test]
    fn prop_deny_propagation_with_command_substitution(
        allowed_cmd in arb_cmd_name(),
        denied_cmd in arb_cmd_name(),
    ) {
        prop_assume!(allowed_cmd != denied_cmd);

        let yaml = indoc::formatdoc! {"
            rules:
              - allow: '{allowed_cmd} *'
              - deny: '{denied_cmd} *'
        "};
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let compound = format!("{allowed_cmd} $({denied_cmd} arg)");
        let result = evaluate_compound(&config, &compound, &ctx).unwrap();
        prop_assert!(
            matches!(result.action, Action::Deny(_)),
            "deny in $() should propagate: command={:?} result={:?}",
            compound, result.action
        );
    }

    #[test]
    fn prop_deny_propagation_compound_generated(
        compound in arb_compound_command(),
    ) {
        let yaml = indoc::indoc! {"
            rules:
              - allow: 'git *'
              - allow: 'curl *'
              - allow: 'echo *'
              - allow: 'npm *'
              - allow: 'ls *'
              - deny: 'rm *'
        "};
        let config = parse_config(yaml).unwrap();
        let ctx = empty_context();

        let result = evaluate_compound(&config, &compound, &ctx).unwrap();

        // Check if "rm" appears as a command (after an operator or at start),
        // not just as an argument to another command.
        let has_rm_command = compound.starts_with("rm ")
            || compound.starts_with("rm\t")
            || compound.contains("&& rm ")
            || compound.contains("|| rm ")
            || compound.contains("| rm ")
            || compound.contains("; rm ");
        if has_rm_command {
            prop_assert!(
                matches!(result.action, Action::Deny(_)),
                "compound with 'rm' command should deny: command={:?} result={:?}",
                compound, result.action
            );
        }
    }
}

// ========================================
// Property E: No panics or infinite loops
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_no_panic_evaluate_command(
        command in arb_simple_command(),
        pattern in arb_rich_pattern(),
        action in prop_oneof![
            Just("allow".to_string()),
            Just("deny".to_string()),
            Just("ask".to_string()),
        ],
    ) {
        let yaml = build_yaml_config(&action, &pattern);
        if let Ok(config) = parse_config(&yaml) {
            let ctx = empty_context();
            let _ = evaluate_command(&config, &command, &ctx);
        }
    }

    #[test]
    fn prop_no_panic_evaluate_compound(
        compound in arb_compound_command(),
        pattern in arb_rich_pattern(),
        action in prop_oneof![
            Just("allow".to_string()),
            Just("deny".to_string()),
            Just("ask".to_string()),
        ],
    ) {
        let yaml = build_yaml_config(&action, &pattern);
        if let Ok(config) = parse_config(&yaml) {
            let ctx = empty_context();
            let _ = evaluate_compound(&config, &compound, &ctx);
        }
    }
}

// ========================================
// Property F: Rule order independence
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_rule_order_independence(
        cmd_name in arb_cmd_name(),
        tokens in proptest::collection::vec(arb_positional(), 0..=3),
        rules in proptest::collection::vec(
            (
                prop_oneof![
                    Just("allow".to_string()),
                    Just("deny".to_string()),
                    Just("ask".to_string()),
                ],
                arb_cmd_name(),
                proptest::collection::vec(
                    prop_oneof![
                        Just("*".to_string()),
                        arb_positional(),
                    ],
                    0..=2
                ),
            ),
            2..=4
        ),
        reverse in proptest::bool::ANY,
    ) {
        let command = build_command(&cmd_name, &tokens);

        let rule_lines: Vec<String> = rules.iter().map(|(action, cmd, suffix)| {
            let pattern = if suffix.is_empty() {
                cmd.clone()
            } else {
                format!("{cmd} {}", suffix.join(" "))
            };
            format!("  - {action}: '{pattern}'")
        }).collect();

        let yaml_original = format!("rules:\n{}", rule_lines.join("\n"));

        let mut reordered_lines = rule_lines.clone();
        if reverse {
            reordered_lines.reverse();
        } else if reordered_lines.len() > 1 {
            let first = reordered_lines.remove(0);
            reordered_lines.push(first);
        }
        let yaml_reordered = format!("rules:\n{}", reordered_lines.join("\n"));

        let config_orig = parse_config(&yaml_original);
        let config_reord = parse_config(&yaml_reordered);

        match (&config_orig, &config_reord) {
            (Ok(c1), Ok(c2)) => {
                let ctx = empty_context();
                let result_orig = evaluate_command(c1, &command, &ctx);
                let result_reord = evaluate_command(c2, &command, &ctx);

                match (result_orig, result_reord) {
                    (Ok(r1), Ok(r2)) => {
                        let a1 = action_variant(&r1.action);
                        let a2 = action_variant(&r2.action);
                        prop_assert_eq!(a1, a2,
                            "rule order should not change result: original={:?} reordered={:?} command={:?}",
                            yaml_original, yaml_reordered, command);
                    }
                    (Err(_), Err(_)) => {}
                    (Ok(r1), Err(e2)) => {
                        prop_assert!(false,
                            "inconsistent: original succeeded ({:?}) but reordered failed ({:?})",
                            r1.action, e2);
                    }
                    (Err(e1), Ok(r2)) => {
                        prop_assert!(false,
                            "inconsistent: original failed ({:?}) but reordered succeeded ({:?})",
                            e1, r2.action);
                    }
                }
            }
            (Err(_), Err(_)) => {}
            _ => {
                prop_assert!(false,
                    "inconsistent parse: one config parsed but the other didn't");
            }
        }
    }
}
