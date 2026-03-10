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

fn arb_flag_value() -> impl Strategy<Value = String> {
    prop_oneof![arb_positional(), arb_flag(),]
}

// ========================================
// Pattern token pair strategies
// Each returns (pattern_fragment, matching_tokens)
// ========================================

fn arb_literal_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    arb_positional().prop_map(|s| (s.clone(), vec![s]))
}

fn arb_wildcard_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    proptest::collection::vec(arb_positional(), 0..=3).prop_map(|tokens| ("*".to_string(), tokens))
}

fn arb_alternation_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    (
        arb_positional(),
        proptest::collection::vec(arb_positional(), 1..=3),
    )
        .prop_map(|(chosen, mut others)| {
            if !others.contains(&chosen) {
                others.push(chosen.clone());
            }
            let pattern_frag = others.join("|");
            (pattern_frag, vec![chosen])
        })
}

fn arb_flag_alternation_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    // Flag alternation is position-independent: flag can appear anywhere in tokens
    (
        arb_flag(),
        proptest::collection::vec(arb_positional(), 0..=2),
    )
        .prop_map(|(flag, mut prefix)| {
            let pattern_frag = flag.clone();
            prefix.push(flag);
            (pattern_frag, prefix)
        })
}

fn arb_flag_with_value_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    // FlagWithValue is position-independent.
    // Generates both space-separated and =joined forms.
    (arb_flag(), arb_positional(), proptest::bool::ANY).prop_map(|(flag, value, use_equals)| {
        let pattern_frag = format!("{flag} *");
        if use_equals {
            (pattern_frag, vec![format!("{flag}={value}")])
        } else {
            (pattern_frag, vec![flag, value])
        }
    })
}

fn arb_flag_negation_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    // Flag negation: !--flag means "this flag must NOT be present"
    // Generate tokens that do NOT contain the negated flag
    (
        arb_flag(),
        proptest::collection::vec(arb_positional(), 0..=2),
    )
        .prop_map(|(negated_flag, positionals)| {
            let pattern_frag = format!("!{negated_flag}");
            (pattern_frag, positionals)
        })
}

fn arb_value_negation_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    // Non-flag negation is position-dependent (matches cmd_tokens[0])
    (arb_positional(), arb_positional())
        .prop_filter(
            "negated value must differ from chosen",
            |(negated, chosen)| negated != chosen,
        )
        .prop_map(|(negated, chosen)| {
            let pattern_frag = format!("!{negated}");
            (pattern_frag, vec![chosen])
        })
}

fn arb_negation_alternation_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    // NegationAlternation: !describe|get|list matches when none of the alternatives is present
    (
        proptest::collection::vec(arb_positional(), 2..=4),
        arb_positional(),
    )
        .prop_filter(
            "chosen must not be in negated set",
            |(negated_set, chosen)| !negated_set.contains(chosen),
        )
        .prop_map(|(negated_set, chosen)| {
            let pattern_frag = format!("!{}", negated_set.join("|"));
            (pattern_frag, vec![chosen])
        })
}

fn arb_quoted_literal_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    // QuotedLiteral: "value*" in a pattern suppresses glob expansion.
    // The token must match the exact string including any `*` characters.
    prop_oneof![
        // Literal with glob-like chars that must match exactly
        arb_positional().prop_map(|s| {
            let quoted_val = format!("{s}*");
            // Pattern uses double quotes to suppress glob
            let pattern_frag = format!("\"{quoted_val}\"");
            (pattern_frag, vec![quoted_val])
        }),
        // Plain quoted literal without special chars
        arb_positional().prop_map(|s| {
            let pattern_frag = format!("\"{s}\"");
            (pattern_frag, vec![s])
        }),
    ]
}

fn arb_optional_pair() -> impl Strategy<Value = (String, Vec<String>)> {
    // Optional flag: [-f] matches with or without
    (arb_flag(), proptest::bool::ANY).prop_map(|(flag, present)| {
        let pattern_frag = format!("[{flag}]");
        if present {
            (pattern_frag, vec![flag])
        } else {
            (pattern_frag, vec![])
        }
    })
}

/// Composite matching pair: combines multiple pattern token types into
/// a single (pattern, command) pair that should always match.
fn arb_matching_pair() -> impl Strategy<Value = (String, String)> {
    (
        arb_cmd_name(),
        arb_literal_pair(),
        arb_optional_pair(),
        arb_wildcard_pair(),
    )
        .prop_map(
            |(cmd, (lit_pat, lit_tok), (opt_pat, opt_tok), (wild_pat, wild_tok))| {
                let pattern = format!("{cmd} {lit_pat} {opt_pat} {wild_pat}");
                let mut tokens = lit_tok;
                tokens.extend(opt_tok);
                tokens.extend(wild_tok);
                let command = build_command(&cmd, &tokens);
                (pattern, command)
            },
        )
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
    format!(
        "rules:\n  - {action}: '{pattern}'",
        action = action,
        pattern = pattern.replace('\'', "''")
    )
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
// Property A: Generated matching pairs must always match
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_matching_pairs_always_allow(
        cmd_name in arb_cmd_name(),
        extra_tokens in proptest::collection::vec(arb_positional(), 0..=4),
    ) {
        let pattern = format!("{cmd_name} *");
        let command = build_command(&cmd_name, &extra_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "pattern={:?} command={:?}", pattern, command);
    }
}

// ========================================
// Property A (extended): individual pattern token types
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_literal_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_literal_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_wildcard_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_wildcard_pair(),
    ) {
        let pattern = format!("{cmd_name} {pattern_frag}");
        let command = build_command(&cmd_name, &tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_alternation_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_alternation_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_flag_alternation_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_flag_alternation_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_flag_with_value_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_flag_with_value_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "pattern={:?} command={:?}", pattern, command);
    }

    #[test]
    fn prop_flag_negation_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_flag_negation_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        // Negated flag is absent from tokens -> should Allow
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "flag negation with absent flag should Allow: pattern={:?} command={:?}",
            pattern, command);
    }

    #[test]
    fn prop_value_negation_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_value_negation_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        // Negated value is absent from first position -> should Allow
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "value negation with different value should Allow: pattern={:?} command={:?}",
            pattern, command);
    }

    #[test]
    fn prop_negation_alternation_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_negation_alternation_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        // None of the negated alternatives present -> should Allow
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "negation alternation with absent values should Allow: pattern={:?} command={:?}",
            pattern, command);
    }

    #[test]
    fn prop_quoted_literal_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_quoted_literal_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        // QuotedLiteral suppresses glob: "WIP*" matches literal "WIP*", not a wildcard
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "quoted literal should match exactly: pattern={:?} command={:?}",
            pattern, command);
    }

    #[test]
    fn prop_quoted_literal_no_glob_expansion(
        cmd_name in arb_cmd_name(),
        base in arb_positional(),
        different_suffix in arb_positional(),
    ) {
        // "base*" in pattern must NOT match "base<something>" (glob suppressed)
        let quoted_val = format!("{base}*");
        let pattern = format!("{cmd_name} \"{quoted_val}\"");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Command with value that would match if glob were active but shouldn't
        let non_matching_val = format!("{base}{different_suffix}");
        prop_assume!(non_matching_val != quoted_val);
        let command = build_command(&cmd_name, &[non_matching_val]);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "quoted literal should NOT glob-expand: pattern={:?} command={:?}",
            pattern, command
        );
    }

    #[test]
    fn prop_optional_pair_matches(
        cmd_name in arb_cmd_name(),
        (pattern_frag, tokens) in arb_optional_pair(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {pattern_frag} *");
        let mut all_tokens = tokens;
        all_tokens.extend(suffix);
        let command = build_command(&cmd_name, &all_tokens);
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "pattern={:?} command={:?}", pattern, command);
    }
}

// ========================================
// Property A (composite): combined pattern token types
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_composite_matching_pair(
        (pattern, command) in arb_matching_pair(),
    ) {
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "composite match failed: pattern={:?} command={:?}", pattern, command);
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
        // Flag alternation is position-independent: flag at any position should match
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
        // FlagWithValue is position-independent: --flag value pair at any position
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
        // Flag negation is position-independent: !--flag should detect the flag at any position
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

        // Both should give the same result (not Allow, since flag is present)
        prop_assert_eq!(&result_start.action, &result_end.action,
            "flag negation position should not matter: start={:?} end={:?}",
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
        // --flag=value and --flag value should produce the same result
        // for FlagWithValue patterns with wildcard value
        let pattern = format!("{cmd_name} {flag} * *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Space-separated form
        let mut tokens_space = vec![flag.clone(), value.clone()];
        tokens_space.extend(suffix.iter().cloned());
        let cmd_space = build_command(&cmd_name, &tokens_space);
        let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

        // Equals-joined form
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
        value in arb_positional(),
        suffix in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        // Value must not start with '-' because --flag=-value is parsed as
        // a single flag token (not flag=value) by the command parser
        prop_assume!(!value.starts_with('-'));

        // --flag=value and --flag value should produce the same result
        // for FlagWithValue patterns with a fixed literal value
        let pattern = format!("{cmd_name} {flag} {value} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Space-separated form
        let mut tokens_space = vec![flag.clone(), value.clone()];
        tokens_space.extend(suffix.iter().cloned());
        let cmd_space = build_command(&cmd_name, &tokens_space);
        let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

        // Equals-joined form
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
        // Optional FlagWithValue: [-X GET] should match -X=GET
        let pattern = format!("{cmd_name} [{flag} {value}] *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Space-separated form
        let mut tokens_space = vec![flag.clone(), value.clone()];
        tokens_space.extend(suffix.iter().cloned());
        let cmd_space = build_command(&cmd_name, &tokens_space);
        let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

        // Equals-joined form
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
        // !--flag should detect --flag=value just like --flag value
        let pattern = format!("{cmd_name} !{negated_flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Space-separated form with the negated flag
        let mut tokens_space = vec![negated_flag.clone(), value.clone()];
        tokens_space.extend(suffix.iter().cloned());
        let cmd_space = build_command(&cmd_name, &tokens_space);
        let result_space = evaluate_command(&config, &cmd_space, &ctx).unwrap();

        // Equals-joined form with the negated flag
        let mut tokens_eq = vec![format!("{negated_flag}={value}")];
        tokens_eq.extend(suffix);
        let cmd_eq = build_command(&cmd_name, &tokens_eq);
        let result_eq = evaluate_command(&config, &cmd_eq, &ctx).unwrap();

        prop_assert_eq!(&result_space.action, &result_eq.action,
            "equals negation equivalence failed: space={:?} eq={:?}", cmd_space, cmd_eq);
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

        let yaml = format!(
            "rules:\n  - allow: '{allowed_cmd} *'\n  - deny: '{denied_cmd} *'"
        );
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

        let yaml = format!(
            "rules:\n  - allow: '{allowed_cmd} *'\n  - deny: '{denied_cmd} *'"
        );
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Denied command inside $() should still produce Deny
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
        // With deny on 'rm *', any compound containing 'rm ...' should deny
        let yaml = "rules:\n  - allow: 'git *'\n  - allow: 'curl *'\n  - allow: 'echo *'\n  - allow: 'npm *'\n  - allow: 'ls *'\n  - deny: 'rm *'";
        let config = parse_config(yaml).unwrap();
        let ctx = empty_context();

        let result = evaluate_compound(&config, &compound, &ctx).unwrap();

        // If "rm" appears as a command in the compound, result must be Deny
        if compound.contains("rm ") || compound.starts_with("rm") {
            prop_assert!(
                matches!(result.action, Action::Deny(_)),
                "compound with 'rm' should deny: command={:?} result={:?}",
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
        pattern_cmd in arb_cmd_name(),
        pattern_suffix in proptest::collection::vec(
            prop_oneof![
                Just("*".to_string()),
                arb_positional(),
                arb_flag(),
            ],
            0..=4
        ),
        action in prop_oneof![
            Just("allow".to_string()),
            Just("deny".to_string()),
            Just("ask".to_string()),
        ],
    ) {
        let pattern = if pattern_suffix.is_empty() {
            pattern_cmd
        } else {
            format!("{pattern_cmd} {}", pattern_suffix.join(" "))
        };
        let yaml = build_yaml_config(&action, &pattern);

        // parse_config might fail on some generated patterns; that's fine
        if let Ok(config) = parse_config(&yaml) {
            let ctx = empty_context();
            // Must not panic; errors are acceptable
            let _ = evaluate_command(&config, &command, &ctx);
        }
    }

    #[test]
    fn prop_no_panic_evaluate_compound(
        compound in arb_compound_command(),
        pattern_cmd in arb_cmd_name(),
        action in prop_oneof![
            Just("allow".to_string()),
            Just("deny".to_string()),
            Just("ask".to_string()),
        ],
    ) {
        let pattern = format!("{pattern_cmd} *");
        let yaml = build_yaml_config(&action, &pattern);

        if let Ok(config) = parse_config(&yaml) {
            let ctx = empty_context();
            // Must not panic
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
        } else {
            // Rotate by 1
            if reordered_lines.len() > 1 {
                let first = reordered_lines.remove(0);
                reordered_lines.push(first);
            }
        }
        let yaml_reordered = format!("rules:\n{}", reordered_lines.join("\n"));

        let config_orig = parse_config(&yaml_original);
        let config_reord = parse_config(&yaml_reordered);

        // Both configs must parse successfully or both must fail
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
                    (Err(_), Err(_)) => {
                        // Both errored, consistent behavior
                    }
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
            (Err(_), Err(_)) => {
                // Both failed to parse, consistent
            }
            _ => {
                prop_assert!(false,
                    "inconsistent parse: one config parsed but the other didn't");
            }
        }
    }
}
