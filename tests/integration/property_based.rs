use super::*;

use proptest::prelude::*;
use runok::config::parse_config;
use runok::rules::rule_engine::{Action, evaluate_command, evaluate_compound};

/// Assert that the action matches the expected allow/deny based on `is_allow`.
macro_rules! prop_assert_allow_or_deny {
    ($action:expr, $is_allow:expr, $ctx:expr) => {
        if $is_allow {
            prop_assert_eq!($action, Action::Allow, "expected Allow: {}", $ctx);
        } else {
            prop_assert!(
                matches!($action, Action::Deny(_)),
                "expected Deny: {} actual={:?}",
                $ctx,
                $action
            );
        }
    };
}

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
    prop_oneof![
        8 => arb_positional(),
        8 => arb_flag(),
        // Low weight: shell special tokens to exercise edge cases
        1 => arb_shell_special_token(),
    ]
}

/// Shell syntax special tokens that have historically caused bugs.
/// Mixed into arb_flag_value at low weight to exercise edge cases
/// without overwhelming normal-path testing.
fn arb_shell_special_token() -> impl Strategy<Value = String> {
    prop_oneof![
        // Redirects
        Just(">".to_string()),
        Just("<".to_string()),
        Just(">>".to_string()),
        Just("2>".to_string()),
        Just("2>&1".to_string()),
        Just("&>".to_string()),
        Just("&>>".to_string()),
        Just("<&".to_string()),
        Just(">&".to_string()),
        Just("/dev/null".to_string()),
        // Here-documents / here-strings
        Just(
            indoc::indoc! {"
            <<EOF
            content
            EOF"}
            .to_string()
        ),
        Just(
            indoc::indoc! {"
            <<'EOF'
            content
            EOF"}
            .to_string()
        ),
        Just("<<-EOF".to_string()),
        Just("<<<word".to_string()),
        // Command substitution
        arb_cmd_name().prop_map(|c| format!("$({c})")),
        arb_cmd_name().prop_map(|c| format!("$({c} arg)")),
        arb_cmd_name().prop_map(|c| format!("`{c}`")),
        // Process substitution
        arb_cmd_name().prop_map(|c| format!("<({c})")),
        arb_cmd_name().prop_map(|c| format!(">({c})")),
        // Subshell / command group
        arb_cmd_name().prop_map(|c| format!("({c})")),
        arb_cmd_name().prop_map(|c| format!("(({c}))")),
        arb_cmd_name().prop_map(|c| format!("{{ {c}; }}")),
        // Conditional expressions
        arb_cmd_name().prop_map(|c| format!("[[ {c} ]]")),
        arb_cmd_name().prop_map(|c| format!("[ {c} ]")),
        // Control structures
        arb_cmd_name().prop_map(|c| format!("for i in a b; do {c}; done")),
        arb_cmd_name().prop_map(|c| format!("while {c}; do {c}; done")),
        arb_cmd_name().prop_map(|c| format!("if {c}; then {c}; fi")),
        arb_cmd_name().prop_map(|c| format!("case word in pattern) {c};; esac")),
        // Argument terminator
        Just("--".to_string()),
        // Background
        Just("&".to_string()),
        // Variables / environment
        Just("$HOME".to_string()),
        Just("${PATH}".to_string()),
        Just("${VAR:-default}".to_string()),
        Just("${VAR:+alt}".to_string()),
        Just("${VAR%pattern}".to_string()),
        Just("${#VAR}".to_string()),
        "[A-Z]{1,4}".prop_map(|k| format!("{k}=value")),
        (
            "[A-Z]{1,3}".prop_map(|k| format!("{k}=bar")),
            arb_cmd_name(),
        )
            .prop_map(|(env, c)| format!("{env} {c}")),
        // Arithmetic expansion
        Just("$((1+2))".to_string()),
        Just("$((x*y))".to_string()),
        // Quoted strings (including nested command substitution)
        arb_positional().prop_map(|s| format!("\"{s}\"")),
        arb_positional().prop_map(|s| format!("'{s}'")),
        arb_cmd_name().prop_map(|c| format!("\"$({c})\"")),
        Just("$'\\n\\t'".to_string()),
        Just("$\"translatable\"".to_string()),
        Just("\"hello\"'world'".to_string()),
        // Comments
        Just("#".to_string()),
        Just("# comment".to_string()),
        // Escapes
        Just("\\;".to_string()),
        Just("\\*".to_string()),
        Just("\\\\".to_string()),
        Just("\\#".to_string()),
        // Brace expansion
        Just("{a,b,c}".to_string()),
        Just("{1..10}".to_string()),
        Just("{01..10..2}".to_string()),
        // Glob / brackets
        Just("?".to_string()),
        Just("[abc]".to_string()),
        Just("[!abc]".to_string()),
        Just("[a-z]".to_string()),
        Just("**".to_string()),
        // Special characters
        Just("!".to_string()),
        Just("~".to_string()),
        Just("~user".to_string()),
        Just("`".to_string()),
        // Builtins
        Just("exec".to_string()),
        Just("eval".to_string()),
        Just("source".to_string()),
        Just(".".to_string()),
        // Function definition
        arb_cmd_name().prop_map(|c| format!("f() {{ {c}; }}")),
        // Compound assignment
        Just("array=(a b c)".to_string()),
        // Empty / whitespace
        Just("".to_string()),
        Just("  ".to_string()),
        // Newline
        Just("\n".to_string()),
        // Nul byte
        Just("\0".to_string()),
        // Non-ASCII
        Just("/tmp/テスト".to_string()),
        Just("日本語".to_string()),
    ]
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
    .prop_filter(
        "need at least one * and one literal, no consecutive globs",
        |segs| {
            segs.iter().any(|(_, _, is_lit)| *is_lit)
                && segs.iter().any(|(_, _, is_lit)| !*is_lit)
                && !segs.windows(2).any(|w| !w[0].2 && !w[1].2)
        },
    )
    .prop_map(|segments| {
        let pattern: String = segments.iter().map(|(p, _, _)| p.as_str()).collect();
        let matching: String = segments.iter().map(|(_, m, _)| m.as_str()).collect();

        // Non-matching: replace ALL characters in ALL segments with '0'.
        // Both literal and glob filler segments must be replaced, because
        // glob filler uses [a-z] which could coincidentally match a literal
        // portion of the pattern when `*` shifts the matching window.
        let non_matching: String = segments
            .iter()
            .map(|(_, m, _)| "0".repeat(m.len()))
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

/// Generates a (pattern, command, is_allow) triple where the pattern is
/// guaranteed to match the command. Uses diverse pattern syntax: wildcard,
/// literal, flag negation (absent), optional flag, alternation.
/// `is_allow` determines whether the rule should be "allow" or "deny".
///
/// `cmd_id` is embedded in the command name to ensure uniqueness across
/// multiple sub-commands in a compound.
fn arb_matching_rule_and_command(cmd_id: usize) -> impl Strategy<Value = (String, String, bool)> {
    let cmd_prefix = format!("cmd{cmd_id}x");
    (
        // Random suffix to make command name unique per generation
        "[a-z]{2,4}",
        prop_oneof![
            // Wildcard: {cmd} * matches any args
            3 => proptest::collection::vec(arb_safe_positional(), 0..=3)
                .prop_map(|tokens| ("wildcard".to_string(), tokens)),
            // Literal: {cmd} {lit} matches exactly
            2 => arb_safe_positional()
                .prop_map(|lit| ("literal".to_string(), vec![lit])),
            // Flag negation (absent): {cmd} !{flag} * matches when flag is NOT present
            2 => proptest::collection::vec(arb_safe_positional(), 1..=3)
                .prop_map(|pos| ("flag_neg".to_string(), pos)),
            // Optional flag: {cmd} [{flag}] * matches with or without
            2 => (arb_flag(), proptest::collection::vec(arb_safe_positional(), 0..=2))
                .prop_map(|(flag, mut pos)| {
                    pos.insert(0, flag);
                    ("optional".to_string(), pos)
                }),
            // Alternation: {cmd} {a|b} * matches when head is in set
            2 => (
                proptest::collection::vec(arb_safe_positional(), 2..=3),
                proptest::collection::vec(arb_safe_positional(), 0..=2),
            )
                .prop_map(|(alts, suffix)| {
                    let mut tokens = vec![alts[0].clone()];
                    tokens.extend(suffix);
                    ("alternation".to_string(), {
                        // Store alternation set as first element with | separator,
                        // then actual tokens
                        let mut v = vec![alts.join("|")];
                        v.extend(tokens);
                        v
                    })
                }),
        ],
        proptest::bool::ANY,
    )
        .prop_map(move |(suffix, (variant, tokens), is_allow)| {
            let cmd_name = format!("{cmd_prefix}{suffix}");
            match variant.as_str() {
                "wildcard" => {
                    let pattern = format!("{cmd_name} *");
                    let command = build_command(&cmd_name, &tokens);
                    (pattern, command, is_allow)
                }
                "literal" => {
                    let pattern = format!("{cmd_name} {}", tokens[0]);
                    let command = build_command(&cmd_name, std::slice::from_ref(&tokens[0]));
                    (pattern, command, is_allow)
                }
                "flag_neg" => {
                    // Use a flag that does NOT appear in the positional tokens
                    let pattern = format!("{cmd_name} !--zzunused *");
                    let command = build_command(&cmd_name, &tokens);
                    (pattern, command, is_allow)
                }
                "optional" => {
                    let flag = &tokens[0];
                    let pattern = format!("{cmd_name} [{flag}] *");
                    let command = build_command(&cmd_name, &tokens);
                    (pattern, command, is_allow)
                }
                "alternation" => {
                    let alt_set = &tokens[0]; // "a|b|c"
                    let cmd_tokens = &tokens[1..]; // actual command tokens
                    let pattern = format!("{cmd_name} {alt_set} *");
                    let command = build_command(&cmd_name, cmd_tokens);
                    (pattern, command, is_allow)
                }
                _ => unreachable!(),
            }
        })
}

fn arb_simple_command() -> impl Strategy<Value = String> {
    prop_oneof![
        // Normal command
        8 => (
            arb_cmd_name(),
            proptest::collection::vec(arb_flag_value(), 0..=4),
        )
            .prop_map(|(name, tokens)| build_command(&name, &tokens)),
        // Command with KEY=VALUE env prefix
        1 => (
            "[A-Z]{1,4}".prop_map(|k| format!("{k}=value")),
            arb_cmd_name(),
            proptest::collection::vec(arb_flag_value(), 0..=3),
        )
            .prop_map(|(env, name, tokens)| {
                let cmd = build_command(&name, &tokens);
                format!("{env} {cmd}")
            }),
    ]
}

fn arb_compound_command() -> impl Strategy<Value = String> {
    prop_oneof![
        // Normal compound: cmd1 op cmd2 op cmd3 ...
        8 => (
            proptest::collection::vec(arb_simple_command(), 2..=4),
            proptest::collection::vec(arb_operator(), 1..=3),
        )
            .prop_map(|(cmds, ops)| {
                let mut result = cmds[0].clone();
                for (i, cmd) in cmds.iter().enumerate().skip(1) {
                    let op = &ops[(i - 1) % ops.len()];
                    result = format!("{result} {op} {cmd}");
                }
                result
            }),
        // Command with redirects (PR #149)
        2 => (arb_simple_command(), arb_simple_command())
            .prop_map(|(cmd, inner)| format!("{cmd} 2>&1 | {inner}")),
        // Command substitution in arguments (PR #151)
        2 => (arb_simple_command(), arb_cmd_name())
            .prop_map(|(cmd, inner)| format!("{cmd} \"$({inner} arg)\"")),
        // Subshell
        1 => (arb_simple_command(), arb_operator(), arb_simple_command())
            .prop_map(|(c1, op, c2)| format!("({c1} {op} {c2})")),
        // Environment variable prefix
        1 => (
            "[A-Z]{1,4}".prop_map(|k| format!("{k}=value")),
            arb_simple_command(),
        )
            .prop_map(|(env, cmd)| format!("{env} {cmd}")),
        // for loop
        1 => arb_cmd_name()
            .prop_map(|c| format!("for i in *.txt; do {c} $i; done")),
        // if/then
        1 => (arb_simple_command(), arb_simple_command())
            .prop_map(|(cond, body)| format!("if {cond}; then {body}; fi")),
    ]
}

/// Generate a random pattern string containing various syntax elements.
/// Used by no-panic tests to exercise the parser with diverse patterns.
fn arb_rich_pattern() -> impl Strategy<Value = String> {
    (
        arb_cmd_name(),
        proptest::collection::vec(
            prop_oneof![
                // Wildcard
                2 => Just("*".to_string()),
                // Positional literal
                2 => arb_positional(),
                // Flag (becomes Alternation in parser)
                2 => arb_flag(),
                // Glob literal (random structure from arb_glob_pattern_and_match)
                1 => arb_glob_pattern_and_match().prop_map(|(pat, _, _)| pat),
                // Negation
                1 => arb_positional().prop_map(|s| format!("!{s}")),
                // Flag negation
                1 => arb_flag().prop_map(|f| format!("!{f}")),
                // Optional
                1 => arb_flag().prop_map(|f| format!("[{f}]")),
                // Alternation
                1 => (arb_positional(), arb_positional()).prop_map(|(a, b)| format!("{a}|{b}")),
                // Quoted literal (grouping only)
                1 => arb_positional().prop_map(|s| format!("\"{s}\"")),
                // Shell special tokens for edge case coverage
                1 => arb_shell_special_token(),
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

/// Build a command string from tokens using shlex for proper quoting.
/// Nul bytes are stripped because shlex::try_join rejects them.
fn build_command(cmd_name: &str, tokens: &[String]) -> String {
    let mut parts = vec![cmd_name.to_string()];
    parts.extend(tokens.iter().map(|t| t.replace('\0', "")));
    match shlex::try_join(parts.iter().map(|s| s.as_str())) {
        Ok(cmd) => cmd,
        Err(_) => unreachable!("shlex::try_join failed after stripping nul bytes"),
    }
}

/// Build a YAML config with a single rule
fn build_yaml_config(action: &str, pattern: &str) -> String {
    let escaped = pattern.replace('\'', "''");
    indoc::formatdoc! {"
        rules:
          - {action}: '{escaped}'
    "}
}

/// Build a YAML config with a single rule AND wrapper definitions
fn build_yaml_config_with_wrappers(action: &str, pattern: &str, wrappers: &[&str]) -> String {
    let escaped = pattern.replace('\'', "''");
    let wrapper_lines: String = wrappers
        .iter()
        .map(|w| {
            let esc = w.replace('\'', "''");
            format!("      - '{esc}'")
        })
        .collect::<Vec<_>>()
        .join("\n");
    indoc::formatdoc! {"
        definitions:
          wrappers:
        {wrapper_lines}
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
// Wildcard subsumption
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
// Literal strictness
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
// Flag negation correctness
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
// Flag negation after preceding literals
// `{cmd} {literal} !{flag} *` allows when flag absent, rejects when present
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_flag_negation_after_literal_allows_when_absent(
        cmd_name in arb_cmd_name(),
        literal in arb_safe_positional(),
        negated_flag in arb_flag(),
        positionals in proptest::collection::vec(arb_safe_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {literal} !{negated_flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Command with the literal but without the negated flag
        let mut tokens = vec![literal];
        tokens.extend(positionals);
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "flag negation after literal should allow when flag absent: pattern={:?} command={:?}",
            pattern, command);
    }

    #[test]
    fn prop_flag_negation_after_literal_rejects_when_present(
        cmd_name in arb_cmd_name(),
        literal in arb_safe_positional(),
        negated_flag in arb_flag(),
        positionals in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
        let pattern = format!("{cmd_name} {literal} !{negated_flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Command with the literal and the negated flag present
        let mut tokens = vec![literal];
        tokens.push(negated_flag.clone());
        tokens.extend(positionals);
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "flag negation after literal should reject when flag present: pattern={:?} command={:?}",
            pattern, command
        );
    }
}

// ========================================
// Value negation correctness (position-dependent)
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
// Alternation correctness
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
// Optional correctness
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
// Glob literal correctness
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
// Quoted literal correctness
// Quotes are grouping only; `*` inside quotes still acts as a glob.
// Use `\*` for a literal asterisk.
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
    fn prop_quoted_star_acts_as_glob(
        cmd_name in arb_cmd_name(),
        base in arb_safe_positional(),
        extra in arb_safe_positional(),
    ) {
        // "base*" SHOULD match "base<extra>" (glob is active inside quotes)
        let quoted_val = format!("{base}*");
        let pattern = format!("{cmd_name} \"{quoted_val}\"");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let matching_val = format!("{base}{extra}");
        let command = build_command(&cmd_name, &[matching_val]);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "quoted star should glob-expand: pattern={:?} command={:?}",
            pattern, command);
    }

    #[test]
    fn prop_escaped_star_suppresses_glob(
        cmd_name in arb_cmd_name(),
        base in arb_safe_positional(),
        extra in arb_safe_positional(),
    ) {
        // "base\*" must NOT match "base<extra>" (escaped star is literal)
        let escaped_val = format!(r#"{base}\*"#);
        let pattern = format!("{cmd_name} \"{escaped_val}\"");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let non_matching_val = format!("{base}{extra}");
        prop_assume!(non_matching_val != format!("{base}*"));
        let command = build_command(&cmd_name, &[non_matching_val]);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "escaped star should NOT glob-expand: pattern={:?} command={:?}",
            pattern, command
        );
    }
}

// ========================================
// Literal matches with interleaved flags
// `{cmd} {literal} *` should match even when flags precede the literal
// in the command (PR #177: order-independent literal matching).
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_literal_matches_with_flags_before(
        cmd_name in arb_cmd_name(),
        literal in arb_safe_positional(),
        flag in arb_flag(),
        trailing in proptest::collection::vec(arb_safe_positional(), 1..=3),
    ) {
        // Pattern: {cmd} {literal} {flag} *
        // Command: {cmd} {flag} {literal} {trailing...}
        let pattern = format!("{cmd_name} {literal} {flag} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens = vec![flag.clone(), literal.clone()];
        tokens.extend(trailing.iter().cloned());
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "literal should match with flag before it: pattern={:?} command={:?}",
            pattern, command);
    }

    #[test]
    fn prop_literal_matches_with_multiple_flags_before(
        cmd_name in arb_cmd_name(),
        literal in arb_safe_positional(),
        flags in proptest::collection::vec(arb_flag(), 1..=3),
        trailing in proptest::collection::vec(arb_safe_positional(), 0..=2),
    ) {
        // Pattern: {cmd} {literal} *
        // Command: {cmd} {flags...} {literal} {trailing...}
        let pattern = format!("{cmd_name} {literal} *");
        let yaml = build_yaml_config("allow", &pattern);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let mut tokens: Vec<String> = flags;
        tokens.push(literal.clone());
        tokens.extend(trailing);
        let command = build_command(&cmd_name, &tokens);
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "literal should match with multiple flags before it: pattern={:?} command={:?}",
            pattern, command);
    }
}

// ========================================
// evaluate_command compound guard
// When evaluate_command receives a compound command (with &&, ||, ;, |),
// wildcard must NOT match across operators (PR #108: 067ab7e)
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_evaluate_command_compound_guard_deny(
        allowed_cmd in arb_cmd_name(),
        denied_cmd in arb_cmd_name(),
        operator in arb_operator(),
        allowed_args in proptest::collection::vec(arb_safe_positional(), 0..=2),
        denied_args in proptest::collection::vec(arb_safe_positional(), 0..=2),
    ) {
        prop_assume!(allowed_cmd != denied_cmd);

        // Only allow the first command with wildcard
        let yaml = indoc::formatdoc! {"
            rules:
              - allow: '{allowed_cmd} *'
              - deny: '{denied_cmd} *'
        "};
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Build a compound command passed to evaluate_command (not evaluate_compound)
        let allowed_part = build_command(&allowed_cmd, &allowed_args);
        let denied_part = build_command(&denied_cmd, &denied_args);
        let compound = format!("{allowed_part} {operator} {denied_part}");

        // evaluate_command should detect the compound and deny
        let result = evaluate_command(&config, &compound, &ctx).unwrap();
        prop_assert!(
            matches!(result.action, Action::Deny(_)),
            "evaluate_command should not let wildcard match across operator: command={:?} result={:?}",
            compound, result.action
        );
    }

    #[test]
    fn prop_evaluate_command_compound_guard_all_allowed(
        cmd1 in arb_cmd_name(),
        cmd2 in arb_cmd_name(),
        operator in arb_operator(),
        args1 in proptest::collection::vec(arb_safe_positional(), 0..=2),
        args2 in proptest::collection::vec(arb_safe_positional(), 0..=2),
    ) {
        // Both commands are allowed
        let yaml = indoc::formatdoc! {"
            rules:
              - allow: '{cmd1} *'
              - allow: '{cmd2} *'
        "};
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let part1 = build_command(&cmd1, &args1);
        let part2 = build_command(&cmd2, &args2);
        let compound = format!("{part1} {operator} {part2}");

        let result = evaluate_command(&config, &compound, &ctx).unwrap();
        prop_assert_eq!(result.action, Action::Allow,
            "evaluate_command should allow when all sub-commands allowed: command={:?}",
            compound);
    }
}

// ========================================
// Flag token position independence
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
        positionals in proptest::collection::vec(arb_positional(), 0..=2),
    ) {
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
// Equals-sign equivalence
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
// Deny propagation in compound commands
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

    /// Compound evaluation with pattern-matching correctness verification.
    /// Each sub-command has a known-matching rule with a known action (allow/deny).
    /// Verifies:
    /// 1. Each sub-command individually evaluates to the expected action
    /// 2. Compound result follows "Deny wins" aggregation
    #[test]
    fn prop_compound_match_correctness(
        pair0 in arb_matching_rule_and_command(0),
        pair1 in arb_matching_rule_and_command(1),
        pair2 in arb_matching_rule_and_command(2),
        operators in proptest::collection::vec(arb_operator(), 2..=2),
    ) {
        let pairs = [&pair0, &pair1, &pair2];

        // Build YAML config from the generated rules
        let rule_lines: Vec<String> = pairs.iter().map(|(pattern, _, is_allow)| {
            let action = if *is_allow { "allow" } else { "deny" };
            let escaped = pattern.replace('\'', "''");
            format!("  - {action}: '{escaped}'")
        }).collect();
        let rules = rule_lines.join("\n");
        let yaml = indoc::formatdoc! {"
            rules:
            {rules}"
        };
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Build compound command
        let compound = format!(
            "{} {} {} {} {}",
            pair0.1, operators[0], pair1.1, operators[1], pair2.1
        );

        // Verify each sub-command individually
        for (pattern, cmd, is_allow) in &pairs {
            let individual = evaluate_command(&config, cmd, &ctx).unwrap();
            if *is_allow {
                let msg = format!(
                    "pattern {:?} should allow command {:?}, got {}",
                    pattern, cmd, action_variant(&individual.action)
                );
                prop_assert_eq!(individual.action, Action::Allow, "{}", msg);
            } else {
                let msg = format!(
                    "pattern {:?} should deny command {:?}, got {}",
                    pattern, cmd, action_variant(&individual.action)
                );
                prop_assert!(matches!(individual.action, Action::Deny(_)), "{}", msg);
            }
        }

        // Verify compound aggregation
        let result = evaluate_compound(&config, &compound, &ctx).unwrap();
        let any_deny = pairs.iter().any(|(_, _, is_allow)| !is_allow);
        if any_deny {
            let msg = format!(
                "compound should Deny (at least one sub-command denied): compound={:?} \
                 sub_results={:?}",
                compound,
                pairs.iter().map(|(p, c, a)| format!("{}->{}={}", p, c, a)).collect::<Vec<_>>()
            );
            prop_assert!(matches!(result.action, Action::Deny(_)), "{}", msg);
        } else {
            let msg = format!(
                "compound should Allow (all sub-commands allowed): compound={:?}",
                compound,
            );
            prop_assert_eq!(result.action, Action::Allow, "{}", msg);
        }
    }
}

// ========================================
// Unmatched sub-commands in compound must not resolve to Allow
// When a compound contains a sub-command that matches no rule, the overall
// result must NOT be Allow (should escalate to Ask). This catches bugs where
// unmatched sub-commands silently resolve to Default->Allow (PR #178: 377f83d).
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_compound_unmatched_subcmd_not_allowed(
        matched_cmd in arb_cmd_name(),
        unmatched_cmd in arb_cmd_name(),
        operator in arb_operator(),
        matched_args in proptest::collection::vec(arb_safe_positional(), 0..=2),
        unmatched_args in proptest::collection::vec(arb_safe_positional(), 0..=2),
        unmatched_first in proptest::bool::ANY,
    ) {
        prop_assume!(matched_cmd != unmatched_cmd);

        // Only configure a rule for matched_cmd; unmatched_cmd has no rule
        let yaml = indoc::formatdoc! {"
            rules:
              - allow: '{matched_cmd} *'
        "};
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let matched_part = build_command(&matched_cmd, &matched_args);
        let unmatched_part = build_command(&unmatched_cmd, &unmatched_args);

        let compound = if unmatched_first {
            format!("{unmatched_part} {operator} {matched_part}")
        } else {
            format!("{matched_part} {operator} {unmatched_part}")
        };

        // evaluate_compound: unmatched sub-command should escalate, NOT Allow
        let result = evaluate_compound(&config, &compound, &ctx).unwrap();
        prop_assert!(
            !matches!(result.action, Action::Allow),
            "compound with unmatched sub-command should NOT be Allow: compound={:?} result={:?}",
            compound, result.action
        );

        // evaluate_command: same property via the compound guard path
        let result_cmd = evaluate_command(&config, &compound, &ctx).unwrap();
        prop_assert!(
            !matches!(result_cmd.action, Action::Allow),
            "evaluate_command with unmatched sub-command should NOT be Allow: compound={:?} result={:?}",
            compound, result_cmd.action
        );
    }
}

// ========================================
// No panics or infinite loops
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

    /// Same as prop_no_panic_evaluate_command but with compound commands fed
    /// into evaluate_command (not evaluate_compound). Tests the compound guard
    /// path in evaluate_command_inner, which was the source of stack overflow
    /// bugs (PR #149: 97b46a7).
    ///
    /// Separated from prop_no_panic_evaluate_command because combining
    /// arb_compound_command with arb_rich_pattern via prop_oneof exceeds
    /// the default thread stack size due to deep proptest Strategy nesting.
    #[test]
    fn prop_no_panic_evaluate_command_with_compound(
        command in arb_compound_command(),
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
// Rule order independence
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

        let rules = rule_lines.join("\n");
        let yaml_original = indoc::formatdoc! {"
            rules:
            {rules}"
        };

        let mut reordered_lines = rule_lines.clone();
        if reverse {
            reordered_lines.reverse();
        } else if reordered_lines.len() > 1 {
            let first = reordered_lines.remove(0);
            reordered_lines.push(first);
        }
        let reordered_rules = reordered_lines.join("\n");
        let yaml_reordered = indoc::formatdoc! {"
            rules:
            {reordered_rules}"
        };

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

// ========================================
// Wrapper recursive evaluation
// Wrappers unwrap the inner command and evaluate it against rules.
// ========================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// `sudo <inner_cmd>` should evaluate the inner command against rules
    #[test]
    fn prop_wrapper_sudo_unwraps(
        inner_cmd in arb_cmd_name(),
        inner_args in proptest::collection::vec(arb_safe_positional(), 0..=3),
        is_allow in proptest::bool::ANY,
    ) {
        let action = if is_allow { "allow" } else { "deny" };
        let pattern = format!("{inner_cmd} *");
        let yaml = build_yaml_config_with_wrappers(action, &pattern, &["sudo <cmd>"]);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let inner = build_command(&inner_cmd, &inner_args);
        let command = format!("sudo {inner}");
        let result = evaluate_command(&config, &command, &ctx).unwrap();

        prop_assert_allow_or_deny!(result.action, is_allow, format!("sudo wrapper: command={:?}", command));
    }

    /// `bash -c '<inner_cmd>'` should evaluate the inner command
    #[test]
    fn prop_wrapper_bash_c_unwraps(
        inner_cmd in arb_cmd_name(),
        inner_args in proptest::collection::vec(arb_safe_positional(), 0..=2),
        is_allow in proptest::bool::ANY,
    ) {
        let action = if is_allow { "allow" } else { "deny" };
        let pattern = format!("{inner_cmd} *");
        let yaml = build_yaml_config_with_wrappers(action, &pattern, &["bash -c <cmd>"]);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let inner = build_command(&inner_cmd, &inner_args);
        let command = format!("bash -c {inner}");
        let result = evaluate_command(&config, &command, &ctx).unwrap();

        prop_assert_allow_or_deny!(result.action, is_allow, format!("bash -c wrapper: command={:?}", command));
    }

    /// Nested wrappers: `sudo bash -c '<inner>'` should unwrap through both
    #[test]
    fn prop_wrapper_nested_unwraps(
        inner_cmd in arb_cmd_name(),
        inner_args in proptest::collection::vec(arb_safe_positional(), 0..=2),
        is_allow in proptest::bool::ANY,
    ) {
        let action = if is_allow { "allow" } else { "deny" };
        let pattern = format!("{inner_cmd} *");
        let yaml = build_yaml_config_with_wrappers(
            action, &pattern, &["sudo <cmd>", "bash -c <cmd>"],
        );
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let inner = build_command(&inner_cmd, &inner_args);
        let command = format!("sudo bash -c {inner}");
        let result = evaluate_command(&config, &command, &ctx).unwrap();

        prop_assert_allow_or_deny!(result.action, is_allow, format!("nested wrapper: command={:?}", command));
    }

    /// Wrapper with compound inner: `bash -c 'allowed && denied'` should deny
    #[test]
    fn prop_wrapper_compound_inner_deny_propagates(
        allowed_cmd in arb_cmd_name(),
        denied_cmd in arb_cmd_name(),
        operator in arb_operator(),
    ) {
        prop_assume!(allowed_cmd != denied_cmd);

        let yaml = indoc::formatdoc! {"
            definitions:
              wrappers:
                - 'bash -c <cmd>'
            rules:
              - allow: '{allowed_cmd} *'
              - deny: '{denied_cmd} *'
        "};
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        let inner = format!("{allowed_cmd} arg {operator} {denied_cmd} arg");
        let command = format!("bash -c '{inner}'");
        let result = evaluate_command(&config, &command, &ctx).unwrap();
        prop_assert!(
            matches!(result.action, Action::Deny(_)),
            "wrapper with compound inner should deny: command={:?} result={:?}",
            command, result.action
        );
    }

    /// No panics with diverse commands passed through wrappers
    #[test]
    fn prop_no_panic_wrapper_evaluation(
        command in arb_simple_command(),
        pattern in arb_rich_pattern(),
        action in prop_oneof![
            Just("allow".to_string()),
            Just("deny".to_string()),
            Just("ask".to_string()),
        ],
        wrapper in prop_oneof![
            Just("sudo <cmd>".to_string()),
            Just("bash -c <cmd>".to_string()),
            Just("sh -c <cmd>".to_string()),
            Just("env <opts> <vars> <cmd>".to_string()),
            Just("xargs * <cmd>".to_string()),
        ],
    ) {
        let escaped_pattern = pattern.replace('\'', "''");
        let escaped_wrapper = wrapper.replace('\'', "''");
        let yaml = indoc::formatdoc! {"
            definitions:
              wrappers:
                - '{escaped_wrapper}'
            rules:
              - {action}: '{escaped_pattern}'
        "};
        if let Ok(config) = parse_config(&yaml) {
            let ctx = empty_context();
            let _ = evaluate_command(&config, &command, &ctx);
        }
    }

    /// Deeply nested wrappers must trigger RecursionDepthExceeded, not
    /// stack-overflow (PR #149: 97b46a7). The depth guard requires that
    /// each recursive call increments `depth`; without `depth + 1` the
    /// guard never fires and this test fails.
    #[test]
    fn prop_wrapper_deep_nesting_hits_depth_guard(
        inner_cmd in arb_cmd_name(),
        inner_args in proptest::collection::vec(arb_safe_positional(), 0..=2),
        nesting in 12..=20usize,
    ) {
        let pattern = format!("{inner_cmd} *");
        let yaml = build_yaml_config_with_wrappers("allow", &pattern, &["sudo <cmd>"]);
        let config = parse_config(&yaml).unwrap();
        let ctx = empty_context();

        // Build: sudo sudo sudo ... <inner_cmd> <args>
        let inner = build_command(&inner_cmd, &inner_args);
        let command = format!("{}{inner}", "sudo ".repeat(nesting));
        let result = evaluate_command(&config, &command, &ctx);
        // Nesting exceeds MAX_WRAPPER_DEPTH (10), so the depth guard must fire
        prop_assert!(result.is_err(),
            "deeply nested wrapper should return RecursionDepthExceeded: command={:?} result={:?}",
            command, result);
    }
}
