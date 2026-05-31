//! Command alias expansion.
//!
//! Aliases rewrite the leading tokens of a command before rule evaluation.
//! Each alias entry maps a name (e.g. `runok`) to one or more patterns
//! (e.g. `cargo run [--quiet] [--release] --`). When a command's tokens
//! match an alias pattern as a prefix, the matched prefix is replaced with
//! the alias name and the rewritten command flows through normal rule
//! evaluation, so existing rules keyed on the alias name (e.g. `runok *`)
//! apply unchanged.
//!
//! Prefix matching is delegated to the regular rule pattern matcher via its
//! `matches_prefix` entry point: the pattern is matched as a partial match
//! and the matcher reports whatever command tokens it did not consume. The
//! rewritten command is the alias name followed by that remainder. This
//! means the full pattern syntax (literals, alternations, optional groups,
//! flag-with-value, var refs, flag groups, ...) is available to alias
//! authors without reimplementing any matching logic, and prefix-consumed
//! tokens (including the value half of `FlagWithValue` like `--context *`)
//! do not leak into the rewritten tail.
//!
//! `fuse_trailing_flag_wildcard` post-processes each parsed alias pattern so
//! that a trailing `<flag> *` (which the parser conservatively leaves as
//! `Alternation(<flag>) Wildcard` to preserve the boolean-flag-plus-trailing
//! semantics of allow rules) is read as `FlagWithValue(<flag>, *)` here.
//!
//! Expansion is recursive: a rewritten command may itself match another
//! alias. Cycles are detected by tracking the chain of applied alias names
//! and a hard depth limit caps runaway expansion.

use std::collections::{HashMap, HashSet};

use crate::config::{AliasDefinition, Config, Definitions};
use crate::rules::RuleError;
use crate::rules::command_parser::{FlagSchema, parse_command};
use crate::rules::pattern_matcher::matches_prefix;
use crate::rules::pattern_parser::{Pattern, PatternToken, parse_multi};
use crate::rules::rule_engine::build_flag_schema;

/// Maximum number of alias rewrites applied to a single command.
pub const MAX_ALIAS_DEPTH: usize = 5;

/// Result of attempting to expand aliases for a command.
#[derive(Debug, Clone, PartialEq)]
pub struct AliasExpansion {
    /// Final command string after all applicable alias rewrites.
    pub command: String,
    /// Names of aliases applied, in order. Empty when no alias matched.
    pub chain: Vec<String>,
}

/// Expand aliases on `command` until no further alias matches, a cycle is
/// detected, or the depth limit is reached.
///
/// Returns the (possibly rewritten) command together with the chain of
/// alias names that fired. When no alias applies, the original command is
/// returned with an empty chain.
pub fn expand_aliases(command: &str, config: &Config) -> Result<AliasExpansion, RuleError> {
    let aliases = match config.aliases.as_ref() {
        Some(a) if !a.is_empty() => a,
        _ => {
            return Ok(AliasExpansion {
                command: command.to_string(),
                chain: Vec::new(),
            });
        }
    };

    let default_defs = Definitions::default();
    let definitions = config.definitions.as_ref().unwrap_or(&default_defs);

    // Pre-parse each alias pattern once and append a trailing wildcard so
    // the existing matcher captures the remaining argv. Ordering by alias
    // name keeps matching deterministic across HashMap iteration orders.
    let parsed = parse_alias_patterns(aliases, definitions)?;

    let mut current = command.to_string();
    let mut chain: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for _ in 0..MAX_ALIAS_DEPTH {
        let Some(hit) = try_apply_once(&current, &parsed, definitions)? else {
            break;
        };
        if !seen.insert(hit.alias.clone()) {
            // Cycle: this alias already fired in the chain. Stop deterministically.
            break;
        }
        chain.push(hit.alias);
        current = hit.command;
    }

    Ok(AliasExpansion {
        command: current,
        chain,
    })
}

struct ParsedAliases {
    entries: Vec<(String, Vec<ParsedAliasPattern>)>,
}

struct ParsedAliasPattern {
    pattern: Pattern,
    schema: FlagSchema,
}

fn parse_alias_patterns(
    aliases: &HashMap<String, AliasDefinition>,
    definitions: &Definitions,
) -> Result<ParsedAliases, RuleError> {
    let mut names: Vec<&String> = aliases.keys().collect();
    names.sort();

    let mut entries = Vec::with_capacity(aliases.len());
    for name in names {
        let def = &aliases[name];
        let mut patterns: Vec<ParsedAliasPattern> = Vec::new();
        for pat_str in def.patterns() {
            for mut pat in parse_multi(pat_str)? {
                fuse_trailing_flag_wildcard(&mut pat.tokens);
                let schema = build_flag_schema(&pat, definitions);
                patterns.push(ParsedAliasPattern {
                    pattern: pat,
                    schema,
                });
            }
        }
        entries.push((name.clone(), patterns));
    }
    Ok(ParsedAliases { entries })
}

struct AliasHit {
    alias: String,
    command: String,
}

fn try_apply_once(
    command: &str,
    parsed: &ParsedAliases,
    definitions: &Definitions,
) -> Result<Option<AliasHit>, RuleError> {
    for (alias, patterns) in &parsed.entries {
        for entry in patterns {
            // A schema-specific parse failure shouldn't abort the whole
            // expansion — other aliases may still match the command with
            // a schema that resolves the offending flag differently.
            let Ok(parsed_command) = parse_command(command, &entry.schema) else {
                continue;
            };
            let Some((_captures, remainder)) =
                matches_prefix(&entry.pattern, &parsed_command, definitions)
            else {
                continue;
            };
            let rewritten = rebuild_command(alias, &remainder)?;
            return Ok(Some(AliasHit {
                alias: alias.clone(),
                command: rewritten,
            }));
        }
    }
    Ok(None)
}

/// Fuse a trailing `[Alternation(<flag>), Wildcard]` into a single
/// `FlagWithValue { aliases: [<flag>], value: Wildcard }`.
///
/// The pattern parser conservatively keeps a trailing `*` after a flag as a
/// standalone `Wildcard`, because for a regular allow rule `cmd -f *` means
/// "boolean flag `-f` plus a trailing wildcard for the remaining argv". In
/// an alias prefix, that reading is meaningless — the trailing argv is
/// already returned separately by `matches_prefix`, so `cmd --context *` at
/// the end of an alias pattern is only useful when read as "`--context`
/// takes a wildcard value". This adjustment lives in `alias_expander` (not
/// in the parser) so the parser stays unaware of alias semantics.
fn fuse_trailing_flag_wildcard(tokens: &mut Vec<PatternToken>) {
    let n = tokens.len();
    if n < 2 {
        return;
    }
    if !matches!(tokens[n - 1], PatternToken::Wildcard) {
        return;
    }
    let is_flag_alt = matches!(
        &tokens[n - 2],
        PatternToken::Alternation(alts)
            if !alts.is_empty() && alts.iter().all(|a| a.starts_with('-') && a != "--")
    );
    if !is_flag_alt {
        return;
    }
    tokens.pop();
    let Some(PatternToken::Alternation(aliases)) = tokens.pop() else {
        unreachable!("checked above");
    };
    tokens.push(PatternToken::FlagWithValue {
        aliases,
        value: Box::new(PatternToken::Wildcard),
    });
}

fn rebuild_command(alias: &str, rest_tokens: &[String]) -> Result<String, RuleError> {
    if rest_tokens.is_empty() {
        return Ok(alias.to_string());
    }
    let joined =
        shlex::try_join(std::iter::once(alias).chain(rest_tokens.iter().map(String::as_str)))?;
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    use crate::config::{Config, parse_config};

    fn config_from(yaml: &str) -> Config {
        parse_config(yaml).unwrap()
    }

    #[test]
    fn parses_alias_section() {
        let cfg = config_from(indoc! {"
            aliases:
              runok:
                - 'cargo run [--quiet] [--release] --'
        "});
        assert!(cfg.aliases.unwrap().contains_key("runok"));
    }

    #[rstest]
    #[case::quiet(
        "cargo run --quiet -- check",
        "runok check",
        vec!["runok"],
    )]
    #[case::release(
        "cargo run --release -- exec git status",
        "runok exec git status",
        vec!["runok"],
    )]
    #[case::both_flags(
        "cargo run --quiet --release -- check",
        "runok check",
        vec!["runok"],
    )]
    #[case::no_flags(
        "cargo run -- check",
        "runok check",
        vec!["runok"],
    )]
    fn expands_runok_alias(#[case] input: &str, #[case] expected: &str, #[case] chain: Vec<&str>) {
        let cfg = config_from(indoc! {"
            aliases:
              runok:
                - 'cargo run [--quiet] [--release] --'
        "});
        let exp = expand_aliases(input, &cfg).unwrap();
        assert_eq!(exp.command, expected);
        let got_chain: Vec<&str> = exp.chain.iter().map(String::as_str).collect();
        assert_eq!(got_chain, chain);
    }

    #[test]
    fn no_match_returns_original() {
        let cfg = config_from(indoc! {"
            aliases:
              runok:
                - 'cargo run --'
        "});
        let exp = expand_aliases("git status", &cfg).unwrap();
        assert_eq!(exp.command, "git status");
        assert!(exp.chain.is_empty());
    }

    #[test]
    fn missing_required_token_skips_alias() {
        // No `--` separator in command, so the alias must not match.
        let cfg = config_from(indoc! {"
            aliases:
              runok:
                - 'cargo run --'
        "});
        let exp = expand_aliases("cargo run check", &cfg).unwrap();
        assert_eq!(exp.command, "cargo run check");
        assert!(exp.chain.is_empty());
    }

    #[test]
    fn quotes_tokens_with_whitespace() {
        let cfg = config_from(indoc! {"
            aliases:
              runok:
                - 'cargo run --'
        "});
        let exp = expand_aliases("cargo run -- 'hello world'", &cfg).unwrap();
        assert_eq!(exp.command, "runok 'hello world'");
    }

    #[test]
    fn recursive_expansion_chains_aliases() {
        let cfg = config_from(indoc! {"
            aliases:
              inner:
                - 'cargo special'
              outer:
                - 'inner'
        "});
        let exp = expand_aliases("cargo special foo", &cfg).unwrap();
        assert_eq!(exp.command, "outer foo");
        assert_eq!(exp.chain, vec!["inner", "outer"]);
    }

    #[test]
    fn cycle_is_detected_and_stops() {
        let cfg = config_from(indoc! {"
            aliases:
              x:
                - 'y'
              y:
                - 'x'
        "});
        let exp = expand_aliases("x foo", &cfg).unwrap();
        assert!(exp.chain.len() <= MAX_ALIAS_DEPTH);
    }

    #[test]
    fn empty_aliases_passthrough() {
        let cfg = parse_config("{}").unwrap();
        let exp = expand_aliases("git status", &cfg).unwrap();
        assert_eq!(exp.command, "git status");
        assert!(exp.chain.is_empty());
    }

    #[test]
    fn single_string_alias_form() {
        let cfg = config_from(indoc! {"
            aliases:
              runok: 'cargo run --'
        "});
        let exp = expand_aliases("cargo run -- check", &cfg).unwrap();
        assert_eq!(exp.command, "runok check");
    }

    #[test]
    fn alternation_in_alias_pattern() {
        let cfg = config_from(indoc! {"
            aliases:
              runok:
                - 'cargo run|r --'
        "});
        let exp_run = expand_aliases("cargo run -- check", &cfg).unwrap();
        assert_eq!(exp_run.command, "runok check");
        let exp_r = expand_aliases("cargo r -- check", &cfg).unwrap();
        assert_eq!(exp_r.command, "runok check");
    }

    #[test]
    fn flag_with_value_in_alias_pattern() {
        // The existing matcher handles `-X|--method GET` (value-taking flag);
        // alias prefix matching reuses that without any special-casing.
        let cfg = config_from(indoc! {"
            aliases:
              curl-get:
                - 'curl -X|--request GET'
        "});
        let exp = expand_aliases("curl -X GET https://example.com", &cfg).unwrap();
        assert_eq!(exp.command, "curl-get https://example.com");
    }

    /// Regression: a flag-with-value whose value is `*` (e.g. `--context *`)
    /// must consume both the flag and its value as part of the alias prefix.
    /// The captured value must not leak into the rewritten tail.
    #[rstest]
    #[case::space_separated("kubectl --context foo bar baz", "kc bar baz")]
    #[case::equals_joined("kubectl --context=foo bar baz", "kc bar baz")]
    #[case::flag_only_no_extra_args("kubectl --context foo", "kc")]
    #[case::flag_after_other_args("kubectl get pods --context foo", "kc get pods")]
    fn wildcard_flag_value_in_alias_pattern(#[case] input: &str, #[case] expected: &str) {
        let cfg = config_from(indoc! {"
            aliases:
              kc:
                - 'kubectl --context *'
        "});
        let exp = expand_aliases(input, &cfg).unwrap();
        assert_eq!(exp.command, expected);
        assert_eq!(exp.chain, vec!["kc"]);
    }

    /// Flag-with-value whose value is `*` inside an optional group or as part
    /// of a flag-alias alternation must not leak captured values either.
    #[rstest]
    #[case::optional_flag_present("git [-C *]", "git -C /tmp status", "g status")]
    #[case::optional_flag_absent("git [-C *]", "git status", "g status")]
    #[case::alternation_short_form(
        "kubectl -n|--namespace *",
        "kubectl -n prod get pods",
        "g get pods"
    )]
    #[case::alternation_long_form(
        "kubectl -n|--namespace *",
        "kubectl --namespace prod get pods",
        "g get pods"
    )]
    #[case::multiple_flag_with_values(
        "kubectl --context * --namespace *",
        "kubectl --context foo --namespace bar get pods",
        "g get pods"
    )]
    fn flag_with_value_value_wildcard_does_not_leak(
        #[case] pat: &str,
        #[case] input: &str,
        #[case] expected: &str,
    ) {
        let yaml = format!(
            indoc! {"
                aliases:
                  g:
                    - '{}'
            "},
            pat
        );
        let cfg = config_from(&yaml);
        let exp = expand_aliases(input, &cfg).unwrap();
        assert_eq!(exp.command, expected);
    }

    /// Other pattern syntax elements used in alias patterns should not cause
    /// captures from the prefix to leak into the rewritten tail.
    #[rstest]
    #[case::command_alternation("cargo run|r --", "cargo r -- build", "a build")]
    #[case::optional_literal_flag_present("cargo build [--release]", "cargo build --release", "a")]
    #[case::optional_literal_flag_absent("cargo build [--release]", "cargo build", "a")]
    #[case::optional_flag_with_literal_value_present(
        "curl [-X|--request GET]",
        "curl -X GET https://example.com",
        "a https://example.com"
    )]
    #[case::optional_flag_with_literal_value_absent(
        "curl [-X|--request GET]",
        "curl https://example.com",
        "a https://example.com"
    )]
    #[case::multi_word_alternation(
        "\"npx prettier\"|prettier",
        "prettier --check .",
        "a --check ."
    )]
    fn alias_pattern_syntax_does_not_leak_prefix(
        #[case] pat: &str,
        #[case] input: &str,
        #[case] expected: &str,
    ) {
        let yaml = format!(
            indoc! {"
                aliases:
                  a:
                    - '{}'
            "},
            pat
        );
        let cfg = config_from(&yaml);
        let exp = expand_aliases(input, &cfg).unwrap();
        assert_eq!(exp.command, expected);
    }

    /// Alias name == command name (e.g. `kubectl: kubectl [-n *]`) must
    /// produce a sensible rewrite without infinite expansion. The cycle
    /// detector stops the loop after one fire even when the rewrite is
    /// identical to the input.
    #[rstest]
    #[case::optional_present("kubectl -n prod get pods", "kubectl get pods")]
    #[case::optional_absent("kubectl get pods", "kubectl get pods")]
    #[case::only_flag_value("kubectl -n prod", "kubectl")]
    fn alias_name_equals_command_name(#[case] input: &str, #[case] expected: &str) {
        let cfg = config_from(indoc! {"
            aliases:
              kubectl:
                - 'kubectl [-n *]'
        "});
        let exp = expand_aliases(input, &cfg).unwrap();
        assert_eq!(exp.command, expected);
        assert_eq!(exp.chain, vec!["kubectl"]);
    }

    /// `<var:name>` captures the matched token but the token is still part
    /// of the consumed prefix, so it must not leak into the rewritten tail.
    #[test]
    fn var_ref_in_alias_pattern_does_not_leak() {
        let cfg = config_from(indoc! {"
            definitions:
              vars:
                instance-id:
                  values:
                    - i-abc123
            aliases:
              ec2-stop:
                - 'aws ec2 stop-instances --instance-ids <var:instance-id>'
        "});
        let exp = expand_aliases(
            "aws ec2 stop-instances --instance-ids i-abc123 --dry-run",
            &cfg,
        )
        .unwrap();
        assert_eq!(exp.command, "ec2-stop --dry-run");
    }
}
