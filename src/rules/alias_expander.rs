//! Command alias expansion.
//!
//! Aliases rewrite the leading tokens of a command before rule evaluation.
//! Each alias entry maps a name (e.g. `a`) to one or more patterns
//! (e.g. `cargo run [--quiet] [--release] --`). When a command's tokens
//! match an alias pattern as a prefix, the matched prefix is replaced with
//! the alias name and the rewritten command flows through normal rule
//! evaluation, so existing rules keyed on the alias name (e.g. `a *`) apply
//! unchanged.
//!
//! Prefix matching is delegated to the regular rule pattern matcher: each
//! alias pattern has a trailing `*` token appended so the matcher captures
//! any remaining argv as wildcards, and the rewritten command is built from
//! the alias name plus those captured tokens. This means the full pattern
//! syntax (literals, alternations, optional groups, flag-with-value, var
//! refs, flag groups, ...) is available to alias authors without reimplementing
//! any matching logic.
//!
//! Expansion is recursive: a rewritten command may itself match another
//! alias. Cycles are detected by tracking the chain of applied alias names
//! and a hard depth limit caps runaway expansion.

use std::collections::{HashMap, HashSet};

use crate::config::{AliasDefinition, Config, Definitions};
use crate::rules::RuleError;
use crate::rules::command_parser::{FlagSchema, parse_command};
use crate::rules::pattern_matcher::matches_with_captures;
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
                // Append a trailing wildcard so the matcher consumes any
                // remaining argv beyond the alias prefix and surfaces it
                // through `MatchCaptures.wildcards`.
                pat.tokens.push(PatternToken::Wildcard);
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
            let Some(captures) =
                matches_with_captures(&entry.pattern, &parsed_command, definitions)
            else {
                continue;
            };
            let rewritten = rebuild_command(alias, &captures.wildcards)?;
            return Ok(Some(AliasHit {
                alias: alias.clone(),
                command: rewritten,
            }));
        }
    }
    Ok(None)
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
              a:
                - 'cargo run [--quiet] [--release] --'
        "});
        assert!(cfg.aliases.unwrap().contains_key("a"));
    }

    #[rstest]
    #[case::quiet(
        "cargo run --quiet -- doctor",
        "a doctor",
        vec!["a"],
    )]
    #[case::release(
        "cargo run --release -- ai draft foo",
        "a ai draft foo",
        vec!["a"],
    )]
    #[case::both_flags(
        "cargo run --quiet --release -- doctor",
        "a doctor",
        vec!["a"],
    )]
    #[case::no_flags(
        "cargo run -- doctor",
        "a doctor",
        vec!["a"],
    )]
    fn expands_runok_alias(#[case] input: &str, #[case] expected: &str, #[case] chain: Vec<&str>) {
        let cfg = config_from(indoc! {"
            aliases:
              a:
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
              a:
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
              a:
                - 'cargo run --'
        "});
        let exp = expand_aliases("cargo run doctor", &cfg).unwrap();
        assert_eq!(exp.command, "cargo run doctor");
        assert!(exp.chain.is_empty());
    }

    #[test]
    fn quotes_tokens_with_whitespace() {
        let cfg = config_from(indoc! {"
            aliases:
              a:
                - 'cargo run --'
        "});
        let exp = expand_aliases("cargo run -- 'hello world'", &cfg).unwrap();
        assert_eq!(exp.command, "a 'hello world'");
    }

    #[test]
    fn recursive_expansion_chains_aliases() {
        let cfg = config_from(indoc! {"
            aliases:
              b:
                - 'cargo special'
              a:
                - 'b'
        "});
        let exp = expand_aliases("cargo special foo", &cfg).unwrap();
        assert_eq!(exp.command, "a foo");
        assert_eq!(exp.chain, vec!["b", "a"]);
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
              a: 'cargo run --'
        "});
        let exp = expand_aliases("cargo run -- doctor", &cfg).unwrap();
        assert_eq!(exp.command, "a doctor");
    }

    #[test]
    fn alternation_in_alias_pattern() {
        let cfg = config_from(indoc! {"
            aliases:
              a:
                - 'cargo run|r --'
        "});
        let exp_run = expand_aliases("cargo run -- doctor", &cfg).unwrap();
        assert_eq!(exp_run.command, "a doctor");
        let exp_r = expand_aliases("cargo r -- doctor", &cfg).unwrap();
        assert_eq!(exp_r.command, "a doctor");
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
}
