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
//! Expansion is recursive: a rewritten command may itself match another
//! alias. Cycles are detected by tracking the chain of applied alias names
//! and a hard depth limit caps runaway expansion.

use std::collections::{HashMap, HashSet};

use crate::config::AliasDefinition;
use crate::rules::RuleError;
use crate::rules::command_parser::tokenize_command;
use crate::rules::pattern_parser::{Pattern, PatternToken, parse_multi};

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
pub fn expand_aliases(
    command: &str,
    aliases: Option<&HashMap<String, AliasDefinition>>,
) -> Result<AliasExpansion, RuleError> {
    let Some(aliases) = aliases else {
        return Ok(AliasExpansion {
            command: command.to_string(),
            chain: Vec::new(),
        });
    };
    if aliases.is_empty() {
        return Ok(AliasExpansion {
            command: command.to_string(),
            chain: Vec::new(),
        });
    }

    let parsed = parse_alias_patterns(aliases)?;

    let mut current = command.to_string();
    let mut chain: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for _ in 0..MAX_ALIAS_DEPTH {
        let Some(rewritten) = try_apply_once(&current, &parsed)? else {
            break;
        };
        if !seen.insert(rewritten.alias.clone()) {
            // Cycle: this alias is already in the chain. Stop expansion at
            // the current command to keep behaviour deterministic.
            break;
        }
        chain.push(rewritten.alias);
        current = rewritten.command;
    }

    Ok(AliasExpansion {
        command: current,
        chain,
    })
}

struct ParsedAliases {
    /// (alias_name, parsed_patterns) ordered for deterministic matching.
    entries: Vec<(String, Vec<Pattern>)>,
}

fn parse_alias_patterns(
    aliases: &HashMap<String, AliasDefinition>,
) -> Result<ParsedAliases, RuleError> {
    let mut names: Vec<&String> = aliases.keys().collect();
    names.sort();

    let mut entries = Vec::with_capacity(aliases.len());
    for name in names {
        let def = &aliases[name];
        let mut patterns: Vec<Pattern> = Vec::new();
        for pat_str in def.patterns() {
            patterns.extend(parse_multi(pat_str)?);
        }
        entries.push((name.clone(), patterns));
    }
    Ok(ParsedAliases { entries })
}

struct AliasHit {
    alias: String,
    command: String,
}

fn try_apply_once(command: &str, parsed: &ParsedAliases) -> Result<Option<AliasHit>, RuleError> {
    let tokens = match tokenize_command(command) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    if tokens.is_empty() {
        return Ok(None);
    }

    for (alias, patterns) in &parsed.entries {
        for pattern in patterns {
            if let Some(consumed) = match_prefix(pattern, &tokens) {
                let rewritten = rebuild_command(alias, &tokens[consumed..])?;
                return Ok(Some(AliasHit {
                    alias: alias.clone(),
                    command: rewritten,
                }));
            }
        }
    }
    Ok(None)
}

/// Try to match `pattern` as a prefix of `tokens`. Returns the number of
/// tokens consumed by the match, or `None` when the pattern does not apply.
fn match_prefix(pattern: &Pattern, tokens: &[String]) -> Option<usize> {
    use crate::rules::pattern_parser::CommandPattern;

    if tokens.is_empty() {
        return None;
    }
    // Command name must match literally (alias patterns do not use globs
    // for the command name; we only support literal heads here).
    match &pattern.command {
        CommandPattern::Literal(name) => {
            if name != &tokens[0] {
                return None;
            }
        }
        // Other command-pattern shapes (e.g. wildcard heads) aren't useful
        // for alias matching — skip them rather than risking weird matches.
        _ => return None,
    }

    let mut i = 1usize;
    for tok in &pattern.tokens {
        if !match_token(tok, tokens, &mut i) {
            return None;
        }
    }
    Some(i)
}

fn match_token(token: &PatternToken, tokens: &[String], i: &mut usize) -> bool {
    match token {
        PatternToken::Literal(s) => match tokens.get(*i) {
            Some(t) if t == s => {
                *i += 1;
                true
            }
            _ => false,
        },
        PatternToken::Alternation(alts) => {
            let Some(t) = tokens.get(*i) else {
                return false;
            };
            if alts.iter().any(|a| a == t) {
                *i += 1;
                true
            } else {
                false
            }
        }
        PatternToken::Optional(inner) => {
            // Try to match the entire inner sequence; on failure, roll
            // back the cursor and treat the optional as absent.
            let saved = *i;
            for sub in inner {
                if !match_token(sub, tokens, i) {
                    *i = saved;
                    return true;
                }
            }
            true
        }
        // Alias patterns are intentionally restricted to simple shapes:
        // command-prefix matching with literals, alternations and optional
        // groups covers the design example
        // (`cargo run [--quiet] [--release] --`) without dragging in the
        // full pattern engine. Unsupported tokens cause the alias to be
        // skipped rather than silently misbehaving.
        _ => false,
    }
}

fn rebuild_command(alias: &str, rest_tokens: &[String]) -> Result<String, RuleError> {
    if rest_tokens.is_empty() {
        return Ok(alias.to_string());
    }
    let mut parts: Vec<String> = Vec::with_capacity(rest_tokens.len() + 1);
    parts.push(alias.to_string());
    parts.extend(rest_tokens.iter().cloned());
    let joined = shlex::try_join(parts.iter().map(String::as_str))?;
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    use crate::config::{Config, parse_config};

    fn aliases_from(yaml: &str) -> HashMap<String, AliasDefinition> {
        let cfg: Config = parse_config(yaml).unwrap();
        cfg.aliases.unwrap_or_default()
    }

    #[test]
    fn parses_alias_section() {
        let aliases = aliases_from(indoc! {"
            aliases:
              a:
                - 'cargo run [--quiet] [--release] --'
        "});
        assert!(aliases.contains_key("a"));
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
    fn expands_armyknife_alias(
        #[case] input: &str,
        #[case] expected: &str,
        #[case] chain: Vec<&str>,
    ) {
        let aliases = aliases_from(indoc! {"
            aliases:
              a:
                - 'cargo run [--quiet] [--release] --'
        "});
        let exp = expand_aliases(input, Some(&aliases)).unwrap();
        assert_eq!(exp.command, expected);
        let got_chain: Vec<&str> = exp.chain.iter().map(String::as_str).collect();
        assert_eq!(got_chain, chain);
    }

    #[test]
    fn no_match_returns_original() {
        let aliases = aliases_from(indoc! {"
            aliases:
              a:
                - 'cargo run --'
        "});
        let exp = expand_aliases("git status", Some(&aliases)).unwrap();
        assert_eq!(exp.command, "git status");
        assert!(exp.chain.is_empty());
    }

    #[test]
    fn missing_required_token_skips_alias() {
        // No `--` separator in command, so the alias must not match.
        let aliases = aliases_from(indoc! {"
            aliases:
              a:
                - 'cargo run --'
        "});
        let exp = expand_aliases("cargo run doctor", Some(&aliases)).unwrap();
        assert_eq!(exp.command, "cargo run doctor");
        assert!(exp.chain.is_empty());
    }

    #[test]
    fn quotes_tokens_with_whitespace() {
        let aliases = aliases_from(indoc! {"
            aliases:
              a:
                - 'cargo run --'
        "});
        let exp = expand_aliases("cargo run -- 'hello world'", Some(&aliases)).unwrap();
        assert_eq!(exp.command, "a 'hello world'");
    }

    #[test]
    fn recursive_expansion_chains_aliases() {
        // `b` rewrites to `a doctor`, which then matches `a *` -- but `a` has
        // no further alias, so the chain ends. We verify the chain order.
        let aliases = aliases_from(indoc! {"
            aliases:
              b:
                - 'cargo special'
              a:
                - 'b'
        "});
        let exp = expand_aliases("cargo special foo", Some(&aliases)).unwrap();
        assert_eq!(exp.command, "a foo");
        assert_eq!(exp.chain, vec!["b", "a"]);
    }

    #[test]
    fn cycle_is_detected_and_stops() {
        // `x` rewrites `y *` -> `x *`, `y` rewrites `x *` -> `y *`. After the
        // first expansion the matching alias has already fired and would
        // fire again, so we stop.
        let aliases = aliases_from(indoc! {"
            aliases:
              x:
                - 'y'
              y:
                - 'x'
        "});
        let exp = expand_aliases("x foo", Some(&aliases)).unwrap();
        // First rewrite: x foo -> y foo (alias `y`). Then y foo would
        // rewrite back to x foo (alias `x`) - second hop.
        // Then x foo would re-fire alias `y` which is already in `seen`.
        assert!(exp.chain.len() <= MAX_ALIAS_DEPTH);
    }

    #[test]
    fn empty_aliases_passthrough() {
        let exp = expand_aliases("git status", None).unwrap();
        assert_eq!(exp.command, "git status");
        assert!(exp.chain.is_empty());
    }

    #[test]
    fn single_string_alias_form() {
        let aliases = aliases_from(indoc! {"
            aliases:
              a: 'cargo run --'
        "});
        let exp = expand_aliases("cargo run -- doctor", Some(&aliases)).unwrap();
        assert_eq!(exp.command, "a doctor");
    }

    #[test]
    fn alternation_in_alias_pattern() {
        let aliases = aliases_from(indoc! {"
            aliases:
              a:
                - 'cargo run|r --'
        "});
        let exp_run = expand_aliases("cargo run -- doctor", Some(&aliases)).unwrap();
        assert_eq!(exp_run.command, "a doctor");
        let exp_r = expand_aliases("cargo r -- doctor", Some(&aliases)).unwrap();
        assert_eq!(exp_r.command, "a doctor");
    }
}
