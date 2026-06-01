//! Rule-time alias expansion.
//!
//! Aliases factor out repeated prefixes from rule patterns. At rule
//! evaluation time, each rule pattern whose leading command token equals
//! an alias name is rewritten — once per alias pattern — by substituting
//! the alias pattern string for the alias name in the rule pattern.
//! Expansion is applied transitively until no leading token matches an
//! alias, with cycle detection and a hard depth cap.
//!
//! Example:
//!
//! ```yaml
//! aliases:
//!   kubectl:
//!     - 'kubectl [--namespace|-n *]'
//! rules:
//!   - allow: 'kubectl get pods'
//! ```
//!
//! The rule `kubectl get pods` expands to
//! `kubectl [--namespace|-n *] get pods`, so all of `kubectl get pods`,
//! `kubectl -n prod get pods`, and `kubectl --namespace prod get pods`
//! match it.

use std::collections::{HashMap, HashSet};

use crate::config::AliasDefinition;
use crate::rules::RuleError;

/// Maximum depth of recursive alias expansion for a single rule pattern.
pub const MAX_ALIAS_DEPTH: usize = 5;

/// A rule pattern after alias expansion.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpandedRulePattern {
    /// The expanded pattern string, ready for `parse_multi`.
    pub pattern: String,
    /// Names of aliases referenced during expansion, in expansion order
    /// (outermost-rule reference first). Empty when no alias was applied.
    pub chain: Vec<String>,
}

/// Expand a rule pattern by replacing leading alias-name tokens with the
/// alias pattern(s). When the pattern's leading token is not an alias,
/// returns the original pattern with an empty chain.
///
/// An alias whose definition has N patterns produces N expanded variants
/// for the rule. Expansion recurses on each variant until the leading
/// token of the expanded pattern is no longer an alias name, a cycle is
/// detected (same alias re-applied in the current chain), or
/// `MAX_ALIAS_DEPTH` is reached.
pub fn expand_rule_pattern(
    pattern: &str,
    aliases: Option<&HashMap<String, AliasDefinition>>,
) -> Result<Vec<ExpandedRulePattern>, RuleError> {
    let aliases = match aliases {
        Some(a) if !a.is_empty() => a,
        _ => {
            return Ok(vec![ExpandedRulePattern {
                pattern: pattern.to_string(),
                chain: Vec::new(),
            }]);
        }
    };
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut chain: Vec<String> = Vec::new();
    expand_recursive(pattern, aliases, &mut seen, &mut chain, 0, &mut out)?;
    Ok(out)
}

fn expand_recursive(
    pattern: &str,
    aliases: &HashMap<String, AliasDefinition>,
    seen: &mut HashSet<String>,
    chain: &mut Vec<String>,
    depth: usize,
    out: &mut Vec<ExpandedRulePattern>,
) -> Result<(), RuleError> {
    let (head, tail) = split_leading_token(pattern);
    let alias_hit = head.and_then(|h| aliases.get(h).map(|def| (h, def)));
    let already_seen = head.is_some_and(|h| seen.contains(h));
    let Some((head_name, def)) = alias_hit.filter(|_| !already_seen && depth < MAX_ALIAS_DEPTH)
    else {
        out.push(ExpandedRulePattern {
            pattern: pattern.to_string(),
            chain: chain.clone(),
        });
        return Ok(());
    };
    let head_string = head_name.to_string();
    seen.insert(head_string.clone());
    chain.push(head_string);
    for alias_pattern in def.patterns() {
        let combined = if tail.is_empty() {
            alias_pattern.to_string()
        } else {
            format!("{alias_pattern} {tail}")
        };
        expand_recursive(&combined, aliases, seen, chain, depth + 1, out)?;
    }
    chain.pop();
    seen.remove(head_name);
    Ok(())
}

/// Split off the leading whitespace-delimited token. Returns
/// `(Some(token), tail)` if a token was found, where `tail` is the
/// remainder with leading whitespace trimmed; otherwise `(None, "")`.
fn split_leading_token(pattern: &str) -> (Option<&str>, &str) {
    let trimmed = pattern.trim_start();
    if trimmed.is_empty() {
        return (None, "");
    }
    match trimmed.split_once(char::is_whitespace) {
        Some((head, rest)) => (Some(head), rest.trim_start()),
        None => (Some(trimmed), ""),
    }
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

    fn expand(pattern: &str, cfg: &Config) -> Vec<ExpandedRulePattern> {
        expand_rule_pattern(pattern, cfg.aliases.as_ref()).unwrap()
    }

    #[test]
    fn no_aliases_passthrough() {
        let cfg = parse_config("{}").unwrap();
        let out = expand("git status", &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, "git status");
        assert!(out[0].chain.is_empty());
    }

    #[test]
    fn non_alias_head_passthrough() {
        let cfg = config_from(indoc! {"
            aliases:
              kubectl:
                - 'kubectl [--namespace|-n *]'
        "});
        let out = expand("git status", &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, "git status");
        assert!(out[0].chain.is_empty());
    }

    #[test]
    fn expands_leading_alias_token() {
        let cfg = config_from(indoc! {"
            aliases:
              kubectl:
                - 'kubectl [--namespace|-n *]'
        "});
        let out = expand("kubectl get pods", &cfg);
        // After one expansion the head is still `kubectl`, which is seen;
        // cycle detection stops further recursion.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, "kubectl [--namespace|-n *] get pods");
        assert_eq!(out[0].chain, vec!["kubectl".to_string()]);
    }

    #[test]
    fn expands_no_tail() {
        let cfg = config_from(indoc! {"
            aliases:
              k:
                - 'kubectl'
        "});
        let out = expand("k", &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, "kubectl");
        assert_eq!(out[0].chain, vec!["k".to_string()]);
    }

    #[test]
    fn multi_pattern_alias_produces_multiple_expansions() {
        let cfg = config_from(indoc! {"
            aliases:
              k:
                - 'kubectl'
                - 'kubectl --kubeconfig *'
        "});
        let out = expand("k get pods", &cfg);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].pattern, "kubectl get pods");
        assert_eq!(out[1].pattern, "kubectl --kubeconfig * get pods");
        for e in &out {
            assert_eq!(e.chain, vec!["k".to_string()]);
        }
    }

    #[test]
    fn recursive_expansion_chain_order() {
        let cfg = config_from(indoc! {"
            aliases:
              outer:
                - 'inner'
              inner:
                - 'cargo special'
        "});
        let out = expand("outer foo", &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, "cargo special foo");
        assert_eq!(out[0].chain, vec!["outer".to_string(), "inner".to_string()]);
    }

    #[test]
    fn cycle_through_two_aliases_is_broken() {
        let cfg = config_from(indoc! {"
            aliases:
              x:
                - 'y'
              y:
                - 'x'
        "});
        let out = expand("x foo", &cfg);
        // x -> y -> (x is seen, stop)
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, "x foo");
        assert_eq!(out[0].chain, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn depth_limit_caps_runaway() {
        let cfg = config_from(indoc! {"
            aliases:
              a:
                - 'b'
              b:
                - 'a x'
        "});
        // a -> b -> a (seen) — cycle detection stops first, but verify
        // depth tracking would also cap if cycles were absent.
        let out = expand("a", &cfg);
        assert!(!out.is_empty());
        for e in &out {
            assert!(e.chain.len() <= MAX_ALIAS_DEPTH);
        }
    }

    #[test]
    fn single_string_alias_form_works() {
        let cfg = config_from(indoc! {"
            aliases:
              k: 'kubectl'
        "});
        let out = expand("k get pods", &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, "kubectl get pods");
        assert_eq!(out[0].chain, vec!["k".to_string()]);
    }

    #[rstest]
    #[case::single_token("kubectl", Some("kubectl"), "")]
    #[case::with_tail("kubectl get pods", Some("kubectl"), "get pods")]
    #[case::leading_spaces("  k  v", Some("k"), "v")]
    #[case::empty("", None, "")]
    #[case::whitespace_only("   ", None, "")]
    fn split_leading_token_cases(
        #[case] input: &str,
        #[case] expected_head: Option<&str>,
        #[case] expected_tail: &str,
    ) {
        let (head, tail) = split_leading_token(input);
        assert_eq!(head, expected_head);
        assert_eq!(tail, expected_tail);
    }
}
