use std::ops::Range;

use yamlpatch::{Op, Patch};
use yamlpath::{Document, Route, route};

use super::MigrateError;
use super::migration::{Migration, MigrationTarget};
use crate::config::{ActionKind, AliasDefinition, Config, VarType, VarValue, parse_config};
use crate::rules::pattern_lexer::{LexToken, tokenize_spanned};

/// Escapes bare `?` (the optional-value marker in pattern strings) back to
/// the literal `\?` form in every pattern-syntax field of a config file, so
/// a pre-existing config that used a bare `?` as a literal flag value keeps
/// matching the same commands under the new syntax.
pub struct QuoteOptionalMarkerMigration;

impl Migration for QuoteOptionalMarkerMigration {
    fn id(&self) -> &'static str {
        "quote-optional-marker"
    }

    fn description(&self) -> &'static str {
        "Escape bare `?` in pattern strings to `\\?` so it stays a literal value instead of the optional-value marker"
    }

    fn target(&self) -> MigrationTarget {
        MigrationTarget::ConfigChain
    }

    fn migrate(&self, content: &str) -> Result<Option<String>, MigrateError> {
        migrate_quote_optional_marker(content)
    }
}

/// Collects every pattern-syntax field's YAML route alongside its escaped
/// replacement (when it contains a bare `?`), applies them as a batch of
/// format-preserving YAML patches, and re-parses the result as a safety
/// net: if anything about the patched output looks wrong, the whole
/// proposal is discarded (as an `Err`, so the caller can warn with the
/// file's path) rather than risking a corrupted config.
fn migrate_quote_optional_marker(content: &str) -> Result<Option<String>, MigrateError> {
    let Ok(config) = parse_config(content) else {
        // Not this migration's concern: an unparseable file can't be
        // migrated by anything that depends on `Config`.
        return Ok(None);
    };
    let patches = collect_patches(&config);

    if patches.is_empty() {
        return Ok(None);
    }

    let document = Document::new(content).map_err(|e| {
        MigrateError::Migration(format!("quote-optional-marker: failed to parse YAML: {e}"))
    })?;
    let patched = yamlpatch::apply_yaml_patches(&document, &patches).map_err(|e| {
        MigrateError::Migration(format!(
            "quote-optional-marker: failed to apply patches: {e}"
        ))
    })?;
    let result = patched.source().to_string();

    if parse_config(&result).is_err() {
        return Err(MigrateError::Migration(
            "quote-optional-marker: patched config fails to re-parse".to_string(),
        ));
    }

    Ok(Some(result))
}

/// Walk every pattern-syntax-bearing field reachable from a parsed `Config`
/// (`rules[].{allow,deny,ask}`, `definitions.wrappers`,
/// `definitions.flag_groups.*`, `definitions.aliases.*`, and
/// `definitions.vars.*.values` for pattern-typed values) and build a
/// `Replace` patch for each one that contains a bare `?`. Inline
/// `rules[].tests[]` are commands, not patterns, so they are not visited.
fn collect_patches(config: &Config) -> Vec<Patch<'_>> {
    let mut patches = Vec::new();

    for (i, rule) in config.rules.iter().flatten().enumerate() {
        let Some((action, pattern)) = rule.action_and_pattern() else {
            continue;
        };
        let key = match action {
            ActionKind::Allow => "allow",
            ActionKind::Deny => "deny",
            ActionKind::Ask => "ask",
        };
        push_patch(&mut patches, route!("rules", i, key), pattern);
    }

    let Some(definitions) = &config.definitions else {
        return patches;
    };

    for (i, pattern) in definitions.wrappers.iter().flatten().enumerate() {
        push_patch(&mut patches, route!("definitions", "wrappers", i), pattern);
    }

    for (name, pattern) in definitions.flag_groups.iter().flatten() {
        push_patch(
            &mut patches,
            route!("definitions", "flag_groups", name.as_str()),
            pattern,
        );
    }

    for (name, alias) in definitions.aliases.iter().flatten() {
        match alias {
            AliasDefinition::Single(pattern) => {
                push_patch(
                    &mut patches,
                    route!("definitions", "aliases", name.as_str()),
                    pattern,
                );
            }
            AliasDefinition::Many(patterns) => {
                for (i, pattern) in patterns.iter().enumerate() {
                    push_patch(
                        &mut patches,
                        route!("definitions", "aliases", name.as_str(), i),
                        pattern,
                    );
                }
            }
        }
    }

    for (name, var_def) in definitions.vars.iter().flatten() {
        for (i, value) in var_def.values.iter().enumerate() {
            if value.effective_type(var_def.var_type) != VarType::Pattern {
                continue;
            }
            let route = match value {
                VarValue::Plain(_) => route!("definitions", "vars", name.as_str(), "values", i),
                VarValue::Typed { .. } => {
                    route!("definitions", "vars", name.as_str(), "values", i, "value")
                }
            };
            push_patch(&mut patches, route, value.value());
        }
    }

    patches
}

fn push_patch<'a>(patches: &mut Vec<Patch<'a>>, route: Route<'a>, pattern: &str) {
    if let Some(escaped) = escape_optional_markers(pattern) {
        patches.push(Patch {
            route,
            operation: Op::Replace(yaml_serde::Value::String(escaped)),
        });
    }
}

/// Returns `pattern` with every bare `?` (lexed as
/// `LexToken::OptionalValue`) rewritten to `\?`, or `None` if it contains no
/// such token. A pattern that fails to lex at all is left untouched -- an
/// unrelated, pre-existing syntax error is reported by rule evaluation, not
/// this migration.
fn escape_optional_markers(pattern: &str) -> Option<String> {
    let spans: Vec<Range<usize>> = tokenize_spanned(pattern)
        .ok()?
        .into_iter()
        .filter(|(token, _)| *token == LexToken::OptionalValue)
        .map(|(_, span)| span)
        .collect();

    if spans.is_empty() {
        return None;
    }

    let mut result = pattern.to_string();
    for span in spans.into_iter().rev() {
        result.replace_range(span, r"\?");
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    /// `migrate_quote_optional_marker` returns `Result<Option<String>, _>` so
    /// the caller can attach file-path context to a failure; tests only
    /// exercise the success path, so unwrap the outer `Result` here once.
    fn migrate(input: &str) -> Option<String> {
        migrate_quote_optional_marker(input).unwrap()
    }

    #[rstest]
    #[case::plain_scalar_rule(
        indoc! {"
            rules:
              - allow: git branch --abbrev ?
        "},
        indoc! {"
            rules:
              - allow: git branch --abbrev \\?
        "},
    )]
    #[case::single_quoted_scalar_rule(
        indoc! {"
            rules:
              - allow: 'git branch --abbrev ?'
        "},
        indoc! {"
            rules:
              - allow: git branch --abbrev \\?
        "},
    )]
    #[case::double_quoted_scalar_rule(
        indoc! {r#"
            rules:
              - allow: "git branch --abbrev ?"
        "#},
        indoc! {"
            rules:
              - allow: git branch --abbrev \\?
        "},
    )]
    #[case::deny_and_ask_keys(
        indoc! {"
            rules:
              - deny: cmd --mode ?
              - ask: cmd2 --mode ?
        "},
        indoc! {"
            rules:
              - deny: cmd --mode \\?
              - ask: cmd2 --mode \\?
        "},
    )]
    #[case::multiple_bare_markers_in_one_pattern(
        indoc! {"
            rules:
              - allow: cmd --a ? --b ?
        "},
        indoc! {"
            rules:
              - allow: cmd --a \\? --b \\?
        "},
    )]
    #[case::wrapper_pattern(
        indoc! {"
            definitions:
              wrappers:
                - sudo --preserve-env ? <cmd>
        "},
        indoc! {"
            definitions:
              wrappers:
                - sudo --preserve-env \\? <cmd>
        "},
    )]
    #[case::flag_group_definition(
        indoc! {"
            definitions:
              flag_groups:
                abbrev: --abbrev ?
            rules:
              - allow: git branch <flag:abbrev>
        "},
        indoc! {"
            definitions:
              flag_groups:
                abbrev: --abbrev \\?
            rules:
              - allow: git branch <flag:abbrev>
        "},
    )]
    #[case::alias_single_string(
        indoc! {"
            definitions:
              aliases:
                gb: git branch --abbrev ?
        "},
        indoc! {"
            definitions:
              aliases:
                gb: git branch --abbrev \\?
        "},
    )]
    #[case::alias_list_of_strings(
        indoc! {"
            definitions:
              aliases:
                gb:
                  - git branch --abbrev ?
                  - git branch -v
        "},
        indoc! {"
            definitions:
              aliases:
                gb:
                  - git branch --abbrev \\?
                  - git branch -v
        "},
    )]
    #[case::pattern_typed_var_plain_value(
        indoc! {"
            definitions:
              vars:
                mode:
                  type: pattern
                  values:
                    - '--mode ?'
        "},
        indoc! {"
            definitions:
              vars:
                mode:
                  type: pattern
                  values:
                    - --mode \\?
        "},
    )]
    #[case::pattern_typed_var_typed_value(
        indoc! {"
            definitions:
              vars:
                mode:
                  type: literal
                  values:
                    - type: pattern
                      value: '--mode ?'
        "},
        indoc! {"
            definitions:
              vars:
                mode:
                  type: literal
                  values:
                    - type: pattern
                      value: --mode \\?
        "},
    )]
    fn migrates_bare_optional_markers(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(migrate(input).unwrap(), expected);
    }

    #[rstest]
    #[case::already_escaped(indoc! {"
        rules:
          - allow: git branch --abbrev \\?
    "})]
    #[case::no_bare_marker_present(indoc! {"
        rules:
          - allow: git status
    "})]
    #[case::question_mark_inside_a_word_is_untouched(indoc! {"
        rules:
          - allow: curl 'https://x?y=z'
    "})]
    #[case::quoted_literal_question_mark_is_untouched(indoc! {"
        rules:
          - allow: cmd '?'
    "})]
    #[case::literal_typed_var_value_is_untouched(indoc! {"
        definitions:
          vars:
            mode:
              type: literal
              values:
                - '?'
    "})]
    #[case::inline_rule_tests_are_untouched(indoc! {"
        rules:
          - allow: git status
            tests:
              - allow: git status ?
    "})]
    fn returns_none_when_nothing_to_migrate(#[case] input: &str) {
        assert_eq!(migrate(input), None);
    }

    #[test]
    fn migration_is_idempotent() {
        let input = indoc! {"
            rules:
              - allow: git branch --abbrev ?
        "};
        let once = migrate(input).unwrap();
        assert_eq!(migrate(&once), None);
    }

    #[test]
    fn preserves_comments_and_key_order() {
        let input = indoc! {"
            rules:
              # allow branch listing with optional abbrev length
              - allow: git branch --abbrev ?  # trailing comment
                message: custom message
        "};
        let expected = indoc! {"
            rules:
              # allow branch listing with optional abbrev length
              - allow: git branch --abbrev \\?  # trailing comment
                message: custom message
        "};
        assert_eq!(migrate(input).unwrap(), expected);
    }
}
