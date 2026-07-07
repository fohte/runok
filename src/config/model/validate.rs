use super::*;

impl Config {
    /// Expand `<path:name>` references in sandbox preset `fs.deny` lists.
    ///
    /// Replaces each `<path:name>` entry with the corresponding path list
    /// from `definitions.paths`. Returns a validation error if a referenced
    /// path name is not defined.
    /// Expand `<path:name>` references in sandbox preset `fs.deny` lists,
    /// collecting all errors so they can be reported together with other
    /// validation errors.
    fn expand_sandbox_path_refs(&mut self, errors: &mut Vec<String>) {
        // Clone paths to avoid borrowing self.definitions both immutably and mutably.
        let paths = self.definitions.as_ref().and_then(|d| d.paths.clone());

        let sandbox = self.definitions.as_mut().and_then(|d| d.sandbox.as_mut());

        let Some(sandbox) = sandbox else {
            return;
        };

        for (preset_name, preset) in sandbox.iter_mut() {
            let Some(fs) = preset.fs.as_mut() else {
                continue;
            };

            // Expand <path:name> references in all deny lists
            let deny_fields: Vec<(&str, Option<&mut Vec<String>>)> = vec![
                (
                    "fs.write.deny",
                    fs.write.as_mut().and_then(|w| w.deny.as_mut()),
                ),
                (
                    "fs.read.deny",
                    fs.read.as_mut().and_then(|r| r.deny.as_mut()),
                ),
            ];

            for (field_name, deny_opt) in deny_fields {
                let Some(deny) = deny_opt else {
                    continue;
                };

                let mut expanded = Vec::new();
                for entry in deny.iter() {
                    if let Some(name) = entry
                        .strip_prefix("<path:")
                        .and_then(|s| s.strip_suffix('>'))
                    {
                        match paths.as_ref().and_then(|p| p.get(name)) {
                            Some(path_list) => expanded.extend(path_list.iter().cloned()),
                            None => errors.push(format!(
                                "sandbox preset '{}': {} references undefined path '{}'. \
                                 Define it in definitions.paths.{}",
                                preset_name, field_name, name, name
                            )),
                        }
                    } else {
                        expanded.push(entry.clone());
                    }
                }
                *deny = expanded;
            }
        }
    }

    /// Validate the config structure.
    ///
    /// Collects all validation errors and returns them at once so that users
    /// can fix every issue in a single pass.
    ///
    /// Checks:
    /// - Sandbox preset `<path:name>` references resolve to `definitions.paths`
    /// - Each rule entry has exactly one of deny/allow/ask set
    /// - deny rules must not have a sandbox attribute
    /// - sandbox values must reference names defined in definitions.sandbox
    pub fn validate(&mut self) -> Result<(), crate::config::ConfigError> {
        let mut errors = Vec::new();

        self.expand_sandbox_path_refs(&mut errors);

        // Reject fs.read.allow — it is accepted by the schema for structural
        // consistency but has no effect at runtime (read access is allowed by
        // default; only read.deny is enforced).
        if let Some(defs) = &self.definitions
            && let Some(sandbox) = &defs.sandbox
        {
            for (name, preset) in sandbox {
                if let Some(fs) = &preset.fs
                    && let Some(read) = &fs.read
                    && read.allow.is_some()
                {
                    errors.push(format!(
                        "sandbox preset '{name}': fs.read.allow is not supported. \
                         Read access is allowed by default; use fs.read.deny to restrict it"
                    ));
                }
            }
        }

        // Reject <path:name> references inside definitions.paths values.
        // The <path:name> syntax is only valid in pattern contexts (rule
        // patterns, fs.deny), not inside path definitions themselves.
        if let Some(defs) = &self.definitions
            && let Some(paths) = &defs.paths
        {
            for (key, values) in paths {
                for value in values {
                    if value.starts_with("<path:") && value.ends_with('>') {
                        errors.push(format!(
                            "definitions.paths.{key}: value '{value}' contains a <path:name> \
                             reference. Path definitions must contain concrete paths, not references"
                        ));
                    }
                }
            }
        }

        // Validate definitions.vars values:
        // - For `literal` / `path` typed values, reject `<var:name>` and
        //   `<path:name>` references because such values must be concrete tokens.
        // - For `pattern` typed values, parse the value as a rule pattern and
        //   reject any nested placeholders (`<cmd>`, `<opts>`, `<vars>`,
        //   `<var:...>`, `<path:...>`, `<flag:...>`).
        if let Some(defs) = &self.definitions
            && let Some(vars) = &defs.vars
        {
            for (key, var_def) in vars {
                for var_value in &var_def.values {
                    let v = var_value.value();
                    let effective_type = var_value.effective_type(var_def.var_type);
                    match effective_type {
                        VarType::Literal | VarType::Path => {
                            if (v.starts_with("<var:") || v.starts_with("<path:"))
                                && v.ends_with('>')
                            {
                                errors.push(format!(
                                    "definitions.vars.{key}: value '{v}' contains a placeholder \
                                     reference. Variable definitions must contain concrete values, not references"
                                ));
                            }
                        }
                        VarType::Pattern => match crate::rules::pattern_parser::parse(v) {
                            Ok(parsed) => {
                                if let Some(disallowed) =
                                    find_disallowed_placeholder_in_pattern(&parsed)
                                {
                                    errors.push(format!(
                                        "definitions.vars.{key}: pattern value '{v}' contains \
                                         disallowed placeholder '{disallowed}'. Nested placeholders \
                                         (<cmd>, <opts>, <vars>, <var:...>, <path:...>, <flag:...>) \
                                         are not allowed in pattern-typed variable values"
                                    ));
                                }
                            }
                            Err(e) => {
                                errors.push(format!(
                                    "definitions.vars.{key}: pattern value '{v}' failed to parse: {e}"
                                ));
                            }
                        },
                    }
                }
            }
        }

        // Validate definitions.flag_groups: each value is a pattern string
        // that must parse successfully and contain at least one valid flag alias.
        if let Some(defs) = &self.definitions
            && let Some(flag_groups) = &defs.flag_groups
        {
            for (key, definition) in flag_groups {
                match crate::rules::pattern_parser::parse_flag_group_definition(definition) {
                    Ok(parsed) => {
                        if parsed.aliases.is_empty() {
                            errors.push(format!(
                                "definitions.flag_groups.{key}: flag group must contain at least one flag"
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(format!("definitions.flag_groups.{key}: {e}"));
                    }
                }
            }
        }

        // Validate that every `<flag:name>` reference in a rule pattern
        // resolves to a group defined in `definitions.flag_groups`.
        let defined_flag_groups: std::collections::HashSet<&str> = self
            .definitions
            .as_ref()
            .and_then(|d| d.flag_groups.as_ref())
            .map(|g| g.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();

        // Set of variable names whose effective definition-level type is
        // `pattern`. Used to reject `[<var:name>]` (pattern-typed var inside
        // an optional group) for the same reason `<flag:name>` is rejected
        // there: pattern-var expansion may itself contain optional groups
        // and value-flags, so wrapping it in another optional layer would
        // break the outer matcher's `optional_flags_absent` accounting.
        let pattern_typed_vars: std::collections::HashSet<&str> = self
            .definitions
            .as_ref()
            .and_then(|d| d.vars.as_ref())
            .map(|vars| {
                vars.iter()
                    .filter(|(_, def)| def.var_type == VarType::Pattern)
                    .map(|(k, _)| k.as_str())
                    .collect()
            })
            .unwrap_or_default();

        if let Some(rules) = &self.rules {
            for (i, rule) in rules.iter().enumerate() {
                let Some((_, pattern_str)) = rule.action_and_pattern() else {
                    continue;
                };
                let parsed = match crate::rules::pattern_parser::parse_multi(pattern_str) {
                    Ok(patterns) => patterns,
                    Err(_) => continue, // Pattern parse errors are surfaced at evaluation time.
                };
                for pattern in &parsed {
                    collect_flag_group_refs(&pattern.tokens, &mut |name| {
                        if !defined_flag_groups.contains(name) {
                            errors.push(format!(
                                "rules[{i}]: pattern references undefined flag group \
                                 '<flag:{name}>'. Define it in definitions.flag_groups."
                            ));
                        }
                    });
                    collect_var_refs_inside_optional(&pattern.tokens, &mut |name| {
                        if pattern_typed_vars.contains(name) {
                            errors.push(format!(
                                "rules[{i}]: pattern places <var:{name}> inside an optional \
                                 group `[...]`. Pattern-typed variables cannot be nested in \
                                 optional groups."
                            ));
                        }
                    });
                }
            }
        }

        let rules = match &self.rules {
            Some(rules) => rules,
            None => {
                return if errors.is_empty() {
                    Ok(())
                } else {
                    Err(crate::config::ConfigError::Validation(errors))
                };
            }
        };

        let defined_sandboxes: std::collections::HashSet<&str> = self
            .definitions
            .as_ref()
            .and_then(|d| d.sandbox.as_ref())
            .map(|s| s.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();

        for (i, rule) in rules.iter().enumerate() {
            let action = match rule.action_and_pattern() {
                Some((action, _)) => action,
                None => {
                    errors.push(format!(
                        "rules[{i}]: must have exactly one of 'deny', 'allow', or 'ask'"
                    ));
                    continue;
                }
            };

            if let Some(sandbox_name) = &rule.sandbox {
                if action == ActionKind::Deny {
                    errors.push(format!(
                        "rules[{i}]: deny rule cannot have a sandbox attribute (sandbox: '{sandbox_name}')"
                    ));
                }

                if !defined_sandboxes.contains(sandbox_name.as_str()) {
                    errors.push(format!(
                        "rules[{i}]: sandbox '{sandbox_name}' is not defined in definitions.sandbox"
                    ));
                }
            }
        }

        if errors.is_empty() {
            // Pre-parse flag group definitions and pattern-typed variable
            // values so pattern matching never has to re-parse them on every
            // `<flag:name>` / `<var:name>` encounter.
            if let Some(defs) = &mut self.definitions {
                defs.resolve_flag_groups();
                defs.resolve_pattern_vars();
            }
            Ok(())
        } else {
            Err(crate::config::ConfigError::Validation(errors))
        }
    }
}

/// Walk a pattern token tree and invoke `report` for every `<flag:name>`
/// reference encountered. Used by config validation to detect undefined flag
/// group references upfront.
fn collect_flag_group_refs(
    tokens: &[crate::rules::pattern_parser::PatternToken],
    report: &mut impl FnMut(&str),
) {
    use crate::rules::pattern_parser::PatternToken;
    for token in tokens {
        match token {
            PatternToken::FlagGroupRef { name, .. } => report(name),
            PatternToken::Optional(inner) => collect_flag_group_refs(inner, report),
            _ => {}
        }
    }
}

/// Walk a pattern token tree and invoke `report` for every `<var:name>`
/// reference that appears strictly inside an `Optional ([...])` group. Used
/// by config validation to forbid pattern-typed `<var:name>` references
/// inside optional groups.
fn collect_var_refs_inside_optional(
    tokens: &[crate::rules::pattern_parser::PatternToken],
    report: &mut impl FnMut(&str),
) {
    use crate::rules::pattern_parser::PatternToken;
    for token in tokens {
        if let PatternToken::Optional(inner) = token {
            collect_var_refs_anywhere(inner, report);
        }
    }
}

fn collect_var_refs_anywhere(
    tokens: &[crate::rules::pattern_parser::PatternToken],
    report: &mut impl FnMut(&str),
) {
    use crate::rules::pattern_parser::PatternToken;
    for token in tokens {
        match token {
            PatternToken::VarRef(name) => report(name),
            PatternToken::Optional(inner) => collect_var_refs_anywhere(inner, report),
            _ => {}
        }
    }
}

/// Walk a parsed pattern tree and return a description of the first nested
/// placeholder found, or `None` if every token is a plain pattern element.
/// Used by `definitions.vars` validation for `pattern`-typed values: pattern
/// vars must not embed other placeholders, since their value is inlined into
/// rule patterns and recursive expansion is not supported.
fn find_disallowed_placeholder_in_pattern(
    pattern: &crate::rules::pattern_parser::Pattern,
) -> Option<String> {
    use crate::rules::pattern_parser::CommandPattern;

    if let CommandPattern::VarRef(name) = &pattern.command {
        return Some(format!("<var:{name}>"));
    }
    find_disallowed_placeholder_in_tokens(&pattern.tokens)
}

fn find_disallowed_placeholder_in_tokens(
    tokens: &[crate::rules::pattern_parser::PatternToken],
) -> Option<String> {
    use crate::rules::pattern_parser::PatternToken;
    for token in tokens {
        match token {
            PatternToken::PathRef(name) => return Some(format!("<path:{name}>")),
            PatternToken::VarRef(name) => return Some(format!("<var:{name}>")),
            PatternToken::FlagGroupRef { name } => return Some(format!("<flag:{name}>")),
            PatternToken::Placeholder(name) => return Some(format!("<{name}>")),
            PatternToken::Opts => return Some("<opts>".to_string()),
            PatternToken::Vars => return Some("<vars>".to_string()),
            PatternToken::Optional(inner) => {
                if let Some(found) = find_disallowed_placeholder_in_tokens(inner) {
                    return Some(found);
                }
            }
            PatternToken::FlagWithValue { value, .. } => {
                if let Some(found) =
                    find_disallowed_placeholder_in_tokens(std::slice::from_ref(value.as_ref()))
                {
                    return Some(found);
                }
            }
            PatternToken::Negation(inner) => {
                if let Some(found) =
                    find_disallowed_placeholder_in_tokens(std::slice::from_ref(inner.as_ref()))
                {
                    return Some(found);
                }
            }
            PatternToken::Literal(_) | PatternToken::Alternation(_) | PatternToken::Wildcard => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::*;

    // === Config::validate ===

    #[test]
    fn validate_valid_config() {
        let mut config = parse_config(indoc! {"
            rules:
              - deny: 'rm -rf /'
              - allow: 'git status'
              - ask: 'git push *'
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_config_without_rules() {
        let mut config = parse_config("{}").unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_errors_on_rule_with_no_action() {
        let mut config = Config {
            required_runok_version: None,
            extends: None,
            defaults: None,
            rules: Some(vec![RuleEntry {
                deny: None,
                allow: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
                tests: None,
            }]),
            definitions: None,
            audit: None,
            tests: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn validate_errors_on_rule_with_multiple_actions() {
        let mut config = Config {
            required_runok_version: None,
            extends: None,
            defaults: None,
            rules: Some(vec![RuleEntry {
                deny: Some("rm -rf /".to_string()),
                allow: Some("git status".to_string()),
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
                tests: None,
            }]),
            definitions: None,
            audit: None,
            tests: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn validate_errors_on_deny_with_sandbox() {
        let mut config = parse_config(indoc! {"
            rules:
              - deny: 'rm -rf /'
                sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("deny"));
        assert!(err.to_string().contains("sandbox"));
    }

    #[test]
    fn validate_errors_on_undefined_sandbox_name() {
        let mut config = parse_config(indoc! {"
            rules:
              - allow: 'python3 *'
                sandbox: nonexistent
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
        assert!(err.to_string().contains("not defined"));
    }

    #[test]
    fn validate_errors_on_undefined_sandbox_name_with_empty_definitions() {
        let mut config = parse_config(indoc! {"
            rules:
              - allow: 'python3 *'
                sandbox: restricted
            definitions:
              paths:
                sensitive:
                  - '.env*'
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("restricted"));
        assert!(err.to_string().contains("not defined"));
    }

    #[test]
    fn validate_allow_with_valid_sandbox() {
        let mut config = parse_config(indoc! {"
            rules:
              - allow: 'python3 *'
                sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_ask_with_valid_sandbox() {
        let mut config = parse_config(indoc! {"
            rules:
              - ask: 'npm run *'
                sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    // === expand_sandbox_path_refs ===

    #[rstest]
    #[case::single_path_ref(
        indoc! {"
            definitions:
              paths:
                sensitive:
                  - /etc/passwd
                  - /etc/shadow
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny:
                      - '<path:sensitive>'
        "},
        vec!["/etc/passwd", "/etc/shadow"],
    )]
    #[case::mixed_concrete_and_ref(
        indoc! {"
            definitions:
              paths:
                sensitive:
                  - /etc/passwd
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny:
                      - /root/.ssh
                      - '<path:sensitive>'
                      - /var/log
        "},
        vec!["/root/.ssh", "/etc/passwd", "/var/log"],
    )]
    fn expand_sandbox_path_refs_success(#[case] yaml: &str, #[case] expected_deny: Vec<&str>) {
        let mut config = parse_config(yaml).unwrap();
        config.validate().unwrap();

        let deny = config
            .definitions
            .as_ref()
            .and_then(|d| d.sandbox.as_ref())
            .and_then(|s| s.get("restricted"))
            .and_then(|p| p.fs.as_ref())
            .and_then(|f| f.write_deny())
            .unwrap();
        assert_eq!(deny, &expected_deny);
    }

    #[rstest]
    #[case::undefined_name(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny:
                      - '<path:nonexistent>'
        "},
        "nonexistent",
    )]
    #[case::no_paths_defined(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny:
                      - '<path:sensitive>'
        "},
        "sensitive",
    )]
    fn expand_sandbox_path_refs_errors(#[case] yaml: &str, #[case] expected_name: &str) {
        let mut config = parse_config(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains(expected_name));
        assert!(err.to_string().contains("undefined path"));
    }

    #[test]
    fn validate_rejects_path_ref_in_definitions_paths() {
        let mut config = parse_config(indoc! {"
            definitions:
              paths:
                sensitive:
                  - /etc/passwd
                  - '<path:more_sensitive>'
                more_sensitive:
                  - /etc/shadow
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("definitions.paths.sensitive"),
            "error should mention the path key: {}",
            err
        );
        assert!(
            err.to_string().contains("concrete paths, not references"),
            "error should explain the constraint: {}",
            err
        );
    }

    #[test]
    fn validate_collects_all_errors() {
        let mut config = Config {
            required_runok_version: None,
            extends: None,
            defaults: None,
            audit: None,
            rules: Some(vec![
                // Error 1: no action set
                RuleEntry {
                    deny: None,
                    allow: None,
                    ask: None,
                    when: None,
                    message: None,
                    fix_suggestion: None,
                    sandbox: None,
                    tests: None,
                },
                // Valid rule (should not appear in errors)
                RuleEntry {
                    deny: Some("rm -rf /".to_string()),
                    allow: None,
                    ask: None,
                    when: None,
                    message: None,
                    fix_suggestion: None,
                    sandbox: None,
                    tests: None,
                },
                // Error 2: deny with sandbox
                RuleEntry {
                    deny: Some("curl *".to_string()),
                    allow: None,
                    ask: None,
                    when: None,
                    message: None,
                    fix_suggestion: None,
                    sandbox: Some("restricted".to_string()),
                    tests: None,
                },
                // Error 3: undefined sandbox
                RuleEntry {
                    deny: None,
                    allow: Some("python3 *".to_string()),
                    ask: None,
                    when: None,
                    message: None,
                    fix_suggestion: None,
                    sandbox: Some("nonexistent".to_string()),
                    tests: None,
                },
            ]),
            definitions: None,
            tests: None,
        };
        let err = config.validate().unwrap_err();
        let expected = indoc! {"
            validation errors:
              - rules[0]: must have exactly one of 'deny', 'allow', or 'ask'
              - rules[2]: deny rule cannot have a sandbox attribute (sandbox: 'restricted')
              - rules[2]: sandbox 'restricted' is not defined in definitions.sandbox
              - rules[3]: sandbox 'nonexistent' is not defined in definitions.sandbox"}
        .trim_start();
        assert_eq!(err.to_string(), expected);
    }

    #[test]
    fn validate_includes_rule_index_in_error() {
        let mut config = parse_config(indoc! {"
            rules:
              - allow: 'git status'
              - deny: 'rm -rf /'
                sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        let expected = indoc! {"
            validation errors:
              - rules[1]: deny rule cannot have a sandbox attribute (sandbox: 'restricted')"}
        .trim_start();
        assert_eq!(err.to_string(), expected);
    }

    // === definitions.vars ===

    #[rstest]
    #[case::var_ref(
        indoc! {"
            definitions:
              vars:
                ids:
                  values:
                    - i-abc123
                    - '<var:other-ids>'
                other-ids:
                  values:
                    - i-xyz999
        "},
        "definitions.vars.ids",
    )]
    #[case::path_ref(
        indoc! {"
            definitions:
              vars:
                scripts:
                  type: path
                  values:
                    - ./run.sh
                    - '<path:sensitive>'
              paths:
                sensitive:
                  - /etc/passwd
        "},
        "definitions.vars.scripts",
    )]
    fn validate_rejects_placeholder_in_definitions_vars(
        #[case] yaml: &str,
        #[case] expected_key_msg: &str,
    ) {
        let mut config = parse_config(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains(expected_key_msg),
            "error should mention the var key: {}",
            err
        );
        assert!(
            err.to_string().contains("concrete values, not references"),
            "error should explain the constraint: {}",
            err
        );
    }

    #[test]
    fn validate_accepts_valid_vars() {
        let mut config = parse_config(indoc! {"
            definitions:
              vars:
                ids:
                  values:
                    - i-abc123
                    - i-def456
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }
}
