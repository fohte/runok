use crate::config::{Config, VarType};

use super::pattern_refs::find_disallowed_placeholder_in_pattern;

impl Config {
    pub(super) fn validate_extension_definitions(&self, errors: &mut Vec<String>) {
        let Some(extensions) = self
            .definitions
            .as_ref()
            .and_then(|definitions| definitions.extensions.as_ref())
        else {
            return;
        };

        for (name, definition) in extensions {
            if !is_cel_identifier(name) {
                errors.push(format!(
                    "definitions.extensions.{name}: name must be a CEL identifier"
                ));
            }
            if cel_or_runok_builtin_names().contains(&name.as_str()) {
                errors.push(format!(
                    "definitions.extensions.{name}: name conflicts with a CEL or runok built-in function"
                ));
            }
            if definition.executor.trim().is_empty() {
                errors.push(format!(
                    "definitions.extensions.{name}.executor must not be empty"
                ));
            }
        }
    }

    /// Reject `fs.read.allow` — it is accepted by the schema for structural
    /// consistency but has no effect at runtime (read access is allowed by
    /// default; only read.deny is enforced).
    pub(super) fn validate_fs_read_allow(&self, errors: &mut Vec<String>) {
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
    }

    /// Reject `<path:name>` references inside `definitions.paths` values.
    /// The `<path:name>` syntax is only valid in pattern contexts (rule
    /// patterns, fs.deny), not inside path definitions themselves.
    pub(super) fn validate_definitions_paths_refs(&self, errors: &mut Vec<String>) {
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
    }

    /// Validate `definitions.vars` values:
    /// - For `literal` / `path` typed values, reject `<var:name>` and
    ///   `<path:name>` references because such values must be concrete tokens.
    /// - For `pattern` typed values, parse the value as a rule pattern and
    ///   reject any nested placeholders (`<cmd>`, `<opts>`, `<vars>`,
    ///   `<var:...>`, `<path:...>`, `<flag:...>`).
    pub(super) fn validate_definitions_vars(&self, errors: &mut Vec<String>) {
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
    }

    pub(super) fn validate_flag_groups(&self, errors: &mut Vec<String>) {
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
    }
}

fn is_cel_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let is_identifier = chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric());
    is_identifier && !["false", "in", "null", "true"].contains(&value)
}

fn cel_or_runok_builtin_names() -> &'static [&'static str] {
    &[
        "all",
        "bytes",
        "contains",
        "double",
        "duration",
        "endsWith",
        "exists",
        "existsOne",
        "exists_one",
        "filter",
        "getDate",
        "getDayOfMonth",
        "getDayOfWeek",
        "getDayOfYear",
        "getFullYear",
        "getHours",
        "getMilliseconds",
        "getMinutes",
        "getMonth",
        "getSeconds",
        "glob_matches",
        "has",
        "int",
        "is_dir",
        "is_file",
        "map",
        "matches",
        "max",
        "min",
        "size",
        "startsWith",
        "string",
        "timestamp",
        "uint",
    ]
}

#[cfg(test)]
mod tests {
    use indoc::{formatdoc, indoc};
    use rstest::rstest;

    use crate::config::parse_config;

    #[rstest]
    #[case::hyphenated("not-valid", "name must be a CEL identifier")]
    #[case::reserved_keyword("true", "name must be a CEL identifier")]
    #[case::builtin_function("contains", "name conflicts with a CEL or runok built-in function")]
    fn validate_rejects_invalid_extension_names(#[case] name: &str, #[case] reason: &str) {
        let mut config = parse_config(&formatdoc! {
            "
            definitions:
              extensions:
                {name}:
                  executor: external-tool
            "
        })
        .unwrap();

        let expected = formatdoc! {
            "
            validation errors:
              - definitions.extensions.{name}: {reason}
            "
        };

        assert_eq!(
            config.validate().unwrap_err().to_string(),
            expected.strip_suffix('\n').unwrap()
        );
    }

    #[rstest]
    #[case::empty("")]
    #[case::whitespace_only("   ")]
    fn validate_rejects_empty_extension_executor(#[case] executor: &str) {
        let mut config = parse_config(&formatdoc! {
            "
            definitions:
              extensions:
                lookup:
                  executor: \"{executor}\"
            "
        })
        .unwrap();

        let expected = indoc! {"
            validation errors:
              - definitions.extensions.lookup.executor must not be empty
        "};

        assert_eq!(
            config.validate().unwrap_err().to_string(),
            expected.strip_suffix('\n').unwrap(),
        );
    }

    #[test]
    fn extension_timeout_accepts_compact_duration() {
        let config = parse_config(indoc! {"
            definitions:
              extensions:
                lookup:
                  executor: external-tool
                  timeout: 250ms
                  env: [RUNOK_TOKEN]
        "})
        .unwrap();
        let timeout = config
            .definitions
            .unwrap()
            .extensions
            .unwrap()
            .get("lookup")
            .unwrap()
            .timeout
            .unwrap();

        assert_eq!(timeout.duration(), std::time::Duration::from_millis(250));
    }

    // === definitions.paths ===

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
