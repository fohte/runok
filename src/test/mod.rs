use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use owo_colors::OwoColorize;
use owo_colors::Stream::Stdout;

use crate::config::{
    ActionKind, Config, ConfigError, InlineTestEntry, PresetCache, parse_config,
    resolve_config_paths, resolve_extends,
};
use crate::rules::RuleError;
use crate::rules::rule_engine::{Action, EvalContext, evaluate_compound};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("config file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    #[error("no test cases found")]
    NoTestCases,

    #[error(transparent)]
    Yaml(#[from] serde_saphyr::Error),

    #[error("extends resolution failed: {path}: {source}")]
    ExtendsResolution {
        path: String,
        #[source]
        source: Box<ConfigError>,
    },

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("rule evaluation error: {0}")]
    RuleEval(#[from] RuleError),
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Expected decision in a test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedDecision {
    Allow,
    Ask,
    Deny,
}

impl fmt::Display for ExpectedDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Ask => write!(f, "ask"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

impl From<ExpectedDecision> for ActionKind {
    fn from(decision: ExpectedDecision) -> Self {
        match decision {
            ExpectedDecision::Allow => ActionKind::Allow,
            ExpectedDecision::Ask => ActionKind::Ask,
            ExpectedDecision::Deny => ActionKind::Deny,
        }
    }
}

/// Source information for a test case.
#[derive(Debug, Clone, PartialEq)]
pub enum TestCaseSource {
    Inline { file: PathBuf, rule_index: usize },
    TopLevel { file: PathBuf },
}

/// A single test case.
#[derive(Debug, Clone)]
pub struct TestCase {
    pub command: String,
    pub expected: ExpectedDecision,
    pub source: TestCaseSource,
    /// When set, evaluate this test case against this scoped config instead
    /// of the full merged config.  Used for inline tests from presets so that
    /// downstream overrides do not affect the preset's own tests.
    pub scope_config: Option<Config>,
}

/// Result of a single test case execution.
#[derive(Debug)]
pub struct TestResult {
    pub test_case: TestCase,
    pub actual: ActionKind,
    pub passed: bool,
    /// Set when rule evaluation itself errored out.
    pub error: Option<String>,
}

/// Aggregated test results.
#[derive(Debug)]
pub struct TestResults {
    pub results: Vec<TestResult>,
}

impl TestResults {
    pub fn is_success(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    pub fn passed_count(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }

    pub fn failed_count(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    pub fn total_count(&self) -> usize {
        self.results.len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn action_to_kind(action: &Action) -> ActionKind {
    match action {
        Action::Allow => ActionKind::Allow,
        Action::Deny(_) => ActionKind::Deny,
        Action::Ask(_) => ActionKind::Ask,
    }
}

fn action_kind_label(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::Allow => "allow",
        ActionKind::Ask => "ask",
        ActionKind::Deny => "deny",
    }
}

// ---------------------------------------------------------------------------
// Test case parsing
// ---------------------------------------------------------------------------

/// Extract `(ExpectedDecision, command)` from an `InlineTestEntry`.
///
/// Exactly one of `allow`, `ask`, or `deny` should be set; the key
/// determines the expected decision and the value is the command string.
fn parse_inline_entry(entry: &InlineTestEntry) -> Option<(ExpectedDecision, String)> {
    match (&entry.allow, &entry.ask, &entry.deny) {
        (Some(cmd), None, None) => Some((ExpectedDecision::Allow, cmd.clone())),
        (None, Some(cmd), None) => Some((ExpectedDecision::Ask, cmd.clone())),
        (None, None, Some(cmd)) => Some((ExpectedDecision::Deny, cmd.clone())),
        _ => None,
    }
}

/// Parse all test cases from a config, using `file` as the source path.
///
/// When `preset_config` is provided, inline tests whose `rule_index` is
/// less than `preset_rule_count` are given `scope_config = Some(preset_config)`
/// so they are evaluated only against the preset's rules.
pub fn parse_test_cases(config: &Config, file: &Path) -> Vec<TestCase> {
    parse_test_cases_scoped(config, file, None, 0)
}

/// Parse test cases with optional preset scoping.
///
/// Inline tests for rules at index `0..preset_rule_count` receive
/// `scope_config` set to `preset_config` so they are evaluated against
/// the preset layer only.
pub fn parse_test_cases_scoped(
    config: &Config,
    file: &Path,
    preset_config: Option<&Config>,
    preset_rule_count: usize,
) -> Vec<TestCase> {
    let mut cases = Vec::new();

    // Inline tests from rules
    if let Some(rules) = &config.rules {
        for (rule_index, rule) in rules.iter().enumerate() {
            if let Some(tests) = &rule.tests {
                for entry in tests {
                    if let Some((expected, command)) = parse_inline_entry(entry) {
                        let scope_config = if rule_index < preset_rule_count {
                            preset_config.cloned()
                        } else {
                            None
                        };
                        cases.push(TestCase {
                            command,
                            expected,
                            source: TestCaseSource::Inline {
                                file: file.to_path_buf(),
                                rule_index,
                            },
                            scope_config,
                        });
                    }
                }
            }
        }
    }

    // Top-level test cases
    if let Some(test_section) = &config.tests
        && let Some(top_cases) = &test_section.cases
    {
        for entry in top_cases {
            if let Some((expected, command)) = parse_inline_entry(entry) {
                cases.push(TestCase {
                    command,
                    expected,
                    source: TestCaseSource::TopLevel {
                        file: file.to_path_buf(),
                    },
                    scope_config: None,
                });
            }
        }
    }

    cases
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

/// Run all test cases against the given config and return aggregated results.
///
/// Each test case is evaluated against its own `scope_config` when present,
/// otherwise against the full merged `config`.  This ensures that inline
/// tests from presets are evaluated only against the preset's rules, not
/// against downstream overrides.
pub fn run_tests(config: &Config, test_cases: &[TestCase]) -> TestResults {
    let context = EvalContext::from_env();
    let results = test_cases
        .iter()
        .map(|tc| {
            let eval_config = tc.scope_config.as_ref().unwrap_or(config);
            match evaluate_compound(eval_config, &tc.command, &context) {
                Ok(result) => {
                    let actual = action_to_kind(&result.action);
                    let expected_kind: ActionKind = tc.expected.into();
                    TestResult {
                        test_case: tc.clone(),
                        actual,
                        passed: actual == expected_kind,
                        error: None,
                    }
                }
                Err(e) => TestResult {
                    test_case: tc.clone(),
                    actual: ActionKind::default(),
                    passed: false,
                    error: Some(e.to_string()),
                },
            }
        })
        .collect();
    TestResults { results }
}

// ---------------------------------------------------------------------------
// Test reporter
// ---------------------------------------------------------------------------

/// Write per-test-case results.
pub fn report(results: &TestResults, writer: &mut impl Write) {
    for result in &results.results {
        if result.passed {
            writeln!(
                writer,
                "{}: {} => {}",
                "PASS".if_supports_color(Stdout, |t| t.green()),
                result.test_case.command,
                action_kind_label(result.actual),
            )
            .ok();
        } else if let Some(err) = &result.error {
            writeln!(
                writer,
                "{}: {} => evaluation error: {}",
                "FAIL".if_supports_color(Stdout, |t| t.red()),
                result.test_case.command,
                err,
            )
            .ok();
        } else {
            writeln!(
                writer,
                "{}: {} => expected {}, got {}",
                "FAIL".if_supports_color(Stdout, |t| t.red()),
                result.test_case.command,
                action_kind_label(result.test_case.expected.into()),
                action_kind_label(result.actual),
            )
            .ok();
        }
    }
}

/// Write the summary line.
pub fn report_summary(results: &TestResults, writer: &mut impl Write) {
    writeln!(
        writer,
        "{} passed, {} failed, {} total",
        results
            .passed_count()
            .if_supports_color(Stdout, |t| t.green()),
        results
            .failed_count()
            .if_supports_color(Stdout, |t| t.red()),
        results.total_count(),
    )
    .ok();
}

// ---------------------------------------------------------------------------
// Config loader (test-specific)
// ---------------------------------------------------------------------------

/// Filenames for the main configuration file, in priority order.
const CONFIG_FILENAMES: &[&str] = &["runok.yml", "runok.yaml"];

/// Load a config for test purposes.
///
/// Unlike the normal loader this intentionally skips the global config
/// (`~/.config/runok/runok.yml`) so that test results are fully determined
/// by the project config alone.
/// Result of loading a test config, containing the merged config and
/// optional preset-only config for scoped inline test evaluation.
pub struct LoadedTestConfig {
    pub config: Config,
    pub path: PathBuf,
    /// The config containing only preset (extends) rules, used to scope
    /// inline tests from presets so they are not affected by local overrides.
    pub preset_config: Option<Config>,
    /// Number of rules that come from presets (extends).
    pub preset_rule_count: usize,
}

pub fn load_test_config(file: &Path) -> Result<LoadedTestConfig, TestError> {
    let path = if file.is_file() {
        file.to_path_buf()
    } else if file.is_dir() {
        CONFIG_FILENAMES
            .iter()
            .map(|name| file.join(name))
            .find(|p| p.exists())
            .ok_or_else(|| TestError::ConfigNotFound {
                path: file.to_path_buf(),
            })?
    } else {
        return Err(TestError::ConfigNotFound {
            path: file.to_path_buf(),
        });
    };

    let yaml = std::fs::read_to_string(&path)?;
    let mut config = parse_config(&yaml)?;

    let base_dir = path.parent().unwrap_or(Path::new("."));
    resolve_config_paths(&mut config, base_dir).map_err(ConfigError::from)?;

    // Resolve normal extends, keeping a snapshot of the preset-only config
    let mut preset_config = None;
    let mut preset_rule_count = 0;

    if config.extends.as_ref().is_some_and(|e| !e.is_empty()) {
        let source_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("runok.yml");
        let cache = PresetCache::from_env().map_err(ConfigError::from)?;

        // Resolve extends with only the extends references (no local rules)
        // to get the preset-only config for scoped test evaluation.
        let extends_only = Config {
            extends: config.extends.clone(),
            defaults: None,
            rules: None,
            definitions: config.definitions.clone(),
            audit: None,
            tests: None,
        };
        let resolved_preset = resolve_extends(extends_only, base_dir, source_name, &cache)
            .map_err(|e| TestError::ExtendsResolution {
                path: source_name.to_string(),
                source: Box::new(e),
            })?;
        preset_rule_count = resolved_preset.rules.as_ref().map_or(0, |r| r.len());

        config = resolve_extends(config, base_dir, source_name, &cache).map_err(|e| {
            TestError::ExtendsResolution {
                path: source_name.to_string(),
                source: Box::new(e),
            }
        })?;

        if preset_rule_count > 0 {
            preset_config = Some(resolved_preset);
        }
    }

    // Resolve tests.extends: merge additional config files into the config
    let test_extends = config
        .tests
        .as_ref()
        .and_then(|t| t.extends.clone())
        .unwrap_or_default();
    if !test_extends.is_empty() {
        let cache = PresetCache::from_env().map_err(ConfigError::from)?;
        for extend_path_str in &test_extends {
            let extend_path = base_dir.join(extend_path_str);
            if !extend_path.exists() {
                return Err(TestError::ConfigNotFound { path: extend_path });
            }
            let extend_yaml = std::fs::read_to_string(&extend_path)?;
            let mut extend_config = parse_config(&extend_yaml)?;
            let extend_base = extend_path.parent().unwrap_or(Path::new("."));
            resolve_config_paths(&mut extend_config, extend_base).map_err(ConfigError::from)?;

            if extend_config
                .extends
                .as_ref()
                .is_some_and(|e| !e.is_empty())
            {
                let ext_source = extend_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("runok.yml");
                extend_config = resolve_extends(extend_config, extend_base, ext_source, &cache)
                    .map_err(|e| TestError::ExtendsResolution {
                        path: extend_path_str.clone(),
                        source: Box::new(e),
                    })?;
            }

            // Strip the tests section from extended configs so they don't
            // overwrite the main config's test definitions.
            extend_config.tests = None;
            config = config.merge(extend_config);
        }
    }

    config.validate()?;
    Ok(LoadedTestConfig {
        config,
        path,
        preset_config,
        preset_rule_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use std::fs;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    struct TestEnv {
        _tmp: TempDir,
        dir: PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let tmp = TempDir::new().expect("failed to create temp dir");
            let dir = tmp.path().to_path_buf();
            Self { _tmp: tmp, dir }
        }

        fn write_file(&self, name: &str, content: &str) {
            fs::write(self.dir.join(name), content).expect("failed to write file");
        }

        fn config_path(&self) -> PathBuf {
            self.dir.join("runok.yml")
        }
    }

    #[fixture]
    fn env() -> TestEnv {
        TestEnv::new()
    }

    // -----------------------------------------------------------------------
    // ExpectedDecision display
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::allow(ExpectedDecision::Allow, "allow")]
    #[case::ask(ExpectedDecision::Ask, "ask")]
    #[case::deny(ExpectedDecision::Deny, "deny")]
    fn expected_decision_display(#[case] decision: ExpectedDecision, #[case] expected: &str) {
        assert_eq!(decision.to_string(), expected);
    }

    // -----------------------------------------------------------------------
    // ExpectedDecision -> ActionKind conversion
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::allow(ExpectedDecision::Allow, ActionKind::Allow)]
    #[case::ask(ExpectedDecision::Ask, ActionKind::Ask)]
    #[case::deny(ExpectedDecision::Deny, ActionKind::Deny)]
    fn expected_decision_to_action_kind(
        #[case] decision: ExpectedDecision,
        #[case] expected: ActionKind,
    ) {
        let kind: ActionKind = decision.into();
        assert_eq!(kind, expected);
    }

    // -----------------------------------------------------------------------
    // TestResults aggregate methods
    // -----------------------------------------------------------------------

    fn make_result(passed: bool) -> TestResult {
        TestResult {
            test_case: TestCase {
                command: "echo test".to_string(),
                expected: ExpectedDecision::Allow,
                source: TestCaseSource::TopLevel {
                    file: PathBuf::from("test.yml"),
                },
                scope_config: None,
            },
            actual: if passed {
                ActionKind::Allow
            } else {
                ActionKind::Deny
            },
            passed,
            error: None,
        }
    }

    #[rstest]
    #[case::all_pass(vec![true, true, true], true, 3, 0, 3)]
    #[case::some_fail(vec![true, false, true], false, 2, 1, 3)]
    #[case::all_fail(vec![false, false], false, 0, 2, 2)]
    #[case::empty(vec![], true, 0, 0, 0)]
    fn test_results_aggregation(
        #[case] pass_flags: Vec<bool>,
        #[case] success: bool,
        #[case] passed: usize,
        #[case] failed: usize,
        #[case] total: usize,
    ) {
        let results = TestResults {
            results: pass_flags.into_iter().map(make_result).collect(),
        };
        assert_eq!(results.is_success(), success);
        assert_eq!(results.passed_count(), passed);
        assert_eq!(results.failed_count(), failed);
        assert_eq!(results.total_count(), total);
    }

    // -----------------------------------------------------------------------
    // parse_inline_entry
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::allow_entry(
        InlineTestEntry { allow: Some("git status".into()), ask: None, deny: None },
        Some((ExpectedDecision::Allow, "git status".into()))
    )]
    #[case::ask_entry(
        InlineTestEntry { allow: None, ask: Some("git push".into()), deny: None },
        Some((ExpectedDecision::Ask, "git push".into()))
    )]
    #[case::deny_entry(
        InlineTestEntry { allow: None, ask: None, deny: Some("rm -rf /".into()) },
        Some((ExpectedDecision::Deny, "rm -rf /".into()))
    )]
    #[case::none_set(
        InlineTestEntry { allow: None, ask: None, deny: None },
        None
    )]
    #[case::multiple_set(
        InlineTestEntry { allow: Some("a".into()), ask: Some("b".into()), deny: None },
        None
    )]
    fn test_parse_inline_entry(
        #[case] entry: InlineTestEntry,
        #[case] expected: Option<(ExpectedDecision, String)>,
    ) {
        assert_eq!(parse_inline_entry(&entry), expected);
    }

    // -----------------------------------------------------------------------
    // parse_test_cases
    // -----------------------------------------------------------------------

    #[rstest]
    fn parse_test_cases_empty_config() {
        let config = Config::default();
        let cases = parse_test_cases(&config, Path::new("test.yml"));
        assert!(cases.is_empty());
    }

    #[rstest]
    fn parse_test_cases_inline_tests(env: TestEnv) {
        let yaml = indoc! {"
            rules:
              - allow: 'git status'
                tests:
                  - allow: 'git status'
                  - allow: 'git status --short'
        "};
        let config = parse_config(yaml).expect("parse failed");
        let cases = parse_test_cases(&config, &env.config_path());
        assert_eq!(cases.len(), 2);

        assert_eq!(cases[0].command, "git status");
        assert_eq!(cases[0].expected, ExpectedDecision::Allow);
        assert!(matches!(
            &cases[0].source,
            TestCaseSource::Inline { rule_index: 0, .. }
        ));

        assert_eq!(cases[1].command, "git status --short");
        assert_eq!(cases[1].expected, ExpectedDecision::Allow);
    }

    #[rstest]
    fn parse_test_cases_top_level(env: TestEnv) {
        let yaml = indoc! {"
            rules:
              - allow: 'git *'
            tests:
              cases:
                - allow: 'git push origin main'
                - deny: 'rm -rf /'
        "};
        let config = parse_config(yaml).expect("parse failed");
        let cases = parse_test_cases(&config, &env.config_path());
        assert_eq!(cases.len(), 2);

        assert_eq!(cases[0].command, "git push origin main");
        assert_eq!(cases[0].expected, ExpectedDecision::Allow);
        assert!(matches!(&cases[0].source, TestCaseSource::TopLevel { .. }));

        assert_eq!(cases[1].command, "rm -rf /");
        assert_eq!(cases[1].expected, ExpectedDecision::Deny);
    }

    #[rstest]
    fn parse_test_cases_mixed(env: TestEnv) {
        let yaml = indoc! {"
            rules:
              - allow: 'git status'
                tests:
                  - allow: 'git status'
              - deny: 'rm -rf /'
                tests:
                  - deny: 'rm -rf /'
            tests:
              cases:
                - ask: 'sudo reboot'
        "};
        let config = parse_config(yaml).expect("parse failed");
        let cases = parse_test_cases(&config, &env.config_path());

        // 2 inline + 1 top-level
        assert_eq!(cases.len(), 3);
        assert_eq!(cases[0].expected, ExpectedDecision::Allow);
        assert_eq!(cases[1].expected, ExpectedDecision::Deny);
        assert_eq!(cases[2].expected, ExpectedDecision::Ask);
    }

    // -----------------------------------------------------------------------
    // run_tests
    // -----------------------------------------------------------------------

    #[rstest]
    fn run_tests_all_pass() {
        let yaml = indoc! {"
            rules:
              - allow: 'git status'
        "};
        let config = parse_config(yaml).expect("parse failed");
        let test_cases = vec![TestCase {
            command: "git status".to_string(),
            expected: ExpectedDecision::Allow,
            source: TestCaseSource::TopLevel {
                file: PathBuf::from("test.yml"),
            },
            scope_config: None,
        }];

        let results = run_tests(&config, &test_cases);
        assert!(results.is_success());
        assert_eq!(results.passed_count(), 1);
    }

    #[rstest]
    fn run_tests_with_failure() {
        let yaml = indoc! {"
            rules:
              - allow: 'git status'
        "};
        let config = parse_config(yaml).expect("parse failed");
        let test_cases = vec![TestCase {
            command: "git status".to_string(),
            expected: ExpectedDecision::Deny,
            source: TestCaseSource::TopLevel {
                file: PathBuf::from("test.yml"),
            },
            scope_config: None,
        }];

        let results = run_tests(&config, &test_cases);
        assert!(!results.is_success());
        assert_eq!(results.failed_count(), 1);
    }

    #[rstest]
    fn run_tests_continues_after_failure() {
        let yaml = indoc! {"
            defaults:
              action: ask
            rules:
              - allow: 'git status'
        "};
        let config = parse_config(yaml).expect("parse failed");
        let test_cases = vec![
            TestCase {
                command: "git status".to_string(),
                expected: ExpectedDecision::Deny,
                source: TestCaseSource::TopLevel {
                    file: PathBuf::from("test.yml"),
                },
                scope_config: None,
            },
            TestCase {
                command: "git status".to_string(),
                expected: ExpectedDecision::Allow,
                source: TestCaseSource::TopLevel {
                    file: PathBuf::from("test.yml"),
                },
                scope_config: None,
            },
        ];

        let results = run_tests(&config, &test_cases);
        // Both tests are run even though the first fails
        assert_eq!(results.total_count(), 2);
        assert_eq!(results.failed_count(), 1);
        assert_eq!(results.passed_count(), 1);
    }

    #[rstest]
    fn run_tests_default_action() {
        // No rules means default action (ask) applies
        let config = Config::default();
        let test_cases = vec![TestCase {
            command: "echo hello".to_string(),
            expected: ExpectedDecision::Ask,
            source: TestCaseSource::TopLevel {
                file: PathBuf::from("test.yml"),
            },
            scope_config: None,
        }];

        let results = run_tests(&config, &test_cases);
        assert!(results.is_success());
    }

    #[rstest]
    fn run_tests_eval_error_is_failure_not_false_positive() {
        // A wrapper pattern with an unsupported token causes an eval error.
        // Even though the expected decision is "ask" (matching the default),
        // the test must fail because the rule was never actually evaluated.
        let config = Config {
            rules: Some(vec![]),
            definitions: Some(crate::config::Definitions {
                wrappers: Some(vec!["sudo [-u root] <cmd>".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let test_cases = vec![TestCase {
            command: "sudo rm foo".to_string(),
            expected: ExpectedDecision::Ask,
            source: TestCaseSource::TopLevel {
                file: PathBuf::from("test.yml"),
            },
            scope_config: None,
        }];

        let results = run_tests(&config, &test_cases);
        assert!(!results.is_success());
        assert_eq!(results.failed_count(), 1);
        assert!(results.results[0].error.is_some());
    }

    // -----------------------------------------------------------------------
    // report / report_summary
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::pass(
        "git status",
        ExpectedDecision::Allow,
        ActionKind::Allow,
        true,
        "PASS: git status => allow\n"
    )]
    #[case::fail(
        "rm -rf /",
        ExpectedDecision::Deny,
        ActionKind::Allow,
        false,
        "FAIL: rm -rf / => expected deny, got allow\n"
    )]
    fn report_output(
        #[case] command: &str,
        #[case] expected: ExpectedDecision,
        #[case] actual: ActionKind,
        #[case] passed: bool,
        #[case] expected_output: &str,
    ) {
        let results = TestResults {
            results: vec![TestResult {
                test_case: TestCase {
                    command: command.to_string(),
                    expected,
                    source: TestCaseSource::TopLevel {
                        file: PathBuf::from("test.yml"),
                    },
                    scope_config: None,
                },
                actual,
                passed,
                error: None,
            }],
        };

        let mut buf = Vec::new();
        report(&results, &mut buf);
        let output = String::from_utf8(buf).expect("invalid utf8");
        assert_eq!(output, expected_output);
    }

    #[rstest]
    fn report_summary_output() {
        let results = TestResults {
            results: vec![make_result(true), make_result(false), make_result(true)],
        };

        let mut buf = Vec::new();
        report_summary(&results, &mut buf);
        let output = String::from_utf8(buf).expect("invalid utf8");
        assert_eq!(output, "2 passed, 1 failed, 3 total\n");
    }

    // -----------------------------------------------------------------------
    // load_test_config
    // -----------------------------------------------------------------------

    #[rstest]
    fn load_test_config_from_file(env: TestEnv) {
        env.write_file(
            "runok.yml",
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        );

        let loaded = load_test_config(&env.config_path()).expect("load failed");
        let config = loaded.config;
        let rules = config.rules.expect("rules missing");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
    }

    #[rstest]
    fn load_test_config_from_directory(env: TestEnv) {
        env.write_file(
            "runok.yml",
            indoc! {"
                rules:
                  - allow: 'echo hello'
            "},
        );

        let loaded = load_test_config(&env.dir).expect("load failed");
        let config = loaded.config;
        let rules = config.rules.expect("rules missing");
        assert_eq!(rules[0].allow.as_deref(), Some("echo hello"));
    }

    #[rstest]
    fn load_test_config_yaml_extension(env: TestEnv) {
        env.write_file(
            "runok.yaml",
            indoc! {"
                rules:
                  - deny: 'rm *'
            "},
        );

        let loaded = load_test_config(&env.dir).expect("load failed");
        let config = loaded.config;
        let rules = config.rules.expect("rules missing");
        assert_eq!(rules[0].deny.as_deref(), Some("rm *"));
    }

    #[rstest]
    fn load_test_config_not_found(env: TestEnv) {
        let result = load_test_config(&env.dir);
        assert!(matches!(result, Err(TestError::ConfigNotFound { .. })));
    }

    #[rstest]
    fn load_test_config_nonexistent_path() {
        let result = load_test_config(Path::new("/nonexistent/path/runok.yml"));
        assert!(matches!(result, Err(TestError::ConfigNotFound { .. })));
    }

    #[rstest]
    fn load_test_config_with_extends(env: TestEnv) {
        env.write_file(
            "base.yml",
            indoc! {"
                rules:
                  - allow: 'echo base'
            "},
        );
        env.write_file(
            "runok.yml",
            indoc! {"
                extends:
                  - ./base.yml
                rules:
                  - allow: 'echo main'
            "},
        );

        let loaded = load_test_config(&env.config_path()).expect("load failed");
        let config = loaded.config;
        let rules = config.rules.expect("rules missing");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].allow.as_deref(), Some("echo base"));
        assert_eq!(rules[1].allow.as_deref(), Some("echo main"));
    }

    #[rstest]
    fn load_test_config_with_tests_extends(env: TestEnv) {
        env.write_file(
            "extra-rules.yml",
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        );
        env.write_file(
            "runok.yml",
            indoc! {"
                rules:
                  - allow: 'git status'
                tests:
                  extends:
                    - ./extra-rules.yml
                  cases:
                    - allow: 'git status'
            "},
        );

        let loaded = load_test_config(&env.config_path()).expect("load failed");
        let config = loaded.config;
        let rules = config.rules.expect("rules missing");
        // Main rule + rules from tests.extends
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
        assert_eq!(rules[1].deny.as_deref(), Some("rm -rf /"));
    }

    #[rstest]
    fn load_test_config_tests_extends_not_found(env: TestEnv) {
        env.write_file(
            "runok.yml",
            indoc! {"
                rules:
                  - allow: 'git status'
                tests:
                  extends:
                    - ./nonexistent.yml
            "},
        );

        let result = load_test_config(&env.config_path());
        assert!(matches!(result, Err(TestError::ConfigNotFound { .. })));
    }

    // -----------------------------------------------------------------------
    // parse_test_cases_scoped
    // -----------------------------------------------------------------------

    #[rstest]
    fn parse_test_cases_scoped_assigns_scope_config(env: TestEnv) {
        let yaml = indoc! {"
            rules:
              - ask: 'gh api *'
                tests:
                  - ask: 'gh api /repos'
              - deny: 'rm *'
                tests:
                  - deny: 'rm foo'
        "};
        let config = parse_config(yaml).expect("parse failed");
        let preset_config = parse_config(indoc! {"
            rules:
              - ask: 'gh api *'
                tests:
                  - ask: 'gh api /repos'
        "})
        .expect("parse failed");

        let cases = parse_test_cases_scoped(&config, &env.config_path(), Some(&preset_config), 1);
        assert_eq!(cases.len(), 2);

        // First rule (index 0) is a preset rule -> should have scope_config
        assert!(
            cases[0].scope_config.is_some(),
            "preset inline test should have scope_config"
        );
        // Second rule (index 1) is a local rule -> should not have scope_config
        assert!(
            cases[1].scope_config.is_none(),
            "local inline test should not have scope_config"
        );
    }

    // -----------------------------------------------------------------------
    // run_tests with scope_config
    // -----------------------------------------------------------------------

    #[rstest]
    fn run_tests_scope_config_isolates_preset_tests() {
        // Simulate a preset rule that asks for 'gh api *'
        // and a local rule that denies 'gh api * --paginate *'.
        // The preset's inline test should pass (evaluated against preset config only).
        let merged_yaml = indoc! {"
            rules:
              - ask: 'gh api *'
              - deny: 'gh api * --paginate *'
        "};
        let merged_config = parse_config(merged_yaml).expect("parse failed");
        let preset_yaml = indoc! {"
            rules:
              - ask: 'gh api *'
        "};
        let preset_config = parse_config(preset_yaml).expect("parse failed");

        let test_cases = vec![
            // Preset inline test: should be evaluated against preset_config
            TestCase {
                command: "gh api --paginate /repos/cli/cli/issues".to_string(),
                expected: ExpectedDecision::Ask,
                source: TestCaseSource::Inline {
                    file: PathBuf::from("preset.yml"),
                    rule_index: 0,
                },
                scope_config: Some(preset_config),
            },
            // Local inline test: should be evaluated against merged_config
            TestCase {
                command: "gh api --paginate /repos/cli/cli/issues".to_string(),
                expected: ExpectedDecision::Deny,
                source: TestCaseSource::Inline {
                    file: PathBuf::from("runok.yml"),
                    rule_index: 1,
                },
                scope_config: None,
            },
        ];

        let results = run_tests(&merged_config, &test_cases);
        assert!(
            results.is_success(),
            "both tests should pass: preset test evaluated against preset config, \
             local test against merged config"
        );
    }

    // -----------------------------------------------------------------------
    // load_test_config with extends (scoped)
    // -----------------------------------------------------------------------

    #[rstest]
    fn load_test_config_with_extends_provides_preset_config(env: TestEnv) {
        env.write_file(
            "preset.yml",
            indoc! {"
                rules:
                  - ask: 'gh api *'
            "},
        );
        env.write_file(
            "runok.yml",
            indoc! {"
                extends:
                  - ./preset.yml
                rules:
                  - deny: 'gh api * --paginate *'
            "},
        );

        let loaded = load_test_config(&env.config_path()).expect("load failed");
        assert!(
            loaded.preset_config.is_some(),
            "preset_config should be present when extends is used"
        );
        assert_eq!(loaded.preset_rule_count, 1);

        // The preset_config should only contain the preset's rules
        let preset_rules = loaded.preset_config.unwrap().rules.unwrap();
        assert_eq!(preset_rules.len(), 1);
        assert_eq!(preset_rules[0].ask.as_deref(), Some("gh api *"));
    }

    #[rstest]
    fn load_test_config_no_extends_has_no_preset_config(env: TestEnv) {
        env.write_file(
            "runok.yml",
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        );

        let loaded = load_test_config(&env.config_path()).expect("load failed");
        assert!(
            loaded.preset_config.is_none(),
            "preset_config should be None when no extends"
        );
        assert_eq!(loaded.preset_rule_count, 0);
    }

    // -----------------------------------------------------------------------
    // action_to_kind
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::allow(Action::Allow, ActionKind::Allow)]
    #[case::deny(
        Action::Deny(crate::rules::rule_engine::DenyResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: "test".to_string(),
        }),
        ActionKind::Deny
    )]
    #[case::ask(Action::Ask(None), ActionKind::Ask)]
    fn test_action_to_kind(#[case] action: Action, #[case] expected: ActionKind) {
        assert_eq!(action_to_kind(&action), expected);
    }

    // -----------------------------------------------------------------------
    // action_kind_label
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::allow(ActionKind::Allow, "allow")]
    #[case::ask(ActionKind::Ask, "ask")]
    #[case::deny(ActionKind::Deny, "deny")]
    fn test_action_kind_label(#[case] kind: ActionKind, #[case] expected: &str) {
        assert_eq!(action_kind_label(kind), expected);
    }

    // -----------------------------------------------------------------------
    // TestError display
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::config_not_found(
        TestError::ConfigNotFound { path: PathBuf::from("/missing.yml") },
        "config file not found: /missing.yml"
    )]
    #[case::no_test_cases(TestError::NoTestCases, "no test cases found")]
    fn test_error_display(#[case] error: TestError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let test_err: TestError = io_err.into();
        assert_eq!(test_err.to_string(), "file not found");
    }

    #[test]
    fn test_error_from_config() {
        let config_err = ConfigError::Validation(vec!["invalid".to_string()]);
        let test_err: TestError = config_err.into();
        assert!(test_err.to_string().contains("invalid"));
    }
}
