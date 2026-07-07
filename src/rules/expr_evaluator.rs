use std::collections::HashMap;
use std::fs::Metadata;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use cel_interpreter::extractors::This;
use cel_interpreter::objects::Key;
use cel_interpreter::{ExecutionError, ResolveResult, Value};

use super::ExprError;
use super::command_parser::{PipeInfo, RedirectInfo};

/// Marker key used to identify the `fs` sentinel map. The `fs.*` functions
/// reject calls whose receiver is not this exact map, so registering them as
/// CEL functions does not accidentally expose them as methods on arbitrary
/// values.
const FS_SENTINEL_KEY: &str = "__runok_fs__";

fn fs_sentinel_key() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(|| Key::String(Arc::new(FS_SENTINEL_KEY.to_string())))
}

fn fs_sentinel() -> HashMap<String, Value> {
    HashMap::from([(FS_SENTINEL_KEY.to_string(), Value::Bool(true))])
}

/// Build the `fs` map exposed to CEL: the sentinel entry that gates
/// `fs.exists`/`fs.is_file`/`fs.is_dir` method dispatch, plus the `home` and
/// `cwd` values that are read as plain map fields (`fs.home`, `fs.cwd`), not
/// function calls.
fn fs_namespace(context: &ExprContext) -> HashMap<String, Value> {
    let mut map = fs_sentinel();
    let home = match &context.home {
        Some(home) => Value::String(home.clone().into()),
        None => Value::Null,
    };
    map.insert("home".to_string(), home);
    map.insert("cwd".to_string(), Value::String(context.cwd.clone().into()));
    map
}

fn require_fs_target(function: &'static str, this: &Value) -> Result<(), ExecutionError> {
    if let Value::Map(map) = this
        && map.map.contains_key(fs_sentinel_key())
    {
        return Ok(());
    }
    Err(ExecutionError::not_supported_as_method(
        function,
        this.clone(),
    ))
}

/// Translate filesystem stat errors into either `Ok(false)` (path does not
/// exist) or a CEL execution error (anything else, e.g. EACCES). Permission
/// errors must not be folded into "false": a `when: fs.exists(marker)` gate
/// would otherwise silently misfire when the process lacks stat permission.
fn classify_io(function: &'static str, err: std::io::Error) -> Result<bool, ExecutionError> {
    if err.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(ExecutionError::function_error(function, err))
    }
}

/// Wrap a stat-style filesystem check: validate the receiver, short-circuit on
/// empty path, then run `check` against the resolved metadata.
fn fs_metadata_check(
    function: &'static str,
    this: &Value,
    path: &str,
    check: fn(&Metadata) -> bool,
) -> ResolveResult {
    require_fs_target(function, this)?;
    if path.is_empty() {
        return Ok(Value::Bool(false));
    }
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Value::Bool(check(&meta))),
        Err(e) => classify_io(function, e).map(Value::Bool),
    }
}

fn fs_exists_impl(This(this): This<Value>, path: Arc<String>) -> ResolveResult {
    require_fs_target("exists", &this)?;
    if path.is_empty() {
        return Ok(Value::Bool(false));
    }
    match Path::new(path.as_str()).try_exists() {
        Ok(b) => Ok(Value::Bool(b)),
        Err(e) => classify_io("exists", e).map(Value::Bool),
    }
}

fn fs_is_file_impl(This(this): This<Value>, path: Arc<String>) -> ResolveResult {
    fs_metadata_check("is_file", &this, path.as_str(), Metadata::is_file)
}

fn fs_is_dir_impl(This(this): This<Value>, path: Arc<String>) -> ResolveResult {
    fs_metadata_check("is_dir", &this, path.as_str(), Metadata::is_dir)
}

/// `glob_matches(pattern, value)`: check whether `value` matches `pattern`,
/// where `*` matches zero or more characters and any other pattern requires
/// an exact match. Delegates to the same `literal_matches` used by pattern
/// matching, so results agree with a `type: pattern` `<var:name>` value
/// (single-token, no nested placeholders). `<path:name>` and the default
/// `literal` / `path` var types use different matching strategies
/// (`resolve_paths` / `match_value_with_type` in `token_matching.rs`) that
/// never treat `*` as a wildcard, so `glob_matches` can disagree with those.
fn glob_matches_impl(pattern: Arc<String>, value: Arc<String>) -> bool {
    super::pattern_matcher::literal_matches(&pattern, &value)
}

/// Context for CEL expression evaluation, providing access to
/// environment variables, parsed flags, positional arguments, path lists,
/// redirect operators, pipeline position, captured variables, flag groups,
/// and the host operating system.
pub struct ExprContext {
    pub env: HashMap<String, String>,
    pub flags: HashMap<String, Option<String>>,
    pub args: Vec<String>,
    pub paths: HashMap<String, Vec<String>>,
    /// Raw values for every `definitions.vars` entry, keyed by variable name.
    /// Exposed to CEL as `definitions.vars`. Unlike `vars` below (only the
    /// value captured by a matched `<var:name>` placeholder in the current
    /// rule), this contains every declared value for every variable
    /// regardless of whether the current rule's pattern captured it.
    pub var_definitions: HashMap<String, Vec<String>>,
    pub redirects: Vec<RedirectInfo>,
    pub pipe: PipeInfo,
    pub vars: HashMap<String, String>,
    /// Values captured by `<flag:name>` placeholders, keyed by flag group
    /// name. Always exposed as a list so that `when` clauses can use the
    /// list-aware CEL macros (`exists`, `all`, etc.). Groups defined in
    /// `definitions.flag_groups` but not matched by the rule are still
    /// present as empty lists, so `flag_groups["name"]` always succeeds.
    pub flag_groups: HashMap<String, Vec<String>>,
    /// Host operating system identifier, matching the values exposed by
    /// Rust's [`std::env::consts::OS`] (e.g. `"macos"`, `"linux"`,
    /// `"windows"`, `"freebsd"`).
    pub os: String,
    /// The kind of shell loop that immediately encloses the command being
    /// evaluated. Exposed to CEL as `shell.loop_kind`. Values: `"while"`,
    /// `"until"`, `"for"`, or `""` when the command is not inside any loop.
    pub loop_kind: String,
    /// Home directory absolute path, exposed to CEL as `fs.home`. `None`
    /// when the home directory cannot be determined (e.g. `HOME` unset),
    /// which CEL sees as `null` -- `fs.home == null` detects this case
    /// explicitly, while using `fs.home` in a string operation (e.g.
    /// `fs.home + '/x'`) raises an evaluation error rather than silently
    /// treating it as an empty prefix that matches everything.
    pub home: Option<String>,
    /// Current working directory absolute path at the time runok was
    /// invoked, exposed to CEL as `fs.cwd`. Falls back to `/` if the
    /// working directory cannot be resolved (see `EvalContext::from_env`).
    pub cwd: String,
}

/// Evaluates a CEL expression against a given context, returning a boolean result.
pub fn evaluate(expr: &str, context: &ExprContext) -> Result<bool, ExprError> {
    let program =
        cel_interpreter::Program::compile(expr).map_err(|e| ExprError::Parse(e.to_string()))?;

    let mut cel_context = cel_interpreter::Context::default();

    cel_context.add_variable_from_value("env", context.env.clone());

    // Convert Option<String> flags to CEL-compatible values.
    // None values become null in CEL.
    let flags_value: HashMap<String, cel_interpreter::Value> = context
        .flags
        .iter()
        .map(|(k, v)| {
            let val = match v {
                Some(s) => cel_interpreter::Value::String(s.clone().into()),
                None => cel_interpreter::Value::Null,
            };
            (k.clone(), val)
        })
        .collect();
    cel_context.add_variable_from_value("flags", flags_value);

    cel_context.add_variable_from_value("args", context.args.clone());

    cel_context
        .add_variable("paths", &context.paths)
        .map_err(|e| ExprError::Eval(e.to_string()))?;

    // Register `definitions`: a nested map exposing the raw definitions data,
    // as opposed to `paths`/`vars`, which expose only what the current rule's
    // pattern captured. `definitions.paths` aliases the same data as `paths`
    // above; `definitions.vars` holds every declared value for every
    // `definitions.vars` entry.
    let definitions_value: HashMap<String, HashMap<String, Vec<String>>> = HashMap::from([
        ("paths".to_string(), context.paths.clone()),
        ("vars".to_string(), context.var_definitions.clone()),
    ]);
    cel_context
        .add_variable("definitions", definitions_value)
        .map_err(|e| ExprError::Eval(e.to_string()))?;

    // Register redirects: list of maps with type, operator, target, descriptor
    let redirects_value: Vec<HashMap<String, cel_interpreter::Value>> = context
        .redirects
        .iter()
        .map(|r| {
            let mut m = HashMap::new();
            m.insert(
                "type".to_string(),
                cel_interpreter::Value::String(r.redirect_type.clone().into()),
            );
            m.insert(
                "operator".to_string(),
                cel_interpreter::Value::String(r.operator.clone().into()),
            );
            m.insert(
                "target".to_string(),
                cel_interpreter::Value::String(r.target.clone().into()),
            );
            m.insert(
                "descriptor".to_string(),
                match r.descriptor {
                    Some(fd) => cel_interpreter::Value::Int(fd),
                    None => cel_interpreter::Value::Null,
                },
            );
            m
        })
        .collect();
    cel_context.add_variable_from_value("redirects", redirects_value);

    // Register pipe: map with stdin and stdout booleans
    let pipe_value: HashMap<String, cel_interpreter::Value> = HashMap::from([
        (
            "stdin".to_string(),
            cel_interpreter::Value::Bool(context.pipe.stdin),
        ),
        (
            "stdout".to_string(),
            cel_interpreter::Value::Bool(context.pipe.stdout),
        ),
    ]);
    cel_context.add_variable_from_value("pipe", pipe_value);

    cel_context.add_variable_from_value("vars", context.vars.clone());

    cel_context
        .add_variable("flag_groups", &context.flag_groups)
        .map_err(|e| ExprError::Eval(e.to_string()))?;

    cel_context.add_variable_from_value("os", context.os.clone());

    // Register shell.* fields as a nested map (currently only `loop_kind`).
    let shell_value: HashMap<String, cel_interpreter::Value> = HashMap::from([(
        "loop_kind".to_string(),
        cel_interpreter::Value::String(context.loop_kind.clone().into()),
    )]);
    cel_context.add_variable_from_value("shell", shell_value);

    cel_context.add_variable_from_value("fs", fs_namespace(context));
    // `exists` is also the name of CEL's built-in comprehension macro
    // (`list.exists(v, pred)`), but cel-parser dispatches the 2-arg
    // comprehension form before function lookup, so a 1-arg `fs.exists(path)`
    // call lands here without colliding. `require_fs_target` rejects any
    // other receiver (e.g. `'foo'.exists('bar')`) so this registration is
    // not an unguarded global identifier. `fs.home` and `fs.cwd` are plain
    // map-field reads on the same `fs` map and do not go through function
    // dispatch, so both forms coexist on the one `fs` identifier.
    cel_context.add_function("exists", fs_exists_impl);
    cel_context.add_function("is_file", fs_is_file_impl);
    cel_context.add_function("is_dir", fs_is_dir_impl);
    cel_context.add_function("glob_matches", glob_matches_impl);

    let result = program
        .execute(&cel_context)
        .map_err(|e| ExprError::Eval(e.to_string()))?;

    match result {
        cel_interpreter::Value::Bool(b) => Ok(b),
        other => Err(ExprError::TypeError(format!("{:?}", other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn empty_context() -> ExprContext {
        ExprContext {
            env: HashMap::new(),
            flags: HashMap::new(),
            args: Vec::new(),
            paths: HashMap::new(),
            var_definitions: HashMap::new(),
            redirects: Vec::new(),
            pipe: PipeInfo::default(),
            vars: HashMap::new(),
            flag_groups: HashMap::new(),
            os: String::new(),
            loop_kind: String::new(),
            home: None,
            cwd: String::new(),
        }
    }

    // === Environment variable access ===

    #[rstest]
    #[case("env.AWS_PROFILE == 'prod'", "AWS_PROFILE", "prod", true)]
    #[case("env.AWS_PROFILE == 'prod'", "AWS_PROFILE", "dev", false)]
    #[case("env.HOME == '/home/user'", "HOME", "/home/user", true)]
    fn env_variable_access(
        #[case] expr: &str,
        #[case] key: &str,
        #[case] value: &str,
        #[case] expected: bool,
    ) {
        let context = ExprContext {
            env: HashMap::from([(key.to_string(), value.to_string())]),
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    // === Flag access ===

    #[rstest]
    #[case("flags.method == 'POST'", "method", Some("POST"), true)]
    #[case("flags.method == 'POST'", "method", Some("GET"), false)]
    #[case("flags.method == 'POST'", "method", None, false)]
    fn flag_access(
        #[case] expr: &str,
        #[case] key: &str,
        #[case] value: Option<&str>,
        #[case] expected: bool,
    ) {
        let context = ExprContext {
            flags: HashMap::from([(key.to_string(), value.map(|s| s.to_string()))]),
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    // === Argument access ===

    #[rstest]
    #[case("args[0] == 'build'", vec!["build", "--release"], true)]
    #[case("args[0] == 'test'", vec!["build", "--release"], false)]
    #[case("args[1] == '--release'", vec!["build", "--release"], true)]
    fn args_index_access(#[case] expr: &str, #[case] args: Vec<&str>, #[case] expected: bool) {
        let context = ExprContext {
            args: args.into_iter().map(|s| s.to_string()).collect(),
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    #[test]
    fn args_starts_with() {
        let context = ExprContext {
            args: vec!["https://prod.example.com/api".to_string()],
            ..empty_context()
        };
        assert!(evaluate("args[0].startsWith('https://prod')", &context).unwrap());
        assert!(!evaluate("args[0].startsWith('http://dev')", &context).unwrap());
    }

    // === Path list access ===

    #[test]
    fn paths_access() {
        let context = ExprContext {
            paths: HashMap::from([(
                "sensitive".to_string(),
                vec![".env".to_string(), ".envrc".to_string()],
            )]),
            ..empty_context()
        };
        let result = evaluate("size(paths.sensitive) == 2", &context);
        assert!(result.unwrap());
    }

    #[test]
    fn paths_contains_check() {
        let context = ExprContext {
            paths: HashMap::from([(
                "sensitive".to_string(),
                vec![
                    ".env".to_string(),
                    ".envrc".to_string(),
                    "~/.ssh/**".to_string(),
                ],
            )]),
            ..empty_context()
        };
        // CEL's `in` operator checks if a value exists in a list
        assert!(evaluate("'.env' in paths.sensitive", &context).unwrap());
        assert!(!evaluate("'.bashrc' in paths.sensitive", &context).unwrap());
    }

    // === `definitions` access ===

    #[test]
    fn definitions_paths_aliases_paths() {
        let context = ExprContext {
            paths: HashMap::from([(
                "sensitive".to_string(),
                vec![".env".to_string(), ".envrc".to_string()],
            )]),
            ..empty_context()
        };
        assert!(evaluate("definitions.paths.sensitive == paths.sensitive", &context).unwrap());
    }

    #[test]
    fn definitions_vars_exposes_every_declared_value() {
        let context = ExprContext {
            var_definitions: HashMap::from([(
                "safe-rm-paths".to_string(),
                vec!["**/node_modules".to_string(), "/tmp/*".to_string()],
            )]),
            ..empty_context()
        };
        assert!(
            evaluate(
                "definitions.vars[\"safe-rm-paths\"] == [\"**/node_modules\", \"/tmp/*\"]",
                &context
            )
            .unwrap()
        );
    }

    #[test]
    fn definitions_vars_empty_when_no_vars_defined() {
        assert!(evaluate("definitions.vars.size() == 0", &empty_context()).unwrap());
    }

    // === `glob_matches` function ===

    #[rstest]
    #[case::glob_prefix_match("**/node_modules", "packages/foo/node_modules", true)]
    #[case::exact_no_glob_match("node_modules", "node_modules", true)]
    #[case::exact_no_glob_no_match("node_modules", "packages/foo/node_modules", false)]
    #[case::glob_no_match("**/dist", "packages/foo/build", false)]
    #[case::glob_double_star_requires_separator("**/node_modules", "node_modules", false)]
    fn glob_matches_function(#[case] pattern: &str, #[case] value: &str, #[case] expected: bool) {
        let expr = format!("glob_matches('{pattern}', '{value}')");
        assert_eq!(evaluate(&expr, &empty_context()).unwrap(), expected);
    }

    #[rstest]
    #[case::all_args_match_a_safe_pattern(vec!["packages/foo/node_modules", "dist"], true)]
    #[case::one_arg_matches_no_safe_pattern(vec!["packages/foo/node_modules", "/important-dir"], false)]
    fn glob_matches_with_definitions_vars_safe_rm_paths(
        #[case] args: Vec<&str>,
        #[case] expected: bool,
    ) {
        let context = ExprContext {
            var_definitions: HashMap::from([(
                "safe-rm-paths".to_string(),
                vec!["**/node_modules".to_string(), "dist".to_string()],
            )]),
            args: args.into_iter().map(str::to_string).collect(),
            ..empty_context()
        };
        assert_eq!(
            evaluate(
                "args.all(a, definitions.vars[\"safe-rm-paths\"].exists(p, glob_matches(p, a)))",
                &context
            )
            .unwrap(),
            expected
        );
    }

    // === Variable reference access ===

    #[rstest]
    #[case::exact_match("vars['instance-ids'] == 'i-abc123'", "instance-ids", "i-abc123", true)]
    #[case::no_match(
        "vars['instance-ids'] == 'i-abc123'",
        "instance-ids",
        "i-xyz999",
        false
    )]
    fn vars_access(
        #[case] expr: &str,
        #[case] key: &str,
        #[case] value: &str,
        #[case] expected: bool,
    ) {
        let context = ExprContext {
            vars: HashMap::from([(key.to_string(), value.to_string())]),
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    #[test]
    fn vars_has_check() {
        let context = ExprContext {
            vars: HashMap::from([("region".to_string(), "us-east-1".to_string())]),
            ..empty_context()
        };
        assert!(evaluate("has(vars.region)", &context).unwrap());
        assert!(evaluate("vars.region == 'us-east-1'", &context).unwrap());
    }

    #[test]
    fn vars_empty_when_no_var_captured() {
        let context = empty_context();
        assert!(evaluate("vars.size() == 0", &context).unwrap());
    }

    // === Flag group access ===

    #[rstest]
    #[case::exists_matches_mutation(
        "field-flag",
        vec!["query=mutation { ... }".to_string(), "variables={}".to_string()],
        "flag_groups[\"field-flag\"].exists(v, v.startsWith(\"query=mutation\"))",
        true,
    )]
    #[case::exists_no_match(
        "field-flag",
        vec!["query=mutation { ... }".to_string(), "variables={}".to_string()],
        "flag_groups[\"field-flag\"].exists(v, v.startsWith(\"query=query\"))",
        false,
    )]
    #[case::size_one(
        "header-flag",
        vec!["Authorization: Bearer".to_string()],
        "size(flag_groups[\"header-flag\"]) == 1",
        true,
    )]
    #[case::size_zero_when_group_unmatched(
        "field-flag",
        Vec::new(),
        "size(flag_groups[\"field-flag\"]) == 0",
        true
    )]
    fn flag_groups_access(
        #[case] key: &str,
        #[case] values: Vec<String>,
        #[case] expr: &str,
        #[case] expected: bool,
    ) {
        let context = ExprContext {
            flag_groups: HashMap::from([(key.to_string(), values)]),
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    // === OS variable access ===

    #[rstest]
    #[case::macos_match("os == 'macos'", "macos", true)]
    #[case::macos_no_match("os == 'macos'", "linux", false)]
    #[case::linux_match("os == 'linux'", "linux", true)]
    #[case::in_list("os in ['macos', 'linux']", "linux", true)]
    #[case::not_in_list("os in ['macos', 'linux']", "windows", false)]
    fn os_variable_access(#[case] expr: &str, #[case] os: &str, #[case] expected: bool) {
        let context = ExprContext {
            os: os.to_string(),
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    // === Logical operators ===

    #[test]
    fn logical_and() {
        let context = ExprContext {
            env: HashMap::from([
                ("A".to_string(), "x".to_string()),
                ("B".to_string(), "y".to_string()),
            ]),
            ..empty_context()
        };
        assert!(evaluate("env.A == 'x' && env.B == 'y'", &context).unwrap());
        assert!(!evaluate("env.A == 'x' && env.B == 'z'", &context).unwrap());
    }

    #[test]
    fn logical_or() {
        let context = ExprContext {
            env: HashMap::from([("A".to_string(), "x".to_string())]),
            ..empty_context()
        };
        assert!(evaluate("env.A == 'x' || env.A == 'z'", &context).unwrap());
        assert!(!evaluate("env.A == 'y' || env.A == 'z'", &context).unwrap());
    }

    #[test]
    fn logical_not() {
        let context = ExprContext {
            env: HashMap::from([("A".to_string(), "x".to_string())]),
            ..empty_context()
        };
        assert!(evaluate("!(env.A == 'y')", &context).unwrap());
        assert!(!evaluate("!(env.A == 'x')", &context).unwrap());
    }

    // === Combined conditions ===

    #[test]
    fn combined_conditions() {
        let context = ExprContext {
            env: HashMap::from([("AWS_PROFILE".to_string(), "prod".to_string())]),
            flags: HashMap::from([("method".to_string(), Some("POST".to_string()))]),
            args: vec!["https://prod.example.com/api".to_string()],
            ..empty_context()
        };
        assert!(
            evaluate(
                "flags.method == 'POST' && args[0].startsWith('https://prod')",
                &context
            )
            .unwrap()
        );
        assert!(
            evaluate(
                "env.AWS_PROFILE == 'prod' && flags.method == 'POST'",
                &context
            )
            .unwrap()
        );
    }

    // === Error cases ===

    #[test]
    fn parse_error_on_invalid_expression() {
        let result = evaluate("@@@ invalid", &empty_context());
        assert!(result.is_err());
        match result.unwrap_err() {
            ExprError::Parse(_) => {}
            other => panic!("expected ExprError::Parse, got {:?}", other),
        }
    }

    #[test]
    fn eval_error_on_undeclared_reference() {
        let result = evaluate("missing.var == 'x'", &empty_context());
        assert!(result.is_err());
        match result.unwrap_err() {
            ExprError::Eval(_) => {}
            other => panic!("expected ExprError::Eval, got {:?}", other),
        }
    }

    #[test]
    fn type_error_on_non_bool_result() {
        let context = ExprContext {
            env: HashMap::from([("A".to_string(), "x".to_string())]),
            ..empty_context()
        };
        let result = evaluate("env.A", &context);
        assert!(result.is_err());
        match result.unwrap_err() {
            ExprError::TypeError(_) => {}
            other => panic!("expected ExprError::TypeError, got {:?}", other),
        }
    }

    // === Redirect variable access ===

    #[rstest]
    #[case::exists_output_redirect_present(
        "redirects.exists(r, r.type == \"output\")",
        vec![RedirectInfo {
            redirect_type: "output".to_string(),
            operator: ">".to_string(),
            target: "/tmp/log.txt".to_string(),
            descriptor: None,
        }],
        true
    )]
    #[case::exists_output_redirect_absent(
        "redirects.exists(r, r.type == \"output\")",
        vec![],
        false
    )]
    #[case::size_redirects_with_entry(
        "size(redirects) > 0",
        vec![RedirectInfo {
            redirect_type: "output".to_string(),
            operator: ">".to_string(),
            target: "/tmp/log.txt".to_string(),
            descriptor: None,
        }],
        true
    )]
    #[case::redirect_target_starts_with(
        "redirects[0].target.startsWith(\"/tmp/\")",
        vec![RedirectInfo {
            redirect_type: "output".to_string(),
            operator: ">".to_string(),
            target: "/tmp/log.txt".to_string(),
            descriptor: None,
        }],
        true
    )]
    #[case::redirect_descriptor_equals_2(
        "redirects[0].descriptor == 2",
        vec![RedirectInfo {
            redirect_type: "dup".to_string(),
            operator: ">&".to_string(),
            target: "&1".to_string(),
            descriptor: Some(2),
        }],
        true
    )]
    fn redirects_variable_access(
        #[case] expr: &str,
        #[case] redirects: Vec<RedirectInfo>,
        #[case] expected: bool,
    ) {
        let context = ExprContext {
            redirects,
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    // === shell.loop_kind variable access ===

    #[rstest]
    #[case::until_matches("shell.loop_kind == 'until'", "until", true)]
    #[case::while_matches("shell.loop_kind == 'while'", "while", true)]
    #[case::for_matches("shell.loop_kind == 'for'", "for", true)]
    #[case::empty_no_loop("shell.loop_kind == ''", "", true)]
    #[case::polling_loop_set("shell.loop_kind in ['while', 'until']", "until", true)]
    #[case::polling_loop_unset("shell.loop_kind in ['while', 'until']", "", false)]
    #[case::for_excluded_from_polling_set("shell.loop_kind in ['while', 'until']", "for", false)]
    fn shell_loop_kind_access(#[case] expr: &str, #[case] loop_kind: &str, #[case] expected: bool) {
        let context = ExprContext {
            loop_kind: loop_kind.to_string(),
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    // === Pipe variable access ===

    #[rstest]
    #[case::pipe_stdin_true("pipe.stdin == true", PipeInfo { stdin: true, stdout: false }, true)]
    #[case::pipe_stdin_false("pipe.stdin == true", PipeInfo { stdin: false, stdout: false }, false)]
    #[case::pipe_stdout_true("pipe.stdout == true", PipeInfo { stdin: false, stdout: true }, true)]
    #[case::pipe_stdout_false("pipe.stdout == true", PipeInfo { stdin: false, stdout: false }, false)]
    fn pipe_variable_access(#[case] expr: &str, #[case] pipe: PipeInfo, #[case] expected: bool) {
        let context = ExprContext {
            pipe,
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    // === Filesystem functions (fs.exists / fs.is_file / fs.is_dir) ===

    fn eval_fs(expr: &str) -> bool {
        evaluate(expr, &empty_context()).unwrap()
    }

    /// What kind of filesystem entry to materialise for a given test case.
    #[derive(Clone, Copy)]
    enum FsKind {
        File,
        Dir,
        Missing,
    }

    fn make_path(dir: &std::path::Path, kind: FsKind) -> std::path::PathBuf {
        match kind {
            FsKind::File => {
                let p = dir.join("entry");
                std::fs::write(&p, b"").unwrap();
                p
            }
            FsKind::Dir => {
                let p = dir.join("entry");
                std::fs::create_dir(&p).unwrap();
                p
            }
            FsKind::Missing => dir.join("entry"),
        }
    }

    #[rstest]
    #[case::exists_file("fs.exists", FsKind::File, true)]
    #[case::exists_dir("fs.exists", FsKind::Dir, true)]
    #[case::exists_missing("fs.exists", FsKind::Missing, false)]
    #[case::is_file_file("fs.is_file", FsKind::File, true)]
    #[case::is_file_dir("fs.is_file", FsKind::Dir, false)]
    #[case::is_file_missing("fs.is_file", FsKind::Missing, false)]
    #[case::is_dir_file("fs.is_dir", FsKind::File, false)]
    #[case::is_dir_dir("fs.is_dir", FsKind::Dir, true)]
    #[case::is_dir_missing("fs.is_dir", FsKind::Missing, false)]
    fn fs_functions_classify_path(
        #[case] func: &str,
        #[case] kind: FsKind,
        #[case] expected: bool,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = make_path(dir.path(), kind);
        let path_str = path.to_str().unwrap();
        assert_eq!(eval_fs(&format!("{func}('{path_str}')")), expected);
    }

    #[rstest]
    #[case::exists("fs.exists('')")]
    #[case::is_file("fs.is_file('')")]
    #[case::is_dir("fs.is_dir('')")]
    fn fs_functions_return_false_for_empty_string(#[case] expr: &str) {
        assert!(!eval_fs(expr));
    }

    #[cfg(unix)]
    #[rstest]
    #[case::exists_to_file("fs.exists", FsKind::File, true)]
    #[case::exists_to_dir("fs.exists", FsKind::Dir, true)]
    #[case::is_file_to_file("fs.is_file", FsKind::File, true)]
    #[case::is_file_to_dir("fs.is_file", FsKind::Dir, false)]
    #[case::is_dir_to_file("fs.is_dir", FsKind::File, false)]
    #[case::is_dir_to_dir("fs.is_dir", FsKind::Dir, true)]
    fn fs_functions_follow_symlinks(
        #[case] func: &str,
        #[case] target_kind: FsKind,
        #[case] expected: bool,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let target = make_path(dir.path(), target_kind);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_str = link.to_str().unwrap();
        assert_eq!(eval_fs(&format!("{func}('{link_str}')")), expected);
    }

    #[cfg(unix)]
    #[rstest]
    #[case::exists("fs.exists")]
    #[case::is_file("fs.is_file")]
    #[case::is_dir("fs.is_dir")]
    fn fs_functions_return_false_for_broken_symlink(#[case] func: &str) {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("missing");
        let link = dir.path().join("broken");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_str = link.to_str().unwrap();
        assert!(!eval_fs(&format!("{func}('{link_str}')")));
    }

    #[rstest]
    #[case::exists("'foo'.exists('bar')")]
    #[case::is_file("'foo'.is_file('bar')")]
    #[case::is_dir("'foo'.is_dir('bar')")]
    fn fs_functions_reject_non_fs_receiver(#[case] expr: &str) {
        let result = evaluate(expr, &empty_context());
        assert!(result.is_err(), "expected error for {expr}, got {result:?}");
        match result.unwrap_err() {
            ExprError::Eval(_) => {}
            other => panic!("expected ExprError::Eval, got {other:?}"),
        }
    }

    // === fs.home / fs.cwd (map-field access on the `fs` namespace) ===

    #[rstest]
    #[case::home_match("fs.home == '/home/user'", Some("/home/user"), "", true)]
    #[case::home_no_match("fs.home == '/home/user'", Some("/home/other"), "", false)]
    #[case::home_null_when_unset("fs.home == null", None, "", true)]
    #[case::cwd_match("fs.cwd == '/repo'", None, "/repo", true)]
    #[case::cwd_no_match("fs.cwd == '/repo'", None, "/other", false)]
    #[case::home_starts_with(
        "fs.cwd.startsWith(fs.home + '/ghq/')",
        Some("/home/user"),
        "/home/user/ghq/github.com/fohte/runok",
        true
    )]
    fn fs_home_and_cwd_access(
        #[case] expr: &str,
        #[case] home: Option<&str>,
        #[case] cwd: &str,
        #[case] expected: bool,
    ) {
        let context = ExprContext {
            home: home.map(str::to_string),
            cwd: cwd.to_string(),
            ..empty_context()
        };
        assert_eq!(evaluate(expr, &context).unwrap(), expected);
    }

    #[test]
    fn fs_home_concat_errors_when_home_is_unset() {
        let context = ExprContext {
            home: None,
            cwd: "/repo".to_string(),
            ..empty_context()
        };
        let result = evaluate("fs.cwd.startsWith(fs.home + '/ghq/')", &context);
        assert!(result.is_err(), "expected error, got {result:?}");
    }

    #[test]
    fn fs_home_and_cwd_coexist_with_fs_functions() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("marker");
        std::fs::write(&marker, b"").unwrap();
        let context = ExprContext {
            cwd: dir.path().to_str().unwrap().to_string(),
            ..empty_context()
        };
        assert!(
            evaluate(
                "fs.exists(fs.cwd + '/marker') && fs.is_file(fs.cwd + '/marker')",
                &context
            )
            .unwrap()
        );
    }
}
