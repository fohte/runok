use std::collections::HashMap;

use super::ExprError;
use super::command_parser::{PipeInfo, RedirectInfo};

/// Context for CEL expression evaluation, providing access to
/// environment variables, parsed flags, positional arguments, path lists,
/// redirect operators, and pipeline position.
pub struct ExprContext {
    pub env: HashMap<String, String>,
    pub flags: HashMap<String, Option<String>>,
    pub args: Vec<String>,
    pub paths: HashMap<String, Vec<String>>,
    pub redirects: Vec<RedirectInfo>,
    pub pipe: PipeInfo,
    pub vars: HashMap<String, String>,
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
            redirects: Vec::new(),
            pipe: PipeInfo::default(),
            vars: HashMap::new(),
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
}
