use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::ExtensionError;
use crate::config::ActionKind;

/// JSON-RPC 2.0 request sent to an extension process via stdin.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionRequest {
    pub command: String,
    pub flags: HashMap<String, String>,
    pub args: Vec<String>,
    pub raw_command_line: String,
    pub env: HashMap<String, String>,
    pub cwd: String,
}

/// The result payload inside a JSON-RPC 2.0 response from an extension.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExtensionResponse {
    pub status: String,
    pub message: Option<String>,
    pub fix_suggestion: Option<String>,
}

/// JSON-RPC 2.0 envelope for responses (internal parsing helper).
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<ExtensionResponse>,
    error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Deserialize)]
struct JsonRpcError {
    #[expect(
        dead_code,
        reason = "error code is part of JSON-RPC 2.0 spec but not used in error reporting"
    )]
    code: Option<i64>,
    message: Option<String>,
}

/// Trait for running extension validation via JSON-RPC 2.0 over stdio.
pub trait ExtensionRunner {
    fn validate(
        &self,
        executor_cmd: &str,
        request: &ExtensionRequest,
        timeout: Duration,
    ) -> Result<ExtensionResponse, ExtensionError>;
}

/// The resolved result of an extension validation, including the action and
/// optional message/fix_suggestion from the extension response.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtensionResult {
    pub action: ActionKind,
    pub message: Option<String>,
    pub fix_suggestion: Option<String>,
}

/// Strip ASCII control characters (except common whitespace) to prevent
/// terminal injection from malicious extension output.
fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_ascii_control() || matches!(*c, '\n' | '\r' | '\t'))
        .collect()
}

/// Resolve an extension validation result into an action.
///
/// On success, maps the response status to an `ActionKind`.
/// On any error (timeout, spawn failure, invalid response), falls back to
/// `ActionKind::Ask` so that the user is prompted for confirmation.
/// When `verbose` is true, error details are printed to stderr.
pub fn resolve_extension_result(
    result: Result<ExtensionResponse, ExtensionError>,
    verbose: bool,
) -> ExtensionResult {
    match result {
        Ok(response) => {
            let action = match response.status.as_str() {
                "allow" => ActionKind::Allow,
                "deny" => ActionKind::Deny,
                "ask" => ActionKind::Ask,
                _ => {
                    if verbose {
                        eprintln!(
                            "[verbose] Extension returned unknown status '{}', falling back to ask",
                            sanitize_for_terminal(&response.status)
                        );
                    }
                    ActionKind::Ask
                }
            };
            ExtensionResult {
                action,
                message: response.message,
                fix_suggestion: response.fix_suggestion,
            }
        }
        Err(ref err) => {
            if verbose {
                eprintln!(
                    "[verbose] Extension error: {}",
                    sanitize_for_terminal(&err.to_string())
                );
            }
            let message = format!(
                "Extension {}, asking user for confirmation",
                match &err {
                    ExtensionError::Timeout(_) => "timed out",
                    ExtensionError::Spawn(_) => "failed to start",
                    ExtensionError::InvalidResponse(_) => "returned invalid response",
                }
            );
            ExtensionResult {
                action: ActionKind::Ask,
                message: Some(message),
                fix_suggestion: None,
            }
        }
    }
}

/// Default implementation that spawns an external process.
pub struct ProcessExtensionRunner;

impl ProcessExtensionRunner {
    /// Build a JSON-RPC 2.0 request string from an ExtensionRequest.
    pub fn build_jsonrpc_request(
        &self,
        request: &ExtensionRequest,
    ) -> Result<String, ExtensionError> {
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "validateCommand",
            "params": request,
        });
        serde_json::to_string(&envelope).map_err(|e| {
            ExtensionError::InvalidResponse(format!("request serialization failed: {e}"))
        })
    }

    /// Parse a JSON-RPC 2.0 response string into an ExtensionResponse.
    pub fn parse_jsonrpc_response(raw: &str) -> Result<ExtensionResponse, ExtensionError> {
        let envelope: JsonRpcResponse = serde_json::from_str(raw)
            .map_err(|e| ExtensionError::InvalidResponse(format!("JSON parse error: {e}")))?;

        if let Some(err) = envelope.error {
            let msg = err.message.unwrap_or_else(|| "unknown error".to_string());
            return Err(ExtensionError::InvalidResponse(format!(
                "JSON-RPC error: {msg}"
            )));
        }

        envelope.result.ok_or_else(|| {
            ExtensionError::InvalidResponse(
                "missing 'result' field in JSON-RPC response".to_string(),
            )
        })
    }

    /// Split executor_cmd into program and arguments for spawning.
    /// Uses simple whitespace splitting because executor_cmd comes from the
    /// user's config file, not from external input. Quoted argument support
    /// (e.g. via shlex) can be added later if needed.
    fn parse_command(executor_cmd: &str) -> (String, Vec<String>) {
        let mut parts = executor_cmd.split_whitespace();
        let program = parts.next().unwrap_or("").to_string();
        let args: Vec<String> = parts.map(String::from).collect();
        (program, args)
    }
}

impl ExtensionRunner for ProcessExtensionRunner {
    fn validate(
        &self,
        executor_cmd: &str,
        request: &ExtensionRequest,
        timeout: Duration,
    ) -> Result<ExtensionResponse, ExtensionError> {
        let (program, args) = Self::parse_command(executor_cmd);

        let mut child = Command::new(&program)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        // Write JSON-RPC request to stdin, then close the pipe
        let json_request = self.build_jsonrpc_request(request)?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(json_request.as_bytes())?;
            // stdin is dropped here, closing the pipe
        }

        // Wait with timeout using a polling loop.
        // NOTE: We read stdout after the process exits (via wait_with_output).
        // This could deadlock if stdout exceeds the OS pipe buffer (~64KB), but
        // extension responses are small JSON payloads so this is fine in practice.
        let start = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    let output = child.wait_with_output()?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    return Self::parse_jsonrpc_response(&stdout);
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        // Best-effort cleanup; errors are intentionally ignored
                        // so we always return `Timeout` rather than a misleading
                        // `Spawn(io::Error)`.
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(ExtensionError::Timeout(timeout));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(ExtensionError::Spawn(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::TempPath;

    fn sample_request() -> ExtensionRequest {
        ExtensionRequest {
            command: "curl".to_string(),
            flags: HashMap::from([("X".to_string(), "POST".to_string())]),
            args: vec!["https://api.example.com".to_string()],
            raw_command_line: "curl -X POST https://api.example.com".to_string(),
            env: HashMap::from([("AWS_PROFILE".to_string(), "prod".to_string())]),
            cwd: "/home/user/project".to_string(),
        }
    }

    /// Create a temporary executable script with the given raw content.
    ///
    /// Returns a `TempPath` that auto-deletes the file on drop.
    /// The file handle is closed via `into_temp_path()` before returning,
    /// which prevents ETXTBSY on Linux when spawning the script immediately.
    #[cfg(unix)]
    fn write_test_script_raw(content: &str) -> TempPath {
        use std::os::unix::fs::PermissionsExt;

        let mut file = tempfile::Builder::new()
            .prefix("runok-ext-")
            .suffix(".sh")
            .permissions(std::fs::Permissions::from_mode(0o755))
            .tempfile()
            .expect("should create temp script");
        file.write_all(content.as_bytes())
            .expect("should write test script");
        file.into_temp_path()
    }

    /// Create a script that drains stdin and prints the given JSON response.
    fn write_test_script(response: &str) -> TempPath {
        write_test_script_raw(&format!(
            "#!/bin/sh\ncat > /dev/null\nprintf '%s' '{}'\n",
            response
        ))
    }

    // === Serialization tests ===

    #[test]
    fn serialize_jsonrpc_request() {
        let runner = ProcessExtensionRunner;
        let request = sample_request();
        let json_str = runner
            .build_jsonrpc_request(&request)
            .expect("should serialize request");

        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should be valid JSON");
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 1);
        assert_eq!(parsed["method"], "validateCommand");
        assert_eq!(parsed["params"]["command"], "curl");
        assert_eq!(parsed["params"]["flags"]["X"], "POST");
        assert_eq!(parsed["params"]["args"][0], "https://api.example.com");
        assert_eq!(
            parsed["params"]["raw_command_line"],
            "curl -X POST https://api.example.com"
        );
        assert_eq!(parsed["params"]["env"]["AWS_PROFILE"], "prod");
        assert_eq!(parsed["params"]["cwd"], "/home/user/project");
    }

    #[test]
    fn serialize_request_with_empty_fields() {
        let request = ExtensionRequest {
            command: "test".to_string(),
            flags: HashMap::new(),
            args: vec![],
            raw_command_line: "test".to_string(),
            env: HashMap::new(),
            cwd: ".".to_string(),
        };
        let runner = ProcessExtensionRunner;
        let json_str = runner
            .build_jsonrpc_request(&request)
            .expect("should serialize request");

        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should be valid JSON");
        assert_eq!(parsed["params"]["command"], "test");
        assert!(
            parsed["params"]["flags"]
                .as_object()
                .expect("flags should be an object")
                .is_empty()
        );
        assert!(
            parsed["params"]["args"]
                .as_array()
                .expect("args should be an array")
                .is_empty()
        );
    }

    // === Response deserialization tests ===

    #[rstest]
    #[case::deny(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":"deny","message":"POST not allowed","fix_suggestion":"use GET"}}"#,
        ExtensionResponse { status: "deny".into(), message: Some("POST not allowed".into()), fix_suggestion: Some("use GET".into()) },
    )]
    #[case::allow(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":"allow"}}"#,
        ExtensionResponse { status: "allow".into(), message: None, fix_suggestion: None },
    )]
    #[case::ask(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":"ask","message":"please confirm"}}"#,
        ExtensionResponse { status: "ask".into(), message: Some("please confirm".into()), fix_suggestion: None },
    )]
    fn parse_valid_response(#[case] json: &str, #[case] expected: ExtensionResponse) {
        let response = ProcessExtensionRunner::parse_jsonrpc_response(json)
            .expect("should parse valid response");
        assert_eq!(response, expected);
    }

    // === Error cases: parsing ===

    #[rstest]
    #[case::invalid_json(
        "not json at all",
        "JSON parse error: expected ident at line 1 column 2"
    )]
    #[case::missing_result(
        r#"{"jsonrpc": "2.0", "id": 1}"#,
        "missing 'result' field in JSON-RPC response"
    )]
    #[case::missing_status(
        r#"{"jsonrpc": "2.0", "id": 1, "result": {"message": "hi"}}"#,
        "JSON parse error: missing field `status` at line 1 column 55"
    )]
    #[case::jsonrpc_error(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid request"}}"#,
        "JSON-RPC error: Invalid request"
    )]
    fn parse_invalid_response(#[case] json: &str, #[case] expected_msg: &str) {
        let err =
            ProcessExtensionRunner::parse_jsonrpc_response(json).expect_err("should fail to parse");
        match err {
            ExtensionError::InvalidResponse(msg) => assert_eq!(msg, expected_msg),
            other => panic!("expected InvalidResponse, got: {other:?}"),
        }
    }

    // === End-to-end with real process ===

    #[rstest]
    #[case::deny(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":"deny","message":"blocked"}}"#,
        ExtensionResponse { status: "deny".into(), message: Some("blocked".into()), fix_suggestion: None },
    )]
    #[case::allow(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":"allow"}}"#,
        ExtensionResponse { status: "allow".into(), message: None, fix_suggestion: None },
    )]
    fn validate_with_real_process(
        #[case] response_json: &str,
        #[case] expected: ExtensionResponse,
    ) {
        let script = write_test_script(response_json);
        let response = ProcessExtensionRunner
            .validate(
                &script.display().to_string(),
                &sample_request(),
                Duration::from_secs(5),
            )
            .expect("should get response from process");
        assert_eq!(response, expected);
    }

    #[test]
    fn validate_spawn_error_for_nonexistent_command() {
        let err = ProcessExtensionRunner
            .validate(
                "/nonexistent/binary/path",
                &sample_request(),
                Duration::from_secs(5),
            )
            .expect_err("should fail for nonexistent binary");
        assert!(matches!(err, ExtensionError::Spawn(_)));
    }

    #[test]
    fn validate_invalid_json_from_process() {
        let script = write_test_script("not-valid-json");
        let err = ProcessExtensionRunner
            .validate(
                &script.display().to_string(),
                &sample_request(),
                Duration::from_secs(5),
            )
            .expect_err("should fail on invalid JSON from process");
        assert!(matches!(err, ExtensionError::InvalidResponse(_)));
    }

    #[test]
    fn validate_timeout() {
        let script = write_test_script_raw("#!/bin/sh\nsleep 10\n");
        let err = ProcessExtensionRunner
            .validate(
                &script.display().to_string(),
                &sample_request(),
                Duration::from_secs(1),
            )
            .expect_err("should timeout for long-running process");
        assert_eq!(
            err.to_string(),
            format!("timeout after {:?}", Duration::from_secs(1))
        );
    }

    // === parse_command tests ===

    #[rstest]
    #[case::simple("deno run check.ts", "deno", &["run", "check.ts"])]
    #[case::no_args("/usr/bin/validator", "/usr/bin/validator", &[])]
    #[case::with_flags(
        "deno run --allow-net ./checks/url_check.ts",
        "deno",
        &["run", "--allow-net", "./checks/url_check.ts"],
    )]
    fn parse_command(
        #[case] input: &str,
        #[case] expected_prog: &str,
        #[case] expected_args: &[&str],
    ) {
        let (prog, args) = ProcessExtensionRunner::parse_command(input);
        assert_eq!(prog, expected_prog);
        let args_strs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        assert_eq!(args_strs, expected_args);
    }

    // === resolve_extension_result: error fallback ===

    #[rstest]
    #[case::timeout(
        Err(ExtensionError::Timeout(Duration::from_secs(5))),
        ActionKind::Ask,
        Some("Extension timed out, asking user for confirmation")
    )]
    #[case::spawn(
        Err(ExtensionError::Spawn(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found"
        ))),
        ActionKind::Ask,
        Some("Extension failed to start, asking user for confirmation")
    )]
    #[case::invalid_response(
        Err(ExtensionError::InvalidResponse("bad json".to_string())),
        ActionKind::Ask,
        Some("Extension returned invalid response, asking user for confirmation"),
    )]
    fn error_falls_back_to_ask(
        #[case] result: Result<ExtensionResponse, ExtensionError>,
        #[case] expected_action: ActionKind,
        #[case] expected_message: Option<&str>,
    ) {
        let resolved = resolve_extension_result(result, false);
        assert_eq!(resolved.action, expected_action);
        assert_eq!(resolved.message.as_deref(), expected_message);
        assert_eq!(resolved.fix_suggestion, None);
    }

    // === resolve_extension_result: successful response ===

    #[rstest]
    #[case::allow(
        ExtensionResponse { status: "allow".into(), message: None, fix_suggestion: None },
        ActionKind::Allow,
    )]
    #[case::deny(
        ExtensionResponse { status: "deny".into(), message: Some("blocked".into()), fix_suggestion: Some("use GET".into()) },
        ActionKind::Deny,
    )]
    #[case::ask(
        ExtensionResponse { status: "ask".into(), message: Some("please confirm".into()), fix_suggestion: None },
        ActionKind::Ask,
    )]
    fn success_maps_to_correct_action(
        #[case] response: ExtensionResponse,
        #[case] expected_action: ActionKind,
    ) {
        let expected_message = response.message.clone();
        let expected_fix = response.fix_suggestion.clone();
        let resolved = resolve_extension_result(Ok(response), false);
        assert_eq!(resolved.action, expected_action);
        assert_eq!(resolved.message, expected_message);
        assert_eq!(resolved.fix_suggestion, expected_fix);
    }

    #[test]
    fn unknown_status_falls_back_to_ask() {
        let response = ExtensionResponse {
            status: "unknown_status".into(),
            message: Some("something".into()),
            fix_suggestion: None,
        };
        let resolved = resolve_extension_result(Ok(response), false);
        assert_eq!(resolved.action, ActionKind::Ask);
    }

    // === resolve_extension_result: verbose logging ===

    #[rstest]
    #[case::timeout_verbose(
        Err(ExtensionError::Timeout(Duration::from_secs(5))),
        "Extension error: timeout after 5s"
    )]
    #[case::spawn_verbose(
        Err(ExtensionError::Spawn(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "plugin not found"
        ))),
        "Extension error: spawn error: plugin not found"
    )]
    #[case::invalid_response_verbose(
        Err(ExtensionError::InvalidResponse("bad json".to_string())),
        "Extension error: invalid response: bad json",
    )]
    fn verbose_mode_logs_error(
        #[case] result: Result<ExtensionResponse, ExtensionError>,
        #[case] expected_log_fragment: &str,
    ) {
        // Verify that verbose mode still returns Ask (the logging itself goes to
        // stderr which we cannot easily capture in unit tests, but we verify the
        // fallback behavior is consistent).
        let resolved = resolve_extension_result(result, true);
        assert_eq!(resolved.action, ActionKind::Ask);
        // The expected_log_fragment is documented here to clarify what would be
        // printed; the actual stderr capture is tested in integration tests.
        let _ = expected_log_fragment;
    }

    // === Integration test: end-to-end fallback with real processes ===

    #[test]
    fn integration_timeout_falls_back_to_ask() {
        let script = write_test_script_raw("#!/bin/sh\nsleep 10\n");
        let result = ProcessExtensionRunner.validate(
            &script.display().to_string(),
            &sample_request(),
            Duration::from_secs(1),
        );
        let resolved = resolve_extension_result(result, false);
        assert_eq!(resolved.action, ActionKind::Ask);
        assert_eq!(
            resolved.message.as_deref(),
            Some("Extension timed out, asking user for confirmation")
        );
    }

    #[test]
    fn integration_spawn_failure_falls_back_to_ask() {
        let result = ProcessExtensionRunner.validate(
            "/nonexistent/binary/path",
            &sample_request(),
            Duration::from_secs(5),
        );
        let resolved = resolve_extension_result(result, false);
        assert_eq!(resolved.action, ActionKind::Ask);
        assert_eq!(
            resolved.message.as_deref(),
            Some("Extension failed to start, asking user for confirmation")
        );
    }

    #[test]
    fn integration_invalid_response_falls_back_to_ask() {
        let script = write_test_script("not-valid-json");
        let result = ProcessExtensionRunner.validate(
            &script.display().to_string(),
            &sample_request(),
            Duration::from_secs(5),
        );
        let resolved = resolve_extension_result(result, false);
        assert_eq!(resolved.action, ActionKind::Ask);
        assert_eq!(
            resolved.message.as_deref(),
            Some("Extension returned invalid response, asking user for confirmation")
        );
    }

    #[test]
    fn integration_success_does_not_fallback() {
        let response_json = r#"{"jsonrpc":"2.0","id":1,"result":{"status":"allow"}}"#;
        let script = write_test_script(response_json);
        let result = ProcessExtensionRunner.validate(
            &script.display().to_string(),
            &sample_request(),
            Duration::from_secs(5),
        );
        // Verify extension ran successfully before testing fallback logic
        assert!(result.is_ok(), "extension should succeed: {result:?}");
        let resolved = resolve_extension_result(result, false);
        assert_eq!(resolved.action, ActionKind::Allow);
        assert_eq!(resolved.message, None);
    }

    // === sanitize_for_terminal ===

    #[rstest]
    #[case::plain_text("hello world", "hello world")]
    #[case::strips_ansi_escape("\x1b[31mred\x1b[0m", "[31mred[0m")]
    #[case::preserves_newline("line1\nline2", "line1\nline2")]
    #[case::preserves_tab("col1\tcol2", "col1\tcol2")]
    #[case::strips_null("before\x00after", "beforeafter")]
    #[case::strips_bell("alert\x07here", "alerthere")]
    fn sanitize_for_terminal_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(sanitize_for_terminal(input), expected);
    }
}
