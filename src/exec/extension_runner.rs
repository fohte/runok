use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::ExtensionError;

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
    #[expect(
        dead_code,
        reason = "included for JSON-RPC 2.0 compliance; validated at protocol level"
    )]
    jsonrpc: Option<String>,
    #[expect(
        dead_code,
        reason = "included for JSON-RPC 2.0 compliance; validated at protocol level"
    )]
    id: Option<serde_json::Value>,
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

/// Default implementation that spawns an external process.
pub struct ProcessExtensionRunner;

impl ProcessExtensionRunner {
    /// Build a JSON-RPC 2.0 request string from an ExtensionRequest.
    pub fn build_jsonrpc_request(&self, request: &ExtensionRequest) -> String {
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "validateCommand",
            "params": request,
        });
        serde_json::to_string(&envelope).unwrap_or_default()
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
    /// Uses simple whitespace splitting, as executor commands are typically
    /// straightforward (e.g., "deno run --allow-net ./checks/url_check.ts").
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
        let json_request = self.build_jsonrpc_request(request);
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(json_request.as_bytes());
            // stdin is dropped here, closing the pipe
        }

        // Wait with timeout using a polling loop
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

    /// Create a temporary script file that drains stdin and prints the given response.
    /// Returns the path to the script. Uses a unique counter to avoid conflicts
    /// between parallel test runs.
    fn write_test_script(response: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let dir = std::env::temp_dir().join("runok-test-extension");
        std::fs::create_dir_all(&dir).expect("should create temp dir");
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("ext-{}-{}.sh", std::process::id(), id));
        std::fs::write(
            &path,
            format!("#!/bin/sh\ncat > /dev/null\nprintf '%s' '{}'\n", response),
        )
        .expect("should write test script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("should set executable permission");
        }
        path
    }

    // === Serialization tests ===

    #[test]
    fn serialize_jsonrpc_request() {
        let runner = ProcessExtensionRunner;
        let request = sample_request();
        let json_str = runner.build_jsonrpc_request(&request);

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
        let json_str = runner.build_jsonrpc_request(&request);

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

    #[test]
    fn deserialize_valid_deny_response() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "status": "deny",
                "message": "POST requests are not allowed",
                "fix_suggestion": "curl -X GET https://api.example.com"
            }
        }"#;

        let response = ProcessExtensionRunner::parse_jsonrpc_response(json)
            .expect("should parse valid deny response");
        assert_eq!(response.status, "deny");
        assert_eq!(
            response.message.as_deref(),
            Some("POST requests are not allowed")
        );
        assert_eq!(
            response.fix_suggestion.as_deref(),
            Some("curl -X GET https://api.example.com")
        );
    }

    #[test]
    fn deserialize_valid_allow_response() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "status": "allow"
            }
        }"#;

        let response = ProcessExtensionRunner::parse_jsonrpc_response(json)
            .expect("should parse valid allow response");
        assert_eq!(response.status, "allow");
        assert_eq!(response.message, None);
        assert_eq!(response.fix_suggestion, None);
    }

    #[test]
    fn deserialize_valid_ask_response() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "status": "ask",
                "message": "This looks risky, please confirm"
            }
        }"#;

        let response = ProcessExtensionRunner::parse_jsonrpc_response(json)
            .expect("should parse valid ask response");
        assert_eq!(response.status, "ask");
        assert_eq!(
            response.message.as_deref(),
            Some("This looks risky, please confirm")
        );
    }

    #[rstest]
    #[case("allow")]
    #[case("deny")]
    #[case("ask")]
    fn valid_status_values(#[case] status: &str) {
        let json = format!(r#"{{"jsonrpc": "2.0", "id": 1, "result": {{"status": "{status}"}}}}"#);
        let response = ProcessExtensionRunner::parse_jsonrpc_response(&json)
            .expect("should parse response with valid status");
        assert_eq!(response.status, status);
    }

    // === Error cases: parsing ===

    #[test]
    fn invalid_json_response() {
        let result = ProcessExtensionRunner::parse_jsonrpc_response("not json at all");
        let err = result.expect_err("should fail on invalid JSON");
        match err {
            ExtensionError::InvalidResponse(msg) => {
                assert_eq!(msg, "JSON parse error: expected ident at line 1 column 2");
            }
            other => panic!("expected InvalidResponse, got: {other:?}"),
        }
    }

    #[test]
    fn missing_result_field() {
        let json = r#"{"jsonrpc": "2.0", "id": 1}"#;
        let err = ProcessExtensionRunner::parse_jsonrpc_response(json)
            .expect_err("should fail when result is missing");
        match err {
            ExtensionError::InvalidResponse(msg) => {
                assert_eq!(msg, "missing 'result' field in JSON-RPC response");
            }
            other => panic!("expected InvalidResponse, got: {other:?}"),
        }
    }

    #[test]
    fn missing_status_in_result() {
        let json = r#"{"jsonrpc": "2.0", "id": 1, "result": {"message": "hi"}}"#;
        let err = ProcessExtensionRunner::parse_jsonrpc_response(json)
            .expect_err("should fail when status is missing");
        match err {
            ExtensionError::InvalidResponse(msg) => {
                assert_eq!(
                    msg,
                    "JSON parse error: missing field `status` at line 1 column 55"
                );
            }
            other => panic!("expected InvalidResponse, got: {other:?}"),
        }
    }

    #[test]
    fn jsonrpc_error_response() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid request"
            }
        }"#;
        let err = ProcessExtensionRunner::parse_jsonrpc_response(json)
            .expect_err("should fail on JSON-RPC error response");
        match err {
            ExtensionError::InvalidResponse(msg) => {
                assert_eq!(msg, "JSON-RPC error: Invalid request");
            }
            other => panic!("expected InvalidResponse, got: {other:?}"),
        }
    }

    // === End-to-end with real process ===

    #[test]
    fn validate_with_real_process_deny_response() {
        let runner = ProcessExtensionRunner;
        let request = sample_request();

        let response_json =
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"deny","message":"blocked"}}"#;
        let script = write_test_script(response_json);
        let cmd = script.display().to_string();

        let response = runner
            .validate(&cmd, &request, Duration::from_secs(5))
            .expect("should get deny response from process");
        assert_eq!(response.status, "deny");
        assert_eq!(response.message.as_deref(), Some("blocked"));
    }

    #[test]
    fn validate_with_real_process_allow_response() {
        let runner = ProcessExtensionRunner;
        let request = sample_request();

        let response_json = r#"{"jsonrpc":"2.0","id":1,"result":{"status":"allow"}}"#;
        let script = write_test_script(response_json);
        let cmd = script.display().to_string();

        let response = runner
            .validate(&cmd, &request, Duration::from_secs(5))
            .expect("should get allow response from process");
        assert_eq!(response.status, "allow");
        assert_eq!(response.message, None);
    }

    #[test]
    fn validate_spawn_error_for_nonexistent_command() {
        let runner = ProcessExtensionRunner;
        let request = sample_request();

        let err = runner
            .validate("/nonexistent/binary/path", &request, Duration::from_secs(5))
            .expect_err("should fail for nonexistent binary");
        match err {
            ExtensionError::Spawn(_) => {}
            other => panic!("expected Spawn error, got: {other:?}"),
        }
    }

    #[test]
    fn validate_invalid_json_from_process() {
        let runner = ProcessExtensionRunner;
        let request = sample_request();

        let script = write_test_script("not-valid-json");
        let cmd = script.display().to_string();

        let err = runner
            .validate(&cmd, &request, Duration::from_secs(5))
            .expect_err("should fail on invalid JSON from process");
        match err {
            ExtensionError::InvalidResponse(_) => {}
            other => panic!("expected InvalidResponse, got: {other:?}"),
        }
    }

    #[test]
    fn validate_timeout() {
        let runner = ProcessExtensionRunner;
        let request = sample_request();

        // Use a script that sleeps longer than the timeout
        let dir = std::env::temp_dir().join("runok-test-extension");
        std::fs::create_dir_all(&dir).expect("should create temp dir");
        let path = dir.join(format!("ext-timeout-{}.sh", std::process::id()));
        std::fs::write(&path, "#!/bin/sh\nsleep 10\n").expect("should write timeout script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("should set executable permission");
        }
        let cmd = path.display().to_string();

        let err = runner
            .validate(&cmd, &request, Duration::from_secs(1))
            .expect_err("should timeout for long-running process");
        match err {
            ExtensionError::Timeout(d) => {
                assert_eq!(d, Duration::from_secs(1));
            }
            other => panic!("expected Timeout error, got: {other:?}"),
        }
    }

    // === parse_command tests ===

    #[test]
    fn parse_command_simple() {
        let (prog, args) = ProcessExtensionRunner::parse_command("deno run check.ts");
        assert_eq!(prog, "deno");
        assert_eq!(args, vec!["run", "check.ts"]);
    }

    #[test]
    fn parse_command_no_args() {
        let (prog, args) = ProcessExtensionRunner::parse_command("/usr/bin/validator");
        assert_eq!(prog, "/usr/bin/validator");
        assert!(args.is_empty());
    }

    #[test]
    fn parse_command_with_flags() {
        let (prog, args) =
            ProcessExtensionRunner::parse_command("deno run --allow-net ./checks/url_check.ts");
        assert_eq!(prog, "deno");
        assert_eq!(args, vec!["run", "--allow-net", "./checks/url_check.ts"]);
    }
}
