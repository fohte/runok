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

    /// Create a temporary executable script with the given raw content.
    fn write_test_script_raw(content: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let dir = std::env::temp_dir().join("runok-test-extension");
        std::fs::create_dir_all(&dir).expect("should create temp dir");
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("ext-{}-{}.sh", std::process::id(), id));
        std::fs::write(&path, content).expect("should write test script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("should set executable permission");
        }
        path
    }

    /// Create a script that drains stdin and prints the given JSON response.
    fn write_test_script(response: &str) -> std::path::PathBuf {
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
}
