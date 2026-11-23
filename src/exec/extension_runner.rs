use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use super::ExtensionError;

/// Inputs required to invoke one configured extension.
pub struct ExtensionCall<'a> {
    pub name: &'a str,
    pub executor_cmd: &'a str,
    pub params: &'a Map<String, Value>,
    pub parent_env: &'a HashMap<String, String>,
    pub extra_env: &'a [String],
    pub cwd: &'a Path,
    pub timeout: Duration,
}

/// Runs an extension and returns its JSON-RPC `result` value.
pub trait ExtensionRunner: Send + Sync {
    fn call(&self, call: ExtensionCall<'_>) -> Result<Value, ExtensionError>;
}

/// Default implementation that starts one process for each call.
pub struct ProcessExtensionRunner;

impl ProcessExtensionRunner {
    fn build_jsonrpc_request(params: &Map<String, Value>) -> Result<String, ExtensionError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": params,
        });
        serde_json::to_string(&request).map_err(|error| {
            ExtensionError::InvalidResponse(format!("request serialization failed: {error}"))
        })
    }

    fn parse_jsonrpc_response(raw: &str) -> Result<Value, ExtensionError> {
        let response: Value = serde_json::from_str(raw).map_err(|error| {
            ExtensionError::InvalidResponse(format!("JSON parse error: {error}"))
        })?;
        let object = response.as_object().ok_or_else(|| {
            ExtensionError::InvalidResponse("response must be a JSON object".to_string())
        })?;

        if object.get("jsonrpc") != Some(&Value::String("2.0".to_string())) {
            return Err(ExtensionError::InvalidResponse(
                "response must set jsonrpc to '2.0'".to_string(),
            ));
        }
        if object.get("id") != Some(&Value::from(1)) {
            return Err(ExtensionError::InvalidResponse(
                "response id must match request id 1".to_string(),
            ));
        }
        if let Some(error) = object.get("error") {
            return Err(ExtensionError::InvalidResponse(format!(
                "JSON-RPC error: {error}"
            )));
        }
        object.get("result").cloned().ok_or_else(|| {
            ExtensionError::InvalidResponse("response is missing 'result'".to_string())
        })
    }

    fn spawn_with_etxtbsy_retry(
        program: &str,
        args: &[String],
        parent_env: &HashMap<String, String>,
        extra_env: &[String],
        cwd: &Path,
    ) -> Result<std::process::Child, std::io::Error> {
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        for name in ["PATH", "HOME"]
            .into_iter()
            .chain(extra_env.iter().map(String::as_str))
        {
            if let Some(value) = parent_env.get(name) {
                command.env(name, value);
            }
        }

        let max_retries = 5;
        for attempt in 0..max_retries {
            match command.spawn() {
                Ok(child) => return Ok(child),
                #[cfg(unix)]
                Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(10 * (attempt as u64 + 1)));
                }
                Err(error) => return Err(error),
            }
        }
        command.spawn()
    }

    fn parse_command(
        executor_cmd: &str,
        parent_env: &HashMap<String, String>,
    ) -> Result<(String, Vec<String>), ExtensionError> {
        let parts = shlex::split(executor_cmd).ok_or_else(|| {
            ExtensionError::InvalidResponse(format!(
                "invalid shell syntax in executor command: {executor_cmd}"
            ))
        })?;
        let mut iter = parts.into_iter();
        let program = iter.next().unwrap_or_default();
        let program = match (program.as_str(), parent_env.get("HOME")) {
            ("~", Some(home)) => home.clone(),
            (value, Some(home)) if value.starts_with("~/") => {
                format!("{home}/{}", &value[2..])
            }
            _ => program,
        };
        if program.is_empty() {
            return Err(ExtensionError::InvalidResponse(
                "executor command must not be empty".to_string(),
            ));
        }
        Ok((program, iter.collect()))
    }

    fn write_request(
        mut stdin: std::process::ChildStdin,
        request: String,
        sender: mpsc::Sender<Result<(), std::io::Error>>,
    ) {
        let result = stdin
            .write_all(request.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"));
        let _ = sender.send(result);
    }
}

impl ExtensionRunner for ProcessExtensionRunner {
    fn call(&self, call: ExtensionCall<'_>) -> Result<Value, ExtensionError> {
        let ExtensionCall {
            executor_cmd,
            params,
            parent_env,
            extra_env,
            cwd,
            timeout,
            ..
        } = call;
        let (program, args) = Self::parse_command(executor_cmd, parent_env)?;
        let request = Self::build_jsonrpc_request(params)?;
        let started = Instant::now();
        let mut child =
            Self::spawn_with_etxtbsy_retry(&program, &args, parent_env, extra_env, cwd)?;

        let mut stdout = child.stdout.take().ok_or_else(|| {
            ExtensionError::InvalidResponse("extension stdout was not captured".to_string())
        })?;
        let (stdout_sender, stdout_receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("runok-extension-stdout".to_string())
            .spawn(move || {
                let mut bytes = Vec::new();
                let result = stdout.read_to_end(&mut bytes).map(|_| bytes);
                let _ = stdout_sender.send(result);
            })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            ExtensionError::InvalidResponse("extension stdin was not captured".to_string())
        })?;
        let (stdin_sender, stdin_receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("runok-extension-stdin".to_string())
            .spawn(move || Self::write_request(stdin, request, stdin_sender))?;

        let mut exit_status = None;
        let mut output = None;
        let mut input_result = None;
        loop {
            if exit_status.is_none() {
                match child.try_wait() {
                    Ok(status) => exit_status = status,
                    Err(error) => return Err(ExtensionError::Spawn(error)),
                }
            }

            if output.is_none() {
                match stdout_receiver.try_recv() {
                    Ok(result) => output = Some(result),
                    Err(TryRecvError::Disconnected) => {
                        return Err(ExtensionError::InvalidResponse(
                            "failed to read extension stdout".to_string(),
                        ));
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }

            if input_result.is_none() {
                match stdin_receiver.try_recv() {
                    Ok(result) => input_result = Some(result),
                    Err(TryRecvError::Disconnected) => {
                        return Err(ExtensionError::InvalidResponse(
                            "failed to write extension stdin".to_string(),
                        ));
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }

            if let (Some(status), Some(output), Some(input_result)) =
                (&exit_status, &output, &input_result)
            {
                input_result.as_ref().map_err(|error| {
                    ExtensionError::InvalidResponse(format!(
                        "failed to write JSON-RPC request: {error}"
                    ))
                })?;
                if !status.success() {
                    return Err(ExtensionError::InvalidResponse(format!(
                        "extension exited with status {status}"
                    )));
                }
                let bytes = output.as_ref().map_err(|error| {
                    ExtensionError::InvalidResponse(format!(
                        "failed to read JSON-RPC response: {error}"
                    ))
                })?;
                let response = String::from_utf8(bytes.clone()).map_err(|error| {
                    ExtensionError::InvalidResponse(format!("response is not valid UTF-8: {error}"))
                })?;
                return Self::parse_jsonrpc_response(&response);
            }

            if started.elapsed() >= timeout {
                Self::terminate_processes(&mut child);
                return Err(ExtensionError::Timeout(timeout));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl ProcessExtensionRunner {
    fn terminate_processes(child: &mut std::process::Child) {
        #[cfg(unix)]
        unsafe {
            let _ = libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
        }
        #[cfg(not(unix))]
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use indoc::indoc;
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::{TempDir, TempPath};

    fn write_script(content: &str) -> Result<TempPath, Box<dyn Error>> {
        let mut file = tempfile::Builder::new()
            .prefix("runok-extension-")
            .suffix(".sh")
            .permissions(fs::Permissions::from_mode(0o755))
            .tempfile()?;
        file.write_all(content.as_bytes())?;
        Ok(file.into_temp_path())
    }

    fn params() -> Map<String, Value> {
        Map::from_iter([("dir".to_string(), Value::String("./sample".into()))])
    }

    fn parent_env() -> HashMap<String, String> {
        HashMap::from([
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("HOME".to_string(), "/home/example".to_string()),
            ("RUNOK_ALLOWED".to_string(), "available".to_string()),
            ("RUNOK_HIDDEN".to_string(), "secret".to_string()),
        ])
    }

    fn call_process_extension(
        executor_cmd: &str,
        params: &Map<String, Value>,
        parent_env: &HashMap<String, String>,
        extra_env: &[String],
        cwd: &Path,
        timeout: Duration,
    ) -> Result<Value, ExtensionError> {
        ProcessExtensionRunner.call(ExtensionCall {
            name: "fixture",
            executor_cmd,
            params,
            parent_env,
            extra_env,
            cwd,
            timeout,
        })
    }

    #[test]
    fn request_contains_only_the_json_rpc_call_parameters() -> Result<(), Box<dyn Error>> {
        let request = ProcessExtensionRunner::build_jsonrpc_request(&params())?;
        let parsed: Value = serde_json::from_str(&request)?;
        assert_eq!(
            parsed,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "call",
                "params": {"dir": "./sample"}
            })
        );
        Ok(())
    }

    #[rstest::rstest]
    #[case::object(r#"{"jsonrpc":"2.0","id":1,"result":{"branch":"topic"}}"#, serde_json::json!({"branch":"topic"}))]
    #[case::list(r#"{"jsonrpc":"2.0","id":1,"result":["ready"]}"#, serde_json::json!(["ready"]))]
    #[case::null(r#"{"jsonrpc":"2.0","id":1,"result":null}"#, Value::Null)]
    fn parses_arbitrary_json_results(
        #[case] raw: &str,
        #[case] expected: Value,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            ProcessExtensionRunner::parse_jsonrpc_response(raw)?,
            expected
        );
        Ok(())
    }

    #[rstest::rstest]
    #[case::bad_json(
        "not-json",
        "invalid response: JSON parse error: expected ident at line 1 column 2"
    )]
    #[case::wrong_id(
        r#"{"jsonrpc":"2.0","id":2,"result":true}"#,
        "invalid response: response id must match request id 1"
    )]
    #[case::missing_result(
        r#"{"jsonrpc":"2.0","id":1}"#,
        "invalid response: response is missing 'result'"
    )]
    fn rejects_invalid_responses(#[case] raw: &str, #[case] expected: &str) {
        assert_eq!(
            ProcessExtensionRunner::parse_jsonrpc_response(raw).map_err(|error| error.to_string()),
            Err(expected.to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn call_limits_environment_and_uses_runok_cwd() -> Result<(), Box<dyn Error>> {
        let temp_dir = TempDir::new()?;
        let script = write_script(indoc! {r#"
            #!/bin/sh
            cat >/dev/null
            printf '{"jsonrpc":"2.0","id":1,"result":{"allowed":"%s","hidden":"%s","home":"%s","path":"%s","cwd":"%s"}}' \
              "${RUNOK_ALLOWED-unset}" "${RUNOK_HIDDEN-unset}" "$HOME" "$PATH" "$PWD"
        "#})?;
        let expected_cwd = temp_dir.path().canonicalize()?;
        let executor_cmd = script.to_string_lossy();
        let params = params();
        let parent_env = parent_env();
        let extra_env = ["RUNOK_ALLOWED".to_string()];
        let result = call_process_extension(
            executor_cmd.as_ref(),
            &params,
            &parent_env,
            &extra_env,
            &expected_cwd,
            Duration::from_secs(2),
        )?;
        assert_eq!(
            result,
            serde_json::json!({
                "allowed": "available",
                "hidden": "unset",
                "home": "/home/example",
                "path": "/usr/bin:/bin",
                "cwd": expected_cwd.to_string_lossy()
            })
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn executor_tilde_expands_from_the_runok_home() -> Result<(), Box<dyn Error>> {
        let home = TempDir::new()?;
        let script = home.path().join("extension.sh");
        fs::write(
            &script,
            indoc! {"
                #!/bin/sh
                cat >/dev/null
                printf '%s' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":true}'
            "},
        )?;
        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
        let parent_env = HashMap::from([
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            (
                "HOME".to_string(),
                home.path().to_string_lossy().into_owned(),
            ),
        ]);

        let params = Map::new();
        let result = call_process_extension(
            "~/extension.sh",
            &params,
            &parent_env,
            &[],
            home.path(),
            Duration::from_secs(2),
        )?;

        assert_eq!(result, Value::Bool(true));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_exit_is_an_extension_failure() -> Result<(), Box<dyn Error>> {
        let script = write_script(indoc! {"
            #!/bin/sh
            cat >/dev/null
            exit 9
        "})?;
        let executor_cmd = script.to_string_lossy();
        let params = params();
        let parent_env = parent_env();
        let result = call_process_extension(
            executor_cmd.as_ref(),
            &params,
            &parent_env,
            &[],
            Path::new("."),
            Duration::from_secs(2),
        );
        assert_eq!(
            result.map_err(|error| error.to_string()),
            Err("invalid response: extension exited with status exit status: 9".to_string())
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn call_enforces_timeout_from_spawn_to_response() -> Result<(), Box<dyn Error>> {
        let script = write_script(indoc! {"
            #!/bin/sh
            cat >/dev/null
            sleep 1
            printf '%s' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":true}'
        "})?;
        let executor_cmd = script.to_string_lossy();
        let params = params();
        let parent_env = parent_env();
        let result = call_process_extension(
            executor_cmd.as_ref(),
            &params,
            &parent_env,
            &[],
            Path::new("."),
            Duration::from_millis(50),
        );
        assert_eq!(
            result.map_err(|error| error.to_string()),
            Err("timeout after 50ms".to_string())
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_descendants_holding_stdout() -> Result<(), Box<dyn Error>> {
        let temp_dir = TempDir::new()?;
        let script = write_script(indoc! {"
            #!/bin/sh
            cat >/dev/null
            (
              sleep 0.5
              printf done > child-finished
            ) &
            exit 0
        "})?;
        let executor_cmd = script.to_string_lossy();
        let params = params();
        let parent_env = parent_env();
        let result = call_process_extension(
            executor_cmd.as_ref(),
            &params,
            &parent_env,
            &[],
            temp_dir.path(),
            Duration::from_millis(50),
        );
        std::thread::sleep(Duration::from_millis(600));

        assert_eq!(
            (
                result.map_err(|error| error.to_string()),
                temp_dir.path().join("child-finished").exists(),
            ),
            (Err("timeout after 50ms".to_string()), false),
        );
        Ok(())
    }
}
