use std::path::Path;
use std::process::Command;

use globset::GlobBuilder;

use super::ExecError;
use super::command_executor::{SandboxExecutor, SandboxPolicy, exit_code_from_status};

/// macOS sandbox executor using sandbox-exec (Seatbelt/SBPL).
///
/// Generates an SBPL profile dynamically from the `SandboxPolicy` and executes
/// the command under `/usr/bin/sandbox-exec -p <profile>`.
#[derive(Default)]
pub struct MacOsSandboxExecutor;

impl MacOsSandboxExecutor {
    pub fn new() -> Self {
        Self
    }

    /// Build the full sandbox-exec command line from a command and policy.
    pub fn build_command(
        command: &[String],
        policy: &SandboxPolicy,
    ) -> Result<Vec<String>, ExecError> {
        let sbpl = Self::generate_sbpl(policy)?;
        let mut args = vec![
            "/usr/bin/sandbox-exec".to_string(),
            "-p".to_string(),
            sbpl,
            "--".to_string(),
        ];
        args.extend(command.iter().cloned());
        Ok(args)
    }

    /// Generate an SBPL (Seatbelt Profile Language) policy string from a `SandboxPolicy`.
    ///
    /// The generated profile:
    /// - Denies all file writes by default
    /// - Allows read+write to writable_roots
    /// - Denies writes to read_only_subpaths (overrides writable_roots)
    /// - Controls network access based on `network_allowed`
    /// - Always allows process-exec, mach-*, sysctl-read, and signal for basic operation
    ///
    /// Deny paths are classified and mapped to the appropriate SBPL filter:
    /// - Absolute paths use `(subpath ...)` for exact subtree matching
    /// - Relative paths are resolved against each writable_root
    /// - Glob patterns (`*`, `**`) are converted to `(regex ...)` filters
    pub fn generate_sbpl(policy: &SandboxPolicy) -> Result<String, ExecError> {
        let mut sbpl = String::new();

        sbpl.push_str("(version 1)\n");
        // Allow everything by default, then restrict via deny rules
        sbpl.push_str("(allow default)\n");

        // Deny file-write* globally, then selectively allow writable roots
        sbpl.push_str("(deny file-write*)\n");

        // Allow writes to writable_roots
        for root in &policy.writable_roots {
            let path_str = root.to_string_lossy();
            let escaped = sbpl_escape_string(&path_str);
            sbpl.push_str(&format!("(allow file-write* (subpath {escaped}))\n"));
        }

        // Deny writes to read_only_subpaths (takes precedence over writable_roots).
        // Paths are classified to use the correct SBPL filter type:
        // - Absolute literal paths -> (subpath ...)
        // - Relative literal paths -> resolved against each writable_root -> (subpath ...)
        // - Glob patterns -> converted to regex -> (regex ...)
        for deny_path in &policy.read_only_subpaths {
            let path_str = deny_path.to_string_lossy();
            match classify_deny_path(&path_str) {
                DenyPathKind::AbsoluteLiteral => {
                    let escaped = sbpl_escape_string(&path_str);
                    sbpl.push_str(&format!("(deny file-write* (subpath {escaped}))\n"));
                }
                DenyPathKind::RelativeLiteral => {
                    // Resolve against each writable_root. When writable_roots is empty,
                    // all writes are already globally denied so the deny rule is redundant.
                    for root in &policy.writable_roots {
                        let full_path = root.join(&*path_str);
                        let full_str = full_path.to_string_lossy();
                        let escaped = sbpl_escape_string(&full_str);
                        sbpl.push_str(&format!("(deny file-write* (subpath {escaped}))\n"));
                    }
                }
                DenyPathKind::GlobPattern => {
                    if path_str.starts_with('/') {
                        // Absolute glob: convert directly to regex
                        let regex = glob_to_sbpl_regex(&path_str)?;
                        let escaped = sbpl_escape_string(&regex);
                        sbpl.push_str(&format!("(deny file-write* (regex {escaped}))\n"));
                    } else {
                        // Relative glob: resolve against each writable_root
                        for root in &policy.writable_roots {
                            let full_pattern = format!("{}/{}", root.to_string_lossy(), path_str);
                            let regex = glob_to_sbpl_regex(&full_pattern)?;
                            let escaped = sbpl_escape_string(&regex);
                            sbpl.push_str(&format!("(deny file-write* (regex {escaped}))\n"));
                        }
                    }
                }
            }
        }

        // Allow writes to /dev/null and temporary directories needed for process execution
        sbpl.push_str("(allow file-write* (literal \"/dev/null\"))\n");
        sbpl.push_str("(allow file-write* (literal \"/dev/dtracehelper\"))\n");

        // Network control
        if !policy.network_allowed {
            sbpl.push_str("(deny network*)\n");
            // Allow local IPC (Unix domain sockets) even when network is denied
            sbpl.push_str("(allow network* (local unix-socket))\n");
        }

        Ok(sbpl)
    }
}

/// Escape a string for use in SBPL. SBPL uses double-quoted strings.
fn sbpl_escape_string(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Classification of deny path patterns for SBPL filter selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenyPathKind {
    /// Absolute path without glob characters (e.g., `/etc/shadow`).
    /// Uses SBPL `(subpath ...)` filter.
    AbsoluteLiteral,
    /// Relative path without glob characters (e.g., `.git`, `.secrets`).
    /// Resolved against each writable_root, then uses `(subpath ...)`.
    RelativeLiteral,
    /// Path containing glob characters `*` or `**` (e.g., `.env*`, `/etc/**`).
    /// Converted to SBPL `(regex ...)` filter.
    GlobPattern,
}

/// Classify a deny path to determine the appropriate SBPL filter type.
fn classify_deny_path(path: &str) -> DenyPathKind {
    if path.contains('*') || path.contains('?') || path.contains('[') {
        DenyPathKind::GlobPattern
    } else if path.starts_with('/') {
        DenyPathKind::AbsoluteLiteral
    } else {
        DenyPathKind::RelativeLiteral
    }
}

/// Convert a glob pattern to a regex string suitable for SBPL `(regex ...)` filter.
///
/// Uses the `globset` crate with `literal_separator(true)` so that `*` does not
/// match `/` (directory separator), while `**` matches across directories.
///
/// The `(?-u)` prefix emitted by globset (Rust regex "disable Unicode" flag) is
/// stripped because SBPL's regex engine uses POSIX ERE and does not support it.
fn glob_to_sbpl_regex(pattern: &str) -> Result<String, ExecError> {
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map_err(|e| {
            ExecError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid glob pattern '{pattern}': {e}"),
            ))
        })?;
    let regex = glob.regex().to_string();
    // Strip Rust-specific `(?-u)` flag prefix; SBPL uses POSIX ERE regex syntax.
    let regex = regex.strip_prefix("(?-u)").unwrap_or(&regex).to_string();
    Ok(regex)
}

impl SandboxExecutor for MacOsSandboxExecutor {
    fn exec_sandboxed(&self, command: &[String], policy: &SandboxPolicy) -> Result<i32, ExecError> {
        if !self.is_supported() {
            return Err(ExecError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "sandbox-exec is not available on this system",
            )));
        }

        let sandbox_cmd = Self::build_command(command, policy)?;
        let status = Command::new(&sandbox_cmd[0])
            .args(&sandbox_cmd[1..])
            .status()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ExecError::NotFound(sandbox_cmd[0].clone()),
                std::io::ErrorKind::PermissionDenied => {
                    ExecError::PermissionDenied(sandbox_cmd[0].clone())
                }
                _ => ExecError::Io(e),
            })?;

        Ok(exit_code_from_status(status))
    }

    fn is_supported(&self) -> bool {
        Path::new("/usr/bin/sandbox-exec").exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use indoc::indoc;
    #[cfg(target_os = "macos")]
    use rstest::fixture;
    use rstest::rstest;

    fn policy_with_writable(roots: Vec<&str>) -> SandboxPolicy {
        SandboxPolicy {
            writable_roots: roots.iter().map(PathBuf::from).collect(),
            read_only_subpaths: vec![],
            network_allowed: true,
        }
    }

    fn full_policy(writable: Vec<&str>, deny: Vec<&str>, network: bool) -> SandboxPolicy {
        SandboxPolicy {
            writable_roots: writable.iter().map(PathBuf::from).collect(),
            read_only_subpaths: deny.iter().map(PathBuf::from).collect(),
            network_allowed: network,
        }
    }

    // === SBPL generation ===

    #[rstest]
    #[case::minimal(
        SandboxPolicy {
            writable_roots: vec![],
            read_only_subpaths: vec![],
            network_allowed: true,
        },
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
        "#}
    )]
    #[case::with_writable_roots(
        policy_with_writable(vec!["/tmp", "/home/user/project"]),
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (subpath "/tmp"))
            (allow file-write* (subpath "/home/user/project"))
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
        "#}
    )]
    #[case::with_read_only_subpaths(
        full_policy(
            vec!["/home/user/project"],
            vec!["/home/user/project/.git", "/home/user/project/.runok"],
            true,
        ),
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (subpath "/home/user/project"))
            (deny file-write* (subpath "/home/user/project/.git"))
            (deny file-write* (subpath "/home/user/project/.runok"))
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
        "#}
    )]
    #[case::network_denied(
        SandboxPolicy {
            writable_roots: vec![],
            read_only_subpaths: vec![],
            network_allowed: false,
        },
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
            (deny network*)
            (allow network* (local unix-socket))
        "#}
    )]
    #[case::full_policy(
        full_policy(vec!["/home/user"], vec!["/home/user/.git"], false),
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (subpath "/home/user"))
            (deny file-write* (subpath "/home/user/.git"))
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
            (deny network*)
            (allow network* (local unix-socket))
        "#}
    )]
    #[case::relative_deny_resolved(
        full_policy(vec!["/home/user/project"], vec![".git"], true),
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (subpath "/home/user/project"))
            (deny file-write* (subpath "/home/user/project/.git"))
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
        "#}
    )]
    #[case::relative_deny_no_writable_roots(
        full_policy(vec![], vec![".git"], true),
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
        "#}
    )]
    #[case::glob_absolute_deny(
        full_policy(vec!["/home/user"], vec!["/etc/**"], false),
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (subpath "/home/user"))
            (deny file-write* (regex "^/etc/.*$"))
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
            (deny network*)
            (allow network* (local unix-socket))
        "#}
    )]
    #[case::glob_relative_deny(
        full_policy(vec!["/home/user/project"], vec![".env*"], true),
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (subpath "/home/user/project"))
            (deny file-write* (regex "^/home/user/project/\\.env[^/]*$"))
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
        "#}
    )]
    #[case::multiple_roots_with_relative_deny(
        full_policy(
            vec!["/home/user/project", "/tmp/workspace"],
            vec![".git"],
            true,
        ),
        indoc! {r#"
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* (subpath "/home/user/project"))
            (allow file-write* (subpath "/tmp/workspace"))
            (deny file-write* (subpath "/home/user/project/.git"))
            (deny file-write* (subpath "/tmp/workspace/.git"))
            (allow file-write* (literal "/dev/null"))
            (allow file-write* (literal "/dev/dtracehelper"))
        "#}
    )]
    fn generate_sbpl(#[case] policy: SandboxPolicy, #[case] expected_sbpl: &str) {
        let sbpl = MacOsSandboxExecutor::generate_sbpl(&policy).unwrap();
        assert_eq!(sbpl, expected_sbpl);
    }

    // === sbpl_escape_string ===

    #[rstest]
    #[case::simple("/tmp", "\"/tmp\"")]
    #[case::with_spaces("/path/with spaces", "\"/path/with spaces\"")]
    #[case::with_backslash("/path\\dir", "\"/path\\\\dir\"")]
    #[case::with_quotes("/path\"dir", "\"/path\\\"dir\"")]
    fn sbpl_escape(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(sbpl_escape_string(input), expected);
    }

    // === classify_deny_path ===

    #[rstest]
    #[case::absolute_path("/etc/shadow", DenyPathKind::AbsoluteLiteral)]
    #[case::absolute_dir("/home/user/.git", DenyPathKind::AbsoluteLiteral)]
    #[case::relative_dotfile(".git", DenyPathKind::RelativeLiteral)]
    #[case::relative_secrets(".secrets", DenyPathKind::RelativeLiteral)]
    #[case::relative_dotenv(".env", DenyPathKind::RelativeLiteral)]
    #[case::glob_relative(".env*", DenyPathKind::GlobPattern)]
    #[case::glob_absolute("/etc/**", DenyPathKind::GlobPattern)]
    #[case::glob_deep("/home/user/.ssh/**", DenyPathKind::GlobPattern)]
    #[case::glob_single_star("/tmp/*.log", DenyPathKind::GlobPattern)]
    #[case::glob_question_mark("file?.txt", DenyPathKind::GlobPattern)]
    #[case::glob_char_class("/tmp/log[0-9].txt", DenyPathKind::GlobPattern)]
    fn classify_deny_path_cases(#[case] input: &str, #[case] expected: DenyPathKind) {
        assert_eq!(classify_deny_path(input), expected);
    }

    // === glob_to_sbpl_regex ===

    #[rstest]
    #[case::single_star(".env*", r"^\.env[^/]*$")]
    #[case::double_star("/etc/**", r"^/etc/.*$")]
    #[case::double_star_nested("/home/user/.ssh/**", r"^/home/user/\.ssh/.*$")]
    #[case::no_glob("/etc/passwd", r"^/etc/passwd$")]
    #[case::dotfile(".envrc", r"^\.envrc$")]
    #[case::star_in_middle("/tmp/*.log", r"^/tmp/[^/]*\.log$")]
    #[case::double_star_with_suffix("/home/**/config", r"^/home(?:/|/.*/)config$")]
    fn glob_to_sbpl_regex_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(glob_to_sbpl_regex(input).unwrap(), expected);
    }

    // === build_command ===

    #[rstest]
    fn build_command_basic() {
        let policy = policy_with_writable(vec!["/tmp"]);
        let command = vec!["echo".to_string(), "hello".to_string()];
        let result = MacOsSandboxExecutor::build_command(&command, &policy).unwrap();

        assert_eq!(result[0], "/usr/bin/sandbox-exec");
        assert_eq!(result[1], "-p");
        // result[2] is the SBPL profile string; verified by generate_sbpl tests
        assert_eq!(result[3], "--");
        assert_eq!(result[4], "echo");
        assert_eq!(result[5], "hello");
    }

    #[rstest]
    fn build_command_preserves_original_args() {
        let policy = SandboxPolicy {
            writable_roots: vec![],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo a && echo b".to_string(),
        ];
        let result = MacOsSandboxExecutor::build_command(&command, &policy).unwrap();

        // After "--", the original command should be preserved exactly
        let cmd_part = &result[4..];
        assert_eq!(cmd_part, &["sh", "-c", "echo a && echo b"]);
    }

    // === is_supported ===

    #[rstest]
    fn is_supported_returns_bool() {
        let executor = MacOsSandboxExecutor::new();
        let supported = executor.is_supported();
        if cfg!(target_os = "macos") {
            assert!(supported, "sandbox-exec should be available on macOS");
        } else {
            assert!(
                !supported,
                "sandbox-exec should not be available on non-macOS"
            );
        }
    }

    // === Integration: exec_sandboxed on macOS ===

    #[cfg(target_os = "macos")]
    #[fixture]
    fn macos_executor() -> MacOsSandboxExecutor {
        MacOsSandboxExecutor::new()
    }

    #[cfg(target_os = "macos")]
    #[fixture]
    fn default_policy() -> SandboxPolicy {
        SandboxPolicy {
            writable_roots: vec![],
            read_only_subpaths: vec![],
            network_allowed: true,
        }
    }

    #[cfg(target_os = "macos")]
    #[rstest]
    fn exec_sandboxed_runs_command_successfully(
        macos_executor: MacOsSandboxExecutor,
        default_policy: SandboxPolicy,
    ) {
        let command = vec!["true".to_string()];
        let exit_code = macos_executor
            .exec_sandboxed(&command, &default_policy)
            .unwrap();
        assert_eq!(exit_code, 0);
    }

    #[cfg(target_os = "macos")]
    #[rstest]
    fn exec_sandboxed_returns_nonzero_exit_code(
        macos_executor: MacOsSandboxExecutor,
        default_policy: SandboxPolicy,
    ) {
        let command = vec!["false".to_string()];
        let exit_code = macos_executor
            .exec_sandboxed(&command, &default_policy)
            .unwrap();
        assert_eq!(exit_code, 1);
    }

    #[cfg(target_os = "macos")]
    #[rstest]
    fn exec_sandboxed_denies_write_outside_writable_roots(
        macos_executor: MacOsSandboxExecutor,
        default_policy: SandboxPolicy,
    ) {
        let dir = std::env::temp_dir();
        let test_file = dir.join("runok_sandbox_test_deny_write");

        // Clean up from previous test runs
        let _ = std::fs::remove_file(&test_file);

        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("touch {}", test_file.display()),
        ];
        let exit_code = macos_executor
            .exec_sandboxed(&command, &default_policy)
            .unwrap();

        // The command should fail because writing is denied
        assert_ne!(exit_code, 0, "touch should fail when writes are denied");
        assert!(!test_file.exists(), "file should not be created");
    }

    #[cfg(target_os = "macos")]
    #[rstest]
    fn exec_sandboxed_allows_write_to_writable_root(macos_executor: MacOsSandboxExecutor) {
        let dir = std::env::temp_dir();
        let canonical_dir = dir.canonicalize().unwrap();
        let test_file = canonical_dir.join("runok_sandbox_test_allow_write");

        // Clean up from previous test runs
        let _ = std::fs::remove_file(&test_file);

        let policy = SandboxPolicy {
            writable_roots: vec![canonical_dir.clone()],
            read_only_subpaths: vec![],
            network_allowed: true,
        };

        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("touch {}", test_file.display()),
        ];
        let exit_code = macos_executor.exec_sandboxed(&command, &policy).unwrap();

        assert_eq!(exit_code, 0, "touch should succeed in writable root");
        assert!(test_file.exists(), "file should be created");

        // Clean up
        let _ = std::fs::remove_file(&test_file);
    }
}
