use std::path::Path;

use crate::exec::command_executor::SandboxPolicy;

/// Build bubblewrap command-line arguments for namespace isolation.
///
/// The bubblewrap arguments set up:
/// - Bind-mount the root filesystem read-only
/// - Bind-mount writable roots as read-write
/// - Re-bind read-only subpaths as read-only (overriding writable)
/// - Bind-mount /proc, /dev, /tmp as needed
/// - Set working directory
/// - Execute the runok binary itself with `__sandbox-exec --apply-sandbox-then-exec` for stage 2
pub fn build_bwrap_args(
    policy: &SandboxPolicy,
    cwd: &Path,
    self_exe: &Path,
    policy_json: &str,
    command: &[String],
) -> Vec<String> {
    let mut args = Vec::new();

    // Bind-mount root filesystem read-only
    args.extend(["--ro-bind".to_string(), "/".to_string(), "/".to_string()]);

    // Mount /proc (needed by many programs)
    args.extend(["--proc".to_string(), "/proc".to_string()]);

    // Mount /dev (basic device nodes)
    args.extend(["--dev".to_string(), "/dev".to_string()]);

    // Bind-mount writable roots as read-write
    for root in &policy.writable_roots {
        let path = root.to_string_lossy().to_string();
        args.extend(["--bind".to_string(), path.clone(), path]);
    }

    // Re-bind read-only subpaths (overrides writable mounts)
    for subpath in &policy.read_only_subpaths {
        let path_str = subpath.to_string_lossy().to_string();

        if is_glob_pattern(&path_str) {
            // Glob patterns are expanded at mount-setup time, so files created
            // after the sandbox starts will not be protected by --ro-bind.
            eprintln!(
                "runok-linux-sandbox: warning: glob deny pattern {path_str:?} is expanded \
                 before sandbox execution; files created later will not be protected. \
                 Use literal paths for complete coverage."
            );
            // Glob pattern: expand against the filesystem and ro-bind each match
            if path_str.starts_with('/') {
                expand_and_ro_bind(&path_str, &mut args);
            } else {
                // Relative glob: resolve against each writable_root
                for root in &policy.writable_roots {
                    let full = root.join(&path_str);
                    expand_and_ro_bind(&full.to_string_lossy(), &mut args);
                }
            }
        } else {
            // Literal path: only bind if the path exists
            if subpath.exists() {
                args.extend(["--ro-bind".to_string(), path_str.clone(), path_str]);
            }
        }
    }

    // /tmp should be writable (tmpfs) unless a writable root is /tmp itself,
    // a parent of /tmp (e.g. "/"), or a child under /tmp (e.g. "/tmp/myproject").
    // In the child case, --tmpfs /tmp would mount over the writable bind and hide it.
    let tmp = std::path::Path::new("/tmp");
    let tmp_overlaps_writable = policy
        .writable_roots
        .iter()
        .any(|r| tmp.starts_with(r) || r.starts_with(tmp));
    if !tmp_overlaps_writable {
        args.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    }

    // Unshare all namespaces
    args.push("--unshare-all".to_string());

    // Share network namespace if network is allowed
    if policy.network_allowed {
        args.push("--share-net".to_string());
    }

    // Die with parent
    args.push("--die-with-parent".to_string());

    // Set working directory
    args.extend(["--chdir".to_string(), cwd.to_string_lossy().to_string()]);

    // Execute the runok binary in stage 2 mode via hidden subcommand
    args.push("--".to_string());
    args.push(self_exe.to_string_lossy().to_string());
    args.push("__sandbox-exec".to_string());
    args.push("--apply-sandbox-then-exec".to_string());
    args.push("--policy".to_string());
    args.push(policy_json.to_string());
    args.push("--cwd".to_string());
    args.push(cwd.to_string_lossy().to_string());
    args.push("--".to_string());
    args.extend_from_slice(command);

    args
}

/// Returns true if the path contains glob metacharacters.
fn is_glob_pattern(path: &str) -> bool {
    path.contains('*') || path.contains('?') || path.contains('[') || path.contains('{')
}

/// Maximum number of paths a single glob pattern may expand to.
/// Prevents excessive memory usage and E2BIG errors when invoking bwrap.
const MAX_GLOB_MATCHES: usize = 10_000;

/// Expand a glob pattern and append `--ro-bind` arguments for each match.
///
/// The `glob` crate does not support brace expansion (`{a,b}`), so braces
/// are expanded into multiple patterns before passing to `glob::glob()`.
///
/// Invalid patterns and individual match errors are silently ignored,
/// consistent with the existing behavior of skipping non-existent literal paths.
/// Expansion is capped at [`MAX_GLOB_MATCHES`] to avoid DoS from overly broad
/// patterns.
fn expand_and_ro_bind(pattern: &str, args: &mut Vec<String>) {
    let mut count = 0;
    for expanded in crate::exec::glob_utils::expand_braces(pattern) {
        let Ok(paths) = glob::glob(&expanded) else {
            continue;
        };
        for entry in paths {
            if count >= MAX_GLOB_MATCHES {
                eprintln!(
                    "runok-linux-sandbox: warning: glob pattern {pattern:?} matched \
                     more than {MAX_GLOB_MATCHES} paths; remaining matches are ignored"
                );
                return;
            }
            let Ok(path) = entry else {
                continue;
            };
            let path_str = path.to_string_lossy().to_string();
            args.extend(["--ro-bind".to_string(), path_str.clone(), path_str]);
            count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};
    use std::path::PathBuf;

    #[fixture]
    fn test_policy() -> SandboxPolicy {
        SandboxPolicy {
            writable_roots: vec![PathBuf::from("/home/user/project")],
            read_only_subpaths: vec![PathBuf::from("/home/user/project/.git")],
            network_allowed: false,
        }
    }

    #[rstest]
    fn bwrap_args_contain_ro_bind_root(test_policy: SandboxPolicy) {
        let policy = test_policy;
        let args = build_bwrap_args(
            &policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            args.windows(3).any(|w| w == ["--ro-bind", "/", "/"]),
            "should have --ro-bind / /"
        );
    }

    #[rstest]
    fn bwrap_args_contain_writable_bind(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            args.windows(3)
                .any(|w| w == ["--bind", "/home/user/project", "/home/user/project"]),
            "should have --bind for writable root"
        );
    }

    #[rstest]
    fn bwrap_args_contain_unshare_all(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            args.iter().any(|a| a == "--unshare-all"),
            "should have --unshare-all"
        );
    }

    #[rstest]
    #[case::network_blocked(false, false)]
    #[case::network_allowed(true, true)]
    fn bwrap_args_share_net(#[case] network_allowed: bool, #[case] should_have_share_net: bool) {
        let policy = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![],
            network_allowed,
        };
        let args = build_bwrap_args(
            &policy,
            Path::new("/tmp"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert_eq!(
            args.iter().any(|a| a == "--share-net"),
            should_have_share_net
        );
    }

    #[rstest]
    fn bwrap_args_contain_stage2_subcommand_and_flag(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["git".to_string(), "status".to_string()],
        );
        assert!(
            args.iter().any(|a| a == "__sandbox-exec"),
            "should contain __sandbox-exec subcommand"
        );
        assert!(
            args.iter().any(|a| a == "--apply-sandbox-then-exec"),
            "should contain --apply-sandbox-then-exec for stage 2"
        );
    }

    #[rstest]
    fn bwrap_args_contain_command(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["git".to_string(), "status".to_string()],
        );
        // The command should appear after the last "--"
        let last_separator = args
            .iter()
            .rposition(|a| a == "--")
            .expect("should have -- separator");
        assert_eq!(args[last_separator + 1], "git");
        assert_eq!(args[last_separator + 2], "status");
    }

    #[rstest]
    fn bwrap_args_contain_chdir(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            args.windows(2)
                .any(|w| w == ["--chdir", "/home/user/project"]),
            "should have --chdir"
        );
    }

    #[rstest]
    fn bwrap_args_tmpfs_when_tmp_not_writable() {
        let policy = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/home/user")],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let args = build_bwrap_args(
            &policy,
            Path::new("/home/user"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]),
            "should have --tmpfs /tmp when /tmp is not in writable_roots"
        );
    }

    #[rstest]
    fn bwrap_args_no_tmpfs_when_tmp_is_writable() {
        let policy = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let args = build_bwrap_args(
            &policy,
            Path::new("/tmp"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            !args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]),
            "should NOT have --tmpfs /tmp when /tmp is in writable_roots"
        );
    }

    #[rstest]
    fn bwrap_args_no_tmpfs_when_parent_is_writable() {
        let policy = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/")],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let args = build_bwrap_args(
            &policy,
            Path::new("/"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            !args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]),
            "should NOT have --tmpfs /tmp when a parent of /tmp is in writable_roots"
        );
    }

    #[rstest]
    fn bwrap_args_no_tmpfs_when_child_of_tmp_is_writable() {
        let policy = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp/myproject")],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let args = build_bwrap_args(
            &policy,
            Path::new("/tmp/myproject"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            !args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]),
            "should NOT have --tmpfs /tmp when a child of /tmp is in writable_roots"
        );
    }

    #[rstest]
    fn bwrap_args_proc_and_dev(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            args.windows(2).any(|w| w == ["--proc", "/proc"]),
            "should have --proc /proc"
        );
        assert!(
            args.windows(2).any(|w| w == ["--dev", "/dev"]),
            "should have --dev /dev"
        );
    }

    #[rstest]
    fn bwrap_args_die_with_parent(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            args.iter().any(|a| a == "--die-with-parent"),
            "should have --die-with-parent"
        );
    }

    // === is_glob_pattern ===

    #[rstest]
    #[case::star(".env*", true)]
    #[case::double_star("/etc/**", true)]
    #[case::question_mark("file?.txt", true)]
    #[case::bracket("/tmp/log[0-9].txt", true)]
    #[case::brace("*.{js,ts}", true)]
    #[case::literal(".git", false)]
    #[case::absolute_literal("/etc/shadow", false)]
    fn is_glob_pattern_cases(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_glob_pattern(input), expected);
    }

    // === glob expansion in bwrap args ===

    #[fixture]
    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[rstest]
    fn bwrap_args_expand_absolute_glob(temp_dir: tempfile::TempDir) {
        let dir = &temp_dir;
        let env_path = dir.path().join(".env");
        let env_local_path = dir.path().join(".env.local");
        let other_path = dir.path().join("README.md");
        std::fs::write(&env_path, "").unwrap();
        std::fs::write(&env_local_path, "").unwrap();
        std::fs::write(&other_path, "").unwrap();

        let glob_pattern = format!("{}/.env*", dir.path().display());
        let policy = SandboxPolicy {
            writable_roots: vec![dir.path().to_path_buf()],
            read_only_subpaths: vec![PathBuf::from(&glob_pattern)],
            network_allowed: false,
        };
        let args = build_bwrap_args(
            &policy,
            dir.path(),
            Path::new("/usr/bin/runok-linux-sandbox"),
            "{}",
            &["ls".to_string()],
        );

        let ro_bind_targets: std::collections::BTreeSet<&str> = args
            .windows(3)
            .filter(|w| w[0] == "--ro-bind" && w[1] != "/")
            .map(|w| w[1].as_str())
            .collect();

        let expected: std::collections::BTreeSet<&str> =
            [env_path.to_str().unwrap(), env_local_path.to_str().unwrap()]
                .into_iter()
                .collect();

        assert_eq!(ro_bind_targets, expected);
    }

    #[rstest]
    fn bwrap_args_expand_relative_glob(temp_dir: tempfile::TempDir) {
        let dir = &temp_dir;
        let env_path = dir.path().join(".env");
        let env_prod_path = dir.path().join(".env.production");
        std::fs::write(&env_path, "").unwrap();
        std::fs::write(&env_prod_path, "").unwrap();

        let policy = SandboxPolicy {
            writable_roots: vec![dir.path().to_path_buf()],
            read_only_subpaths: vec![PathBuf::from(".env*")],
            network_allowed: false,
        };
        let args = build_bwrap_args(
            &policy,
            dir.path(),
            Path::new("/usr/bin/runok-linux-sandbox"),
            "{}",
            &["ls".to_string()],
        );

        let ro_bind_targets: std::collections::BTreeSet<&str> = args
            .windows(3)
            .filter(|w| w[0] == "--ro-bind" && w[1] != "/")
            .map(|w| w[1].as_str())
            .collect();

        let expected: std::collections::BTreeSet<&str> =
            [env_path.to_str().unwrap(), env_prod_path.to_str().unwrap()]
                .into_iter()
                .collect();

        assert_eq!(ro_bind_targets, expected);
    }

    #[rstest]
    fn bwrap_args_glob_no_matches_produces_no_ro_bind(temp_dir: tempfile::TempDir) {
        let dir = &temp_dir;
        // No files created - glob should match nothing
        let glob_pattern = format!("{}/.env*", dir.path().display());
        let policy = SandboxPolicy {
            writable_roots: vec![dir.path().to_path_buf()],
            read_only_subpaths: vec![PathBuf::from(&glob_pattern)],
            network_allowed: false,
        };
        let args = build_bwrap_args(
            &policy,
            dir.path(),
            Path::new("/usr/bin/runok-linux-sandbox"),
            "{}",
            &["ls".to_string()],
        );

        let ro_bind_count = args
            .windows(3)
            .filter(|w| w[0] == "--ro-bind" && w[1] != "/")
            .count();
        assert_eq!(
            ro_bind_count, 0,
            "glob with no matches should produce no --ro-bind entries"
        );
    }

    #[rstest]
    fn bwrap_args_expand_brace_glob(temp_dir: tempfile::TempDir) {
        let dir = &temp_dir;
        let js_path = dir.path().join("app.js");
        let ts_path = dir.path().join("index.ts");
        let rs_path = dir.path().join("main.rs");
        std::fs::write(&js_path, "").unwrap();
        std::fs::write(&ts_path, "").unwrap();
        std::fs::write(&rs_path, "").unwrap();

        let glob_pattern = format!("{}/*.{{js,ts}}", dir.path().display());
        let policy = SandboxPolicy {
            writable_roots: vec![dir.path().to_path_buf()],
            read_only_subpaths: vec![PathBuf::from(&glob_pattern)],
            network_allowed: false,
        };
        let args = build_bwrap_args(
            &policy,
            dir.path(),
            Path::new("/usr/bin/runok-linux-sandbox"),
            "{}",
            &["ls".to_string()],
        );

        let ro_bind_targets: std::collections::BTreeSet<&str> = args
            .windows(3)
            .filter(|w| w[0] == "--ro-bind" && w[1] != "/")
            .map(|w| w[1].as_str())
            .collect();

        let expected: std::collections::BTreeSet<&str> =
            [js_path.to_str().unwrap(), ts_path.to_str().unwrap()]
                .into_iter()
                .collect();

        assert_eq!(ro_bind_targets, expected);
    }
}
