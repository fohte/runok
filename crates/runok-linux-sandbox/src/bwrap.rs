use std::path::Path;

use crate::policy::SandboxPolicy;

/// Build bubblewrap command-line arguments for namespace isolation.
///
/// The bubblewrap arguments set up:
/// - Bind-mount the root filesystem read-only
/// - Bind-mount writable roots as read-write
/// - Re-bind read-only subpaths as read-only (overriding writable)
/// - Bind-mount /proc, /dev, /tmp as needed
/// - Set working directory
/// - Execute the helper binary itself with --apply-sandbox-then-exec for stage 2
pub fn build_bwrap_args(
    policy: &SandboxPolicy,
    cwd: &Path,
    helper_binary: &Path,
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
        // Skip glob patterns - bubblewrap operates on actual paths
        if path_str.contains('*') || path_str.contains('?') {
            continue;
        }
        // Only bind if the path exists
        if subpath.exists() {
            args.extend(["--ro-bind".to_string(), path_str.clone(), path_str]);
        }
    }

    // /tmp should be writable (tmpfs) unless it's already in writable_roots
    let tmp_in_writable = policy
        .writable_roots
        .iter()
        .any(|r| r.as_os_str() == "/tmp");
    if !tmp_in_writable {
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

    // Execute the helper binary in stage 2 mode
    args.push("--".to_string());
    args.push(helper_binary.to_string_lossy().to_string());
    args.push("--apply-sandbox-then-exec".to_string());
    args.push("--policy".to_string());
    args.push(policy_json.to_string());
    args.push("--cwd".to_string());
    args.push(cwd.to_string_lossy().to_string());
    args.push("--".to_string());
    args.extend_from_slice(command);

    args
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
            Path::new("/usr/bin/runok-linux-sandbox"),
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
            Path::new("/usr/bin/runok-linux-sandbox"),
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
            Path::new("/usr/bin/runok-linux-sandbox"),
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
            Path::new("/usr/bin/runok-linux-sandbox"),
            "{}",
            &["ls".to_string()],
        );
        assert_eq!(
            args.iter().any(|a| a == "--share-net"),
            should_have_share_net
        );
    }

    #[rstest]
    fn bwrap_args_contain_stage2_flag(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok-linux-sandbox"),
            "{}",
            &["git".to_string(), "status".to_string()],
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
            Path::new("/usr/bin/runok-linux-sandbox"),
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
            Path::new("/usr/bin/runok-linux-sandbox"),
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
            Path::new("/usr/bin/runok-linux-sandbox"),
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
            Path::new("/usr/bin/runok-linux-sandbox"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            !args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]),
            "should NOT have --tmpfs /tmp when /tmp is in writable_roots"
        );
    }

    #[rstest]
    fn bwrap_args_proc_and_dev(test_policy: SandboxPolicy) {
        let args = build_bwrap_args(
            &test_policy,
            Path::new("/home/user/project"),
            Path::new("/usr/bin/runok-linux-sandbox"),
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
            Path::new("/usr/bin/runok-linux-sandbox"),
            "{}",
            &["ls".to_string()],
        );
        assert!(
            args.iter().any(|a| a == "--die-with-parent"),
            "should have --die-with-parent"
        );
    }
}
