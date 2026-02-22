use landlock::{
    ABI, Access, AccessFs, CompatLevel, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr,
};

use crate::error::SandboxError;
use crate::policy::SandboxPolicy;

/// Apply landlock restrictions based on the sandbox policy.
///
/// Strategy:
/// 1. Handle all filesystem access types for ABI V5 (BestEffort for newer features)
/// 2. Default: entire filesystem is governed by the ruleset (no rule = no access)
/// 3. Add read-only access to root `/` as the baseline
/// 4. Add read-write access to writable_roots
/// 5. Re-apply read-only access to read_only_subpaths (overrides writable)
/// 6. Always allow read-write to /dev/null (needed by many programs)
pub fn apply_landlock(policy: &SandboxPolicy) -> Result<(), SandboxError> {
    let abi = ABI::V5;
    let access_rw = AccessFs::from_all(abi);
    let access_ro = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(access_rw)
        .map_err(|e| SandboxError::Landlock(format!("handle_access failed: {e}")))?
        .create()
        .map_err(|e| SandboxError::Landlock(format!("create ruleset failed: {e}")))?
        .set_no_new_privs(true);

    // Root filesystem is read-only by default
    ruleset = add_path_rule(ruleset, "/", access_ro)?;

    // /dev/null must be read-write for many programs
    ruleset = add_path_rule(ruleset, "/dev/null", access_rw)?;

    // /dev/zero, /dev/urandom, /dev/random are commonly needed
    for dev_path in &["/dev/zero", "/dev/urandom", "/dev/random"] {
        ruleset = add_path_rule_if_exists(ruleset, dev_path, access_ro)?;
    }

    // /tmp is often needed for temporary files; only add if not in writable_roots
    // to avoid duplicate rules
    let tmp_in_writable = policy.writable_roots.iter().any(|r| {
        r.as_os_str() == "/tmp"
            || r.starts_with("/tmp/")
            || std::path::Path::new("/tmp").starts_with(r)
    });
    if !tmp_in_writable {
        ruleset = add_path_rule_if_exists(ruleset, "/tmp", access_rw)?;
    }

    // Add writable roots
    for root in &policy.writable_roots {
        ruleset = add_path_rule(
            ruleset,
            root.to_str()
                .ok_or_else(|| SandboxError::Landlock("non-UTF8 path".to_string()))?,
            access_rw,
        )?;
    }

    // Re-apply read-only to protected subpaths (overrides writable)
    for subpath in &policy.read_only_subpaths {
        let path_str = subpath
            .to_str()
            .ok_or_else(|| SandboxError::Landlock("non-UTF8 path".to_string()))?;
        // Skip glob patterns - landlock operates on actual filesystem paths
        if path_str.contains('*') || path_str.contains('?') {
            continue;
        }
        ruleset = add_path_rule_if_exists(ruleset, path_str, access_ro)?;
    }

    ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(format!("restrict_self failed: {e}")))?;

    Ok(())
}

fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &str,
    access: landlock::BitFlags<AccessFs>,
) -> Result<landlock::RulesetCreated, SandboxError> {
    let fd = PathFd::new(path)
        .map_err(|e| SandboxError::Landlock(format!("cannot open path '{path}': {e}")))?;
    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map_err(|e| SandboxError::Landlock(format!("add_rule for '{path}' failed: {e}")))
}

fn add_path_rule_if_exists(
    ruleset: landlock::RulesetCreated,
    path: &str,
    access: landlock::BitFlags<AccessFs>,
) -> Result<landlock::RulesetCreated, SandboxError> {
    if !std::path::Path::new(path).exists() {
        return Ok(ruleset);
    }
    add_path_rule(ruleset, path, access)
}

/// Build the list of landlock rules for inspection/testing purposes.
/// Returns pairs of (path, is_writable).
pub fn build_landlock_rules(policy: &SandboxPolicy) -> Vec<(String, bool)> {
    let mut rules = Vec::new();

    // Root is read-only
    rules.push(("/".to_string(), false));

    // /dev/null is read-write
    rules.push(("/dev/null".to_string(), true));

    // Writable roots
    for root in &policy.writable_roots {
        if let Some(path_str) = root.to_str() {
            rules.push((path_str.to_string(), true));
        }
    }

    // Read-only subpaths
    for subpath in &policy.read_only_subpaths {
        if let Some(path_str) = subpath.to_str() {
            if !path_str.contains('*') && !path_str.contains('?') {
                rules.push((path_str.to_string(), false));
            }
        }
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::path::PathBuf;

    #[rstest]
    #[case::basic_policy(
        SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/home/user/project")],
            read_only_subpaths: vec![PathBuf::from("/home/user/project/.git")],
            network_allowed: true,
        },
        vec![
            ("/", false),
            ("/dev/null", true),
            ("/tmp", true),
            ("/home/user/project", true),
            ("/home/user/project/.git", false),
        ]
    )]
    #[case::no_writable(
        SandboxPolicy {
            writable_roots: vec![],
            read_only_subpaths: vec![],
            network_allowed: false,
        },
        vec![
            ("/", false),
            ("/dev/null", true),
        ]
    )]
    #[case::glob_patterns_skipped(
        SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![
                PathBuf::from(".env*"),
                PathBuf::from("/etc/**"),
                PathBuf::from("/home/user/.git"),
            ],
            network_allowed: true,
        },
        vec![
            ("/", false),
            ("/dev/null", true),
            ("/tmp", true),
            ("/home/user/.git", false),
        ]
    )]
    #[case::multiple_writable_and_readonly(
        SandboxPolicy {
            writable_roots: vec![
                PathBuf::from("/workspace"),
                PathBuf::from("/var/tmp"),
            ],
            read_only_subpaths: vec![
                PathBuf::from("/workspace/.git"),
                PathBuf::from("/workspace/.runok"),
            ],
            network_allowed: false,
        },
        vec![
            ("/", false),
            ("/dev/null", true),
            ("/workspace", true),
            ("/var/tmp", true),
            ("/workspace/.git", false),
            ("/workspace/.runok", false),
        ]
    )]
    fn build_rules_from_policy(#[case] policy: SandboxPolicy, #[case] expected: Vec<(&str, bool)>) {
        let rules = build_landlock_rules(&policy);
        let expected_owned: Vec<(String, bool)> = expected
            .into_iter()
            .map(|(p, w)| (p.to_string(), w))
            .collect();
        assert_eq!(rules, expected_owned);
    }
}
