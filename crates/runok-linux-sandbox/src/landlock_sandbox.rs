use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
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
/// 5. Always allow read-write to /dev/null (needed by many programs)
///
/// Note: Landlock rules within a single ruleset are additive (union of permissions).
/// Read-only enforcement on subpaths of writable_roots is handled by bubblewrap's
/// mount ordering (`--ro-bind` after `--bind`), not by landlock.
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
    ruleset = add_path_rule(ruleset, std::path::Path::new("/"), access_ro)?;

    // /dev/null must be read-write for many programs
    ruleset = add_path_rule(ruleset, std::path::Path::new("/dev/null"), access_rw)?;

    // /dev/zero, /dev/urandom, /dev/random are commonly needed
    for dev_path in &["/dev/zero", "/dev/urandom", "/dev/random"] {
        ruleset = add_path_rule_if_exists(ruleset, std::path::Path::new(dev_path), access_ro)?;
    }

    // /tmp is often needed for temporary files; only add if not already covered
    // by a writable root. Skip when /tmp itself, a parent (e.g. "/"), or a child
    // under /tmp (e.g. "/tmp/myproject") is a writable root. Adding /tmp write
    // access when only a child is writable would grant overly broad permissions.
    let tmp = std::path::Path::new("/tmp");
    let tmp_overlaps_writable = policy
        .writable_roots
        .iter()
        .any(|r| tmp.starts_with(r) || r.starts_with(tmp));
    if !tmp_overlaps_writable {
        ruleset = add_path_rule_if_exists(ruleset, std::path::Path::new("/tmp"), access_rw)?;
    }

    // Add writable roots
    for root in &policy.writable_roots {
        ruleset = add_path_rule(ruleset, root, access_rw)?;
    }

    ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(format!("restrict_self failed: {e}")))?;

    Ok(())
}

fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &std::path::Path,
    access: landlock::BitFlags<AccessFs>,
) -> Result<landlock::RulesetCreated, SandboxError> {
    let fd = PathFd::new(path).map_err(|e| {
        SandboxError::Landlock(format!("cannot open path '{}': {e}", path.display()))
    })?;
    ruleset.add_rule(PathBeneath::new(fd, access)).map_err(|e| {
        SandboxError::Landlock(format!("add_rule for '{}' failed: {e}", path.display()))
    })
}

fn add_path_rule_if_exists(
    ruleset: landlock::RulesetCreated,
    path: &std::path::Path,
    access: landlock::BitFlags<AccessFs>,
) -> Result<landlock::RulesetCreated, SandboxError> {
    if !path.exists() {
        return Ok(ruleset);
    }
    add_path_rule(ruleset, path, access)
}

/// Build the list of landlock rules for inspection/testing purposes.
/// Returns pairs of (path, is_writable).
///
/// Note: read_only_subpaths are not included because landlock rules are
/// additive. Read-only enforcement is handled by bubblewrap's mount ordering.
pub fn build_landlock_rules(policy: &SandboxPolicy) -> Vec<(String, bool)> {
    let mut rules = Vec::new();

    // Root is read-only
    rules.push(("/".to_string(), false));

    // /dev/null is read-write
    rules.push(("/dev/null".to_string(), true));

    // Writable roots
    for root in &policy.writable_roots {
        rules.push((root.to_string_lossy().to_string(), true));
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
    #[case::multiple_writable(
        SandboxPolicy {
            writable_roots: vec![
                PathBuf::from("/workspace"),
                PathBuf::from("/var/tmp"),
            ],
            read_only_subpaths: vec![
                PathBuf::from("/workspace/.git"),
            ],
            network_allowed: false,
        },
        vec![
            ("/", false),
            ("/dev/null", true),
            ("/workspace", true),
            ("/var/tmp", true),
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
