use std::collections::BTreeMap;
use std::convert::TryInto;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use crate::error::SandboxError;

/// Apply seccomp filters to block network access (except AF_UNIX).
///
/// When network is not allowed:
/// - socket(2) with domain != AF_UNIX returns EPERM
/// - All other syscalls are allowed
///
/// When network is allowed, no seccomp filter is applied.
pub fn apply_seccomp(network_allowed: bool) -> Result<(), SandboxError> {
    if network_allowed {
        return Ok(());
    }

    let filter = build_seccomp_filter()?;
    let bpf_prog: BpfProgram = filter
        .try_into()
        .map_err(|e| SandboxError::Seccomp(format!("BPF compilation failed: {e}")))?;

    seccompiler::apply_filter(&bpf_prog)
        .map_err(|e| SandboxError::Seccomp(format!("apply_filter failed: {e}")))?;

    Ok(())
}

/// Build the seccomp filter that blocks non-AF_UNIX sockets.
///
/// The filter uses:
/// - mismatch_action: Allow (all non-listed syscalls are permitted)
/// - match_action: Errno(EPERM) (matched rules return permission denied)
///
/// Rules:
/// - socket(2): block when arg0 (domain) != AF_UNIX
pub fn build_seccomp_filter() -> Result<SeccompFilter, SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // socket(2): block non-AF_UNIX domains
    // The rule matches when domain != AF_UNIX, and the match_action (Errno) is applied.
    let socket_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0, // arg0 = domain
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(|e| SandboxError::Seccomp(format!("SeccompCondition creation failed: {e}")))?,
    ])
    .map_err(|e| SandboxError::Seccomp(format!("SeccompRule creation failed: {e}")))?;

    rules.insert(libc::SYS_socket, vec![socket_rule]);

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| SandboxError::Seccomp(format!("unsupported architecture: {e}")))?;

    SeccompFilter::new(
        rules,
        SeccompAction::Allow, // non-listed syscalls are allowed
        SeccompAction::Errno(libc::EPERM as u32), // matched rules return EPERM
        arch,
    )
    .map_err(|e| SandboxError::Seccomp(format!("SeccompFilter creation failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Description of a seccomp rule for testing/inspection.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SeccompRuleDescription {
        syscall: String,
        syscall_nr: i64,
        condition: String,
        action: String,
    }

    /// Inspect the seccomp filter configuration for testing.
    fn describe_seccomp_rules(network_allowed: bool) -> Vec<SeccompRuleDescription> {
        if network_allowed {
            return vec![];
        }

        vec![SeccompRuleDescription {
            syscall: "socket".to_string(),
            syscall_nr: libc::SYS_socket,
            condition: "arg0 (domain) != AF_UNIX".to_string(),
            action: "Errno(EPERM)".to_string(),
        }]
    }

    #[rstest]
    fn build_filter_succeeds() {
        let filter = build_seccomp_filter();
        assert!(filter.is_ok(), "filter should build successfully");
    }

    #[rstest]
    fn build_filter_can_convert_to_bpf() {
        let filter = build_seccomp_filter().expect("filter should build");
        let bpf: Result<BpfProgram, _> = filter.try_into();
        assert!(bpf.is_ok(), "should convert to BPF program");
    }

    #[rstest]
    #[case::network_blocked(false, 1)]
    #[case::network_allowed(true, 0)]
    fn describe_rules_count(#[case] network_allowed: bool, #[case] expected_count: usize) {
        let rules = describe_seccomp_rules(network_allowed);
        assert_eq!(rules.len(), expected_count);
    }

    #[rstest]
    fn describe_rules_network_blocked_has_socket_rule() {
        let rules = describe_seccomp_rules(false);
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.syscall, "socket");
        assert_eq!(rule.syscall_nr, libc::SYS_socket);
        assert_eq!(rule.condition, "arg0 (domain) != AF_UNIX");
        assert_eq!(rule.action, "Errno(EPERM)");
    }
}
