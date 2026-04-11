//! Runtime check for the `required_runok_version` config field.
//!
//! Each config/preset file may declare a semver requirement that the running
//! runok must satisfy. The check is performed per file as it is loaded so
//! that violations surface with the exact source of the constraint rather
//! than after merging multiple layers together.

#[cfg(test)]
use std::cell::RefCell;

use semver::{Version, VersionReq};

use super::error::ConfigError;

#[cfg(test)]
thread_local! {
    /// Test-only override for `current_runok_version`. When `Some`, the
    /// override wins so that test scenarios can simulate arbitrary runok
    /// versions (including "pretend we're an old release") regardless of the
    /// actual build-time `RUNOK_VERSION`.
    static VERSION_OVERRIDE: RefCell<Option<Version>> = const { RefCell::new(None) };
}

/// RAII guard that sets a test override and restores the previous value on drop.
#[cfg(test)]
pub(crate) struct VersionOverrideGuard {
    previous: Option<Version>,
}

#[cfg(test)]
impl VersionOverrideGuard {
    pub fn set(version: Version) -> Self {
        let previous = VERSION_OVERRIDE.with(|cell| cell.borrow().clone());
        VERSION_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(version));
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for VersionOverrideGuard {
    fn drop(&mut self) {
        let prev = self.previous.clone();
        VERSION_OVERRIDE.with(|cell| *cell.borrow_mut() = prev);
    }
}

/// Sentinel version returned for nightly builds so that any `required_runok_version`
/// with an upper bound of "some released version" still matches. Nightly builds
/// are produced from `main` and may ship any unreleased feature, so treating
/// them as "newer than every release" matches intent.
fn nightly_sentinel() -> Version {
    Version::new(u64::MAX, u64::MAX, u64::MAX)
}

/// Parse the `RUNOK_VERSION` string (set by `build.rs`) into a `semver::Version`
/// suitable for `VersionReq::matches`.
///
/// - Release builds (`0.2.1`): parsed as-is.
/// - Nightly builds (`0.2.1-nightly+abc1234`): returned as the nightly sentinel
///   so they match any `required_runok_version` constraint.
/// - Unparseable strings: treated as nightly (best-effort, should never happen
///   in practice because `build.rs` always produces valid semver).
pub(crate) fn current_runok_version_from(raw: &str) -> Version {
    if raw.contains("-nightly") {
        return nightly_sentinel();
    }
    Version::parse(raw).unwrap_or_else(|_| nightly_sentinel())
}

/// Return the current runok version, using the `RUNOK_VERSION` env var
/// baked in at build time by `build.rs`. During tests, a thread-local
/// override may replace the resolved value to simulate arbitrary versions.
pub fn current_runok_version() -> Version {
    #[cfg(test)]
    if let Some(v) = VERSION_OVERRIDE.with(|cell| cell.borrow().clone()) {
        return v;
    }
    current_runok_version_from(env!("RUNOK_VERSION"))
}

/// Check whether `current` satisfies the `required_runok_version` declared in
/// a single config file.
///
/// `source_label` is shown in error messages so that users can identify which
/// file carries the constraint (e.g. the file path or preset reference).
///
/// Returns `Ok(())` if the field is absent or the requirement is satisfied.
pub fn check_required_runok_version(
    required: Option<&str>,
    current: &Version,
    source_label: &str,
) -> Result<(), ConfigError> {
    let Some(requirement) = required else {
        return Ok(());
    };

    let req =
        VersionReq::parse(requirement).map_err(|e| ConfigError::InvalidVersionRequirement {
            source_label: source_label.to_string(),
            requirement: requirement.to_string(),
            message: e.to_string(),
        })?;

    if req.matches(current) {
        Ok(())
    } else {
        Err(ConfigError::UnsupportedRunokVersion {
            source_label: source_label.to_string(),
            requirement: requirement.to_string(),
            current: current.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === current_runok_version_from ===

    #[rstest]
    #[case::release("0.2.1", "0.2.1")]
    #[case::release_with_v_patch("1.2.3", "1.2.3")]
    #[case::nightly_short(
        "0.2.1-nightly+abc1234",
        "18446744073709551615.18446744073709551615.18446744073709551615"
    )]
    #[case::nightly_bare(
        "0.3.0-nightly",
        "18446744073709551615.18446744073709551615.18446744073709551615"
    )]
    #[case::unparseable(
        "not-a-version",
        "18446744073709551615.18446744073709551615.18446744073709551615"
    )]
    fn current_runok_version_from_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(current_runok_version_from(input).to_string(), expected);
    }

    // === check_required_runok_version ===

    #[rstest]
    #[case::none_always_ok(None, "0.1.0")]
    #[case::exact_match(Some("=0.2.1"), "0.2.1")]
    #[case::ge_match(Some(">=0.2.0"), "0.2.1")]
    #[case::caret_match(Some("^0.2"), "0.2.5")]
    #[case::range_inclusive(Some(">=0.2, <0.4"), "0.3.0")]
    fn check_required_runok_version_ok(#[case] required: Option<&str>, #[case] current: &str) {
        let v = Version::parse(current).unwrap();
        assert!(check_required_runok_version(required, &v, "source.yml").is_ok());
    }

    #[rstest]
    #[case::too_old(">=0.3.0", "0.2.1")]
    #[case::upper_bound_violated(">=0.2, <0.3", "0.3.0")]
    fn check_required_runok_version_unsupported(#[case] required: &str, #[case] current: &str) {
        let v = Version::parse(current).unwrap();
        let err = check_required_runok_version(Some(required), &v, "source.yml").unwrap_err();
        match err {
            ConfigError::UnsupportedRunokVersion {
                source_label,
                requirement,
                current: current_str,
            } => {
                assert_eq!(source_label, "source.yml");
                assert_eq!(requirement, required);
                assert_eq!(current_str, current);
            }
            other => panic!("expected UnsupportedRunokVersion, got {other:?}"),
        }
    }

    #[rstest]
    fn check_required_runok_version_invalid_requirement() {
        let v = Version::parse("0.2.1").unwrap();
        let err = check_required_runok_version(Some("not-a-req"), &v, "source.yml").unwrap_err();
        match err {
            ConfigError::InvalidVersionRequirement {
                source_label,
                requirement,
                ..
            } => {
                assert_eq!(source_label, "source.yml");
                assert_eq!(requirement, "not-a-req");
            }
            other => panic!("expected InvalidVersionRequirement, got {other:?}"),
        }
    }

    #[rstest]
    fn nightly_satisfies_any_lower_bound() {
        let v = current_runok_version_from("0.2.1-nightly+abc1234");
        // Nightly should always satisfy any `>=X.Y.Z` requirement, even for
        // versions far beyond the current cargo_version.
        assert!(check_required_runok_version(Some(">=999.0.0"), &v, "n.yml").is_ok());
    }

    #[rstest]
    fn nightly_violates_strict_upper_bound() {
        // Nightly = MAX, so a `<0.4` constraint genuinely excludes it. This is
        // the documented trade-off: nightly = latest, so upper-bounded ranges
        // reject it.
        let v = current_runok_version_from("0.2.1-nightly+abc1234");
        assert!(check_required_runok_version(Some(">=0.2, <0.4"), &v, "n.yml").is_err());
    }
}
