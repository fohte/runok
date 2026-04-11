use semver::Version;

/// Precision of a version tag specified by the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSpec {
    /// `v1` or `1` -- major version only
    Major { major: u64, v_prefix: bool },
    /// `v1.0` or `1.0` -- major + minor
    MajorMinor {
        major: u64,
        minor: u64,
        v_prefix: bool,
    },
    /// `v1.0.0` or `1.0.0` -- full semver
    Full(Version, bool),
}

/// Parse a version tag into a `VersionSpec`.
///
/// Handles `v` prefix, partial versions (`1`, `1.0`), and full semver (`1.0.0`).
/// Returns `None` for non-version strings like `main` or `stable`.
pub fn parse_version_spec(tag: &str) -> Option<VersionSpec> {
    let v_prefix = tag.starts_with('v');
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    let parts: Vec<&str> = stripped.split('.').collect();

    // All parts must be numeric
    if !parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        // Could be a full semver with pre-release (e.g., "1.0.0-beta.1")
        if parts.len() >= 3 {
            return Version::parse(stripped)
                .ok()
                .map(|v| VersionSpec::Full(v, v_prefix));
        }
        return None;
    }

    match parts.len() {
        1 => {
            let major = parts[0].parse().ok()?;
            Some(VersionSpec::Major { major, v_prefix })
        }
        2 => {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            Some(VersionSpec::MajorMinor {
                major,
                minor,
                v_prefix,
            })
        }
        3 => {
            let version = Version::parse(stripped).ok()?;
            Some(VersionSpec::Full(version, v_prefix))
        }
        _ => None,
    }
}

/// Strip `v` prefix and parse as semver. Returns `None` if unparseable.
pub fn parse_semver_tag(tag: &str) -> Option<Version> {
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    Version::parse(stripped).ok()
}

/// Return only the newest compatible upgrade, matching the pre-candidate API
/// used by the tests. Kept as a thin wrapper so the existing table-driven
/// tests continue to exercise the candidate logic end-to-end.
#[cfg(test)]
fn find_latest_upgrade(current_tag: &str, available_tags: &[String]) -> Option<String> {
    find_upgrade_candidates(current_tag, available_tags)
        .into_iter()
        .next()
}

/// Return all compatible upgrade candidates for `current_tag`, ordered from
/// newest to oldest. The caller can iterate through candidates and pick the
/// first one that satisfies additional constraints (e.g. `required_runok_version`).
///
/// Returns an empty `Vec` if `current_tag` is not a recognized version spec
/// or no newer versions are available.
pub fn find_upgrade_candidates(current_tag: &str, available_tags: &[String]) -> Vec<String> {
    let Some(spec) = parse_version_spec(current_tag) else {
        return Vec::new();
    };

    match spec {
        VersionSpec::Major { major, v_prefix } => {
            find_major_candidates(major, v_prefix, available_tags)
        }
        VersionSpec::MajorMinor {
            major,
            minor,
            v_prefix,
        } => find_minor_candidates(major, minor, v_prefix, available_tags),
        VersionSpec::Full(ref version, v_prefix) => {
            find_full_candidates(version, v_prefix, available_tags)
        }
    }
}

/// Return all candidate major versions greater than `current_major`, as tag
/// strings in the same `v`-prefix format, ordered from newest to oldest.
///
/// Scans all available tags (both partial and full) to determine candidate
/// major versions, then formats them as partial tags (e.g., `v2`). Each
/// major is emitted only once, even if multiple tags share it.
fn find_major_candidates(
    current_major: u64,
    v_prefix: bool,
    available_tags: &[String],
) -> Vec<String> {
    let mut majors: Vec<u64> = available_tags
        .iter()
        .filter(|t| t.starts_with('v') == v_prefix)
        .filter_map(|t| {
            let candidate = parse_version_spec(t)?;
            let candidate_major = match candidate {
                VersionSpec::Major { major, .. } => major,
                VersionSpec::MajorMinor { major, .. } => major,
                VersionSpec::Full(ref v, _) if v.pre.is_empty() => v.major,
                _ => return None,
            };
            (candidate_major > current_major).then_some(candidate_major)
        })
        .collect();

    majors.sort_unstable_by(|a, b| b.cmp(a));
    majors.dedup();

    let prefix = if v_prefix { "v" } else { "" };
    majors.into_iter().map(|m| format!("{prefix}{m}")).collect()
}

/// Return all candidate minor versions within the same major, greater than
/// `current_minor`, as partial tag strings ordered from newest to oldest.
fn find_minor_candidates(
    current_major: u64,
    current_minor: u64,
    v_prefix: bool,
    available_tags: &[String],
) -> Vec<String> {
    let mut minors: Vec<u64> = available_tags
        .iter()
        .filter(|t| t.starts_with('v') == v_prefix)
        .filter_map(|t| {
            let candidate = parse_version_spec(t)?;
            let (major, minor) = match candidate {
                VersionSpec::MajorMinor { major, minor, .. } => (major, minor),
                VersionSpec::Full(ref v, _) if v.pre.is_empty() => (v.major, v.minor),
                _ => return None,
            };
            (major == current_major && minor > current_minor).then_some(minor)
        })
        .collect();

    minors.sort_unstable_by(|a, b| b.cmp(a));
    minors.dedup();

    let prefix = if v_prefix { "v" } else { "" };
    minors
        .into_iter()
        .map(|m| format!("{prefix}{current_major}.{m}"))
        .collect()
}

/// Return all full semver tags within the same major version that are newer
/// than `current_version`, ordered from newest to oldest.
fn find_full_candidates(
    current_version: &Version,
    v_prefix: bool,
    available_tags: &[String],
) -> Vec<String> {
    let mut candidates: Vec<(String, Version)> = available_tags
        .iter()
        .filter(|t| t.starts_with('v') == v_prefix)
        .filter_map(|t| {
            let version = parse_semver_tag(t)?;
            if version.major == current_version.major
                && version > *current_version
                && version.pre.is_empty()
            {
                Some((t.clone(), version))
            } else {
                None
            }
        })
        .collect();

    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    candidates.into_iter().map(|(tag, _)| tag).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === parse_version_spec ===

    #[rstest]
    #[case::major_with_v("v1", Some(VersionSpec::Major { major: 1, v_prefix: true }))]
    #[case::major_without_v("1", Some(VersionSpec::Major { major: 1, v_prefix: false }))]
    #[case::major_zero("v0", Some(VersionSpec::Major { major: 0, v_prefix: true }))]
    #[case::major_minor_with_v("v1.0", Some(VersionSpec::MajorMinor { major: 1, minor: 0, v_prefix: true }))]
    #[case::major_minor_without_v("1.2", Some(VersionSpec::MajorMinor { major: 1, minor: 2, v_prefix: false }))]
    #[case::full_with_v("v1.0.0", Some(VersionSpec::Full(Version::new(1, 0, 0), true)))]
    #[case::full_without_v("1.2.3", Some(VersionSpec::Full(Version::new(1, 2, 3), false)))]
    #[case::branch_name("main", None)]
    #[case::non_semver_tag("stable", None)]
    #[case::four_parts("v1.2.3.4", None)]
    #[case::non_digit("v1a", None)]
    #[case::empty_part("v1.", None)]
    fn parse_version_spec_test(#[case] input: &str, #[case] expected: Option<VersionSpec>) {
        assert_eq!(parse_version_spec(input), expected);
    }

    #[rstest]
    fn parse_version_spec_pre_release() {
        let result = parse_version_spec("v1.0.0-beta.1");
        match result {
            Some(VersionSpec::Full(v, true)) => {
                assert_eq!(v.major, 1);
                assert_eq!(v.to_string(), "1.0.0-beta.1");
            }
            other => panic!("expected Full with pre-release, got {other:?}"),
        }
    }

    // === parse_semver_tag ===

    #[rstest]
    #[case::with_v_prefix("v1.0.0", Some("1.0.0"))]
    #[case::without_prefix("1.0.0", Some("1.0.0"))]
    #[case::with_patch("v1.2.3", Some("1.2.3"))]
    #[case::pre_release("v1.0.0-beta.1", Some("1.0.0-beta.1"))]
    #[case::branch_name("main", None)]
    #[case::non_semver_tag("stable", None)]
    #[case::partial_version("v1", None)]
    #[case::partial_version_two("v1.0", None)]
    fn parse_semver_tag_test(#[case] input: &str, #[case] expected: Option<&str>) {
        let result = parse_semver_tag(input);
        assert_eq!(
            result.as_ref().map(|v| v.to_string()),
            expected.map(String::from)
        );
    }

    // === find_latest_upgrade ===

    // -- Full semver (same behavior as before) --

    #[rstest]
    #[case::full_basic_upgrade(
        "v1.0.0",
        &["v1.0.0", "v1.1.0", "v1.2.0"],
        Some("v1.2.0"),
    )]
    #[case::full_respects_major_boundary(
        "v1.0.0",
        &["v1.0.0", "v2.0.0"],
        None,
    )]
    #[case::full_no_newer_version(
        "v1.2.0",
        &["v1.0.0", "v1.1.0", "v1.2.0"],
        None,
    )]
    #[case::full_skips_pre_release(
        "v1.0.0",
        &["v1.0.0", "v1.1.0-beta.1", "v1.1.0"],
        Some("v1.1.0"),
    )]
    #[case::full_only_pre_release_available(
        "v1.0.0",
        &["v1.0.0", "v1.1.0-beta.1"],
        None,
    )]
    #[case::full_without_v_prefix(
        "1.0.0",
        &["1.0.0", "1.1.0", "1.2.0"],
        Some("1.2.0"),
    )]
    #[case::full_v_prefix_mismatch_excluded(
        "v1.0.0",
        &["1.1.0", "v1.1.0"],
        Some("v1.1.0"),
    )]
    #[case::full_mixed_major_versions(
        "v1.0.0",
        &["v0.9.0", "v1.0.0", "v1.3.0", "v2.0.0", "v2.1.0"],
        Some("v1.3.0"),
    )]
    // -- Major only --
    #[case::major_upgrade_to_v2(
        "v1",
        &["v1.0.0", "v1.1.0", "v2.0.0"],
        Some("v2"),
    )]
    #[case::major_upgrade_to_v3(
        "v1",
        &["v1.0.0", "v2.0.0", "v3.0.0"],
        Some("v3"),
    )]
    #[case::major_no_newer(
        "v2",
        &["v1.0.0", "v2.0.0"],
        None,
    )]
    #[case::major_without_v_prefix(
        "1",
        &["1.0.0", "2.0.0", "2.1.0"],
        Some("2"),
    )]
    #[case::major_v_prefix_mismatch(
        "v1",
        &["2.0.0", "v2.0.0"],
        Some("v2"),
    )]
    #[case::major_from_partial_tags(
        "v1",
        &["v1", "v2", "v3"],
        Some("v3"),
    )]
    #[case::major_skips_pre_release(
        "v1",
        &["v1.0.0", "v2.0.0-beta.1"],
        None,
    )]
    // -- MajorMinor --
    #[case::minor_upgrade(
        "v1.0",
        &["v1.0.0", "v1.1.0", "v1.2.0"],
        Some("v1.2"),
    )]
    #[case::minor_no_newer(
        "v1.2",
        &["v1.0.0", "v1.1.0", "v1.2.0"],
        None,
    )]
    #[case::minor_respects_major_boundary(
        "v1.0",
        &["v1.0.0", "v2.0.0"],
        None,
    )]
    #[case::minor_without_v_prefix(
        "1.0",
        &["1.0.0", "1.1.0", "1.3.0"],
        Some("1.3"),
    )]
    #[case::minor_from_partial_tags(
        "v1.0",
        &["v1.0", "v1.1", "v1.3"],
        Some("v1.3"),
    )]
    #[case::minor_skips_pre_release(
        "v1.0",
        &["v1.0.0", "v1.1.0-beta.1"],
        None,
    )]
    fn find_latest_upgrade_test(
        #[case] current: &str,
        #[case] available: &[&str],
        #[case] expected: Option<&str>,
    ) {
        let tags: Vec<String> = available.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            find_latest_upgrade(current, &tags),
            expected.map(String::from)
        );
    }

    #[rstest]
    fn non_semver_current_returns_none() {
        let tags = vec!["v1.0.0".to_string(), "v2.0.0".to_string()];
        assert_eq!(find_latest_upgrade("main", &tags), None);
    }
}
