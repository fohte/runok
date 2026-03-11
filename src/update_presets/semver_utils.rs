use semver::Version;

/// Strip `v` prefix and parse as semver. Returns `None` if unparseable.
pub fn parse_semver_tag(tag: &str) -> Option<Version> {
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    Version::parse(stripped).ok()
}

/// Find the latest tag within the same major version that is newer than `current_tag`.
///
/// Returns `None` if no newer compatible tag exists.
/// Matches the v-prefix convention of `current_tag` (e.g., if current is `v1.0.0`,
/// only considers tags starting with `v`).
/// Pre-release versions are excluded from upgrade candidates.
pub fn find_latest_compatible_tag(current_tag: &str, available_tags: &[String]) -> Option<String> {
    let current_version = parse_semver_tag(current_tag)?;
    let has_v_prefix = current_tag.starts_with('v');

    available_tags
        .iter()
        .filter(|t| t.starts_with('v') == has_v_prefix)
        .filter_map(|t| {
            let version = parse_semver_tag(t)?;
            // Same major version, newer, stable (no pre-release)
            if version.major == current_version.major
                && version > current_version
                && version.pre.is_empty()
            {
                Some((t.clone(), version))
            } else {
                None
            }
        })
        .max_by(|a, b| a.1.cmp(&b.1))
        .map(|(tag, _)| tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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

    // === find_latest_compatible_tag ===

    #[rstest]
    #[case::basic_upgrade(
        "v1.0.0",
        &["v1.0.0", "v1.1.0", "v1.2.0"],
        Some("v1.2.0"),
    )]
    #[case::respects_major_boundary(
        "v1.0.0",
        &["v1.0.0", "v2.0.0"],
        None,
    )]
    #[case::no_newer_version(
        "v1.2.0",
        &["v1.0.0", "v1.1.0", "v1.2.0"],
        None,
    )]
    #[case::skips_pre_release(
        "v1.0.0",
        &["v1.0.0", "v1.1.0-beta.1", "v1.1.0"],
        Some("v1.1.0"),
    )]
    #[case::only_pre_release_available(
        "v1.0.0",
        &["v1.0.0", "v1.1.0-beta.1"],
        None,
    )]
    #[case::without_v_prefix(
        "1.0.0",
        &["1.0.0", "1.1.0", "1.2.0"],
        Some("1.2.0"),
    )]
    #[case::v_prefix_mismatch_excluded(
        "v1.0.0",
        &["1.1.0", "v1.1.0"],
        Some("v1.1.0"),
    )]
    #[case::mixed_major_versions(
        "v1.0.0",
        &["v0.9.0", "v1.0.0", "v1.3.0", "v2.0.0", "v2.1.0"],
        Some("v1.3.0"),
    )]
    fn find_latest_compatible_tag_test(
        #[case] current: &str,
        #[case] available: &[&str],
        #[case] expected: Option<&str>,
    ) {
        let tags: Vec<String> = available.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            find_latest_compatible_tag(current, &tags),
            expected.map(String::from)
        );
    }

    #[rstest]
    fn non_semver_current_returns_none() {
        let tags = vec!["v1.0.0".to_string(), "v2.0.0".to_string()];
        assert_eq!(find_latest_compatible_tag("main", &tags), None);
    }
}
