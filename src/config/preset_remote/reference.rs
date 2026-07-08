use std::path::PathBuf;

use crate::config::PresetError;

/// Parsed preset reference indicating where to load a preset from.
#[derive(Debug, Clone, PartialEq)]
pub enum PresetReference {
    /// Local file path (relative, absolute, or `~/`-prefixed).
    Local(PathBuf),
    /// GitHub shorthand (`github:owner/repo[/path][@version]`).
    GitHub {
        owner: String,
        repo: String,
        /// Optional path within the repository to a preset file (without extension).
        path: Option<String>,
        version: GitHubVersion,
    },
    /// Generic git URL (HTTPS or SSH), optionally with a ref.
    GitUrl {
        url: String,
        git_ref: Option<String>,
    },
}

/// Version specifier for GitHub shorthand references.
#[derive(Debug, Clone, PartialEq)]
pub enum GitHubVersion {
    /// Commit SHA (40-char hex) — immutable, cached permanently.
    CommitSha(String),
    /// Tag or branch name — cached with TTL.
    Tag(String),
    /// No version specified — uses default branch, cached with TTL.
    Latest,
}

impl GitHubVersion {
    /// Whether this is an immutable reference (only commit SHA).
    pub fn is_immutable(&self) -> bool {
        matches!(self, Self::CommitSha(_))
    }

    /// Convert to a git ref string for `--branch` or `checkout`.
    pub fn as_git_ref(&self) -> Option<&str> {
        match self {
            Self::CommitSha(s) | Self::Tag(s) => Some(s),
            Self::Latest => None,
        }
    }
}

/// Check if a string looks like a full commit SHA (40-char hex).
pub(super) fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a preset reference string into a `PresetReference`.
///
/// Detection rules:
/// 1. `github:` prefix → `GitHub` shorthand
/// 2. `https://` prefix → `GitUrl` (HTTPS)
/// 3. `git@` prefix → `GitUrl` (SSH)
/// 4. Otherwise → `Local` path
pub fn parse_preset_reference(reference: &str) -> Result<PresetReference, PresetError> {
    if let Some(rest) = reference.strip_prefix("github:") {
        parse_github_shorthand(rest)
    } else if reference.starts_with("https://")
        || reference.starts_with("http://")
        || reference.starts_with("git@")
    {
        parse_git_url(reference)
    } else {
        Ok(PresetReference::Local(PathBuf::from(reference)))
    }
}

/// Parse `owner/repo[/path][@version]` from a GitHub shorthand.
///
/// The path portion starts after `owner/repo/` and extends until `@` or end of string.
/// GitHub repository names cannot contain `/`, so there is no ambiguity.
fn parse_github_shorthand(rest: &str) -> Result<PresetReference, PresetError> {
    let (path_part, version_part) = match rest.split_once('@') {
        Some((path, version)) => (path, Some(version)),
        None => (rest, None),
    };

    let (owner, after_owner) = path_part.split_once('/').ok_or_else(|| {
        PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: expected 'github:owner/repo', got 'github:{rest}'"
        ))
    })?;

    // Split repo from optional path: "repo/path/to/preset" → ("repo", Some("path/to/preset"))
    let (repo, preset_path) = match after_owner.split_once('/') {
        Some((repo, path)) => (repo, Some(path)),
        None => (after_owner, None),
    };

    if owner.is_empty() || repo.is_empty() {
        return Err(PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: owner and repo must not be empty in 'github:{rest}'"
        )));
    }

    // Validate path: must not be empty, must not contain traversal sequences or absolute paths
    if let Some(p) = preset_path
        && (p.is_empty()
            || p.starts_with('/')
            || p.split('/')
                .any(|seg| seg.is_empty() || seg == ".." || seg == "."))
    {
        return Err(PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: invalid path in 'github:{rest}'"
        )));
    }

    let version = match version_part {
        Some("") => {
            return Err(PresetError::InvalidReference(format!(
                "invalid GitHub shorthand: version must not be empty after '@' in 'github:{rest}'"
            )));
        }
        Some(v) if is_commit_sha(v) => GitHubVersion::CommitSha(v.to_string()),
        Some(v) => GitHubVersion::Tag(v.to_string()),
        None => GitHubVersion::Latest,
    };

    Ok(PresetReference::GitHub {
        owner: owner.to_string(),
        repo: repo.to_string(),
        path: preset_path.map(String::from),
        version,
    })
}

/// Parse a git URL with optional `@ref` suffix.
///
/// The ref separator is `@` after the `.git` extension or at the end.
/// Examples:
/// - `https://github.com/org/repo.git@v1.0` → url=..., ref=v1.0
/// - `git@github.com:org/repo.git@main` → url=..., ref=main
/// - `https://github.com/org/repo.git` → url=..., ref=None
fn parse_git_url(reference: &str) -> Result<PresetReference, PresetError> {
    // For SSH URLs (git@...), the `@` in `git@` is part of the URL itself.
    // We look for `@` after `.git` suffix as the ref separator.
    if let Some(idx) = reference.rfind(".git@") {
        let url = &reference[..idx + 4]; // include ".git"
        let git_ref = &reference[idx + 5..]; // after ".git@"
        if git_ref.is_empty() {
            return Err(PresetError::InvalidReference(format!(
                "invalid git URL: ref must not be empty after '@' in '{reference}'"
            )));
        }
        return Ok(PresetReference::GitUrl {
            url: url.to_string(),
            git_ref: Some(git_ref.to_string()),
        });
    }

    // No .git@ pattern found. Check for trailing @ref (only for URLs without .git suffix).
    // But for git@ SSH URLs, the first @ is part of the URL, so we need to be careful.
    if reference.starts_with("git@") {
        // SSH URL without .git suffix: look for @ after the colon (host:path@ref).
        // The first @ is part of "git@", so we find the colon first, then look for
        // @ in the path portion.
        if let Some(colon_idx) = reference.find(':') {
            let path_part = &reference[colon_idx + 1..];
            if let Some(at_idx) = path_part.rfind('@') {
                let ref_str = &path_part[at_idx + 1..];
                if !ref_str.is_empty() {
                    let url = &reference[..colon_idx + 1 + at_idx];
                    return Ok(PresetReference::GitUrl {
                        url: url.to_string(),
                        git_ref: Some(ref_str.to_string()),
                    });
                }
            }
        }
        Ok(PresetReference::GitUrl {
            url: reference.to_string(),
            git_ref: None,
        })
    } else {
        // HTTPS URL: check for trailing @ref after the path portion.
        // We must not split on the `@` in userinfo (e.g., `https://user@host/...`).
        // Strategy: find the path start (after `://host`) and only look for `@` there.
        let ref_split_start = reference
            .find("://")
            .map(|scheme_end| {
                // Skip past `://host` to the first `/` of the path
                reference[scheme_end + 3..]
                    .find('/')
                    .map(|slash| scheme_end + 3 + slash)
                    .unwrap_or(reference.len())
            })
            .unwrap_or(0);

        if let Some(at_offset) = reference[ref_split_start..].rfind('@') {
            let idx = ref_split_start + at_offset;
            let url = &reference[..idx];
            let git_ref = &reference[idx + 1..];
            if !git_ref.is_empty() && !url.is_empty() {
                return Ok(PresetReference::GitUrl {
                    url: url.to_string(),
                    git_ref: Some(git_ref.to_string()),
                });
            }
        }
        Ok(PresetReference::GitUrl {
            url: reference.to_string(),
            git_ref: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    // === parse_preset_reference tests ===

    #[rstest]
    #[case::github_latest(
        "github:org/repo",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: None,
            version: GitHubVersion::Latest,
        }
    )]
    #[case::github_tag(
        "github:org/repo@v1.0.0",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: None,
            version: GitHubVersion::Tag("v1.0.0".into()),
        }
    )]
    #[case::github_sha(
        "github:org/repo@abc1234def567890abc1234def567890abc12345",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: None,
            version: GitHubVersion::CommitSha(
                "abc1234def567890abc1234def567890abc12345".into()
            ),
        }
    )]
    #[case::github_branch_name(
        "github:org/repo@main",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: None,
            version: GitHubVersion::Tag("main".into()),
        }
    )]
    #[case::github_with_path(
        "github:org/repo/presets/readonly",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: Some("presets/readonly".into()),
            version: GitHubVersion::Latest,
        }
    )]
    #[case::github_with_path_and_tag(
        "github:fohte/runok-presets/readonly-unix@v1",
        PresetReference::GitHub {
            owner: "fohte".into(),
            repo: "runok-presets".into(),
            path: Some("readonly-unix".into()),
            version: GitHubVersion::Tag("v1".into()),
        }
    )]
    #[case::github_with_nested_path_and_sha(
        "github:org/repo/path/to/preset@abc1234def567890abc1234def567890abc12345",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: Some("path/to/preset".into()),
            version: GitHubVersion::CommitSha(
                "abc1234def567890abc1234def567890abc12345".into()
            ),
        }
    )]
    #[case::https_url_no_ref(
        "https://github.com/org/repo.git",
        PresetReference::GitUrl {
            url: "https://github.com/org/repo.git".into(),
            git_ref: None,
        }
    )]
    #[case::https_url_with_ref(
        "https://github.com/org/repo.git@v1.0",
        PresetReference::GitUrl {
            url: "https://github.com/org/repo.git".into(),
            git_ref: Some("v1.0".into()),
        }
    )]
    #[case::ssh_url_no_ref(
        "git@github.com:org/repo.git",
        PresetReference::GitUrl {
            url: "git@github.com:org/repo.git".into(),
            git_ref: None,
        }
    )]
    #[case::ssh_url_with_ref(
        "git@github.com:org/repo.git@main",
        PresetReference::GitUrl {
            url: "git@github.com:org/repo.git".into(),
            git_ref: Some("main".into()),
        }
    )]
    #[case::ssh_url_no_git_suffix_with_ref(
        "git@github.com:org/repo@v2.0",
        PresetReference::GitUrl {
            url: "git@github.com:org/repo".into(),
            git_ref: Some("v2.0".into()),
        }
    )]
    #[case::https_url_with_userinfo(
        "https://user@github.com/org/repo.git",
        PresetReference::GitUrl {
            url: "https://user@github.com/org/repo.git".into(),
            git_ref: None,
        }
    )]
    #[case::https_url_with_userinfo_and_ref(
        "https://user@github.com/org/repo.git@v1.0",
        PresetReference::GitUrl {
            url: "https://user@github.com/org/repo.git".into(),
            git_ref: Some("v1.0".into()),
        }
    )]
    #[case::local_relative(
        "./rules/preset.yml",
        PresetReference::Local(PathBuf::from("./rules/preset.yml"))
    )]
    #[case::local_absolute(
        "/etc/runok/global.yml",
        PresetReference::Local(PathBuf::from("/etc/runok/global.yml"))
    )]
    #[case::local_home(
        "~/presets/base.yml",
        PresetReference::Local(PathBuf::from("~/presets/base.yml"))
    )]
    fn parse_reference(#[case] input: &str, #[case] expected: PresetReference) {
        let result = parse_preset_reference(input).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::no_slash("github:invalid", "invalid GitHub shorthand")]
    #[case::empty_owner("github:/repo", "owner and repo must not be empty")]
    #[case::empty_repo("github:org/", "owner and repo must not be empty")]
    #[case::empty_version("github:org/repo@", "version must not be empty")]
    #[case::empty_path_with_version("github:org/repo/@v1", "invalid path")]
    #[case::path_traversal("github:org/repo/../../etc/passwd@v1", "invalid path")]
    #[case::path_traversal_no_ref("github:org/repo/../secret", "invalid path")]
    #[case::absolute_path("github:org/repo//etc/passwd@v1", "invalid path")]
    #[case::dot_segment("github:org/repo/./foo@v1", "invalid path")]
    #[case::trailing_slash("github:org/repo/foo/bar/@v1", "invalid path")]
    fn parse_reference_errors(#[case] input: &str, #[case] expected_msg: &str) {
        let err = parse_preset_reference(input).unwrap_err();
        assert!(
            err.to_string().contains(expected_msg),
            "expected error containing '{expected_msg}', got: {err}"
        );
    }

    // === is_commit_sha tests ===

    #[rstest]
    #[case::valid_sha("abc1234def567890abc1234def567890abc12345", true)]
    #[case::all_digits("1234567890123456789012345678901234567890", true)]
    #[case::too_short("abc123", false)]
    #[case::too_long("abc1234def567890abc1234def567890abc123456", false)]
    #[case::non_hex("xyz1234def567890abc1234def567890abc12345", false)]
    #[case::tag("v1.0.0", false)]
    #[case::empty("", false)]
    fn commit_sha_detection(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_commit_sha(input), expected);
    }
}
