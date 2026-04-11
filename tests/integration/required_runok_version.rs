//! Integration tests for the `required_runok_version` field.
//!
//! Exercise the full config-loading pipeline: YAML → parse →
//! `load_preset` / `resolve_extends` → `required_runok_version` enforcement.
//!
//! These tests only cover cases that do not depend on the actual runok
//! version at runtime, because the version-mismatch test override is an
//! internal `#[cfg(test)]` hook not exposed to integration tests. The
//! "version-too-old" path is covered exhaustively by unit tests in
//! `src/config/required_version.rs` and `src/update_presets/mod.rs`.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use indoc::indoc;
use rstest::{fixture, rstest};
use tempfile::TempDir;

use runok::config::{
    ConfigError, PresetCache, check_required_runok_version, load_preset, parse_config,
    resolve_extends,
};
use semver::Version;

struct Env {
    _tmp: TempDir,
    project_dir: PathBuf,
    cache: PresetCache,
}

fn make_env() -> Result<Env, Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let project_dir = tmp.path().join("project");
    fs::create_dir_all(&project_dir)?;
    let cache = PresetCache::with_config(tmp.path().join("cache"), Duration::from_secs(3600));
    Ok(Env {
        _tmp: tmp,
        project_dir,
        cache,
    })
}

#[fixture]
fn env() -> Env {
    make_env().unwrap_or_else(|_| std::process::abort())
}

// === Direct check API: version-based rejection is verified here against a
// controlled version argument rather than the runtime runok version. ===

#[rstest]
#[case::satisfies(">=0.2.0", "0.2.1", true)]
#[case::not_satisfies(">=0.3.0", "0.2.1", false)]
#[case::caret(">=0.2, <0.3", "0.2.5", true)]
#[case::upper_exclusive(">=0.2, <0.3", "0.3.0", false)]
fn direct_check_api(#[case] req: &str, #[case] current: &str, #[case] expect_ok: bool) {
    let v = Version::parse(current).unwrap();
    let result = check_required_runok_version(Some(req), &v, "sample.yml");
    assert_eq!(result.is_ok(), expect_ok);
}

// === Local preset load: the field is preserved and `>=0.0.1` (which every
// real build satisfies) is accepted. ===

#[rstest]
fn load_local_preset_accepts_compatible_version(env: Env) {
    let preset_path = env.project_dir.join("preset.yml");
    fs::write(
        &preset_path,
        indoc! {"
            required_runok_version: '>=0.0.1'
            rules:
              - allow: 'echo *'
        "},
    )
    .unwrap();

    let config = load_preset("./preset.yml", &env.project_dir, &env.cache).unwrap();
    assert_eq!(config.required_runok_version.as_deref(), Some(">=0.0.1"));
}

// === extends chain: loose constraint in a child preset passes through. ===

#[rstest]
fn extends_chain_passes_when_child_constraint_is_loose(env: Env) {
    fs::write(
        env.project_dir.join("child.yml"),
        indoc! {"
            required_runok_version: '>=0.0.1'
            rules:
              - allow: 'echo *'
        "},
    )
    .unwrap();
    fs::write(
        env.project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./child.yml
        "},
    )
    .unwrap();

    let parent_yaml = fs::read_to_string(env.project_dir.join("runok.yml")).unwrap();
    let parent = parse_config(&parent_yaml).unwrap();
    let resolved =
        resolve_extends(parent, &env.project_dir, "runok.yml", &env.cache).expect("resolves");
    assert!(resolved.rules.is_some());
}

// === Invalid requirement strings are flagged clearly. This path is
// independent of the runtime runok version, so it works under any build. ===

#[rstest]
fn invalid_requirement_is_reported_with_source(env: Env) {
    fs::write(
        env.project_dir.join("preset.yml"),
        indoc! {"
            required_runok_version: 'not-a-valid-req'
            rules:
              - allow: 'echo *'
        "},
    )
    .unwrap();

    // `load_local_preset` labels errors with the resolved path built from
    // `base_dir.join(reference)`, so mirror that construction here to get an
    // exact string match for `assert_eq!`.
    let expected_label = env.project_dir.join("./preset.yml").display().to_string();

    let err = load_preset("./preset.yml", &env.project_dir, &env.cache).unwrap_err();
    match err {
        ConfigError::InvalidVersionRequirement {
            source_label,
            requirement,
            ..
        } => {
            assert_eq!(source_label, expected_label);
            assert_eq!(requirement, "not-a-valid-req");
        }
        other => panic!("expected InvalidVersionRequirement, got {other:?}"),
    }
}

#[rstest]
fn invalid_requirement_in_extends_child_is_reported(env: Env) {
    fs::write(
        env.project_dir.join("child.yml"),
        indoc! {"
            required_runok_version: 'wat'
            rules:
              - allow: 'echo *'
        "},
    )
    .unwrap();
    fs::write(
        env.project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./child.yml
        "},
    )
    .unwrap();

    // Same path-construction quirk as above: the label is the resolved path
    // built from `base_dir.join("./child.yml")`.
    let expected_label = env.project_dir.join("./child.yml").display().to_string();

    let parent_yaml = fs::read_to_string(env.project_dir.join("runok.yml")).unwrap();
    let parent = parse_config(&parent_yaml).unwrap();
    let err = resolve_extends(parent, &env.project_dir, "runok.yml", &env.cache).unwrap_err();

    match err {
        ConfigError::InvalidVersionRequirement {
            source_label,
            requirement,
            ..
        } => {
            assert_eq!(source_label, expected_label);
            assert_eq!(requirement, "wat");
        }
        other => panic!("expected InvalidVersionRequirement for child.yml, got {other:?}"),
    }
}
