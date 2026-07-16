use indoc::indoc;
use rstest::rstest;
use std::fs;
use tempfile::TempDir;

/// Writes `input` to `filename` in a fresh temp dir, runs `runok migrate`
/// against it, and returns the file's contents afterward.
fn migrate_and_read(filename: &str, input: &str) -> Result<String, Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let config_path = tmp.path().join(filename);
    fs::write(&config_path, input)?;

    runok::migrate::run(Some(&config_path), true)?;

    Ok(fs::read_to_string(&config_path)?)
}

#[rstest]
#[case::rewrites_legacy_sandbox_fs(
    "runok.yml",
    indoc! {"
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp, /tmp]
                deny:
                  - .env
              network:
                allow: true
    "},
    indoc! {"
        definitions:
          sandbox:
            restricted:
              fs:
                write:
                  allow: [./tmp, /tmp]
                  deny:
                    - .env
              network:
                allow: true
    "},
)]
#[case::no_changes_when_already_new_format(
    "runok.yml",
    indoc! {"
        definitions:
          sandbox:
            restricted:
              fs:
                write:
                  allow: [./tmp]
                  deny: [.env]
    "},
    indoc! {"
        definitions:
          sandbox:
            restricted:
              fs:
                write:
                  allow: [./tmp]
                  deny: [.env]
    "},
)]
#[case::targets_specific_file(
    "custom.yml",
    indoc! {"
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "},
    indoc! {"
        definitions:
          sandbox:
            restricted:
              fs:
                write:
                  allow: [./tmp]
    "},
)]
#[case::skips_remote_extends(
    "runok.yml",
    indoc! {"
        extends:
          - github:fohte/runok-presets
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "},
    indoc! {"
        extends:
          - github:fohte/runok-presets
        definitions:
          sandbox:
            restricted:
              fs:
                write:
                  allow: [./tmp]
    "},
)]
fn migrate_single_file(#[case] filename: &str, #[case] input: &str, #[case] expected: &str) {
    assert_eq!(migrate_and_read(filename, input).unwrap(), expected);
}

#[rstest]
#[case::escapes_bare_optional_marker(
    indoc! {"
        rules:
          - allow: git branch --abbrev ?
    "},
    indoc! {"
        rules:
          - allow: git branch --abbrev \\?
    "},
)]
#[case::escapes_across_rules_flag_groups_and_aliases(
    indoc! {"
        definitions:
          flag_groups:
            abbrev: --abbrev ?
          aliases:
            gb: git branch --abbrev ?
        rules:
          - allow: git branch <flag:abbrev>
          - allow: gb
    "},
    indoc! {"
        definitions:
          flag_groups:
            abbrev: --abbrev \\?
          aliases:
            gb: git branch --abbrev \\?
        rules:
          - allow: git branch <flag:abbrev>
          - allow: gb
    "},
)]
#[case::flow_sequence_alias_list(
    indoc! {"
        definitions:
          aliases:
            gb: [git branch --abbrev ?, git branch -v]
    "},
    indoc! {"
        definitions:
          aliases:
            gb: [git branch --abbrev \\?, git branch -v]
    "},
)]
#[case::no_changes_when_already_escaped(
    indoc! {"
        rules:
          - allow: git branch --abbrev \\?
    "},
    indoc! {"
        rules:
          - allow: git branch --abbrev \\?
    "},
)]
fn migrate_quote_optional_marker_single_file(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(migrate_and_read("runok.yml", input).unwrap(), expected);
}

#[test]
fn migrate_quote_optional_marker_is_idempotent() {
    let input = indoc! {"
        rules:
          - allow: git branch --abbrev ?
    "};
    let once = migrate_and_read("runok.yml", input).unwrap();
    let twice = migrate_and_read("runok.yml", &once).unwrap();

    assert_eq!(once, twice);
}

#[rstest]
fn migrate_follows_local_extends() {
    let tmp = TempDir::new().unwrap();

    // Preset file with legacy format
    let preset_path = tmp.path().join("preset.yml");
    fs::write(
        &preset_path,
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [/tmp]
                    deny: [.env]
        "},
    )
    .unwrap();

    // Main config that extends the preset
    let config_path = tmp.path().join("runok.yml");
    fs::write(
        &config_path,
        indoc! {"
            extends:
              - ./preset.yml
            rules:
              - allow: echo hello
        "},
    )
    .unwrap();

    runok::migrate::run(Some(&config_path), true).unwrap();

    // Main config should be unchanged (no legacy fields)
    let main_result = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        main_result,
        indoc! {"
            extends:
              - ./preset.yml
            rules:
              - allow: echo hello
        "},
    );

    // Preset should be migrated
    let preset_result = fs::read_to_string(&preset_path).unwrap();
    assert_eq!(
        preset_result,
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow: [/tmp]
                      deny: [.env]
        "},
    );
}
