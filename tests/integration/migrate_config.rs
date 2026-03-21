use indoc::indoc;
use rstest::rstest;
use std::fs;
use tempfile::TempDir;

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
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join(filename);
    fs::write(&config_path, input).unwrap();

    runok::migrate::run(Some(&config_path), true).unwrap();

    let result = fs::read_to_string(&config_path).unwrap();
    assert_eq!(result, expected);
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
