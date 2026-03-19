use indoc::indoc;
use rstest::rstest;
use std::fs;
use tempfile::TempDir;

#[rstest]
fn migrate_rewrites_legacy_sandbox_fs() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("runok.yml");
    fs::write(
        &config_path,
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
    )
    .unwrap();

    // yes=true to skip interactive prompt in tests
    runok::migrate::run(Some(&config_path), true).unwrap();

    let result = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        result,
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
    );
}

#[rstest]
fn migrate_no_changes_when_already_new_format() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("runok.yml");
    let content = indoc! {"
        definitions:
          sandbox:
            restricted:
              fs:
                write:
                  allow: [./tmp]
                  deny: [.env]
    "};
    fs::write(&config_path, content).unwrap();

    runok::migrate::run(Some(&config_path), true).unwrap();

    let result = fs::read_to_string(&config_path).unwrap();
    assert_eq!(result, content);
}

#[rstest]
fn migrate_with_config_path_targets_specific_file() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("custom.yml");
    fs::write(
        &config_path,
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "},
    )
    .unwrap();

    runok::migrate::run(Some(&config_path), true).unwrap();

    let result = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        result,
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow: [./tmp]
        "},
    );
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

#[rstest]
fn migrate_skips_remote_extends() {
    let tmp = TempDir::new().unwrap();

    // Main config that extends a remote preset (should not try to follow it)
    let config_path = tmp.path().join("runok.yml");
    fs::write(
        &config_path,
        indoc! {"
            extends:
              - github:fohte/runok-presets
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "},
    )
    .unwrap();

    runok::migrate::run(Some(&config_path), true).unwrap();

    let result = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        result,
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
    );
}
