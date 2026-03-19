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

    runok::migrate::run(Some(&config_path)).unwrap();

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

    runok::migrate::run(Some(&config_path)).unwrap();

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

    runok::migrate::run(Some(&config_path)).unwrap();

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
