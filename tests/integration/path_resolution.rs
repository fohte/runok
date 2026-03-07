//! 異なる cwd からの実行でもパス解決結果が一貫することを検証する統合テスト。

use std::fs;

use indoc::indoc;
use rstest::{fixture, rstest};
use runok::config::{ConfigLoader, DefaultConfigLoader};
use tempfile::TempDir;

struct PathResolutionEnv {
    _tmp: TempDir,
    project_dir: std::path::PathBuf,
}

#[fixture]
fn env() -> PathResolutionEnv {
    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("project");
    fs::create_dir_all(project_dir.join("src")).unwrap();
    fs::create_dir_all(project_dir.join("src/nested")).unwrap();

    fs::write(
        project_dir.join("runok.yml"),
        indoc! {r#"
            definitions:
              paths:
                sensitive:
                  - ".env*"
                  - "secrets/credentials.json"
              sandbox:
                restricted:
                  fs:
                    writable:
                      - "./tmp"
                    deny:
                      - ".env*"
                      - "/etc/shadow"
        "#},
    )
    .unwrap();

    // writable に使うディレクトリを実際に作成 (canonicalize のため)
    fs::create_dir_all(project_dir.join("tmp")).unwrap();

    PathResolutionEnv {
        _tmp: tmp,
        project_dir,
    }
}

/// 異なる cwd からロードしても、definitions.paths の相対パスが
/// 設定ファイルの親ディレクトリ基準で解決される。
#[rstest]
#[case::from_project_root("")]
#[case::from_src("src")]
#[case::from_nested("src/nested")]
fn paths_resolved_relative_to_config_file(env: PathResolutionEnv, #[case] subdir: &str) {
    let cwd = if subdir.is_empty() {
        env.project_dir.clone()
    } else {
        env.project_dir.join(subdir)
    };

    let loader = DefaultConfigLoader::with_global_dir(env.project_dir.join("nonexistent_global"));
    let config = loader.load(&cwd).unwrap();

    let defs = config.definitions.unwrap();
    let paths = defs.paths.unwrap();
    let sensitive = &paths["sensitive"];

    // 相対パスは設定ファイルの親ディレクトリ (project_dir) で解決される
    let expected_env = format!("{}/.env*", env.project_dir.display());
    let expected_creds = format!("{}/secrets/credentials.json", env.project_dir.display());
    assert_eq!(sensitive[0], expected_env, "cwd={}", cwd.display());
    assert_eq!(sensitive[1], expected_creds, "cwd={}", cwd.display());
}

/// 異なる cwd からロードしても、sandbox の writable/deny パスが
/// 設定ファイルの親ディレクトリ基準で解決される。
#[rstest]
#[case::from_project_root("")]
#[case::from_src("src")]
fn sandbox_paths_resolved_relative_to_config_file(env: PathResolutionEnv, #[case] subdir: &str) {
    let cwd = if subdir.is_empty() {
        env.project_dir.clone()
    } else {
        env.project_dir.join(subdir)
    };

    let loader = DefaultConfigLoader::with_global_dir(env.project_dir.join("nonexistent_global"));
    let config = loader.load(&cwd).unwrap();

    let defs = config.definitions.unwrap();
    let sandbox = defs.sandbox.unwrap();
    let restricted = &sandbox["restricted"];
    let fs_policy = restricted.fs.as_ref().unwrap();

    // writable の相対パスが解決されている
    let writable = fs_policy.writable.as_ref().unwrap();
    let expected_tmp = format!("{}/tmp", env.project_dir.display());
    assert_eq!(writable[0], expected_tmp, "cwd={}", cwd.display());

    // deny の相対パスが解決されている
    let deny = fs_policy.deny.as_ref().unwrap();
    let expected_deny_env = format!("{}/.env*", env.project_dir.display());
    assert_eq!(deny[0], expected_deny_env, "cwd={}", cwd.display());
    // 絶対パスはそのまま
    assert_eq!(deny[1], "/etc/shadow", "cwd={}", cwd.display());
}

/// グローバル設定とローカル設定で異なる base_dir が使われ、
/// マージ前にパスが解決される。
#[rstest]
fn global_and_local_use_different_base_dirs() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let global_dir = tmp.path().join("global");
    let project_dir = home.join("project");

    fs::create_dir_all(&global_dir).unwrap();
    fs::create_dir_all(&project_dir).unwrap();

    fs::write(
        global_dir.join("runok.yml"),
        indoc! {r#"
            definitions:
              paths:
                global_paths:
                  - "global-data/**"
        "#},
    )
    .unwrap();

    fs::write(
        project_dir.join("runok.yml"),
        indoc! {r#"
            definitions:
              paths:
                local_paths:
                  - "local-data/**"
        "#},
    )
    .unwrap();

    let loader = DefaultConfigLoader::with_global_dir(global_dir.clone());
    let config = loader.load(&project_dir).unwrap();

    let defs = config.definitions.unwrap();
    let paths = defs.paths.unwrap();

    // グローバル設定のパスはグローバルディレクトリ基準
    let global = &paths["global_paths"];
    assert_eq!(
        global[0],
        format!("{}/global-data/**", global_dir.display())
    );

    // ローカル設定のパスはプロジェクトディレクトリ基準
    let local = &paths["local_paths"];
    assert_eq!(local[0], format!("{}/local-data/**", project_dir.display()));
}

/// extends で読み込まれたプリセット内のパスが
/// プリセットファイルの親ディレクトリで解決される。
/// load_local_preset を直接呼んでパス解決を検証する。
#[rstest]
fn preset_paths_resolved_relative_to_preset_file() {
    use runok::config::load_local_preset;

    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("project");
    let presets_dir = project_dir.join("presets");
    fs::create_dir_all(&presets_dir).unwrap();

    fs::write(
        presets_dir.join("base.yml"),
        indoc! {r#"
            definitions:
              paths:
                preset_sensitive:
                  - "preset-data/.env*"
        "#},
    )
    .unwrap();

    // load_local_preset は内部でパス解決を行う
    let config = load_local_preset("./presets/base.yml", &project_dir).unwrap();

    let defs = config.definitions.unwrap();
    let paths = defs.paths.unwrap();

    // プリセット内のパスはプリセットの親ディレクトリ (presets/) で解決される
    let preset_paths = &paths["preset_sensitive"];
    assert_eq!(
        preset_paths[0],
        format!("{}/preset-data/.env*", presets_dir.display())
    );
}
