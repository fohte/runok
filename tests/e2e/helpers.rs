// Test helpers are always called from #[test] functions but are not themselves
// annotated with #[test], so clippy's allow-*-in-tests doesn't apply.
#![allow(clippy::panic, reason = "test helper")]

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use tempfile::TempDir;

/// Test environment that manages a temporary directory with a `runok.yml`
/// config file and provides a pre-configured `Command` for running the
/// `runok` binary.
pub struct TestEnv {
    _tmp: TempDir,
    pub cwd: PathBuf,
    /// Isolated HOME directory to prevent global config interference.
    pub home: PathBuf,
}

impl TestEnv {
    /// Create a new test environment with the given `runok.yml` content.
    pub fn new(config_yaml: &str) -> Self {
        let tmp = TempDir::new().unwrap_or_else(|e| panic!("failed to create tempdir: {e}"));
        let cwd = tmp.path().join("project");
        let home = tmp.path().join("home");
        fs::create_dir_all(&cwd).unwrap_or_else(|e| panic!("failed to create cwd: {e}"));
        fs::create_dir_all(&home).unwrap_or_else(|e| panic!("failed to create home: {e}"));
        fs::write(cwd.join("runok.yml"), config_yaml)
            .unwrap_or_else(|e| panic!("failed to write config: {e}"));
        Self {
            _tmp: tmp,
            cwd,
            home,
        }
    }

    /// Build a `Command` for the `runok` binary, configured to run in the
    /// test environment's working directory with an isolated HOME.
    pub fn command(&self) -> Command {
        let mut cmd = assert_cmd::cargo_bin_cmd!("runok");
        cmd.current_dir(&self.cwd);
        cmd.env("HOME", &self.home);
        cmd
    }
}
