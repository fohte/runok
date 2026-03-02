use predicates::prelude::*;

#[test]
fn version_flag_prints_version() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("runok");
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}
