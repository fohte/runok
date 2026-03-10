fn main() {
    // When RUNOK_NIGHTLY_VERSION is set (nightly CI builds), use it as the version string.
    // Otherwise, fall back to the Cargo.toml version (CARGO_PKG_VERSION).
    #[expect(
        clippy::expect_used,
        reason = "CARGO_PKG_VERSION is guaranteed by Cargo"
    )]
    let version = std::env::var("RUNOK_NIGHTLY_VERSION")
        .or_else(|_| std::env::var("CARGO_PKG_VERSION"))
        .expect("CARGO_PKG_VERSION must be set by Cargo");
    println!("cargo::rustc-env=RUNOK_VERSION={version}");
    println!("cargo::rerun-if-env-changed=RUNOK_NIGHTLY_VERSION");
    println!("cargo::rerun-if-env-changed=CARGO_PKG_VERSION");
}
