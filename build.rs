fn main() {
    // When RUNOK_NIGHTLY_VERSION is set (nightly CI builds), use it as the version string.
    // Otherwise, fall back to the Cargo.toml version (CARGO_PKG_VERSION).
    let version = std::env::var("RUNOK_NIGHTLY_VERSION")
        .or_else(|_| std::env::var("CARGO_PKG_VERSION"))
        .unwrap_or_else(|_| String::from("unknown"));
    println!("cargo:rustc-env=RUNOK_VERSION={version}");
    println!("cargo:rerun-if-env-changed=RUNOK_NIGHTLY_VERSION");
}
