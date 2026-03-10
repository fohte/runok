fn main() {
    // When RUNOK_NIGHTLY_VERSION is set (nightly CI builds), use it as the version string.
    // Otherwise, fall back to the Cargo.toml version (CARGO_PKG_VERSION).
    let version = match std::env::var("RUNOK_NIGHTLY_VERSION") {
        Ok(v) => v,
        Err(_) => match std::env::var("CARGO_PKG_VERSION") {
            Ok(v) => v,
            Err(e) => {
                eprintln!("cargo::warning=CARGO_PKG_VERSION must be set by Cargo: {e}");
                std::process::exit(1);
            }
        },
    };
    println!("cargo:rustc-env=RUNOK_VERSION={version}");
    println!("cargo:rerun-if-env-changed=RUNOK_NIGHTLY_VERSION");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
}
