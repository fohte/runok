use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

/// Outcome of resolving a command name to something runnable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandResolution {
    /// The name resolves to an executable, shell builtin, or keyword.
    Found,
    /// The name does not resolve to anything runnable.
    NotFound,
    /// Resolution could not be determined; callers should fail safe.
    Unknown,
}

/// Seam for PATH-dependent command lookup.
///
/// Injected into `EvalContext` so rule evaluation never queries the host
/// environment directly. `runok test` substitutes `StubCommandResolver` so
/// results stay independent of the invoking machine's `$PATH`.
pub trait CommandResolver: Send + Sync {
    fn resolve(&self, name: &str) -> CommandResolution;
}

/// Shell keywords and builtins that a POSIX `sh` may not recognize via
/// `command -v` even though bash/zsh always treat them as runnable.
const STATIC_FOUND_NAMES: &[&str] = &["[[", "local", "declare", "typeset", "source", "shopt"];

/// Resolves command names by shelling out to `command -v`, memoizing
/// results per process so the same name is never probed twice.
pub struct ProcessCommandResolver {
    cache: Mutex<HashMap<String, CommandResolution>>,
}

impl ProcessCommandResolver {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for ProcessCommandResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandResolver for ProcessCommandResolver {
    fn resolve(&self, name: &str) -> CommandResolution {
        if STATIC_FOUND_NAMES.contains(&name) {
            return CommandResolution::Found;
        }

        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(resolution) = cache.get(name) {
            return *resolution;
        }

        let resolution = resolve_via_shell(name);
        cache.insert(name.to_string(), resolution);
        resolution
    }
}

fn resolve_via_shell(name: &str) -> CommandResolution {
    let Ok(quoted) = shlex::try_quote(name) else {
        return CommandResolution::Unknown;
    };

    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v -- {quoted}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(status) if status.success() => CommandResolution::Found,
        Ok(_) => CommandResolution::NotFound,
        Err(_) => CommandResolution::Unknown,
    }
}

/// Stand-in resolver that treats every name as `Found`.
///
/// Used by `runok test` so rule evaluation results stay independent of the
/// host's `$PATH`.
pub struct StubCommandResolver;

impl CommandResolver for StubCommandResolver {
    fn resolve(&self, _name: &str) -> CommandResolution {
        CommandResolution::Found
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::resolve_via_shell;
    use super::{CommandResolution, CommandResolver, ProcessCommandResolver, StubCommandResolver};

    #[rstest]
    #[case::double_bracket("[[")]
    #[case::local("local")]
    #[case::declare("declare")]
    #[case::typeset("typeset")]
    #[case::source("source")]
    #[case::shopt("shopt")]
    fn static_list_names_resolve_as_found(#[case] name: &str) {
        let resolver = ProcessCommandResolver::new();
        assert_eq!(resolver.resolve(name), CommandResolution::Found);
    }

    #[rstest]
    fn existing_executable_resolves_as_found() {
        let resolver = ProcessCommandResolver::new();
        assert_eq!(resolver.resolve("sh"), CommandResolution::Found);
    }

    #[rstest]
    fn nonexistent_executable_resolves_as_not_found() {
        let resolver = ProcessCommandResolver::new();
        assert_eq!(
            resolver.resolve("runok-test-definitely-not-a-real-command-xyz"),
            CommandResolution::NotFound
        );
    }

    #[rstest]
    fn repeated_lookup_is_memoized_and_consistent() {
        let resolver = ProcessCommandResolver::new();
        assert_eq!(resolver.resolve("sh"), resolver.resolve("sh"));
    }

    #[rstest]
    fn name_with_nul_byte_resolves_as_unknown() {
        assert_eq!(resolve_via_shell("bad\0name"), CommandResolution::Unknown);
    }

    #[rstest]
    #[case::regular_name("definitely-not-a-real-command")]
    #[case::empty_name("")]
    fn stub_resolver_always_resolves_as_found(#[case] name: &str) {
        let resolver = StubCommandResolver;
        assert_eq!(resolver.resolve(name), CommandResolution::Found);
    }
}
