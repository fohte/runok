use std::collections::HashMap;

/// Tracks `name() { body }` function definitions seen so far while
/// walking a single command string, keyed by function name, so a later
/// call to that name can be resolved to its body text.
///
/// Scoped to one [`super::extract_commands_with_metadata`] call, mirroring
/// [`super::var_env::VarEnv`]: a subshell / command substitution clones
/// the table for its own scope and discards the clone afterward, so a
/// function defined inside never leaks back to the parent shell.
#[derive(Debug, Default, Clone, PartialEq)]
pub(in crate::rules::command_parser) struct FunctionTable {
    bodies: HashMap<String, Vec<String>>,
}

impl FunctionTable {
    pub(in crate::rules::command_parser) fn new() -> Self {
        Self::default()
    }

    /// Record a `name() { body }` definition. Appends to any bodies
    /// already recorded under `name` -- multiple (re)definitions of the
    /// same name (e.g. one per branch of an `if`) accumulate, and every
    /// candidate is evaluated worst-case at call time.
    pub(in crate::rules::command_parser) fn define(&mut self, name: String, body: String) {
        self.bodies.entry(name).or_default().push(body);
    }

    /// Look up the body texts recorded for `name` so far, if any.
    pub(in crate::rules::command_parser) fn lookup(&self, name: &str) -> Option<&[String]> {
        self.bodies.get(name).map(Vec::as_slice)
    }
}
