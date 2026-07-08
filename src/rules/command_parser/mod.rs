mod redirect;
mod splitter;
mod tokenizer;

pub use splitter::{extract_commands, extract_commands_with_metadata, split_top_level_commands};
pub use tokenizer::{parse_command, tokenize_command};

use std::collections::{HashMap, HashSet};

/// Schema describing which flags take values vs. are boolean-only.
///
/// Derived from rule patterns (Policy-Derived Schema): if a rule writes
/// `deny: "curl -X POST"`, then `-X` is inferred to take a value.
/// Flags not listed in `value_flags` are treated as boolean (no value).
#[derive(Debug, Default)]
pub struct FlagSchema {
    /// Flags known to take a following value (e.g., `-X`, `--request`).
    pub value_flags: HashSet<String>,
}

/// A parsed command with structured flag and argument information.
#[derive(Debug, PartialEq)]
pub struct ParsedCommand {
    /// The command name (first token).
    pub command: String,
    /// Flags and their optional values. Boolean flags have `None`.
    /// For `=`-joined tokens like `-Dkey=value`, the key is the flag name
    /// and the value is the part after `=`.
    ///
    /// Duplicate flags are last-wins (HashMap semantics). This is acceptable
    /// because the matching engine uses `raw_tokens` for pattern matching,
    /// not this map. This map is for structured access in `when` expressions.
    pub flags: HashMap<String, Option<String>>,
    /// Positional arguments (non-flag tokens after the command name).
    pub args: Vec<String>,
    /// The original raw tokens from tokenization.
    pub raw_tokens: Vec<String>,
}

/// Information about a single redirect operator attached to a command.
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectInfo {
    /// Redirect category: "input", "output", or "dup".
    pub redirect_type: String,
    /// The redirect operator (e.g., ">", ">>", "<", "<<<", ">&", "<&", "&>", "&>>", ">|").
    pub operator: String,
    /// The redirect target (e.g., "/dev/null", "&1", "file.txt").
    pub target: String,
    /// File descriptor number, if explicitly specified (e.g., `2` in `2>`).
    pub descriptor: Option<i64>,
}

/// Information about a command's position in a pipeline.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PipeInfo {
    /// Whether stdin comes from a preceding pipe.
    pub stdin: bool,
    /// Whether stdout feeds into a following pipe.
    pub stdout: bool,
}

/// A `KEY=VALUE` environment variable assignment that prefixes a
/// command (e.g. `FOO=bar BAZ=qux helmfile template`).
#[derive(Debug, Clone, PartialEq)]
pub struct EnvAssignment {
    /// Variable name.
    pub name: String,
    /// Variable value with shell quotes resolved. `None` when bash
    /// permits the bare form `FOO= cmd` (clear the variable).
    pub value: Option<String>,
}

/// A command extracted from a compound shell expression, with metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedCommand {
    /// The command string (redirects stripped, as before).
    pub command: String,
    /// Inline environment variable assignments that prefixed the
    /// command (`FOO=bar cmd ...`). Empty when the command had no
    /// such prefix or when the AST shape made them unattributable
    /// (e.g. process substitutions emitted as standalone commands).
    pub env: Vec<EnvAssignment>,
    /// The command + argument tokens with shell quoting resolved
    /// (env prefix, redirects, and HEREDOC bodies excluded). Empty
    /// when the AST surfaced a non-`command` node — currently only
    /// the leaf-text fallback in `collect_commands` — so callers
    /// must treat the empty case as "argv unavailable" rather than
    /// "argv had no tokens".
    pub argv: Vec<String>,
    /// Redirect operators that were attached to this command.
    pub redirects: Vec<RedirectInfo>,
    /// Pipeline position information.
    pub pipe: PipeInfo,
    /// The kind of shell loop that immediately encloses this command:
    /// `"while"`, `"until"`, `"for"`, or `""` when outside any loop.
    /// Nested loops surface the nearest enclosing kind. Subshells do
    /// not reset this — a command in `(while x; do sleep 1; done)`
    /// still sees `"while"`.
    pub loop_kind: String,
}

/// Join tokens into a shell-safe string by quoting tokens that contain
/// spaces or shell metacharacters. Tokens without special characters are
/// emitted verbatim.
///
/// Returns an error if any token contains a NUL byte (which cannot be
/// represented in shell syntax).
pub fn shell_quote_join(tokens: &[String]) -> Result<String, shlex::QuoteError> {
    shlex::try_join(tokens.iter().map(|s| s.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ========================================
    // shell_quote_join
    // ========================================

    #[rstest]
    #[case::simple(&["echo", "hello"], "echo hello")]
    #[case::space_in_token(&["echo", "hello world"], "echo 'hello world'")]
    #[case::empty_token(&["echo", ""], "echo ''")]
    #[case::single_quote_in_token(&["echo", "it's"], "echo \"it's\"")]
    #[case::flags_and_paths(&["rm", "-rf", "/tmp/dir"], "rm -rf /tmp/dir")]
    #[case::single_token(&["ls"], "ls")]
    fn shell_quote_join_cases(#[case] tokens: &[&str], #[case] expected: &str) {
        let owned: Vec<String> = tokens.iter().map(|s| s.to_string()).collect();
        assert_eq!(shell_quote_join(&owned).unwrap(), expected);
    }
}
