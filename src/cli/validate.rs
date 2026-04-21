/// Flag definition: name and whether it takes a value argument.
struct FlagDef {
    name: &'static str,
    short: Option<&'static str>,
    takes_value: bool,
}

/// Result of matching a single CLI token against a set of known flags.
enum FlagMatch {
    /// Token consumes its value from the same token (e.g. `--config=foo`
    /// or fused short `-cfoo`). Do not skip the next token.
    AttachedValue,
    /// Token is the flag name alone and takes a separate value argument
    /// (e.g. `--config foo` or `-c foo`). The caller should skip one token.
    SeparateValue,
    /// Token is a boolean flag with no value (e.g. `--verbose`).
    Boolean,
    /// The token is not a known flag from this set.
    Unknown,
}

/// Match a `-`/`--`-prefixed token against `flags`, supporting:
/// - exact long form: `--config`
/// - equals long form: `--config=value`
/// - exact short form: `-c`
/// - fused short form: `-cvalue`
fn match_flag(token: &str, flags: &[FlagDef]) -> FlagMatch {
    for f in flags {
        if token == f.name {
            return if f.takes_value {
                FlagMatch::SeparateValue
            } else {
                FlagMatch::Boolean
            };
        }
        if f.takes_value && token.starts_with(&format!("{}=", f.name)) {
            return FlagMatch::AttachedValue;
        }
        if let Some(short) = f.short {
            if token == short {
                return if f.takes_value {
                    FlagMatch::SeparateValue
                } else {
                    FlagMatch::Boolean
                };
            }
            // Fused short form `-cVALUE` is only meaningful for value-taking
            // flags: require `len > short.len()` so we don't mis-match `-c`
            // itself.
            if f.takes_value && token.starts_with(short) && token.len() > short.len() {
                return FlagMatch::AttachedValue;
            }
        }
    }
    FlagMatch::Unknown
}

/// Global flags defined on the `Cli` struct. These can appear before or after
/// the subcommand name, so subcommand detection must skip over them.
const GLOBAL_FLAGS: &[FlagDef] = &[FlagDef {
    name: "--config",
    short: Some("-c"),
    takes_value: true,
}];

/// Find the subcommand token (name and position) in the raw CLI arguments,
/// skipping over any leading global flags. Returns `None` if no subcommand
/// is present.
///
/// The position is the index into `raw_args` of the subcommand token itself,
/// which lets callers distinguish it from a global flag value that happens
/// to be spelled the same (e.g. `runok -c check check ...`).
///
/// Examples:
/// - `["runok", "exec", "--", "ls"]` -> `Some(("exec", 1))`
/// - `["runok", "-c", "config.yml", "exec", "--", "ls"]` -> `Some(("exec", 3))`
/// - `["runok", "--config=config.yml", "check"]` -> `Some(("check", 2))`
pub fn find_subcommand(raw_args: &[String]) -> Option<(&str, usize)> {
    let mut i = 1;
    while i < raw_args.len() {
        let token = &raw_args[i];
        if !token.starts_with('-') {
            return Some((token.as_str(), i));
        }

        match match_flag(token, GLOBAL_FLAGS) {
            FlagMatch::SeparateValue => i += 2,
            FlagMatch::AttachedValue | FlagMatch::Boolean => i += 1,
            FlagMatch::Unknown => {
                // Unknown token starting with `-` before any subcommand —
                // let clap report the error later.
                return None;
            }
        }
    }
    None
}

/// Known flags for each subcommand.
const EXEC_FLAGS: &[FlagDef] = &[
    FlagDef {
        name: "--config",
        short: Some("-c"),
        takes_value: true,
    },
    FlagDef {
        name: "--sandbox",
        short: None,
        takes_value: true,
    },
    FlagDef {
        name: "--verbose",
        short: None,
        takes_value: false,
    },
];

const CHECK_FLAGS: &[FlagDef] = &[
    FlagDef {
        name: "--config",
        short: Some("-c"),
        takes_value: true,
    },
    FlagDef {
        name: "--input-format",
        short: None,
        takes_value: true,
    },
    FlagDef {
        name: "--output-format",
        short: None,
        takes_value: true,
    },
    FlagDef {
        name: "--verbose",
        short: None,
        takes_value: false,
    },
];

/// Validate that no unknown flags appear before `--` in the raw CLI arguments
/// for `exec` and `check` subcommands.
///
/// Because `trailing_var_arg = true` + `allow_hyphen_values = true` causes clap
/// to silently absorb unknown flags into the `command` Vec, we must perform this
/// check ourselves using the raw process arguments.
pub fn validate_no_unknown_flags(
    raw_args: &[String],
    subcommand: &str,
    subcommand_pos: usize,
) -> Result<(), String> {
    let flags = match subcommand {
        "exec" => EXEC_FLAGS,
        "check" => CHECK_FLAGS,
        _ => return Ok(()),
    };

    // Get args after the subcommand. `subcommand_pos` is supplied by the
    // caller (via `find_subcommand`) rather than recomputed here, because a
    // naive `position(|a| a == subcommand)` would pick up preceding
    // global-flag values that happen to match the subcommand name
    // (e.g. `runok -c check check --typo`).
    let after_sub = &raw_args[subcommand_pos + 1..];

    // Find `--` position (relative to after_sub)
    let double_dash_pos = after_sub.iter().position(|a| a == "--");

    // The region to check is everything before `--` (or everything if no `--`)
    let region = match double_dash_pos {
        Some(pos) => &after_sub[..pos],
        None => after_sub,
    };

    // Walk the region using an iterator, skipping values of known flags.
    // Once we see a non-flag token (the command name), stop checking.
    let mut tokens = region.iter();

    while let Some(token) = tokens.next() {
        if !token.starts_with('-') {
            // Non-flag token: this is the start of the command
            break;
        }

        // clap automatically adds these flags to every subcommand; let clap handle them
        if matches!(token.as_str(), "--help" | "-h" | "--version" | "-V") {
            continue;
        }

        match match_flag(token, flags) {
            FlagMatch::SeparateValue => {
                tokens.next(); // skip the separate value argument
            }
            FlagMatch::AttachedValue | FlagMatch::Boolean => {}
            FlagMatch::Unknown => {
                return Err(format!(
                    "unknown flag '{token}' for 'runok {subcommand}'. \
                     Use '--' to separate runok flags from the command: \
                     runok {subcommand} [OPTIONS] -- <COMMAND>"
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn args(s: &str) -> Vec<String> {
        shlex::split(s).expect("invalid shell syntax in test input")
    }

    // === Valid cases (should pass) ===

    #[rstest]
    #[case::exec_with_double_dash("runok exec -- ls -la")]
    #[case::exec_known_flag_before_double_dash("runok exec --verbose -- ls -la")]
    #[case::exec_sandbox_with_value("runok exec --sandbox strict -- ls")]
    #[case::exec_sandbox_eq_form("runok exec --sandbox=strict -- ls")]
    #[case::exec_all_flags("runok exec --sandbox strict --verbose -- ls")]
    #[case::exec_command_without_double_dash("runok exec ls -la")]
    #[case::exec_command_with_flag_args("runok exec git log --oneline")]
    #[case::check_with_double_dash("runok check -- ls -la")]
    #[case::check_known_flags("runok check --input-format claude-code-hook --verbose -- ls")]
    #[case::check_output_format("runok check --output-format json -- ls")]
    #[case::check_command_without_double_dash("runok check ls -la")]
    #[case::check_no_args("runok check")]
    #[case::unknown_after_double_dash("runok exec -- --unknown-flag ls")]
    #[case::check_unknown_after_double_dash("runok check -- --config foo break")]
    #[case::exec_help("runok exec --help")]
    #[case::exec_help_short("runok exec -h")]
    #[case::check_help("runok check --help")]
    #[case::check_help_short("runok check -h")]
    #[case::exec_config_long("runok exec --config path/to/config.yml -- ls")]
    #[case::exec_config_short("runok exec -c path/to/config.yml -- ls")]
    #[case::exec_config_eq("runok exec --config=path/to/config.yml -- ls")]
    #[case::exec_config_fused_short("runok exec -cpath/to/config.yml -- ls")]
    #[case::check_config_long("runok check --config path/to/config.yml -- ls")]
    #[case::check_config_short("runok check -c path/to/config.yml -- ls")]
    #[case::check_config_fused_short("runok check -cpath/to/config.yml -- ls")]
    #[case::exec_version("runok exec --version")]
    #[case::exec_version_short("runok exec -V")]
    fn valid_args(#[case] input: &str) {
        let raw = args(input);
        let (subcommand, sub_pos) = find_subcommand(&raw).unwrap_or_else(|| {
            panic!("expected to find a subcommand in: {input}");
        });
        assert!(
            validate_no_unknown_flags(&raw, subcommand, sub_pos).is_ok(),
            "expected Ok for: {input}"
        );
    }

    // === Invalid cases (should fail) ===

    #[rstest]
    #[case::exec_unknown_flag("runok exec --unknown -- ls", "exec", "--unknown")]
    #[case::check_unknown_short_flag("runok check -x -- ls", "check", "-x")]
    #[case::exec_unknown_no_double_dash("runok exec --unknown ls", "exec", "--unknown")]
    #[case::exec_unknown_with_leading_global_config(
        "runok -c config.yml exec --typo -- ls",
        "exec",
        "--typo"
    )]
    #[case::check_unknown_with_leading_global_config_short(
        "runok -c config.yml check --typo -- ls",
        "check",
        "--typo"
    )]
    #[case::check_unknown_with_leading_global_config_long(
        "runok --config config.yml check --typo -- ls",
        "check",
        "--typo"
    )]
    #[case::check_unknown_with_leading_global_config_eq(
        "runok --config=config.yml check --typo -- ls",
        "check",
        "--typo"
    )]
    // Regression: if the value of `-c` happens to equal the subcommand name
    // (e.g. a config file literally called "check"), naive string-position
    // lookup picks the flag value instead of the real subcommand token, and
    // the unknown-flag validation is silently skipped.
    #[case::check_config_value_equals_subcommand_name(
        "runok -c check check --typo -- ls",
        "check",
        "--typo"
    )]
    #[case::exec_config_value_equals_subcommand_name(
        "runok -c exec exec --typo -- ls",
        "exec",
        "--typo"
    )]
    // Fused short-form `-cVALUE` with no space is valid clap syntax; the
    // pre-parse validator must skip over it as a single token instead of
    // treating it as an unknown flag, and must still detect `--typo`.
    #[case::check_unknown_with_fused_short_config(
        "runok -cconfig.yml check --typo -- ls",
        "check",
        "--typo"
    )]
    #[case::exec_unknown_with_fused_short_config(
        "runok -cconfig.yml exec --typo -- ls",
        "exec",
        "--typo"
    )]
    fn invalid_args(#[case] input: &str, #[case] subcommand: &str, #[case] expected_flag: &str) {
        let raw = args(input);
        let (detected_sub, sub_pos) = find_subcommand(&raw).unwrap_or_else(|| {
            panic!("expected to find a subcommand in: {input}");
        });
        assert_eq!(
            detected_sub, subcommand,
            "subcommand detection mismatch for: {input}"
        );
        let result = validate_no_unknown_flags(&raw, subcommand, sub_pos);
        let err = result.expect_err(&format!("expected Err for: {input}"));
        assert_eq!(
            err,
            format!(
                "unknown flag '{expected_flag}' for 'runok {subcommand}'. \
                 Use '--' to separate runok flags from the command: \
                 runok {subcommand} [OPTIONS] -- <COMMAND>"
            )
        );
    }

    // === find_subcommand tests ===

    #[rstest]
    #[case::simple_exec("runok exec -- ls", Some(("exec", 1)))]
    #[case::simple_check("runok check", Some(("check", 1)))]
    #[case::global_config_short_before("runok -c config.yml exec -- ls", Some(("exec", 3)))]
    #[case::global_config_long_before(
        "runok --config config.yml check -- ls",
        Some(("check", 3))
    )]
    #[case::global_config_eq_before("runok --config=config.yml exec", Some(("exec", 2)))]
    #[case::global_config_fused_short_before("runok -cconfig.yml exec", Some(("exec", 2)))]
    // Regression: the value of `-c` happens to match a subcommand name.
    // The returned position must point at the real subcommand token (index 3),
    // not at the flag value (index 2).
    #[case::config_value_equals_subcommand("runok -c check check", Some(("check", 3)))]
    #[case::no_subcommand("runok", None)]
    #[case::only_global_flag("runok -c config.yml", None)]
    fn find_subcommand_cases(#[case] input: &str, #[case] expected: Option<(&str, usize)>) {
        let raw = args(input);
        assert_eq!(find_subcommand(&raw), expected);
    }
}
