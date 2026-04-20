/// Flag definition: name and whether it takes a value argument.
struct FlagDef {
    name: &'static str,
    short: Option<&'static str>,
    takes_value: bool,
}

/// Global flags defined on the `Cli` struct. These can appear before or after
/// the subcommand name, so subcommand detection must skip over them.
const GLOBAL_FLAGS: &[FlagDef] = &[FlagDef {
    name: "--config",
    short: Some("-c"),
    takes_value: true,
}];

/// Find the subcommand name in the raw CLI arguments, skipping over any
/// leading global flags. Returns `None` if no subcommand is present.
///
/// Examples:
/// - `["runok", "exec", "--", "ls"]` -> `Some("exec")`
/// - `["runok", "-c", "config.yml", "exec", "--", "ls"]` -> `Some("exec")`
/// - `["runok", "--config=config.yml", "check"]` -> `Some("check")`
pub fn find_subcommand(raw_args: &[String]) -> Option<&str> {
    let mut tokens = raw_args.iter().skip(1);
    while let Some(token) = tokens.next() {
        if !token.starts_with('-') {
            return Some(token.as_str());
        }

        let matched = GLOBAL_FLAGS.iter().find(|f| {
            token == f.name
                || token.starts_with(&format!("{}=", f.name))
                || f.short.is_some_and(|s| token == s)
        });

        match matched {
            Some(flag) if flag.takes_value && !token.contains('=') => {
                tokens.next();
            }
            Some(_) => {}
            None => {
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
pub fn validate_no_unknown_flags(raw_args: &[String], subcommand: &str) -> Result<(), String> {
    let flags = match subcommand {
        "exec" => EXEC_FLAGS,
        "check" => CHECK_FLAGS,
        _ => return Ok(()),
    };

    // Find the subcommand position in raw args
    let sub_pos = match raw_args.iter().position(|a| a == subcommand) {
        Some(pos) => pos,
        None => return Ok(()),
    };

    // Get args after the subcommand
    let after_sub = &raw_args[sub_pos + 1..];

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

        // Check if it's a known flag (exact match, short form, or `--flag=value` form)
        let matched_flag = flags.iter().find(|f| {
            token == f.name
                || token.starts_with(&format!("{}=", f.name))
                || f.short.is_some_and(|s| token == s)
        });

        match matched_flag {
            Some(flag) => {
                // If this known flag takes a value and isn't `--flag=value` form, skip the next token
                if flag.takes_value && !token.contains('=') {
                    tokens.next(); // skip value
                }
            }
            None => {
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
    #[case::check_config_long("runok check --config path/to/config.yml -- ls")]
    #[case::check_config_short("runok check -c path/to/config.yml -- ls")]
    #[case::exec_version("runok exec --version")]
    #[case::exec_version_short("runok exec -V")]
    fn valid_args(#[case] input: &str) {
        let raw = args(input);
        let subcommand = if input.contains("exec") {
            "exec"
        } else {
            "check"
        };
        assert!(
            validate_no_unknown_flags(&raw, subcommand).is_ok(),
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
    fn invalid_args(#[case] input: &str, #[case] subcommand: &str, #[case] expected_flag: &str) {
        let raw = args(input);
        let result = validate_no_unknown_flags(&raw, subcommand);
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
    #[case::simple_exec("runok exec -- ls", Some("exec"))]
    #[case::simple_check("runok check", Some("check"))]
    #[case::global_config_short_before("runok -c config.yml exec -- ls", Some("exec"))]
    #[case::global_config_long_before("runok --config config.yml check -- ls", Some("check"))]
    #[case::global_config_eq_before("runok --config=config.yml exec", Some("exec"))]
    #[case::no_subcommand("runok", None)]
    #[case::only_global_flag("runok -c config.yml", None)]
    fn find_subcommand_cases(#[case] input: &str, #[case] expected: Option<&str>) {
        let raw = args(input);
        assert_eq!(find_subcommand(&raw), expected);
    }
}
