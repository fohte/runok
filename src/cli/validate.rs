/// Validate that no unknown flags appear before `--` in the raw CLI arguments
/// for `exec` and `check` subcommands.
///
/// Because `trailing_var_arg = true` + `allow_hyphen_values = true` causes clap
/// to silently absorb unknown flags into the `command` Vec, we must perform this
/// check ourselves using the raw process arguments.
pub fn validate_no_unknown_flags(raw_args: &[String], subcommand: &str) -> Result<(), String> {
    let known_flags = match subcommand {
        "exec" => &["--sandbox", "--dry-run", "--verbose"] as &[&str],
        "check" => &["--input-format", "--output-format", "--verbose"] as &[&str],
        _ => return Ok(()),
    };

    // Flags that take a value argument (the next token is consumed as a value)
    let flags_with_value = match subcommand {
        "exec" => &["--sandbox"] as &[&str],
        "check" => &["--input-format", "--output-format"] as &[&str],
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

    // Walk the region, skipping values of known flags
    let mut i = 0;
    // Track whether we've seen a non-flag token (the command name).
    // Once we see a command name, subsequent tokens are command arguments, not runok flags.
    let mut seen_command_name = false;

    while i < region.len() {
        let token = &region[i];

        if seen_command_name {
            // After the command name, everything is a command argument
            break;
        }

        if token.starts_with('-') {
            // Check if it's a known flag (exact match or `--flag=value` form)
            let is_known = known_flags
                .iter()
                .any(|f| token == *f || token.starts_with(&format!("{f}=")));

            if !is_known {
                return Err(format!(
                    "unknown flag '{token}' for 'runok {subcommand}'. \
                     Use '--' to separate runok flags from the command: \
                     runok {subcommand} [OPTIONS] -- <COMMAND>"
                ));
            }

            // If this known flag takes a value and isn't `--flag=value` form, skip the next token
            let takes_value = flags_with_value.iter().any(|f| token == *f);
            if takes_value && !token.contains('=') {
                i += 1; // skip value
            }
        } else {
            // Non-flag token: this is the start of the command
            seen_command_name = true;
        }

        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    // === Valid cases (should pass) ===

    #[rstest]
    #[case::exec_with_double_dash("runok exec -- ls -la")]
    #[case::exec_known_flag_before_double_dash("runok exec --verbose -- ls -la")]
    #[case::exec_sandbox_with_value("runok exec --sandbox strict -- ls")]
    #[case::exec_sandbox_eq_form("runok exec --sandbox=strict -- ls")]
    #[case::exec_dry_run("runok exec --dry-run -- git status")]
    #[case::exec_all_flags("runok exec --sandbox strict --dry-run --verbose -- ls")]
    #[case::exec_command_without_double_dash("runok exec ls -la")]
    #[case::exec_command_with_flag_args("runok exec git log --oneline")]
    #[case::check_with_double_dash("runok check -- ls -la")]
    #[case::check_known_flags("runok check --input-format claude-code-hook --verbose -- ls")]
    #[case::check_output_format("runok check --output-format json -- ls")]
    #[case::check_command_without_double_dash("runok check ls -la")]
    #[case::check_no_args("runok check")]
    #[case::unknown_after_double_dash("runok exec -- --unknown-flag ls")]
    #[case::check_unknown_after_double_dash("runok check -- --config foo break")]
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
    #[case::exec_unknown_before_known(
        "runok exec --config foo --verbose -- ls",
        "exec",
        "--config"
    )]
    #[case::check_unknown_flag("runok check --config foo -- break", "check", "--config")]
    #[case::check_unknown_short_flag("runok check -x -- ls", "check", "-x")]
    #[case::exec_unknown_no_double_dash("runok exec --unknown ls", "exec", "--unknown")]
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
}
