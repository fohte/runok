//! Tree-formatted `--verbose` rendering for `runok check` / `exec` / `hook`.
//!
//! All output here is written to stderr by the caller; colors are applied
//! via `owo-colors` and automatically fall back to plain text on non-TTY
//! streams (piped output, tests).

use owo_colors::{OwoColorize, Stream::Stderr};

use crate::config::ActionKind;
use crate::rules::rule_engine::{Action, RuleMatchInfo, SubCommandDetail};

const FOOTER_RULE: &str = "────────────────────────────────────────────";

fn action_kind_of(action: &Action) -> ActionKind {
    match action {
        Action::Allow => ActionKind::Allow,
        Action::Ask(_) => ActionKind::Ask,
        Action::Deny(_) => ActionKind::Deny,
    }
}

fn action_label(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::Allow => "allow",
        ActionKind::Ask => "ask",
        ActionKind::Deny => "deny",
    }
}

fn colorize(word: &str, kind: ActionKind) -> String {
    match kind {
        ActionKind::Allow => word.if_supports_color(Stderr, |t| t.green()).to_string(),
        ActionKind::Ask => word.if_supports_color(Stderr, |t| t.yellow()).to_string(),
        ActionKind::Deny => word.if_supports_color(Stderr, |t| t.red()).to_string(),
    }
}

fn colorize_bold(word: &str, kind: ActionKind) -> String {
    bold(&colorize(word, kind))
}

fn bold(s: &str) -> String {
    s.if_supports_color(Stderr, |t| t.bold()).to_string()
}

/// Escape control characters (including the ESC that starts an ANSI escape
/// sequence) before embedding externally-controlled text -- command strings
/// and matched tokens, which may originate from an agent's proposed tool
/// input -- into the tree. Without this, a command containing e.g. `\x1b[2K\r`
/// could repaint or hide the verbose output it is displayed in.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    out
}

fn format_tokens_suffix(tokens: &[String]) -> String {
    if tokens.is_empty() {
        String::new()
    } else {
        let sanitized: Vec<String> = tokens.iter().map(|t| sanitize(t)).collect();
        format!("  (tokens: {})", sanitized.join(", "))
    }
}

/// Render the matched-rule branches followed by the trailing `result:` line
/// for one command's evaluation. `indent` is the leading whitespace before
/// the `├─`/`└─` glyphs.
fn render_branches(matched_rules: &[RuleMatchInfo], action: &Action, indent: &str) -> Vec<String> {
    let mut lines = Vec::with_capacity(matched_rules.len() + 1);
    for info in matched_rules {
        let label = colorize(action_label(info.action_kind), info.action_kind);
        let tokens = format_tokens_suffix(&info.matched_tokens);
        lines.push(format!("{indent}├─ {label}  '{}'{tokens}", info.pattern));
    }

    let result_kind = action_kind_of(action);
    let result_label = colorize(action_label(result_kind), result_kind);
    let no_match_suffix = if matched_rules.is_empty() {
        "  (no rules matched)"
    } else {
        ""
    };
    lines.push(format!(
        "{indent}└─ result: {result_label}{no_match_suffix}"
    ));
    lines
}

/// Render the bold `Result: <LABEL>` footer line, optionally noting which
/// sub-command's action caused a non-allow overall result.
fn render_result_line(kind: ActionKind, blocked_by: Option<&str>) -> String {
    let label = action_label(kind).to_uppercase();
    let mut line = format!("{}{}", bold("Result: "), colorize_bold(&label, kind));
    if let Some(desc) = blocked_by {
        line.push_str(&format!("  (blocked by {desc})"));
    }
    line
}

/// Find the first sub-command whose resolved action shares the overall
/// action's `ActionKind`. Compound evaluation folds sub-results left to
/// right and only replaces the running action when a *stricter* one is
/// found (see `rule_engine::compound::merge_actions`), so the first
/// sub-command at the winning priority is the one that decided the result.
fn find_blocking_subcommand(
    sub_commands: &[SubCommandDetail],
    overall_kind: ActionKind,
) -> Option<String> {
    sub_commands.iter().enumerate().find_map(|(i, detail)| {
        (action_kind_of(&detail.action) == overall_kind)
            .then(|| format!("[{}] {}", i + 1, sanitize(&detail.command)))
    })
}

/// Render just the header line, for when evaluation fails before an action
/// can be determined (e.g. a `when` clause CEL compile error) -- `--verbose`
/// should still show which command was being evaluated instead of only the
/// bare error.
pub(super) fn render_error_header(command: &str) -> String {
    format!(
        "{}\n",
        bold(&format!("▶ Evaluating: {}", sanitize(command)))
    )
}

/// Render verbose output for a single (non-compound) command evaluation.
///
/// `extracted` is `Some` when a compound shell construct (e.g. a for-loop)
/// was simplified down to a single sub-command that differs from `command`.
pub(super) fn render_single(
    command: &str,
    extracted: Option<&str>,
    matched_rules: &[RuleMatchInfo],
    action: &Action,
    sandbox_preset: Option<&str>,
) -> String {
    let mut lines = vec![bold(&format!("▶ Evaluating: {}", sanitize(command)))];
    if let Some(extracted_cmd) = extracted {
        lines.push(format!("  extracted: {}", sanitize(extracted_cmd)));
    }
    lines.extend(render_branches(matched_rules, action, "  "));

    lines.push(String::new());
    lines.push(FOOTER_RULE.to_owned());
    lines.push(render_result_line(action_kind_of(action), None));
    if let Some(preset) = sandbox_preset {
        lines.push(format!("Sandbox: {preset}"));
    }

    format!("{}\n", lines.join("\n"))
}

/// Render verbose output for a compound command evaluation (multiple
/// sub-commands joined by pipes, `&&`, `||`, or `;`).
pub(super) fn render_compound(
    command: &str,
    sub_commands: &[SubCommandDetail],
    overall_action: &Action,
) -> String {
    let mut lines = vec![bold(&format!("▶ Evaluating: {}", sanitize(command)))];
    lines.push(format!(
        "  Compound command ({} sub-commands)",
        sub_commands.len()
    ));

    for (i, detail) in sub_commands.iter().enumerate() {
        lines.push(String::new());
        lines.push(format!("  [{}] {}", i + 1, sanitize(&detail.command)));
        lines.extend(render_branches(
            &detail.matched_rules,
            &detail.action,
            "      ",
        ));
    }

    let overall_kind = action_kind_of(overall_action);
    let blocked_by = (overall_kind != ActionKind::Allow)
        .then(|| find_blocking_subcommand(sub_commands, overall_kind))
        .flatten();

    lines.push(String::new());
    lines.push(format!("  {FOOTER_RULE}"));
    lines.push(format!(
        "  {}",
        render_result_line(overall_kind, blocked_by.as_deref())
    ));

    format!("{}\n", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::*;
    use crate::rules::rule_engine::DenyResponse;

    fn rule(action_kind: ActionKind, pattern: &str, tokens: &[&str]) -> RuleMatchInfo {
        RuleMatchInfo {
            action_kind,
            pattern: pattern.to_owned(),
            matched_tokens: tokens.iter().map(|t| t.to_string()).collect(),
        }
    }

    fn sub(command: &str, action: Action, matched_rules: Vec<RuleMatchInfo>) -> SubCommandDetail {
        SubCommandDetail {
            command: command.to_owned(),
            action,
            matched_rules,
        }
    }

    #[rstest]
    #[case::allow_one_rule_match(
        "git status",
        None,
        vec![rule(ActionKind::Allow, "git *", &["status"])],
        Action::Allow,
        None,
        indoc! {"
            ▶ Evaluating: git status
              ├─ allow  'git *'  (tokens: status)
              └─ result: allow

            ────────────────────────────────────────────
            Result: ALLOW
        "}
    )]
    #[case::no_match_asks(
        "rm -rf /",
        None,
        vec![],
        Action::Ask(None),
        None,
        indoc! {"
            ▶ Evaluating: rm -rf /
              └─ result: ask  (no rules matched)

            ────────────────────────────────────────────
            Result: ASK
        "}
    )]
    #[case::multiple_rule_matches(
        "nr test:unit src/core/job-queue.test.ts",
        None,
        vec![
            rule(
                ActionKind::Allow,
                "nr [-C *] *",
                &["test:unit", "src/core/job-queue.test.ts"],
            ),
            rule(
                ActionKind::Allow,
                "nr [-C|--filter *] vitest|test|test:*|typecheck *",
                &["src/core/job-queue.test.ts"],
            ),
        ],
        Action::Allow,
        None,
        indoc! {"
            ▶ Evaluating: nr test:unit src/core/job-queue.test.ts
              ├─ allow  'nr [-C *] *'  (tokens: test:unit, src/core/job-queue.test.ts)
              ├─ allow  'nr [-C|--filter *] vitest|test|test:*|typecheck *'  (tokens: src/core/job-queue.test.ts)
              └─ result: allow

            ────────────────────────────────────────────
            Result: ALLOW
        "}
    )]
    #[case::with_sandbox_preset(
        "python3 script.py",
        None,
        vec![rule(ActionKind::Allow, "python3 *", &[])],
        Action::Allow,
        Some("restricted"),
        indoc! {"
            ▶ Evaluating: python3 script.py
              ├─ allow  'python3 *'
              └─ result: allow

            ────────────────────────────────────────────
            Result: ALLOW
            Sandbox: restricted
        "}
    )]
    #[case::extracted_from_for_loop(
        "for f in *.yaml; do echo $f; done",
        Some("echo $f"),
        vec![rule(ActionKind::Allow, "echo *", &["$f"])],
        Action::Allow,
        None,
        indoc! {"
            ▶ Evaluating: for f in *.yaml; do echo $f; done
              extracted: echo $f
              ├─ allow  'echo *'  (tokens: $f)
              └─ result: allow

            ────────────────────────────────────────────
            Result: ALLOW
        "}
    )]
    fn render_single_cases(
        #[case] command: &str,
        #[case] extracted: Option<&str>,
        #[case] matched: Vec<RuleMatchInfo>,
        #[case] action: Action,
        #[case] sandbox_preset: Option<&str>,
        #[case] expected: &str,
    ) {
        assert_eq!(
            render_single(command, extracted, &matched, &action, sandbox_preset),
            expected
        );
    }

    #[rstest]
    #[case::all_allow(
        "set -a && set +a",
        vec![
            sub(
                "set -a",
                Action::Allow,
                vec![rule(ActionKind::Allow, "set *", &["-a"])],
            ),
            sub(
                "set +a",
                Action::Allow,
                vec![rule(ActionKind::Allow, "set *", &["+a"])],
            ),
        ],
        Action::Allow,
        indoc! {"
            ▶ Evaluating: set -a && set +a
              Compound command (2 sub-commands)

              [1] set -a
                  ├─ allow  'set *'  (tokens: -a)
                  └─ result: allow

              [2] set +a
                  ├─ allow  'set *'  (tokens: +a)
                  └─ result: allow

              ────────────────────────────────────────────
              Result: ALLOW
        "}
    )]
    #[case::ask_blocks_from_a_middle_subcommand(
        "set -a && source .env.runtime && set +a",
        vec![
            sub(
                "set -a",
                Action::Allow,
                vec![rule(ActionKind::Allow, "set *", &["-a"])],
            ),
            sub("source .env.runtime", Action::Ask(None), vec![]),
            sub(
                "set +a",
                Action::Allow,
                vec![rule(ActionKind::Allow, "set *", &["+a"])],
            ),
        ],
        Action::Ask(None),
        indoc! {"
            ▶ Evaluating: set -a && source .env.runtime && set +a
              Compound command (3 sub-commands)

              [1] set -a
                  ├─ allow  'set *'  (tokens: -a)
                  └─ result: allow

              [2] source .env.runtime
                  └─ result: ask  (no rules matched)

              [3] set +a
                  ├─ allow  'set *'  (tokens: +a)
                  └─ result: allow

              ────────────────────────────────────────────
              Result: ASK  (blocked by [2] source .env.runtime)
        "}
    )]
    #[case::deny_blocks_from_a_non_leading_subcommand(
        "git status && rm -rf /",
        vec![
            sub(
                "git status",
                Action::Allow,
                vec![rule(ActionKind::Allow, "git status", &[])],
            ),
            sub(
                "rm -rf /",
                Action::Deny(DenyResponse {
                    message: None,
                    fix_suggestion: None,
                    matched_rule: "rm -rf /".to_owned(),
                }),
                vec![rule(ActionKind::Deny, "rm -rf /", &[])],
            ),
        ],
        Action::Deny(DenyResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: "rm -rf /".to_owned(),
        }),
        indoc! {"
            ▶ Evaluating: git status && rm -rf /
              Compound command (2 sub-commands)

              [1] git status
                  ├─ allow  'git status'
                  └─ result: allow

              [2] rm -rf /
                  ├─ deny  'rm -rf /'
                  └─ result: deny

              ────────────────────────────────────────────
              Result: DENY  (blocked by [2] rm -rf /)
        "}
    )]
    fn render_compound_cases(
        #[case] command: &str,
        #[case] sub_commands: Vec<SubCommandDetail>,
        #[case] overall_action: Action,
        #[case] expected: &str,
    ) {
        assert_eq!(
            render_compound(command, &sub_commands, &overall_action),
            expected
        );
    }

    #[rstest]
    #[case::plain_text_passthrough("git status", "git status")]
    #[case::escapes_ansi_escape_and_carriage_return("git\x1b[2K\rstatus", "git\\u{1b}[2K\\rstatus")]
    fn sanitize_escapes_control_chars(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(sanitize(input), expected);
    }
}
