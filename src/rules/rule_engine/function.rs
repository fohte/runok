use crate::config::Config;
use crate::rules::RuleError;
use crate::rules::command_parser::{FunctionCallInfo, RedirectInfo, extract_commands_with_context};

use super::compound::merge_results;
use super::dispatch::{MAX_WRAPPER_DEPTH, evaluate_command_inner};
use super::{EvalContext, EvalResult};

/// Try to resolve a call to a function defined earlier in the same
/// command string, evaluating its body (or bodies, if the name was
/// (re)defined more than once) with `$1`..`$N` / `$@` / `$*` / `$#`
/// bound to the call's own arguments.
///
/// Returns `Ok(None)` when the call cannot be resolved -- a cycle
/// (`call_info.function_name` is already on `call_stack`), the shared
/// [`MAX_WRAPPER_DEPTH`] recursion limit would be exceeded, or every
/// candidate body fails to re-parse -- so the caller falls back to
/// treating the call as an ordinary, unknown command instead of
/// propagating an error.
pub(super) fn try_unwrap_function_call(
    config: &Config,
    context: &EvalContext,
    call_info: &FunctionCallInfo,
    depth: usize,
    redirects: &[RedirectInfo],
    loop_kind: &str,
    call_stack: &[String],
) -> Result<Option<EvalResult>, RuleError> {
    if call_stack.contains(&call_info.function_name) {
        return Ok(None);
    }
    if depth + 1 > MAX_WRAPPER_DEPTH {
        return Ok(None);
    }

    let mut positional_env = call_info.var_env.clone();
    positional_env.bind_positional_params(&call_info.call_args);

    let mut new_stack = call_stack.to_vec();
    new_stack.push(call_info.function_name.clone());

    let mut merged: Option<EvalResult> = None;
    for body in &call_info.bodies {
        // A candidate body that fails to re-parse is skipped, not
        // propagated as an error -- the same "never error, fall back"
        // principle as an unresolved call. If every candidate fails,
        // `merged` stays `None` and the caller falls back too.
        let Ok(sub_commands) = extract_commands_with_context(
            body,
            positional_env.clone(),
            call_info.function_table.clone(),
            redirects,
            loop_kind,
        ) else {
            continue;
        };

        for sub in &sub_commands {
            let sub_result = evaluate_command_inner(
                config,
                &sub.command,
                context,
                depth + 1,
                &sub.redirects,
                &sub.pipe,
                &sub.loop_kind,
                sub.function_call.as_ref(),
                &new_stack,
            )?;
            merged = Some(match merged {
                Some(prev) => merge_results(prev, sub_result),
                None => sub_result,
            });
        }
    }

    Ok(merged)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::config::{ActionKind, Config, Defaults};
    use crate::rules::rule_engine::{Action, evaluate_command};

    use super::super::test_support::{allow_rule, ask_rule, deny_rule, empty_context, make_config};
    use super::*;

    #[rstest]
    fn resolves_allowed_function_body(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git push")]);
        let result = evaluate_command(&config, "f() { git push; }; f", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[rstest]
    fn positional_parameter_flows_into_deny_rule(empty_context: EvalContext) {
        // The motivating case: `$1` on the body's `git push` line must
        // pick up the call's own `--force` argument for the deny rule to
        // see it -- definition-time evaluation alone (`$1` verbatim)
        // cannot catch this.
        let config = make_config(vec![allow_rule("git push"), deny_rule("git push --force*")]);
        let result =
            evaluate_command(&config, "f() { git push $1; }; f --force", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn definition_time_evaluation_still_denies_dangerous_body(empty_context: EvalContext) {
        // The safety-backstop unconditional definition-time evaluation
        // must still catch this even though `f` is never called.
        let config = make_config(vec![deny_rule("rm -rf *")]);
        let result = evaluate_command(&config, "f() { rm -rf /; }", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn call_resolution_also_denies_dangerous_body(empty_context: EvalContext) {
        let config = make_config(vec![deny_rule("rm -rf *")]);
        let result = evaluate_command(&config, "f() { rm -rf /; }; f", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn self_recursion_falls_back_to_defaults_action(empty_context: EvalContext) {
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Ask),
                sandbox: None,
            }),
            rules: Some(vec![allow_rule("git push")]),
            ..Default::default()
        };
        let result = evaluate_command(&config, "f() { f; }; f", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Ask(_)));
    }

    #[rstest]
    fn mutual_recursion_falls_back_to_defaults_action(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git push")]);
        let result =
            evaluate_command(&config, "f() { g; }; g() { f; }; f", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Ask(_)));
    }

    #[rstest]
    fn call_before_definition_stays_unknown(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git push")]);
        let result = evaluate_command(&config, "f; f() { git push; }", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    #[rstest]
    fn nested_function_calls_resolve(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git push")]);
        let result =
            evaluate_command(&config, "g() { git push; }; f() { g; }; f", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[rstest]
    fn function_shadows_real_command(empty_context: EvalContext) {
        // Real bash runs the shadowing function, not the actual `git`
        // binary -- the resolved body's action wins over whatever a
        // `git *` rule would otherwise say.
        let config = make_config(vec![deny_rule("git *"), allow_rule("echo *")]);
        let result =
            evaluate_command(&config, "git() { echo hi; }; git push", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[rstest]
    fn call_site_redirect_is_inherited_by_body(empty_context: EvalContext) {
        let mut rule = ask_rule("git push");
        rule.when = Some("redirects.exists(r, r.type == 'output')".to_string());
        let config = make_config(vec![rule]);
        let result =
            evaluate_command(&config, "f() { git push; }; f > /tmp/out", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Ask(_)));
    }

    #[rstest]
    fn multiple_redefinitions_merge_worst_case(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("echo *"), deny_rule("rm -rf *")]);
        let result = evaluate_command(
            &config,
            "if true; then f() { echo a; }; else f() { rm -rf /; }; fi; f",
            &empty_context,
        )
        .unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }
}
