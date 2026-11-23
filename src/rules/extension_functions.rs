use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cel_interpreter::extractors::Arguments;
use cel_interpreter::functions::FunctionContext;
use cel_interpreter::objects::{Key, Map as CelMap};
use cel_interpreter::{Context, ExecutionError, Value as CelValue};
use serde_json::{Map as JsonMap, Number, Value as JsonValue};

use crate::config::{ExtensionDefinition, ExtensionTimeout};
use crate::exec::extension_runner::{ExtensionCall, ExtensionRunner};

const EXTENSION_SENTINEL_KEY: &str = "__runok_extension_namespace__";
const DEFAULT_EXTENSION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct ExtensionExecutionContext {
    pub definitions: Arc<HashMap<String, ExtensionDefinition>>,
    pub runner: Arc<dyn ExtensionRunner>,
    pub parent_env: Arc<HashMap<String, String>>,
    pub cwd: PathBuf,
    pub calls_allowed: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtensionCallFailure {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ExtensionCallSnapshot {
    pub names: Vec<String>,
    pub failure: Option<ExtensionCallFailure>,
}

#[derive(Default)]
pub(crate) struct ExtensionCallState {
    names: Vec<String>,
    failure: Option<ExtensionCallFailure>,
    cache: HashMap<(String, String), Result<JsonValue, String>>,
}

impl ExtensionCallState {
    fn record_call(&mut self, name: &str) {
        if !self.names.iter().any(|existing| existing == name) {
            self.names.push(name.to_string());
        }
    }

    fn record_failure(&mut self, name: &str, reason: &str) {
        self.failure = Some(ExtensionCallFailure {
            name: name.to_string(),
            reason: sanitize_for_terminal(reason),
        });
    }

    fn snapshot(&self) -> ExtensionCallSnapshot {
        ExtensionCallSnapshot {
            names: self.names.clone(),
            failure: self.failure.clone(),
        }
    }
}

/// Rewrite `ext.<name>(...)` into an internal method name so CEL built-ins and
/// comprehension macros cannot intercept an extension call with the same name.
pub(crate) fn rewrite_extension_calls(expression: &str) -> (String, Vec<String>) {
    let bytes = expression.as_bytes();
    let mut replacements = Vec::new();
    let mut names = HashSet::new();
    let mut index = 0;
    let mut previous_non_whitespace = None;

    while index < bytes.len() {
        if let Some(string_end) = cel_string_end(bytes, index) {
            index = string_end;
            previous_non_whitespace = Some(b' ');
            continue;
        }

        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_continue(bytes[index]) {
                index += 1;
            }
            if &expression[start..index] == "ext" && previous_non_whitespace != Some(b'.') {
                let name_start = skip_whitespace(bytes, index);
                if bytes.get(name_start) == Some(&b'.') {
                    let identifier_start = skip_whitespace(bytes, name_start + 1);
                    if identifier_start < bytes.len()
                        && is_identifier_start(bytes[identifier_start])
                    {
                        let mut identifier_end = identifier_start + 1;
                        while identifier_end < bytes.len()
                            && is_identifier_continue(bytes[identifier_end])
                        {
                            identifier_end += 1;
                        }
                        let call_start = skip_whitespace(bytes, identifier_end);
                        if bytes.get(call_start) == Some(&b'(') {
                            let name = expression[identifier_start..identifier_end].to_string();
                            replacements.push((
                                identifier_start,
                                identifier_end,
                                format!("__runok_extension_call_{name}"),
                            ));
                            names.insert(name);
                        }
                    }
                }
            }
            previous_non_whitespace = bytes.get(index.saturating_sub(1)).copied();
            continue;
        }

        if !bytes[index].is_ascii_whitespace() {
            previous_non_whitespace = Some(bytes[index]);
        }
        index += 1;
    }

    let mut rewritten = String::with_capacity(expression.len() + replacements.len() * 24);
    let mut copied_until = 0;
    for (start, end, replacement) in replacements {
        rewritten.push_str(&expression[copied_until..start]);
        rewritten.push_str(&replacement);
        copied_until = end;
    }
    rewritten.push_str(&expression[copied_until..]);
    let mut names: Vec<String> = names.into_iter().collect();
    names.sort();
    (rewritten, names)
}

fn cel_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let prefix = bytes.get(start).copied()?;
    let (quote_start, raw) = if matches!(prefix, b'r' | b'R')
        && bytes
            .get(start + 1)
            .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
    {
        (start + 1, true)
    } else if matches!(prefix, b'b' | b'B')
        && bytes
            .get(start + 1)
            .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
    {
        (start + 1, false)
    } else if matches!(prefix, b'\'' | b'"') {
        (start, false)
    } else {
        return None;
    };

    let quote = bytes[quote_start];
    let delimiter_len = if bytes.get(quote_start..quote_start + 3) == Some(&[quote; 3]) {
        3
    } else {
        1
    };
    let mut index = quote_start + delimiter_len;
    while index < bytes.len() {
        if !raw && bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes.get(index..index + delimiter_len)
            == Some(&bytes[quote_start..quote_start + delimiter_len])
        {
            return Some(index + delimiter_len);
        } else {
            index += 1;
        }
    }
    Some(bytes.len())
}

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit()
}

fn skip_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

pub(crate) fn register_extension_functions(
    context: &mut Context<'_>,
    extension_names: &[String],
    execution: Option<ExtensionExecutionContext>,
) -> Arc<Mutex<ExtensionCallState>> {
    let mut sentinel_map = HashMap::new();
    sentinel_map.insert(EXTENSION_SENTINEL_KEY.to_string(), CelValue::Bool(true));
    let namespace = CelMap::from(sentinel_map);
    let namespace_identity = Arc::clone(&namespace.map);
    context.add_variable_from_value("ext", CelValue::Map(namespace));

    let state = Arc::new(Mutex::new(ExtensionCallState::default()));
    for name in extension_names {
        let registered_function_name = format!("__runok_extension_call_{name}");
        let error_function_name = registered_function_name.clone();
        let extension_name = name.clone();
        let execution = execution.clone();
        let state = Arc::clone(&state);
        let namespace_identity = Arc::clone(&namespace_identity);
        context.add_function(
            &registered_function_name,
            move |function_context: &FunctionContext,
                  Arguments(args): Arguments|
                  -> Result<CelValue, ExecutionError> {
                let Some(CelValue::Map(target)) = function_context.this.as_ref() else {
                    return Err(ExecutionError::not_supported_as_method(
                        &error_function_name,
                        function_context.this.clone().unwrap_or(CelValue::Null),
                    ));
                };
                if !Arc::ptr_eq(&target.map, &namespace_identity) {
                    return Err(ExecutionError::not_supported_as_method(
                        &error_function_name,
                        CelValue::Map(target.clone()),
                    ));
                }

                let mut call_state = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                call_state.record_call(&extension_name);
                let result = invoke_extension(
                    &extension_name,
                    args.as_slice(),
                    execution.as_ref(),
                    &mut call_state,
                );
                match result {
                    Ok(value) => cel_interpreter::to_value(&value).map_err(|error| {
                        call_state.record_failure(&extension_name, &error.to_string());
                        ExecutionError::function_error(
                            &error_function_name,
                            sanitize_for_terminal(&error.to_string()),
                        )
                    }),
                    Err(reason) => {
                        call_state.record_failure(&extension_name, &reason);
                        if execution
                            .as_ref()
                            .is_some_and(|execution| execution.verbose)
                        {
                            eprintln!(
                                "[verbose] Extension '{}' failed: {}",
                                sanitize_for_terminal(&extension_name),
                                sanitize_for_terminal(&reason)
                            );
                        }
                        Err(ExecutionError::function_error(
                            &error_function_name,
                            sanitize_for_terminal(&reason),
                        ))
                    }
                }
            },
        );
    }
    state
}

fn invoke_extension(
    name: &str,
    args: &[CelValue],
    execution: Option<&ExtensionExecutionContext>,
    state: &mut ExtensionCallState,
) -> Result<JsonValue, String> {
    let params = match args {
        [] => JsonMap::new(),
        [CelValue::Map(map)] => cel_map_to_json(map)?,
        [_] => return Err("extension argument must be a map".to_string()),
        _ => return Err("extension accepts at most one map argument".to_string()),
    };
    let key = serde_json::to_string(&JsonValue::Object(params.clone()))
        .map_err(|error| format!("failed to serialize extension arguments: {error}"))?;
    let cache_key = (name.to_string(), key);
    if let Some(result) = state.cache.get(&cache_key) {
        return result.clone();
    }

    let result = match execution {
        None => Err("extension execution is unavailable".to_string()),
        Some(execution) if !execution.calls_allowed => {
            Err("extension calls from project-discovered rules are not permitted".to_string())
        }
        Some(execution) => match execution.definitions.get(name) {
            None => Err(format!("extension '{name}' is not defined")),
            Some(definition) => {
                let timeout = definition
                    .timeout
                    .map(ExtensionTimeout::duration)
                    .unwrap_or(DEFAULT_EXTENSION_TIMEOUT);
                execution
                    .runner
                    .call(ExtensionCall {
                        name,
                        executor_cmd: &definition.executor,
                        params: &params,
                        parent_env: &execution.parent_env,
                        extra_env: definition.env.as_deref().unwrap_or_default(),
                        cwd: &execution.cwd,
                        timeout,
                    })
                    .map_err(|error| error.to_string())
            }
        },
    };
    state.cache.insert(cache_key, result.clone());
    result
}

fn cel_map_to_json(map: &CelMap) -> Result<JsonMap<String, JsonValue>, String> {
    let mut json = JsonMap::new();
    for (key, value) in map.map.iter() {
        let Key::String(name) = key else {
            return Err("extension map keys must be strings".to_string());
        };
        json.insert(name.to_string(), cel_value_to_json(value)?);
    }
    Ok(json)
}

fn cel_value_to_json(value: &CelValue) -> Result<JsonValue, String> {
    match value {
        CelValue::String(value) => Ok(JsonValue::String(value.to_string())),
        CelValue::Int(value) => Ok(JsonValue::Number((*value).into())),
        CelValue::UInt(value) => Ok(JsonValue::Number((*value).into())),
        CelValue::Float(value) => Number::from_f64(*value)
            .map(JsonValue::Number)
            .ok_or_else(|| "extension arguments cannot contain non-finite numbers".to_string()),
        CelValue::Bool(value) => Ok(JsonValue::Bool(*value)),
        CelValue::Null => Ok(JsonValue::Null),
        CelValue::List(values) => values
            .iter()
            .map(cel_value_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(JsonValue::Array),
        CelValue::Map(map) => cel_map_to_json(map).map(JsonValue::Object),
        _ => Err(format!(
            "extension arguments cannot contain CEL value type {}",
            value.type_of()
        )),
    }
}

pub(crate) fn call_snapshot(state: &Arc<Mutex<ExtensionCallState>>) -> ExtensionCallSnapshot {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .snapshot()
}

pub(crate) fn extension_error_message(
    snapshot: &ExtensionCallSnapshot,
    evaluation_error: &str,
) -> String {
    if let Some(failure) = &snapshot.failure {
        return format!(
            "Extension '{}' failed: {}; asking user for confirmation",
            sanitize_for_terminal(&failure.name),
            sanitize_for_terminal(&failure.reason)
        );
    }
    let names = snapshot
        .names
        .iter()
        .map(|name| format!("'{}'", sanitize_for_terminal(name)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "when evaluation failed after calling extension {names}: {}; asking user for confirmation",
        sanitize_for_terminal(evaluation_error)
    )
}

fn sanitize_for_terminal(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            !character.is_ascii_control() || matches!(*character, '\n' | '\r' | '\t')
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::single_call("ext.repo_info({'dir': '.'})", "ext.__runok_extension_call_repo_info({'dir': '.'})", vec!["repo_info"])]
    #[case::macro_collision("ext.exists({'dir': '.'}, x, x)", "ext.__runok_extension_call_exists({'dir': '.'}, x, x)", vec!["exists"])]
    #[case::multiple_calls("ext.a() && ext.b({})", "ext.__runok_extension_call_a() && ext.__runok_extension_call_b({})", vec!["a", "b"])]
    #[case::string_literal("'ext.repo_info()' == 'ext.repo_info()'", "'ext.repo_info()' == 'ext.repo_info()'", vec![])]
    #[case::multiline_string("\"\"\"ext.repo_info()\"\"\" == 'value'", "\"\"\"ext.repo_info()\"\"\" == 'value'", vec![])]
    #[case::raw_string("r'ext.repo_info()' == 'value'", "r'ext.repo_info()' == 'value'", vec![])]
    #[case::qualified_member("rule.ext.repo_info()", "rule.ext.repo_info()", vec![])]
    fn rewrites_only_extension_calls(
        #[case] expression: &str,
        #[case] expected_expression: &str,
        #[case] expected_names: Vec<&str>,
    ) {
        let (rewritten, names) = rewrite_extension_calls(expression);
        assert_eq!(
            (rewritten, names),
            (
                expected_expression.to_string(),
                expected_names.into_iter().map(str::to_string).collect()
            )
        );
    }
}
