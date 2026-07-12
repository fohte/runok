/// Walk a pattern token tree and invoke `report` for every `<flag:name>`
/// reference encountered. Used by config validation to detect undefined flag
/// group references upfront.
pub(super) fn collect_flag_group_refs(
    tokens: &[crate::rules::pattern_parser::PatternToken],
    report: &mut impl FnMut(&str),
) {
    use crate::rules::pattern_parser::PatternToken;
    for token in tokens {
        match token {
            PatternToken::FlagGroupRef { name, .. } => report(name),
            PatternToken::Optional(inner) => collect_flag_group_refs(inner, report),
            _ => {}
        }
    }
}

/// Walk a pattern token tree and invoke `report` for every `<var:name>`
/// reference that appears strictly inside an `Optional ([...])` group. Used
/// by config validation to forbid pattern-typed `<var:name>` references
/// inside optional groups.
pub(super) fn collect_var_refs_inside_optional(
    tokens: &[crate::rules::pattern_parser::PatternToken],
    report: &mut impl FnMut(&str),
) {
    use crate::rules::pattern_parser::PatternToken;
    for token in tokens {
        if let PatternToken::Optional(inner) = token {
            collect_var_refs_anywhere(inner, report);
        }
    }
}

fn collect_var_refs_anywhere(
    tokens: &[crate::rules::pattern_parser::PatternToken],
    report: &mut impl FnMut(&str),
) {
    use crate::rules::pattern_parser::PatternToken;
    for token in tokens {
        match token {
            PatternToken::VarRef(name) => report(name),
            PatternToken::Optional(inner) => collect_var_refs_anywhere(inner, report),
            _ => {}
        }
    }
}

/// Walk a parsed pattern tree and return a description of the first nested
/// placeholder found, or `None` if every token is a plain pattern element.
/// Used by `definitions.vars` validation for `pattern`-typed values: pattern
/// vars must not embed other placeholders, since their value is inlined into
/// rule patterns and recursive expansion is not supported.
pub(super) fn find_disallowed_placeholder_in_pattern(
    pattern: &crate::rules::pattern_parser::Pattern,
) -> Option<String> {
    use crate::rules::pattern_parser::CommandPattern;

    if let CommandPattern::VarRef(name) = &pattern.command {
        return Some(format!("<var:{name}>"));
    }
    find_disallowed_placeholder_in_tokens(&pattern.tokens)
}

fn find_disallowed_placeholder_in_tokens(
    tokens: &[crate::rules::pattern_parser::PatternToken],
) -> Option<String> {
    use crate::rules::pattern_parser::PatternToken;
    for token in tokens {
        match token {
            PatternToken::PathRef(name) => return Some(format!("<path:{name}>")),
            PatternToken::VarRef(name) => return Some(format!("<var:{name}>")),
            PatternToken::FlagGroupRef { name } => return Some(format!("<flag:{name}>")),
            PatternToken::Placeholder(name) => return Some(format!("<{name}>")),
            PatternToken::Opts => return Some("<opts>".to_string()),
            PatternToken::Vars => return Some("<vars>".to_string()),
            PatternToken::Optional(inner) => {
                if let Some(found) = find_disallowed_placeholder_in_tokens(inner) {
                    return Some(found);
                }
            }
            PatternToken::FlagWithValue { value, .. } => {
                if let Some(found) =
                    find_disallowed_placeholder_in_tokens(std::slice::from_ref(value.as_ref()))
                {
                    return Some(found);
                }
            }
            PatternToken::Negation(inner) => {
                if let Some(found) =
                    find_disallowed_placeholder_in_tokens(std::slice::from_ref(inner.as_ref()))
                {
                    return Some(found);
                }
            }
            PatternToken::Literal(_)
            | PatternToken::Alternation(_)
            | PatternToken::Wildcard
            | PatternToken::OptionalValue => {}
        }
    }
    None
}
