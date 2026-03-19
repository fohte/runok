/// Migrate legacy sandbox fs config (`writable`/`deny`) to the new format
/// (`write: { allow: [...], deny: [...] }`).
///
/// Operates on YAML text line-by-line to preserve comments and formatting.
pub fn migrate_sandbox_fs(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut result: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let stripped = line.trim_start();
        let indent = &line[..line.len() - stripped.len()];

        if let Some(rest) = stripped.strip_prefix("writable:") {
            // Replace `writable:` with `write:\n{indent}  allow:`
            result.push(format!("{indent}write:"));
            result.push(format!("{indent}  allow:{rest}"));
            i += 1;

            // Consume continuation lines (list items at deeper indent)
            while i < lines.len() && is_child_line(lines[i], indent) {
                let child = lines[i];
                let child_stripped = child.trim_start();
                let child_indent = &child[..child.len() - child_stripped.len()];
                // Add 2 spaces of extra indent (under `allow:`)
                result.push(format!("{child_indent}  {child_stripped}"));
                i += 1;
            }
            continue;
        }

        if let Some(rest) = stripped
            .strip_prefix("deny:")
            .filter(|_| is_sandbox_fs_deny(&lines, i))
        {
            // Replace `deny:` with `write:\n{indent}  deny:` only when it's
            // a sibling of `writable:` inside a sandbox fs block.
            // We process top-to-bottom, so if `writable:` appeared before,
            // it was already converted to `write:` + `allow:`. We check if
            // the previous non-empty/comment line is under a `write:` block,
            // and if so, just add `deny:` nested under it.

            if should_nest_under_existing_write(&result, indent) {
                // The `write:` block already exists from a converted `writable:`.
                // Add `deny:` at the same level as `allow:`.
                result.push(format!("{indent}  deny:{rest}"));
            } else {
                result.push(format!("{indent}write:"));
                result.push(format!("{indent}  deny:{rest}"));
            }
            i += 1;

            // Consume continuation lines
            while i < lines.len() && is_child_line(lines[i], indent) {
                let child = lines[i];
                let child_stripped = child.trim_start();
                let child_indent = &child[..child.len() - child_stripped.len()];
                result.push(format!("{child_indent}  {child_stripped}"));
                i += 1;
            }
            continue;
        }

        result.push(line.to_string());
        i += 1;
    }

    let mut output = result.join("\n");
    // Preserve trailing newline if original had one
    if input.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// Returns true if `line` is a child (more deeply indented) of the given `parent_indent`.
fn is_child_line(line: &str, parent_indent: &str) -> bool {
    let stripped = line.trim_start();
    // Blank lines and comments within the block are considered children
    if stripped.is_empty() || stripped.starts_with('#') {
        return true;
    }
    let line_indent = line.len() - stripped.len();
    line_indent > parent_indent.len()
}

/// Heuristic: check if this `deny:` key is inside a sandbox `fs:` block
/// by looking backwards for an `fs:` parent or a sibling `writable:`.
fn is_sandbox_fs_deny(lines: &[&str], deny_idx: usize) -> bool {
    let deny_line = lines[deny_idx];
    let deny_stripped = deny_line.trim_start();
    let deny_indent = deny_line.len() - deny_stripped.len();

    // Look backwards for a sibling or parent
    for j in (0..deny_idx).rev() {
        let prev = lines[j];
        let prev_stripped = prev.trim_start();
        if prev_stripped.is_empty() || prev_stripped.starts_with('#') {
            continue;
        }
        let prev_indent = prev.len() - prev_stripped.len();

        // Sibling at the same indent level
        if prev_indent == deny_indent && prev_stripped.starts_with("writable:") {
            return true;
        }

        // Parent at a smaller indent level
        if prev_indent < deny_indent {
            if prev_stripped.starts_with("fs:") {
                return true;
            }
            // Reached a parent that isn't `fs:`, so this `deny:` isn't in a sandbox fs block
            return false;
        }
    }
    false
}

/// Check if we should nest `deny:` under an existing `write:` block
/// (i.e., `writable:` was already converted in this pass).
fn should_nest_under_existing_write(result: &[String], deny_indent: &str) -> bool {
    // Look backwards in the result for a `write:` at the same indent level
    for prev in result.iter().rev() {
        let prev_stripped = prev.trim_start();
        if prev_stripped.is_empty() || prev_stripped.starts_with('#') {
            continue;
        }
        let prev_indent = &prev[..prev.len() - prev_stripped.len()];

        if prev_indent == deny_indent && prev_stripped.starts_with("write:") {
            return true;
        }

        // If we hit something at a lesser or equal indent that isn't `write:`,
        // or at greater indent (child of write), keep looking
        if prev_indent.len() <= deny_indent.len() && !prev_stripped.starts_with("write:") {
            // Check if this is a child of `write:` (e.g. `allow:` line)
            if prev_indent.len() < deny_indent.len() {
                return false;
            }
            // Same indent, not `write:` — might be the `allow:` line that was
            // nested, so keep looking
            if prev_indent.len() == deny_indent.len() {
                return false;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    #[rstest]
    #[case::writable_only(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp, /tmp]
        "},
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow: [./tmp, /tmp]
        "},
    )]
    #[case::writable_and_deny_inline(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny: [.env]
        "},
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow: [./tmp]
                      deny: [.env]
        "},
    )]
    #[case::writable_and_deny_block(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp, /tmp]
                    deny:
                      - '<path:sensitive>'
        "},
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow: [./tmp, /tmp]
                      deny:
                        - '<path:sensitive>'
        "},
    )]
    #[case::deny_only(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    deny:
                      - .env
                      - .envrc
        "},
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      deny:
                        - .env
                        - .envrc
        "},
    )]
    #[case::writable_block_style(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable:
                      - ./tmp
                      - /tmp
                    deny:
                      - .env
        "},
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow:
                        - ./tmp
                        - /tmp
                      deny:
                        - .env
        "},
    )]
    #[case::preserves_comments(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    # writable dirs
                    writable: [./tmp]
                    deny: [.env]
        "},
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    # writable dirs
                    write:
                      allow: [./tmp]
                      deny: [.env]
        "},
    )]
    #[case::no_changes_needed(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow: [./tmp]
                      deny: [.env]
        "},
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow: [./tmp]
                      deny: [.env]
        "},
    )]
    #[case::non_sandbox_deny_untouched(
        indoc! {"
            rules:
              - deny: rm -rf /
        "},
        indoc! {"
            rules:
              - deny: rm -rf /
        "},
    )]
    #[case::with_network(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny: [.env]
                  network:
                    allow: true
        "},
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow: [./tmp]
                      deny: [.env]
                  network:
                    allow: true
        "},
    )]
    fn test_migrate_sandbox_fs(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(migrate_sandbox_fs(input), expected);
    }
}
