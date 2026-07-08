#[cfg(any(feature = "config-schema", test))]
use super::Config;

/// Transform the generated `RuleEntry` schema into a `oneOf` with three variants:
/// - `deny`: requires `deny`, forbids `allow`/`ask`/`sandbox`
/// - `allow`: requires `allow`, forbids `deny`/`ask`
/// - `ask`: requires `ask`, forbids `deny`/`allow`
#[cfg(any(feature = "config-schema", test))]
pub(super) fn rule_entry_one_of_transform(schema: &mut schemars::Schema) {
    let common_optional = ["when", "message", "fix_suggestion"];

    let make_variant = |action: &str, extra_optional: &[&str]| -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let required = vec![serde_json::Value::String(action.to_string())];

        // Action field (required)
        properties.insert(
            action.to_string(),
            serde_json::json!({ "type": "string", "description": schema.get("properties").and_then(|p| p.get(action)).and_then(|a| a.get("description")).cloned().unwrap_or(serde_json::Value::Null) }),
        );

        // Common optional fields
        for field in &common_optional {
            if let Some(prop) = schema
                .get("properties")
                .and_then(|p| p.get(*field))
                .cloned()
            {
                properties.insert(field.to_string(), prop);
            }
        }

        // Extra optional fields (e.g., sandbox)
        for field in extra_optional {
            if let Some(prop) = schema
                .get("properties")
                .and_then(|p| p.get(*field))
                .cloned()
            {
                properties.insert(field.to_string(), prop);
            }
        }

        serde_json::json!({
            "type": "object",
            "properties": serde_json::Value::Object(properties),
            "required": serde_json::Value::Array(required),
            "additionalProperties": false
        })
    };

    let deny_variant = make_variant("deny", &["tests"]);
    let allow_variant = make_variant("allow", &["sandbox", "tests"]);
    let ask_variant = make_variant("ask", &["sandbox", "tests"]);

    // Replace the schema with oneOf
    let description = schema.get("description").cloned();

    // Remove all existing keys
    if let Some(obj) = schema.as_object_mut() {
        obj.clear();
    }

    // Set oneOf
    schema.insert(
        "oneOf".to_owned(),
        serde_json::Value::Array(vec![deny_variant, allow_variant, ask_variant]),
    );

    if let Some(desc) = description {
        schema.insert("description".to_owned(), desc);
    }
}

/// Transform the generated `InlineTestEntry` schema into a `oneOf` with three variants:
/// - `allow`: requires `allow`, forbids `ask`/`deny`
/// - `ask`: requires `ask`, forbids `allow`/`deny`
/// - `deny`: requires `deny`, forbids `allow`/`ask`
#[cfg(any(feature = "config-schema", test))]
pub(super) fn inline_test_entry_one_of_transform(schema: &mut schemars::Schema) {
    let make_variant = |action: &str| -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let required = vec![serde_json::Value::String(action.to_string())];

        if let Some(prop) = schema
            .get("properties")
            .and_then(|p| p.get(action))
            .cloned()
        {
            properties.insert(action.to_string(), prop);
        }

        serde_json::json!({
            "type": "object",
            "properties": serde_json::Value::Object(properties),
            "required": serde_json::Value::Array(required),
            "additionalProperties": false
        })
    };

    let allow_variant = make_variant("allow");
    let ask_variant = make_variant("ask");
    let deny_variant = make_variant("deny");

    let description = schema.get("description").cloned();

    if let Some(obj) = schema.as_object_mut() {
        obj.clear();
    }

    schema.insert(
        "oneOf".to_owned(),
        serde_json::Value::Array(vec![allow_variant, ask_variant, deny_variant]),
    );

    if let Some(desc) = description {
        schema.insert("description".to_owned(), desc);
    }
}

/// Print the JSON Schema for the runok configuration to stdout.
#[cfg(feature = "config-schema")]
pub fn print_config_schema() -> Result<(), serde_json::Error> {
    let schema = schemars::schema_for!(Config);
    let json = serde_json::to_string_pretty(&schema)?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // === JSON Schema ===

    const SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/runok.schema.json");

    fn generate_schema_value() -> serde_json::Value {
        let schema = schemars::schema_for!(Config);
        serde_json::to_value(schema).unwrap()
    }

    #[test]
    fn schema_is_up_to_date() {
        let expected = generate_schema_value();
        let actual_str = std::fs::read_to_string(SCHEMA_PATH).unwrap_or_else(|e| {
            panic!(
                "Failed to read schema file at {SCHEMA_PATH}: {e}. \
                 Run `cargo run --features config-schema -- config-schema > schema/runok.schema.json` to generate it."
            )
        });
        let actual: serde_json::Value = serde_json::from_str(&actual_str)
            .unwrap_or_else(|e| panic!("Schema file is not valid JSON: {e}"));
        assert_eq!(
            actual, expected,
            "Schema file is out of date. \
             Run `cargo run --features config-schema -- config-schema > schema/runok.schema.json` to regenerate."
        );
    }
}
