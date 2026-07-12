use std::path::Path;

use runok::audit::filter::{AuditFilter, TimeSpec};
use runok::audit::reader::AuditReader;
use runok::config::{ActionKind, ConfigLoader, ConfigSource, DefaultConfigLoader};

use crate::cli::AuditArgs;

pub fn run_audit(args: AuditArgs, config_path: Option<&Path>, cwd: &Path) -> i32 {
    let loader = DefaultConfigLoader::new();
    let source = ConfigSource::from_flag(config_path, cwd);
    let config = match loader.load(&source) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runok: config error: {e}");
            return 1;
        }
    };

    let audit_config = config.audit.unwrap_or_default();
    let log_dir = audit_config.base_dir();

    let mut filter = AuditFilter::new();
    filter.limit = args.limit;

    if let Some(action_str) = &args.action {
        match action_str.as_str() {
            "allow" => filter.action = Some(ActionKind::Allow),
            "deny" => filter.action = Some(ActionKind::Deny),
            "ask" => filter.action = Some(ActionKind::Ask),
            other => {
                eprintln!("runok: invalid action filter '{other}': expected allow, deny, or ask");
                return 1;
            }
        }
    }

    if let Some(since_str) = &args.since {
        match TimeSpec::parse(since_str) {
            Ok(ts) => filter.since = Some(ts),
            Err(e) => {
                eprintln!("runok: {e}");
                return 1;
            }
        }
    }

    if let Some(until_str) = &args.until {
        match TimeSpec::parse(until_str) {
            Ok(ts) => filter.until = Some(ts),
            Err(e) => {
                eprintln!("runok: {e}");
                return 1;
            }
        }
    }

    filter.command_pattern = args.command;

    if let Some(dir_arg) = args.dir {
        let dir_path = Path::new(&dir_arg);
        match dir_path.canonicalize() {
            Ok(canonical) => filter.cwd = Some(canonical.to_string_lossy().into_owned()),
            Err(e) => {
                eprintln!("runok: failed to resolve directory path '{}': {e}", dir_arg);
                return 1;
            }
        }
    }

    let reader = AuditReader::new(log_dir);
    let entries = match reader.read(&filter) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("runok: failed to read audit log: {e}");
            return 1;
        }
    };

    // Resolutions only exist for asks; skip reading them when the action
    // filter excludes ask entries.
    let resolutions = if matches!(filter.action, None | Some(ActionKind::Ask)) {
        match reader.read_resolutions(&filter) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("runok: failed to read audit log: {e}");
                return 1;
            }
        }
    } else {
        Vec::new()
    };

    if args.json {
        // Emit decision entries and resolution records as-is, merged into
        // one timestamp-ordered JSONL stream.
        let mut records: Vec<(&str, String)> = Vec::new();
        for entry in &entries {
            match serde_json::to_string(entry) {
                Ok(json) => records.push((&entry.timestamp, json)),
                Err(e) => {
                    eprintln!("runok: serialization error: {e}");
                    return 1;
                }
            }
        }
        for resolution in &resolutions {
            match serde_json::to_string(resolution) {
                Ok(json) => records.push((&resolution.timestamp, json)),
                Err(e) => {
                    eprintln!("runok: serialization error: {e}");
                    return 1;
                }
            }
        }
        records.sort_by(|a, b| a.0.cmp(b.0));
        // --limit bounds the merged output stream: resolutions are read
        // without a limit (the text-mode join needs all of them), so keep
        // only the newest `limit` records here.
        let skip = records.len().saturating_sub(filter.limit);
        for (_, json) in &records[skip..] {
            println!("{json}");
        }
    } else {
        runok::audit::formatter::print_entries(&entries, &resolutions);
    }

    0
}
