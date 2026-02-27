use std::path::PathBuf;

pub fn home_dir() -> Option<PathBuf> {
    non_empty_env("HOME").map(PathBuf::from)
}

pub fn config_dir() -> Option<PathBuf> {
    if let Some(xdg) = non_empty_env("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg));
    }
    home_dir().map(|home| home.join(".config"))
}

pub fn cache_dir() -> Option<PathBuf> {
    if let Some(xdg) = non_empty_env("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg));
    }
    home_dir().map(|home| home.join(".cache"))
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rstest::rstest;

    // Pure functions that take env values as arguments, mirroring the public API logic.
    // This avoids depending on actual environment variables in tests.

    fn home_dir_with(home: Option<&str>) -> Option<PathBuf> {
        home.filter(|v| !v.is_empty()).map(PathBuf::from)
    }

    fn config_dir_with(xdg_config_home: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
        if let Some(xdg) = xdg_config_home.filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(xdg));
        }
        home_dir_with(home).map(|h| h.join(".config"))
    }

    fn cache_dir_with(xdg_cache_home: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
        if let Some(xdg) = xdg_cache_home.filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(xdg));
        }
        home_dir_with(home).map(|h| h.join(".cache"))
    }

    #[rstest]
    #[case::set(Some("/home/user"), Some(PathBuf::from("/home/user")))]
    #[case::empty(Some(""), None)]
    #[case::unset(None, None)]
    fn home_dir(#[case] home: Option<&str>, #[case] expected: Option<PathBuf>) {
        assert_eq!(home_dir_with(home), expected);
    }

    #[rstest]
    #[case::xdg_set(
        Some("/xdg/config"),
        Some("/home/user"),
        Some(PathBuf::from("/xdg/config"))
    )]
    #[case::xdg_empty_falls_back(
        Some(""),
        Some("/home/user"),
        Some(PathBuf::from("/home/user/.config"))
    )]
    #[case::xdg_unset_falls_back(
        None,
        Some("/home/user"),
        Some(PathBuf::from("/home/user/.config"))
    )]
    #[case::both_unset(None, None, None)]
    fn config_dir(
        #[case] xdg: Option<&str>,
        #[case] home: Option<&str>,
        #[case] expected: Option<PathBuf>,
    ) {
        assert_eq!(config_dir_with(xdg, home), expected);
    }

    #[rstest]
    #[case::xdg_set(
        Some("/xdg/cache"),
        Some("/home/user"),
        Some(PathBuf::from("/xdg/cache"))
    )]
    #[case::xdg_empty_falls_back(
        Some(""),
        Some("/home/user"),
        Some(PathBuf::from("/home/user/.cache"))
    )]
    #[case::xdg_unset_falls_back(
        None,
        Some("/home/user"),
        Some(PathBuf::from("/home/user/.cache"))
    )]
    #[case::both_unset(None, None, None)]
    fn cache_dir(
        #[case] xdg: Option<&str>,
        #[case] home: Option<&str>,
        #[case] expected: Option<PathBuf>,
    ) {
        assert_eq!(cache_dir_with(xdg, home), expected);
    }
}
