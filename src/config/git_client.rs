use std::path::Path;
use std::process::Command;

use super::PresetError;

/// Abstraction for git command execution.
///
/// Enables testing with `MockGitClient` while `ProcessGitClient` runs real git processes.
pub trait GitClient {
    /// Run `git clone --depth 1 [--branch <branch>] <url> .` into `dest`.
    fn clone_shallow(
        &self,
        url: &str,
        dest: &Path,
        branch: Option<&str>,
    ) -> Result<(), PresetError>;

    /// Run `git fetch --depth 1 origin [<branch>]` in `repo_dir`.
    fn fetch(&self, repo_dir: &Path, branch: Option<&str>) -> Result<(), PresetError>;

    /// Run `git checkout <git_ref>` in `repo_dir`.
    fn checkout(&self, repo_dir: &Path, git_ref: &str) -> Result<(), PresetError>;

    /// Run `git rev-parse HEAD` in `repo_dir` and return the commit SHA.
    fn rev_parse_head(&self, repo_dir: &Path) -> Result<String, PresetError>;
}

/// Strip credentials from a URL for safe use in error messages.
///
/// Replaces `user:pass@` or `user@` in the authority component with `***@`.
fn sanitize_url(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let authority_start = scheme_end + 3;
        let rest = &url[authority_start..];
        // Find the end of the authority (first `/` after `://`)
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];

        if let Some(at_pos) = authority.rfind('@') {
            // There are credentials; replace them with `***`
            return format!("{}***@{}", &url[..authority_start], &rest[at_pos + 1..]);
        }
    }
    url.to_string()
}

/// Real git client that spawns `git` subprocesses.
///
/// Sanitizes environment by removing `GIT_DIR` and `GIT_INDEX_FILE` so that
/// git operations work correctly inside worktree environments (lefthook approach).
pub struct ProcessGitClient;

impl ProcessGitClient {
    fn git_command(working_dir: &Path) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(working_dir);
        // Remove env vars that interfere with git in worktree contexts
        cmd.env_remove("GIT_DIR");
        cmd.env_remove("GIT_INDEX_FILE");
        cmd
    }

    fn run_git(cmd: &mut Command, context: &str) -> Result<(), PresetError> {
        let output = cmd.output().map_err(|e| PresetError::GitClone {
            reference: context.to_string(),
            message: format!("failed to execute git: {e}"),
        })?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(PresetError::GitClone {
                reference: context.to_string(),
                message: stderr.trim().to_string(),
            })
        }
    }
}

impl GitClient for ProcessGitClient {
    fn clone_shallow(
        &self,
        url: &str,
        dest: &Path,
        branch: Option<&str>,
    ) -> Result<(), PresetError> {
        let parent = dest.parent().ok_or_else(|| PresetError::GitClone {
            reference: sanitize_url(url),
            message: "destination has no parent directory".to_string(),
        })?;

        let mut cmd = Self::git_command(parent);
        cmd.args(["clone", "--quiet", "--depth", "1"]);

        if let Some(branch) = branch {
            cmd.args(["--branch", branch]);
        }

        // `--` separates options from positional arguments to prevent
        // argument injection via crafted URL strings.
        cmd.arg("--");
        cmd.arg(url);
        cmd.arg(dest);

        Self::run_git(&mut cmd, &sanitize_url(url))
    }

    fn fetch(&self, repo_dir: &Path, branch: Option<&str>) -> Result<(), PresetError> {
        let mut cmd = Self::git_command(repo_dir);
        cmd.args(["fetch", "--quiet", "--depth", "1", "origin"]);

        if let Some(branch) = branch {
            // `--` prevents the branch string from being interpreted as an
            // option (e.g., `--upload-pack=...`) by git fetch.
            cmd.arg("--");
            cmd.arg(branch);
        }

        Self::run_git(&mut cmd, &repo_dir.display().to_string())
    }

    fn checkout(&self, repo_dir: &Path, git_ref: &str) -> Result<(), PresetError> {
        let mut cmd = Self::git_command(repo_dir);
        // Place `git_ref` before `--` so it is interpreted as a tree-ish,
        // not a pathspec. The trailing `--` prevents ambiguity if a file
        // happens to share the same name as the ref.
        cmd.args(["checkout", "--quiet", git_ref, "--"]);

        Self::run_git(&mut cmd, git_ref)
    }

    fn rev_parse_head(&self, repo_dir: &Path) -> Result<String, PresetError> {
        let mut cmd = Self::git_command(repo_dir);
        cmd.args(["rev-parse", "HEAD"]);

        let output = cmd.output().map_err(|e| PresetError::GitClone {
            reference: repo_dir.display().to_string(),
            message: format!("failed to execute git rev-parse: {e}"),
        })?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(PresetError::GitClone {
                reference: repo_dir.display().to_string(),
                message: format!("git rev-parse HEAD failed: {}", stderr.trim()),
            })
        }
    }
}

#[cfg(test)]
pub mod mock {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::Path;

    use super::{GitClient, PresetError};

    /// Records of calls made to MockGitClient methods.
    #[derive(Debug, Clone)]
    pub enum GitCall {
        CloneShallow { branch: Option<String> },
        Fetch,
        Checkout { git_ref: String },
        RevParseHead,
    }

    /// Test double for `GitClient` that returns pre-configured results.
    pub struct MockGitClient {
        clone_results: RefCell<VecDeque<Result<(), PresetError>>>,
        fetch_results: RefCell<VecDeque<Result<(), PresetError>>>,
        checkout_results: RefCell<VecDeque<Result<(), PresetError>>>,
        rev_parse_results: RefCell<VecDeque<Result<String, PresetError>>>,
        pub calls: RefCell<Vec<GitCall>>,
    }

    impl Default for MockGitClient {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockGitClient {
        pub fn new() -> Self {
            Self {
                clone_results: RefCell::new(VecDeque::new()),
                fetch_results: RefCell::new(VecDeque::new()),
                checkout_results: RefCell::new(VecDeque::new()),
                rev_parse_results: RefCell::new(VecDeque::new()),
                calls: RefCell::new(Vec::new()),
            }
        }

        /// Queue a result for the next `clone_shallow` call.
        pub fn on_clone(&self, result: Result<(), PresetError>) -> &Self {
            self.clone_results.borrow_mut().push_back(result);
            self
        }

        /// Queue a result for the next `fetch` call.
        pub fn on_fetch(&self, result: Result<(), PresetError>) -> &Self {
            self.fetch_results.borrow_mut().push_back(result);
            self
        }

        /// Queue a result for the next `checkout` call.
        pub fn on_checkout(&self, result: Result<(), PresetError>) -> &Self {
            self.checkout_results.borrow_mut().push_back(result);
            self
        }

        /// Queue a result for the next `rev_parse_head` call.
        pub fn on_rev_parse(&self, result: Result<String, PresetError>) -> &Self {
            self.rev_parse_results.borrow_mut().push_back(result);
            self
        }

        fn pop_result<T>(
            results: &RefCell<VecDeque<Result<T, PresetError>>>,
        ) -> Result<T, PresetError> {
            results.borrow_mut().pop_front().unwrap_or_else(|| {
                Err(PresetError::GitClone {
                    reference: "mock".to_string(),
                    message: "no more mock results queued".to_string(),
                })
            })
        }
    }

    impl GitClient for MockGitClient {
        fn clone_shallow(
            &self,
            _url: &str,
            _dest: &Path,
            branch: Option<&str>,
        ) -> Result<(), PresetError> {
            self.calls.borrow_mut().push(GitCall::CloneShallow {
                branch: branch.map(String::from),
            });
            Self::pop_result(&self.clone_results)
        }

        fn fetch(&self, _repo_dir: &Path, _branch: Option<&str>) -> Result<(), PresetError> {
            self.calls.borrow_mut().push(GitCall::Fetch);
            Self::pop_result(&self.fetch_results)
        }

        fn checkout(&self, _repo_dir: &Path, git_ref: &str) -> Result<(), PresetError> {
            self.calls.borrow_mut().push(GitCall::Checkout {
                git_ref: git_ref.to_string(),
            });
            Self::pop_result(&self.checkout_results)
        }

        fn rev_parse_head(&self, _repo_dir: &Path) -> Result<String, PresetError> {
            self.calls.borrow_mut().push(GitCall::RevParseHead);
            Self::pop_result(&self.rev_parse_results)
        }
    }
}
