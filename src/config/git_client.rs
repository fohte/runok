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
        // Clone into the dest directory. We use `git clone ... <url> <dest>`
        // with the parent of dest as working directory.
        let parent = dest.parent().ok_or_else(|| PresetError::GitClone {
            reference: url.to_string(),
            message: "destination has no parent directory".to_string(),
        })?;

        let mut cmd = Command::new("git");
        cmd.current_dir(parent);
        cmd.env_remove("GIT_DIR");
        cmd.env_remove("GIT_INDEX_FILE");
        cmd.args(["clone", "--quiet", "--depth", "1"]);

        if let Some(branch) = branch {
            cmd.args(["--branch", branch]);
        }

        cmd.arg(url);
        cmd.arg(dest);

        Self::run_git(&mut cmd, url)
    }

    fn fetch(&self, repo_dir: &Path, branch: Option<&str>) -> Result<(), PresetError> {
        let mut cmd = Self::git_command(repo_dir);
        cmd.args(["fetch", "--quiet", "--depth", "1", "origin"]);

        if let Some(branch) = branch {
            cmd.arg(branch);
        }

        Self::run_git(&mut cmd, &repo_dir.display().to_string())
    }

    fn checkout(&self, repo_dir: &Path, git_ref: &str) -> Result<(), PresetError> {
        let mut cmd = Self::git_command(repo_dir);
        cmd.args(["checkout", "--quiet", git_ref]);

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
    use std::path::{Path, PathBuf};

    use super::{GitClient, PresetError};

    /// Records of calls made to MockGitClient methods.
    #[derive(Debug, Clone)]
    #[expect(
        dead_code,
        reason = "fields used for test assertions via pattern matching"
    )]
    pub enum GitCall {
        CloneShallow {
            url: String,
            dest: PathBuf,
            branch: Option<String>,
        },
        Fetch {
            repo_dir: PathBuf,
            branch: Option<String>,
        },
        Checkout {
            repo_dir: PathBuf,
            git_ref: String,
        },
        RevParseHead {
            repo_dir: PathBuf,
        },
    }

    /// Test double for `GitClient` that returns pre-configured results.
    pub struct MockGitClient {
        clone_results: RefCell<Vec<Result<(), PresetError>>>,
        fetch_results: RefCell<Vec<Result<(), PresetError>>>,
        checkout_results: RefCell<Vec<Result<(), PresetError>>>,
        rev_parse_results: RefCell<Vec<Result<String, PresetError>>>,
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
                clone_results: RefCell::new(Vec::new()),
                fetch_results: RefCell::new(Vec::new()),
                checkout_results: RefCell::new(Vec::new()),
                rev_parse_results: RefCell::new(Vec::new()),
                calls: RefCell::new(Vec::new()),
            }
        }

        /// Queue a result for the next `clone_shallow` call.
        pub fn on_clone(&self, result: Result<(), PresetError>) -> &Self {
            self.clone_results.borrow_mut().push(result);
            self
        }

        /// Queue a result for the next `fetch` call.
        pub fn on_fetch(&self, result: Result<(), PresetError>) -> &Self {
            self.fetch_results.borrow_mut().push(result);
            self
        }

        /// Queue a result for the next `checkout` call.
        pub fn on_checkout(&self, result: Result<(), PresetError>) -> &Self {
            self.checkout_results.borrow_mut().push(result);
            self
        }

        /// Queue a result for the next `rev_parse_head` call.
        pub fn on_rev_parse(&self, result: Result<String, PresetError>) -> &Self {
            self.rev_parse_results.borrow_mut().push(result);
            self
        }

        fn pop_result<T>(results: &RefCell<Vec<Result<T, PresetError>>>) -> Result<T, PresetError> {
            let mut queue = results.borrow_mut();
            if queue.is_empty() {
                return Err(PresetError::GitClone {
                    reference: "mock".to_string(),
                    message: "no more mock results queued".to_string(),
                });
            }
            queue.remove(0)
        }
    }

    impl GitClient for MockGitClient {
        fn clone_shallow(
            &self,
            url: &str,
            dest: &Path,
            branch: Option<&str>,
        ) -> Result<(), PresetError> {
            self.calls.borrow_mut().push(GitCall::CloneShallow {
                url: url.to_string(),
                dest: dest.to_path_buf(),
                branch: branch.map(String::from),
            });
            Self::pop_result(&self.clone_results)
        }

        fn fetch(&self, repo_dir: &Path, branch: Option<&str>) -> Result<(), PresetError> {
            self.calls.borrow_mut().push(GitCall::Fetch {
                repo_dir: repo_dir.to_path_buf(),
                branch: branch.map(String::from),
            });
            Self::pop_result(&self.fetch_results)
        }

        fn checkout(&self, repo_dir: &Path, git_ref: &str) -> Result<(), PresetError> {
            self.calls.borrow_mut().push(GitCall::Checkout {
                repo_dir: repo_dir.to_path_buf(),
                git_ref: git_ref.to_string(),
            });
            Self::pop_result(&self.checkout_results)
        }

        fn rev_parse_head(&self, repo_dir: &Path) -> Result<String, PresetError> {
            self.calls.borrow_mut().push(GitCall::RevParseHead {
                repo_dir: repo_dir.to_path_buf(),
            });
            Self::pop_result(&self.rev_parse_results)
        }
    }
}
