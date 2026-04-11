use std::path::Path;
use std::process::Command;

use super::PresetError;

/// Whether a remote ref is a tag or a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    Tag,
    Branch,
}

/// A remote ref returned by `ls-remote`, with its name and kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRef {
    pub name: String,
    pub kind: RefKind,
}

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

    /// Run `git ls-remote --tags --heads --refs <url>` and return remote refs
    /// with their kind (tag or branch).
    fn ls_remote_refs(&self, url: &str) -> Result<Vec<RemoteRef>, PresetError>;

    /// Run `git show <git_ref>:<path>` in `repo_dir` and return the file
    /// contents as a UTF-8 string.
    ///
    /// This is used by preset refresh to read a candidate file at a specific
    /// ref without touching the working tree. The working tree must stay
    /// untouched until the candidate has been validated, so concurrent runok
    /// processes never observe an inconsistent intermediate state
    /// (level A guarantee).
    fn show_file(&self, repo_dir: &Path, git_ref: &str, path: &str) -> Result<String, PresetError>;
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

    fn show_file(&self, repo_dir: &Path, git_ref: &str, path: &str) -> Result<String, PresetError> {
        let mut cmd = Self::git_command(repo_dir);
        // Use the `<rev>:<path>` form so that `git show` prints only the blob
        // contents to stdout (no commit header, no diff). `git show` treats
        // this as a single argument and does not accept a `--` separator
        // before it, so rely on the fact that git refs and preset paths do
        // not start with `-` in practice.
        let spec = format!("{git_ref}:{path}");
        cmd.args(["show", spec.as_str()]);

        let output = cmd.output().map_err(|e| PresetError::GitClone {
            reference: format!("{git_ref}:{path}"),
            message: format!("failed to execute git show: {e}"),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PresetError::GitClone {
                reference: format!("{git_ref}:{path}"),
                message: format!("git show failed: {}", stderr.trim()),
            });
        }

        String::from_utf8(output.stdout).map_err(|e| PresetError::GitClone {
            reference: format!("{git_ref}:{path}"),
            message: format!("git show returned non-UTF8 output: {e}"),
        })
    }

    fn ls_remote_refs(&self, url: &str) -> Result<Vec<RemoteRef>, PresetError> {
        let mut cmd = Command::new("git");
        cmd.env_remove("GIT_DIR");
        cmd.env_remove("GIT_INDEX_FILE");
        // --tags --heads: list both tags and branches; --refs excludes peeled refs (^{})
        cmd.args(["ls-remote", "--tags", "--heads", "--refs", "--", url]);

        let output = cmd.output().map_err(|e| PresetError::GitClone {
            reference: sanitize_url(url),
            message: format!("failed to execute git ls-remote: {e}"),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PresetError::GitClone {
                reference: sanitize_url(url),
                message: format!("git ls-remote failed: {}", stderr.trim()),
            });
        }

        // Output format: "<sha>\trefs/tags/<name>" or "<sha>\trefs/heads/<name>"
        let stdout = String::from_utf8_lossy(&output.stdout);
        let refs = stdout
            .lines()
            .filter_map(|line| {
                let (_sha, refname) = line.split_once('\t')?;
                if let Some(name) = refname.strip_prefix("refs/tags/") {
                    Some(RemoteRef {
                        name: name.to_string(),
                        kind: RefKind::Tag,
                    })
                } else {
                    refname.strip_prefix("refs/heads/").map(|name| RemoteRef {
                        name: name.to_string(),
                        kind: RefKind::Branch,
                    })
                }
            })
            .collect();

        Ok(refs)
    }
}

#[cfg(test)]
pub mod mock {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::Path;

    use super::{GitClient, PresetError, RemoteRef};

    /// Records of calls made to MockGitClient methods.
    #[derive(Debug, Clone)]
    pub enum GitCall {
        CloneShallow { branch: Option<String> },
        Fetch,
        Checkout { git_ref: String },
        RevParseHead,
        LsRemoteRefs { url: String },
        ShowFile { git_ref: String, path: String },
    }

    /// Key used to look up a `show_file` mock result: `(git_ref, path)`.
    type ShowFileKey = (String, String);

    /// Mock outcome for a `show_file` call. `PresetError` is not `Clone`, so
    /// entries store either the blob content or an error message and a new
    /// error is constructed on each lookup.
    #[derive(Debug, Clone)]
    pub enum ShowFileOutcome {
        Ok(String),
        Err(String),
    }

    /// Test double for `GitClient` that returns pre-configured results.
    pub struct MockGitClient {
        clone_results: RefCell<VecDeque<Result<(), PresetError>>>,
        fetch_results: RefCell<VecDeque<Result<(), PresetError>>>,
        checkout_results: RefCell<VecDeque<Result<(), PresetError>>>,
        rev_parse_results: RefCell<VecDeque<Result<String, PresetError>>>,
        ls_remote_refs_results: RefCell<VecDeque<Result<Vec<RemoteRef>, PresetError>>>,
        /// Mapping from `(git_ref, path)` to the content returned by
        /// `show_file`. Each entry may be queried repeatedly.
        show_file_results: RefCell<std::collections::HashMap<ShowFileKey, ShowFileOutcome>>,
        /// FIFO queue of outcomes used when repeated calls for the same
        /// `(git_ref, path)` need to return different contents (e.g. the
        /// upgrade path fetches several candidate tags into `FETCH_HEAD` in
        /// sequence). When a queued entry exists it takes precedence over
        /// the static `show_file_results` map.
        show_file_queue: RefCell<std::collections::HashMap<ShowFileKey, VecDeque<ShowFileOutcome>>>,
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
                ls_remote_refs_results: RefCell::new(VecDeque::new()),
                show_file_results: RefCell::new(std::collections::HashMap::new()),
                show_file_queue: RefCell::new(std::collections::HashMap::new()),
                calls: RefCell::new(Vec::new()),
            }
        }

        /// Append an outcome to the FIFO queue for a `(git_ref, path)` pair.
        /// Each matching `show_file` call pops the oldest entry until the
        /// queue is empty, at which point the static map (populated via
        /// `on_show_file`) is consulted.
        pub fn push_show_file(&self, git_ref: &str, path: &str, content: &str) -> &Self {
            self.show_file_queue
                .borrow_mut()
                .entry((git_ref.to_string(), path.to_string()))
                .or_default()
                .push_back(ShowFileOutcome::Ok(content.to_string()));
            self
        }

        /// Register the blob content returned by `show_file` for a specific
        /// `(git_ref, path)` pair.
        pub fn on_show_file(&self, git_ref: &str, path: &str, content: &str) -> &Self {
            self.show_file_results.borrow_mut().insert(
                (git_ref.to_string(), path.to_string()),
                ShowFileOutcome::Ok(content.to_string()),
            );
            self
        }

        /// Register an error for a specific `(git_ref, path)` pair, simulating
        /// a missing file at that revision.
        pub fn on_show_file_missing(&self, git_ref: &str, path: &str) -> &Self {
            self.show_file_results.borrow_mut().insert(
                (git_ref.to_string(), path.to_string()),
                ShowFileOutcome::Err(format!(
                    "fatal: path '{path}' does not exist in '{git_ref}'"
                )),
            );
            self
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

        /// Queue a result for the next `ls_remote_refs` call.
        pub fn on_ls_remote_refs(&self, result: Result<Vec<RemoteRef>, PresetError>) -> &Self {
            self.ls_remote_refs_results.borrow_mut().push_back(result);
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

        fn ls_remote_refs(&self, url: &str) -> Result<Vec<RemoteRef>, PresetError> {
            self.calls.borrow_mut().push(GitCall::LsRemoteRefs {
                url: url.to_string(),
            });
            Self::pop_result(&self.ls_remote_refs_results)
        }

        fn show_file(
            &self,
            _repo_dir: &Path,
            git_ref: &str,
            path: &str,
        ) -> Result<String, PresetError> {
            self.calls.borrow_mut().push(GitCall::ShowFile {
                git_ref: git_ref.to_string(),
                path: path.to_string(),
            });
            let key = (git_ref.to_string(), path.to_string());
            // Prefer queued per-call outcomes so the upgrade path can stage a
            // sequence of different FETCH_HEAD contents.
            if let Some(queue) = self.show_file_queue.borrow_mut().get_mut(&key)
                && let Some(outcome) = queue.pop_front()
            {
                return match outcome {
                    ShowFileOutcome::Ok(content) => Ok(content),
                    ShowFileOutcome::Err(msg) => Err(PresetError::GitClone {
                        reference: format!("{git_ref}:{path}"),
                        message: msg,
                    }),
                };
            }
            match self.show_file_results.borrow().get(&key) {
                Some(ShowFileOutcome::Ok(content)) => Ok(content.clone()),
                Some(ShowFileOutcome::Err(msg)) => Err(PresetError::GitClone {
                    reference: format!("{git_ref}:{path}"),
                    message: msg.clone(),
                }),
                None => Err(PresetError::GitClone {
                    reference: format!("{git_ref}:{path}"),
                    message: "no mock result for show_file".to_string(),
                }),
            }
        }
    }
}
