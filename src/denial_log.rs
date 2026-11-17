use anyhow::{bail, Context, Result};
use codex_network_proxy::{BlockedRequest, BlockedRequestObserver, BlockedRequestObserverFuture};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct DenialLog {
    file: Mutex<Option<File>>,
    path: PathBuf,
    session: Option<String>,
}

impl DenialLog {
    pub fn open(session: Option<String>) -> Result<Self> {
        let path = crate::config::session_policy_path(session.as_deref().unwrap_or("no-session"))?
            .with_extension("proxy-denys.jsonl");
        Ok(Self {
            file: Mutex::new(None),
            path,
            session,
        })
    }

    fn open_file(path: &Path) -> Result<File> {
        let directory = path.parent().context("denial log path has no parent")?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .with_context(|| format!("create denial log directory {}", directory.display()))?;
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "denial log directory {} must be a real directory with mode 0700",
                directory.display()
            );
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            // Linux O_NOFOLLOW: never append audit events through a substituted symlink.
            .custom_flags(0x20000)
            .open(path)
            .with_context(|| format!("open denial log {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "denial log {} must be a regular file with mode 0600",
                path.display()
            );
        }
        Ok(file)
    }

    fn record(&self, request: BlockedRequest) -> Result<()> {
        let mut event = serde_json::to_value(request)?;
        event["session_id"] = serde_json::to_value(&self.session)?;
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("denial log lock poisoned"))?;
        if file.is_none() {
            *file = Some(Self::open_file(&self.path)?);
        }
        file.as_mut()
            .context("denial log was not opened")?
            .write_all(&line)
            .context("append proxy denial event")
    }
}

impl BlockedRequestObserver for DenialLog {
    fn on_blocked_request(&self, request: BlockedRequest) -> BlockedRequestObserverFuture<'_> {
        Box::pin(async move {
            if let Err(err) = self.record(request) {
                // Audit loss is a security failure; do not continue running an unlogged proxy.
                eprintln!("proxy denial logging failed: {err:#}");
                std::process::exit(1);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_does_not_create_a_file() {
        let log = DenialLog::open(Some(format!("lazy-test-{}", std::process::id()))).unwrap();
        assert!(log.file.lock().unwrap().is_none());
        assert!(!log.path.exists());
    }

    #[test]
    fn rejects_symlink_log() {
        let root = std::env::temp_dir().join(format!("pi-denial-log-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        std::os::unix::fs::symlink("/dev/null", root.join("denials.jsonl")).unwrap();
        assert!(DenialLog::open_file(&root.join("denials.jsonl")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
