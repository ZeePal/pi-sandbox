use anyhow::{Context, Result};
use codex_protocol::permissions::{
    FileSystemAccessMode, FileSystemPath, FileSystemSandboxEntry, FileSystemSandboxPolicy,
};
use codex_utils_path_uri::PathUri;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

fn protect_path(
    policy: &mut FileSystemSandboxPolicy,
    path: &Path,
    access: FileSystemAccessMode,
) -> Result<()> {
    // Missing children cannot be created beneath the read-only protected roots.
    if !path.try_exists()? {
        return Ok(());
    }
    let target = path
        .canonicalize()
        .with_context(|| format!("resolve protected path {}", path.display()))?;
    // Mount resolved paths: Bubblewrap cannot reliably mask a symlink itself.
    // The containing configuration trees are read-only, preventing retargeting.
    policy.entries.push(FileSystemSandboxEntry::new(
        FileSystemPath::Path {
            path: PathUri::from_host_native_path(&target)?,
        },
        access,
    ));
    Ok(())
}

/// Protect agent state and configuration, including symlink destinations.
pub fn protect_home(policy: &mut FileSystemSandboxPolicy, cwd: &Path) -> Result<()> {
    let home = std::env::var_os("HOME").context("HOME is required to protect agent state")?;
    protect_roots(policy, Path::new(&home), cwd)
}

fn protect_roots(policy: &mut FileSystemSandboxPolicy, home: &Path, cwd: &Path) -> Result<()> {
    for root in [home.join(".pi"), home.join(".dotfiles/pi")] {
        protect_path(policy, &root, FileSystemAccessMode::Read)?;
    }
    let sessions = home.join(".pi/agent/sessions");
    protect_config_targets(policy, &home.join(".pi"), &sessions, &mut HashSet::new())?;
    protect_sessions(policy, &sessions, cwd)
}

fn protect_sessions(
    policy: &mut FileSystemSandboxPolicy,
    sessions: &Path,
    cwd: &Path,
) -> Result<()> {
    use FileSystemAccessMode::Deny;
    // Pi's default folder encoding is lossy. Verify each session's header too,
    // so /a-b and /a/b cannot accidentally expose each other's conversations.
    let encoded = format!(
        "--{}--",
        cwd.to_string_lossy()
            .trim_start_matches('/')
            .replace(['/', '\\', ':'], "-")
    );
    for folder in read_entries(sessions)? {
        if folder.file_name().and_then(|name| name.to_str()) != Some(&encoded)
            || folder.symlink_metadata()?.file_type().is_symlink()
            || !folder.is_dir()
        {
            protect_path(policy, &folder, Deny)?;
            continue;
        }
        for file in read_entries(&folder)? {
            if !session_matches_workspace(&file, cwd)? {
                protect_path(policy, &file, Deny)?;
            }
        }
    }
    Ok(())
}

fn session_matches_workspace(path: &Path, cwd: &Path) -> Result<bool> {
    if !path.symlink_metadata()?.is_file()
        || path.extension().and_then(|ext| ext.to_str()) != Some("jsonl")
    {
        return Ok(false);
    }
    let file = std::fs::File::open(path)?;
    let mut header = String::new();
    // Only the metadata header is needed; never load conversation contents.
    BufReader::new(file).take(65536).read_line(&mut header)?;
    let Ok(header) = serde_json::from_str::<serde_json::Value>(&header) else {
        return Ok(false);
    };
    Ok(header["type"] == "session" && header["cwd"].as_str() == cwd.to_str())
}

fn read_entries(path: &Path) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("inspect protected directory {}", path.display()))
        }
    };
    entries.map(|entry| Ok(entry?.path())).collect()
}

fn protect_config_targets(
    policy: &mut FileSystemSandboxPolicy,
    path: &Path,
    sessions: &Path,
    seen: &mut HashSet<PathBuf>,
) -> Result<()> {
    if path == sessions
        || matches!((path.canonicalize(), sessions.canonicalize()),
        (Ok(target), Ok(root)) if target.starts_with(&root))
    {
        return Ok(());
    }
    let secret = matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("auth.json")
    );
    if secret {
        return protect_path(policy, path, FileSystemAccessMode::Deny);
    }
    protect_path(policy, path, FileSystemAccessMode::Read)?;
    if !path.is_dir() || !seen.insert(path.canonicalize()?) {
        return Ok(());
    }
    for entry in read_entries(path)? {
        protect_config_targets(policy, &entry, sessions, seen)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_optional_directories_add_no_rules() {
        let root = std::env::temp_dir().join(format!("pi-no-dotfiles-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut policy = FileSystemSandboxPolicy::workspace_write(&[], false, false);
        let original = policy.entries.clone();
        protect_roots(&mut policy, &root, &root).unwrap();
        assert_eq!(policy.entries, original);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn session_header_must_match_workspace() {
        let root = std::env::temp_dir().join(format!("pi-session-header-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("session.jsonl");
        std::fs::write(&path, r#"{"type":"session","cwd":"/a-b"}"#).unwrap();
        assert!(session_matches_workspace(&path, Path::new("/a-b")).unwrap());
        assert!(!session_matches_workspace(&path, Path::new("/a/b")).unwrap());
        std::fs::write(&path, "malformed").unwrap();
        assert!(!session_matches_workspace(&path, Path::new("/a-b")).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlink_targets_are_protected() {
        let root = std::env::temp_dir().join(format!("pi-protection-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".pi/agent")).unwrap();
        std::fs::write(root.join("secret"), "secret").unwrap();
        std::os::unix::fs::symlink(root.join("secret"), root.join(".pi/agent/auth.json")).unwrap();
        let mut policy = FileSystemSandboxPolicy::workspace_write(&[], false, false);
        protect_roots(&mut policy, &root, &root).unwrap();
        let target = FileSystemPath::Path {
            path: PathUri::from_host_native_path(root.join("secret")).unwrap(),
        };
        assert!(policy
            .entries
            .iter()
            .any(|e| e.path == target && e.access == FileSystemAccessMode::Deny));
        std::fs::remove_dir_all(root).unwrap();
    }
}
