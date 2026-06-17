use crate::types::{FsMode, NetMode, PolicyAction, PolicyScope};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SessionPolicyFile {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SandboxConfigFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetMode>,
    #[serde(default, skip_serializing_if = "NetworkProxyConfig::is_empty")]
    pub network_proxy: NetworkProxyConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NetworkProxyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    #[serde(default, alias = "allowLocal", skip_serializing_if = "Option::is_none")]
    pub allow_local: Option<bool>,
}

impl NetworkProxyConfig {
    fn is_empty(&self) -> bool {
        self.allow.is_none() && self.deny.is_none() && self.allow_local.is_none()
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub fs: Option<FsMode>,
    pub net: Option<NetMode>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_local: bool,
}

pub async fn load_effective_config(cwd: &Path) -> Result<EffectiveConfig> {
    let user_path = user_config_path()?;
    let project_path = project_config_path(cwd);
    let user = load_config_file(&user_path).await?;
    let project = load_config_file(&project_path).await?;

    let allow = project
        .network_proxy
        .allow
        .or(user.network_proxy.allow)
        .unwrap_or_default();
    let deny = project
        .network_proxy
        .deny
        .or(user.network_proxy.deny)
        .unwrap_or_default();
    let allow_local = project
        .network_proxy
        .allow_local
        .or(user.network_proxy.allow_local)
        .unwrap_or(false);

    validate_host_patterns(&allow)?;
    validate_host_patterns(&deny)?;

    Ok(EffectiveConfig {
        fs: project.fs.or(user.fs),
        net: project.net.or(user.net),
        allow,
        deny,
        allow_local,
    })
}

pub async fn set_policy(
    cwd: &Path,
    scope: PolicyScope,
    action: PolicyAction,
    host: &str,
    session: Option<&str>,
) -> Result<()> {
    validate_host_pattern(host)?;
    match scope {
        PolicyScope::Session => {
            let session = session.context("--session is required for session scope")?;
            let mut policy = load_session_policy(session).await?;
            update_policy_lists(&mut policy.allow, &mut policy.deny, action, host);
            save_session_policy(session, &policy).await
        }
        PolicyScope::Persistent => {
            let path = auto_persistent_policy_path(cwd)?;
            let mut cfg = load_config_file(&path).await?;
            let allow = cfg.network_proxy.allow.get_or_insert_with(Vec::new);
            let deny = cfg.network_proxy.deny.get_or_insert_with(Vec::new);
            update_policy_lists(allow, deny, action, host);
            save_config_file(&path, &cfg).await
        }
    }
}

pub(crate) async fn load_session_policy(session: &str) -> Result<SessionPolicyFile> {
    let path = session_policy_path(session)?;
    match fs::read_to_string(&path).await {
        Ok(content) => Ok(serde_json::from_str(&content)
            .with_context(|| format!("invalid session JSON in {}", path.display()))?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(SessionPolicyFile::default()),
        Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
    }
}

async fn load_config_file(path: &Path) -> Result<SandboxConfigFile> {
    match fs::read_to_string(path).await {
        Ok(content) => Ok(serde_json::from_str::<SandboxConfigFile>(&content)
            .with_context(|| format!("invalid config JSON in {}", path.display()))?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(SandboxConfigFile::default()),
        Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
    }
}

async fn save_config_file(path: &Path, config: &SandboxConfigFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
        set_mode(parent, 0o700).await?;
    }

    let content = serde_json::to_string_pretty(config)? + "\n";
    fs::write(path, content)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    set_mode(path, 0o600).await?;
    Ok(())
}

async fn save_session_policy(session: &str, policy: &SessionPolicyFile) -> Result<()> {
    let dir = session_policy_dir()?;
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create {}", dir.display()))?;
    set_mode(&dir, 0o700).await?;

    let path = session_policy_path(session)?;
    let content = serde_json::to_string_pretty(policy)? + "\n";
    fs::write(&path, content)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    set_mode(&path, 0o600).await?;
    Ok(())
}

fn user_config_path() -> Result<PathBuf> {
    Ok(agent_dir()?.join("sandbox.json"))
}

fn session_policy_dir() -> Result<PathBuf> {
    Ok(agent_dir()?.join("sandbox-sessions"))
}

fn session_policy_path(session: &str) -> Result<PathBuf> {
    let safe = session
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    Ok(session_policy_dir()?.join(format!("{safe}.json")))
}

fn agent_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".pi").join("agent"))
}

fn project_config_path(cwd: &Path) -> PathBuf {
    discover_project_root(cwd).join(".pi").join("sandbox.json")
}

fn auto_persistent_policy_path(cwd: &Path) -> Result<PathBuf> {
    let project_root = discover_project_root(cwd);
    let has_project_marker = project_root.join(".git").exists()
        || project_root.join(".pi").exists()
        || project_root != cwd;
    if has_project_marker {
        Ok(project_root.join(".pi").join("sandbox.json"))
    } else {
        user_config_path()
    }
}

fn discover_project_root(cwd: &Path) -> PathBuf {
    for ancestor in cwd.ancestors() {
        if ancestor.join(".pi").exists() || ancestor.join(".git").exists() {
            return ancestor.to_path_buf();
        }
    }
    cwd.to_path_buf()
}

fn update_policy_lists(
    allow: &mut Vec<String>,
    deny: &mut Vec<String>,
    action: PolicyAction,
    host: &str,
) {
    allow.retain(|item| item != host);
    deny.retain(|item| item != host);
    match action {
        PolicyAction::Allow => allow.push(host.to_string()),
        PolicyAction::Deny => deny.push(host.to_string()),
    }
}

fn validate_host_patterns(hosts: &[String]) -> Result<()> {
    for host in hosts {
        validate_host_pattern(host)?;
    }
    Ok(())
}

fn validate_host_pattern(host: &str) -> Result<()> {
    if host.trim().is_empty() {
        bail!("host pattern cannot be empty")
    }
    if host.trim() == "*" {
        bail!("global '*' wildcard is not allowed")
    }
    Ok(())
}

async fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let permissions = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)
            .await
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, mode);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("pi-sandbox-config-{label}-{nonce}"))
    }

    #[test]
    fn reads_new_top_level_config_shape() {
        let config = serde_json::from_str::<SandboxConfigFile>(
            r#"{
                "fs": "write",
                "net": "none",
                "network_proxy": {
                    "allow": ["github.com"],
                    "deny": ["example.com"],
                    "allow_local": false
                }
            }"#,
        )
        .unwrap();

        assert_eq!(config.fs, Some(FsMode::Write));
        assert_eq!(config.net, Some(NetMode::None));
        assert_eq!(
            config.network_proxy.allow,
            Some(vec!["github.com".to_string()])
        );
        assert_eq!(
            config.network_proxy.deny,
            Some(vec!["example.com".to_string()])
        );
        assert_eq!(config.network_proxy.allow_local, Some(false));
    }

    #[test]
    fn reads_camel_case_allow_local() {
        let config = serde_json::from_str::<SandboxConfigFile>(
            r#"{
                "network_proxy": {
                    "allowLocal": true
                }
            }"#,
        )
        .unwrap();

        assert_eq!(config.network_proxy.allow_local, Some(true));
    }

    #[tokio::test]
    async fn resolves_global_and_project_defaults() {
        let home = temp_home("defaults");
        let project = home.join("project");
        std::fs::create_dir_all(home.join(".pi/agent")).unwrap();
        std::fs::create_dir_all(project.join(".pi")).unwrap();
        std::fs::write(
            home.join(".pi/agent/sandbox.json"),
            r#"{
                "fs": "readonly",
                "net": "none",
                "network_proxy": {
                    "allow": ["global.example.com"],
                    "allowLocal": true
                }
            }"#,
        )
        .unwrap();
        std::fs::write(
            project.join(".pi/sandbox.json"),
            r#"{
                "fs": "write",
                "net": "restricted",
                "network_proxy": {
                    "allow": ["project.example.com"],
                    "deny": ["blocked.example.com"]
                }
            }"#,
        )
        .unwrap();

        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);
        let config = load_effective_config(&project).await.unwrap();
        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(config.fs, Some(FsMode::Write));
        assert_eq!(config.net, Some(NetMode::Restricted));
        assert_eq!(config.allow, vec!["project.example.com".to_string()]);
        assert_eq!(config.deny, vec!["blocked.example.com".to_string()]);
        assert!(config.allow_local);
        let _ = std::fs::remove_dir_all(home);
    }
}
