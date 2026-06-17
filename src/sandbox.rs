use crate::approval::{
    ApprovalBroker, ApprovalDecision, ApprovalKey, ApprovalRequest, ExecutionCancellation,
    PromptApprovalBroker,
};
use crate::config::{load_effective_config, load_session_policy, set_policy, EffectiveConfig};
use crate::internal_tools::{dispatch_internal_tool, tool_error_json, InternalToolName};
use crate::text::{truncate_tail_text, MAX_TOOL_TEXT_BYTES, MAX_TOOL_TEXT_LINES};
use crate::types::{ApprovalMode, FsMode, NetMode, PolicyAction, PolicyScope, RuntimeOptions};
use anyhow::{anyhow, bail, Context, Result};
#[cfg(test)]
use async_trait::async_trait;
use codex_network_proxy::{
    build_config_state, ConfigReloader, ConfigReloaderFuture, ConfigState, NetworkDecision,
    NetworkPolicyDecider, NetworkPolicyDeciderFuture, NetworkPolicyRequest, NetworkProtocol,
    NetworkProxy, NetworkProxyConfig, NetworkProxyConstraints, NetworkProxyState, PROXY_ENV_KEYS,
};
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::{
    FileSystemAccessMode, FileSystemPath, FileSystemSandboxEntry, FileSystemSandboxPolicy,
    FileSystemSpecialPath, NetworkSandboxPolicy,
};
use codex_sandboxing::find_system_bwrap_in_path;
use codex_sandboxing::landlock::{
    allow_network_for_proxy, create_linux_sandbox_command_args_for_permission_profile,
    CODEX_LINUX_SANDBOX_ARG0,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;

#[derive(Debug, Deserialize)]
struct BashToolInput {
    command: String,
    timeout: Option<u64>,
}

#[derive(Debug)]
struct CommandCapture {
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
}

struct NoopReloader;

impl ConfigReloader for NoopReloader {
    fn source_label(&self) -> String {
        "pi-sandbox static config".to_string()
    }

    fn maybe_reload(&self) -> ConfigReloaderFuture<'_, Option<ConfigState>> {
        Box::pin(async { Ok(None) })
    }

    fn reload_now(&self) -> ConfigReloaderFuture<'_, ConfigState> {
        Box::pin(async { Err(anyhow!("reload is not supported")) })
    }
}

struct ManagedProxyRuntime {
    proxy: NetworkProxy,
    handle: codex_network_proxy::NetworkProxyHandle,
}

impl ManagedProxyRuntime {
    async fn shutdown(self) {
        let _ = self.handle.shutdown().await;
    }
}

struct PendingApproval {
    result: Mutex<Option<Result<ApprovalDecision, String>>>,
    notify: Notify,
}

impl Default for PendingApproval {
    fn default() -> Self {
        Self {
            result: Mutex::new(None),
            notify: Notify::new(),
        }
    }
}

struct ApprovalManager {
    cwd: PathBuf,
    session: Option<String>,
    allow_once_hosts: Mutex<HashSet<String>>,
    pending: Mutex<HashMap<ApprovalKey, Arc<PendingApproval>>>,
    broker: Arc<dyn ApprovalBroker>,
}

impl ApprovalManager {
    fn new(options: &RuntimeOptions, broker: Arc<dyn ApprovalBroker>) -> Self {
        Self {
            cwd: options.cwd.clone(),
            session: options.session.clone(),
            allow_once_hosts: Mutex::new(options.allow_once_hosts.iter().cloned().collect()),
            pending: Mutex::new(HashMap::new()),
            broker,
        }
    }

    async fn decide_request(&self, request: NetworkPolicyRequest) -> Result<ApprovalDecision> {
        if self.is_host_allowed(&request.host).await {
            return Ok(ApprovalDecision::AllowOnce);
        }

        let approval_request = approval_request_from_policy_request(&request);
        let (pending, is_owner) = {
            let mut pending = self.pending.lock().await;
            if let Some(existing) = pending.get(&approval_request.key) {
                (Arc::clone(existing), false)
            } else {
                let entry = Arc::new(PendingApproval::default());
                pending.insert(approval_request.key.clone(), Arc::clone(&entry));
                (entry, true)
            }
        };

        if is_owner {
            let outcome = self.resolve_owner_request(&approval_request).await;
            {
                let mut slot = pending.result.lock().await;
                *slot = Some(outcome.clone());
            }
            self.pending.lock().await.remove(&approval_request.key);
            pending.notify.notify_waiters();
            outcome.map_err(|err| anyhow!(err))
        } else {
            loop {
                if let Some(result) = pending.result.lock().await.clone() {
                    return result.map_err(|err| anyhow!(err));
                }
                pending.notify.notified().await;
            }
        }
    }

    async fn resolve_owner_request(
        &self,
        request: &ApprovalRequest,
    ) -> std::result::Result<ApprovalDecision, String> {
        let result = async {
            let decision = self.broker.request_approval(request).await?;
            self.apply_decision(request, decision).await?;
            Ok(decision)
        }
        .await;

        if result.is_err() {
            if let Some(cancellation) = self.broker.cancellation() {
                cancellation.cancel();
            }
        }

        result.map_err(|err: anyhow::Error| err.to_string())
    }

    async fn apply_decision(
        &self,
        request: &ApprovalRequest,
        decision: ApprovalDecision,
    ) -> Result<()> {
        match decision {
            ApprovalDecision::AllowOnce => {
                self.allow_once_hosts
                    .lock()
                    .await
                    .insert(request.key.host.clone());
            }
            ApprovalDecision::AllowForSession => {
                let session = self
                    .session
                    .as_deref()
                    .context("allow for session requires --session")?;
                set_policy(
                    &self.cwd,
                    PolicyScope::Session,
                    PolicyAction::Allow,
                    &request.key.host,
                    Some(session),
                )
                .await?;
                self.allow_once_hosts
                    .lock()
                    .await
                    .insert(request.key.host.clone());
            }
            ApprovalDecision::AlwaysAllow => {
                set_policy(
                    &self.cwd,
                    PolicyScope::Persistent,
                    PolicyAction::Allow,
                    &request.key.host,
                    None,
                )
                .await?;
                self.allow_once_hosts
                    .lock()
                    .await
                    .insert(request.key.host.clone());
            }
            ApprovalDecision::Deny => {}
        }
        Ok(())
    }

    async fn is_host_allowed(&self, host: &str) -> bool {
        self.allow_once_hosts.lock().await.contains(host)
    }
}

impl NetworkPolicyDecider for ApprovalManager {
    fn decide(&self, request: NetworkPolicyRequest) -> NetworkPolicyDeciderFuture<'_> {
        Box::pin(async move {
            match self.decide_request(request).await {
                Ok(ApprovalDecision::AllowOnce)
                | Ok(ApprovalDecision::AllowForSession)
                | Ok(ApprovalDecision::AlwaysAllow) => NetworkDecision::Allow,
                Ok(ApprovalDecision::Deny) => NetworkDecision::deny("not_allowed"),
                Err(err) => {
                    eprintln!("network approval flow failed: {err:#}");
                    NetworkDecision::deny("approval_runtime_error")
                }
            }
        })
    }
}

pub fn is_linux_sandbox_helper_invocation(args: &[String]) -> bool {
    args.first()
        .and_then(|arg0| Path::new(arg0).file_name())
        .and_then(|name| name.to_str())
        .map(|name| name == CODEX_LINUX_SANDBOX_ARG0)
        .unwrap_or(false)
}

pub async fn run_command(command: Vec<String>, options: RuntimeOptions) -> Result<i32> {
    if command.is_empty() {
        bail!("no command provided")
    }

    if direct_passthrough_mode(&options) {
        return execute_command_direct_inherit(command, &options).await;
    }

    let base_config = load_effective_config(&options.cwd).await?;
    let approval_manager = build_approval_manager(&options);
    let exit_code = execute_command_inherit(command, &options, &base_config, approval_manager)
        .await
        .context("sandboxed command failed")?;
    Ok(exit_code)
}

pub async fn run_tool_bash(payload_json: &str, options: RuntimeOptions) -> Result<Value> {
    let input: BashToolInput =
        serde_json::from_str(payload_json).context("invalid bash tool input")?;
    if direct_passthrough_mode(&options) {
        let capture = execute_command_direct_capture(
            vec!["bash".to_string(), "-lc".to_string(), input.command.clone()],
            None,
            input.timeout.map(Duration::from_secs),
            &options,
        )
        .await?;
        return Ok(bash_result_json(capture));
    }

    let base_config = load_effective_config(&options.cwd).await?;
    let approval_manager = build_approval_manager(&options);
    let capture = execute_command_capture(
        vec!["bash".to_string(), "-lc".to_string(), input.command.clone()],
        None,
        input.timeout.map(Duration::from_secs),
        &options,
        &base_config,
        approval_manager,
    )
    .await?;

    Ok(bash_result_json(capture))
}

pub async fn run_tool_via_internal(
    name: InternalToolName,
    payload_json: &str,
    options: RuntimeOptions,
) -> Result<Value> {
    let tool_options = internal_tool_runtime_options(name, options);
    if direct_passthrough_mode(&tool_options) {
        return Ok(dispatch_internal_tool(
            name,
            payload_json,
            &tool_options.cwd,
        ));
    }

    let command = vec![
        current_exe_string()?,
        "__internal-tool".to_string(),
        name.as_str().to_string(),
    ];

    let capture = execute_command_capture(
        command,
        Some(payload_json.as_bytes().to_vec()),
        None,
        &tool_options,
        &load_effective_config(&tool_options.cwd).await?,
        None,
    )
    .await?;

    if capture.exit_code != 0 {
        let message = if capture.stderr.trim().is_empty() {
            format!("internal tool exited with code {}", capture.exit_code)
        } else {
            capture.stderr.trim().to_string()
        };
        return Ok(tool_error_json(&message));
    }

    serde_json::from_str(&capture.stdout).context("internal tool returned invalid JSON")
}

async fn execute_command_capture(
    command: Vec<String>,
    stdin_bytes: Option<Vec<u8>>,
    timeout_duration: Option<Duration>,
    options: &RuntimeOptions,
    config: &EffectiveConfig,
    approval_manager: Option<Arc<ApprovalManager>>,
) -> Result<CommandCapture> {
    ensure_bwrap_available()?;

    let permission_profile = permission_profile(options.fs, options.net, &options.cwd);
    let mut env = current_env_without_proxy();
    let mut proxy_runtime = None;

    if options.net == NetMode::Restricted {
        let proxy = start_managed_proxy(options, config, approval_manager).await?;
        proxy.proxy.apply_to_env(&mut env);
        proxy_runtime = Some(proxy);
    }

    let helper_args = create_linux_sandbox_command_args_for_permission_profile(
        command,
        &options.cwd,
        &permission_profile,
        &options.cwd,
        false,
        allow_network_for_proxy(options.net == NetMode::Restricted),
    );

    let mut child = Command::new(std::env::current_exe()?);
    child.arg0(CODEX_LINUX_SANDBOX_ARG0);
    child.args(helper_args);
    child.current_dir(&options.cwd);
    child.env_clear();
    child.envs(
        env.into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    );
    child.stdin(Stdio::piped());
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());
    child.kill_on_drop(true);

    let mut child = child.spawn().context("failed to spawn sandbox helper")?;

    if let Some(bytes) = stdin_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            tokio::spawn(async move {
                let _ = stdin.write_all(&bytes).await;
                let _ = stdin.shutdown().await;
            });
        }
    } else {
        drop(child.stdin.take());
    }

    let mut stdout_reader = child.stdout.take().context("missing child stdout")?;
    let mut stderr_reader = child.stderr.take().context("missing child stderr")?;

    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stdout_reader.read_to_end(&mut buf).await?;
        Result::<Vec<u8>>::Ok(buf)
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stderr_reader.read_to_end(&mut buf).await?;
        Result::<Vec<u8>>::Ok(buf)
    });

    let (status, timed_out) = wait_for_child(
        &mut child,
        timeout_duration,
        options.execution_cancellation.clone(),
    )
    .await?;

    let stdout = String::from_utf8_lossy(&stdout_task.await??).to_string();
    let stderr = String::from_utf8_lossy(&stderr_task.await??).to_string();

    if let Some(proxy) = proxy_runtime {
        proxy.shutdown().await;
    }

    Ok(CommandCapture {
        stdout,
        stderr,
        exit_code: status.code().unwrap_or(1),
        timed_out,
    })
}

async fn execute_command_inherit(
    command: Vec<String>,
    options: &RuntimeOptions,
    config: &EffectiveConfig,
    approval_manager: Option<Arc<ApprovalManager>>,
) -> Result<i32> {
    ensure_bwrap_available()?;

    let permission_profile = permission_profile(options.fs, options.net, &options.cwd);
    let mut env = current_env_without_proxy();
    let mut proxy_runtime = None;

    if options.net == NetMode::Restricted {
        let proxy = start_managed_proxy(options, config, approval_manager).await?;
        proxy.proxy.apply_to_env(&mut env);
        proxy_runtime = Some(proxy);
    }

    let helper_args = create_linux_sandbox_command_args_for_permission_profile(
        command,
        &options.cwd,
        &permission_profile,
        &options.cwd,
        false,
        allow_network_for_proxy(options.net == NetMode::Restricted),
    );

    #[cfg(unix)]
    if proxy_runtime.is_none() {
        exec_sandbox_helper_inherit(helper_args.clone(), &options.cwd, env.clone())?;
    }

    let mut child = Command::new(std::env::current_exe()?);
    child.arg0(CODEX_LINUX_SANDBOX_ARG0);
    child.args(helper_args);
    child.current_dir(&options.cwd);
    child.env_clear();
    child.envs(
        env.into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    );
    child.stdin(Stdio::inherit());
    child.stdout(Stdio::inherit());
    child.stderr(Stdio::inherit());
    child.kill_on_drop(true);

    let mut child = child.spawn().context("failed to spawn sandbox helper")?;
    let (status, _timed_out) =
        wait_for_child(&mut child, None, options.execution_cancellation.clone()).await?;

    if let Some(proxy) = proxy_runtime {
        proxy.shutdown().await;
    }

    Ok(status.code().unwrap_or(1))
}

async fn wait_for_child(
    child: &mut tokio::process::Child,
    timeout_duration: Option<Duration>,
    cancellation: Option<Arc<ExecutionCancellation>>,
) -> Result<(ExitStatus, bool)> {
    match (timeout_duration, cancellation) {
        (None, None) => Ok((child.wait().await?, false)),
        (Some(duration), None) => match timeout(duration, child.wait()).await {
            Ok(status) => Ok((status?, false)),
            Err(_) => {
                let _ = child.kill().await;
                Ok((child.wait().await?, true))
            }
        },
        (None, Some(cancellation)) => {
            tokio::select! {
                status = child.wait() => Ok((status?, false)),
                _ = cancellation.cancelled() => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    bail!("approval controller disconnected")
                }
            }
        }
        (Some(duration), Some(cancellation)) => {
            let sleep = tokio::time::sleep(duration);
            tokio::pin!(sleep);
            tokio::select! {
                status = child.wait() => Ok((status?, false)),
                _ = cancellation.cancelled() => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    bail!("approval controller disconnected")
                }
                _ = &mut sleep => {
                    let _ = child.kill().await;
                    Ok((child.wait().await?, true))
                }
            }
        }
    }
}

async fn execute_command_direct_capture(
    command: Vec<String>,
    stdin_bytes: Option<Vec<u8>>,
    timeout_duration: Option<Duration>,
    options: &RuntimeOptions,
) -> Result<CommandCapture> {
    let mut child = Command::new(command.first().context("no command provided")?);
    child.args(command.iter().skip(1));
    child.current_dir(&options.cwd);
    child.stdin(Stdio::piped());
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());
    child.kill_on_drop(true);

    let mut child = child.spawn().context("failed to spawn command")?;

    if let Some(bytes) = stdin_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            tokio::spawn(async move {
                let _ = stdin.write_all(&bytes).await;
                let _ = stdin.shutdown().await;
            });
        }
    } else {
        drop(child.stdin.take());
    }

    let mut stdout_reader = child.stdout.take().context("missing child stdout")?;
    let mut stderr_reader = child.stderr.take().context("missing child stderr")?;
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stdout_reader.read_to_end(&mut buf).await?;
        Result::<Vec<u8>>::Ok(buf)
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stderr_reader.read_to_end(&mut buf).await?;
        Result::<Vec<u8>>::Ok(buf)
    });

    let (status, timed_out) = match timeout_duration {
        Some(duration) => match timeout(duration, child.wait()).await {
            Ok(status) => (status?, false),
            Err(_) => {
                let _ = child.kill().await;
                (child.wait().await?, true)
            }
        },
        None => (child.wait().await?, false),
    };

    Ok(CommandCapture {
        stdout: String::from_utf8_lossy(&stdout_task.await??).to_string(),
        stderr: String::from_utf8_lossy(&stderr_task.await??).to_string(),
        exit_code: status.code().unwrap_or(1),
        timed_out,
    })
}

async fn execute_command_direct_inherit(
    command: Vec<String>,
    options: &RuntimeOptions,
) -> Result<i32> {
    #[cfg(unix)]
    exec_direct_command_inherit(command.clone(), &options.cwd)?;

    let mut child = Command::new(command.first().context("no command provided")?);
    child.args(command.iter().skip(1));
    child.current_dir(&options.cwd);
    child.stdin(Stdio::inherit());
    child.stdout(Stdio::inherit());
    child.stderr(Stdio::inherit());
    child.kill_on_drop(true);

    let status = child
        .spawn()
        .context("failed to spawn command")?
        .wait()
        .await?;
    Ok(status.code().unwrap_or(1))
}

async fn start_managed_proxy(
    options: &RuntimeOptions,
    config: &EffectiveConfig,
    approval_manager: Option<Arc<ApprovalManager>>,
) -> Result<ManagedProxyRuntime> {
    let mut allowed = config.allow.clone();
    let mut denied = config.deny.clone();
    if let Some(session) = options.session.as_deref() {
        let session_policy = load_session_policy(session).await?;
        allowed.extend(session_policy.allow);
        denied.extend(session_policy.deny);
    }
    allowed.extend(options.allow_once_hosts.iter().cloned());

    let mut domains = serde_json::Map::new();
    for host in allowed {
        domains.insert(host, Value::String("allow".to_string()));
    }
    for host in denied {
        domains.insert(host, Value::String("deny".to_string()));
    }

    let config: NetworkProxyConfig = serde_json::from_value(json!({
        "network": {
            "enabled": true,
            "mode": "full",
            "allow_local_binding": config.allow_local,
            "domains": Value::Object(domains),
        }
    }))?;
    let state = build_config_state(config, NetworkProxyConstraints::default())?;
    let state = Arc::new(NetworkProxyState::with_reloader(
        state,
        Arc::new(NoopReloader),
    ));

    let mut builder = NetworkProxy::builder().state(state);
    if let Some(manager) = approval_manager {
        let decider: Arc<dyn NetworkPolicyDecider> = manager;
        builder = builder.policy_decider_arc(decider);
    }
    let proxy = builder.build().await?;
    let handle = proxy.run().await?;

    Ok(ManagedProxyRuntime { proxy, handle })
}

fn build_approval_manager(options: &RuntimeOptions) -> Option<Arc<ApprovalManager>> {
    if options.net != NetMode::Restricted {
        return None;
    }

    let broker: Option<Arc<dyn ApprovalBroker>> = match options.approval {
        ApprovalMode::Prompt => Some(Arc::new(PromptApprovalBroker)),
        ApprovalMode::External => options.approval_broker.clone(),
        ApprovalMode::Deny => None,
    };

    broker.map(|broker| Arc::new(ApprovalManager::new(options, broker)))
}

fn approval_request_from_policy_request(request: &NetworkPolicyRequest) -> ApprovalRequest {
    let display_protocol = protocol_display(request.protocol).to_string();
    let normalized_protocol = protocol_id_component(request.protocol).to_string();
    ApprovalRequest::new(
        request.host.clone(),
        display_protocol,
        normalized_protocol,
        request.port,
    )
}

fn protocol_display(protocol: NetworkProtocol) -> &'static str {
    match protocol {
        NetworkProtocol::Http => "http",
        NetworkProtocol::HttpsConnect => "https_connect",
        NetworkProtocol::Socks5Tcp => "socks5_tcp",
        NetworkProtocol::Socks5Udp => "socks5_udp",
    }
}

fn protocol_id_component(protocol: NetworkProtocol) -> &'static str {
    protocol_display(protocol)
}

fn internal_tool_runtime_options(
    name: InternalToolName,
    mut options: RuntimeOptions,
) -> RuntimeOptions {
    if !matches!(options.net, NetMode::Unrestricted) {
        options.net = NetMode::None;
    }
    if is_readonly_internal_tool(name) && !matches!(options.fs, FsMode::Unrestricted) {
        options.fs = FsMode::Readonly;
    }
    options
}

fn is_readonly_internal_tool(name: InternalToolName) -> bool {
    matches!(
        name,
        InternalToolName::Read
            | InternalToolName::Ls
            | InternalToolName::Find
            | InternalToolName::Grep
    )
}

fn bash_result_json(capture: CommandCapture) -> Value {
    let (stdout, stdout_truncated) =
        truncate_tail_text(&capture.stdout, MAX_TOOL_TEXT_LINES, MAX_TOOL_TEXT_BYTES);
    let (stderr, stderr_truncated) =
        truncate_tail_text(&capture.stderr, MAX_TOOL_TEXT_LINES, MAX_TOOL_TEXT_BYTES);
    json!({
        "ok": true,
        "stdout": stdout,
        "stderr": stderr,
        "exitCode": capture.exit_code,
        "truncated": stdout_truncated || stderr_truncated,
        "timedOut": capture.timed_out,
    })
}

fn permission_profile(fs_mode: FsMode, net_mode: NetMode, cwd: &Path) -> PermissionProfile {
    if matches!(fs_mode, FsMode::Unrestricted) && matches!(net_mode, NetMode::Unrestricted) {
        return PermissionProfile::Disabled;
    }

    let network = match net_mode {
        NetMode::None => NetworkSandboxPolicy::Restricted,
        NetMode::Unrestricted | NetMode::Restricted => NetworkSandboxPolicy::Enabled,
    };

    let file_system = match fs_mode {
        FsMode::Readonly => FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        }]),
        FsMode::Write => {
            let mut policy = FileSystemSandboxPolicy::workspace_write(&[], false, false);
            if cwd.join(".pi").exists() {
                policy.entries.push(FileSystemSandboxEntry {
                    path: FileSystemPath::Special {
                        value: FileSystemSpecialPath::project_roots(Some(
                            std::path::PathBuf::from(".pi"),
                        )),
                    },
                    access: FileSystemAccessMode::Read,
                });
            }
            policy
        }
        FsMode::Unrestricted => FileSystemSandboxPolicy::unrestricted(),
    };

    PermissionProfile::from_runtime_permissions(&file_system, network)
}

fn current_env_without_proxy() -> HashMap<String, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    for key in PROXY_ENV_KEYS {
        env.remove(*key);
    }
    env
}

fn current_exe_string() -> Result<String> {
    Ok(std::env::current_exe()?
        .to_str()
        .context("current executable path is not valid UTF-8")?
        .to_string())
}

#[cfg(unix)]
fn exec_sandbox_helper_inherit(
    helper_args: Vec<String>,
    cwd: &Path,
    env: HashMap<String, String>,
) -> Result<i32> {
    let mut child = std::process::Command::new(std::env::current_exe()?);
    child.arg0(CODEX_LINUX_SANDBOX_ARG0);
    child.args(helper_args);
    child.current_dir(cwd);
    child.env_clear();
    child.envs(
        env.into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    );
    child.stdin(Stdio::inherit());
    child.stdout(Stdio::inherit());
    child.stderr(Stdio::inherit());

    Err(child.exec()).context("failed to exec sandbox helper")
}

#[cfg(unix)]
fn exec_direct_command_inherit(command: Vec<String>, cwd: &Path) -> Result<i32> {
    let mut child = std::process::Command::new(command.first().context("no command provided")?);
    child.args(command.iter().skip(1));
    child.current_dir(cwd);
    child.stdin(Stdio::inherit());
    child.stdout(Stdio::inherit());
    child.stderr(Stdio::inherit());

    Err(child.exec()).context("failed to exec command")
}

fn ensure_bwrap_available() -> Result<()> {
    if find_system_bwrap_in_path().is_none() {
        bail!("bubblewrap (bwrap) is required but was not found in PATH")
    }
    Ok(())
}

fn direct_passthrough_mode(options: &RuntimeOptions) -> bool {
    matches!(options.fs, FsMode::Unrestricted) && matches!(options.net, NetMode::Unrestricted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::{sleep, Duration};

    #[derive(Clone)]
    struct CountingBroker {
        decision: ApprovalDecision,
        calls: Arc<AtomicUsize>,
        delay: Duration,
    }

    #[async_trait]
    impl ApprovalBroker for CountingBroker {
        async fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            sleep(self.delay).await;
            Ok(self.decision)
        }
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pi-sandbox-{label}-{nonce}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn test_request(host: &str, protocol: NetworkProtocol, port: u16) -> NetworkPolicyRequest {
        NetworkPolicyRequest {
            protocol,
            host: host.to_string(),
            port,
            client_addr: None,
            method: None,
            command: None,
            exec_policy_hint: None,
        }
    }

    fn runtime_options(fs: FsMode, net: NetMode) -> RuntimeOptions {
        RuntimeOptions {
            fs,
            net,
            cwd: temp_test_dir("runtime-options"),
            session: None,
            approval: ApprovalMode::Deny,
            allow_once_hosts: Vec::new(),
            approval_broker: None,
            execution_cancellation: None,
        }
    }

    #[test]
    fn readonly_internal_tools_drop_to_readonly_and_no_network() {
        let options = internal_tool_runtime_options(
            InternalToolName::Read,
            runtime_options(FsMode::Write, NetMode::Restricted),
        );
        assert_eq!(options.fs, FsMode::Readonly);
        assert_eq!(options.net, NetMode::None);
    }

    #[test]
    fn unrestricted_internal_tools_stay_unrestricted() {
        let options = internal_tool_runtime_options(
            InternalToolName::Grep,
            runtime_options(FsMode::Unrestricted, NetMode::Unrestricted),
        );
        assert_eq!(options.fs, FsMode::Unrestricted);
        assert_eq!(options.net, NetMode::Unrestricted);
    }

    #[tokio::test]
    async fn pending_approval_dedupes_same_target() {
        let calls = Arc::new(AtomicUsize::new(0));
        let broker: Arc<dyn ApprovalBroker> = Arc::new(CountingBroker {
            decision: ApprovalDecision::AllowOnce,
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(50),
        });
        let manager = Arc::new(ApprovalManager {
            cwd: temp_test_dir("dedupe"),
            session: None,
            allow_once_hosts: Mutex::new(HashSet::new()),
            pending: Mutex::new(HashMap::new()),
            broker,
        });

        let first = manager.decide(test_request("google.com", NetworkProtocol::Http, 80));
        let second = manager.decide(test_request("google.com", NetworkProtocol::Http, 80));
        let (left, right) = tokio::join!(first, second);

        assert!(matches!(left, NetworkDecision::Allow));
        assert!(matches!(right, NetworkDecision::Allow));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_hosts_do_not_dedupe() {
        let calls = Arc::new(AtomicUsize::new(0));
        let broker: Arc<dyn ApprovalBroker> = Arc::new(CountingBroker {
            decision: ApprovalDecision::AllowOnce,
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(50),
        });
        let manager = Arc::new(ApprovalManager {
            cwd: temp_test_dir("distinct-hosts"),
            session: None,
            allow_once_hosts: Mutex::new(HashSet::new()),
            pending: Mutex::new(HashMap::new()),
            broker,
        });

        let first = manager.decide(test_request("google.com", NetworkProtocol::Http, 80));
        let second = manager.decide(test_request("yahoo.com", NetworkProtocol::Http, 80));
        let (left, right) = tokio::join!(first, second);

        assert!(matches!(left, NetworkDecision::Allow));
        assert!(matches!(right, NetworkDecision::Allow));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn allow_once_updates_current_process_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let broker: Arc<dyn ApprovalBroker> = Arc::new(CountingBroker {
            decision: ApprovalDecision::AllowOnce,
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(1),
        });
        let manager = Arc::new(ApprovalManager {
            cwd: temp_test_dir("allow-once-cache"),
            session: None,
            allow_once_hosts: Mutex::new(HashSet::new()),
            pending: Mutex::new(HashMap::new()),
            broker,
        });

        let first = manager
            .decide(test_request("google.com", NetworkProtocol::Http, 80))
            .await;
        let second = manager
            .decide(test_request(
                "google.com",
                NetworkProtocol::HttpsConnect,
                443,
            ))
            .await;

        assert!(matches!(first, NetworkDecision::Allow));
        assert!(matches!(second, NetworkDecision::Allow));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
