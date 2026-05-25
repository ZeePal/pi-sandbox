use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex, Notify};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ApprovalKey {
    pub host: String,
    pub protocol: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct ApprovalRequest {
    pub id: String,
    pub key: ApprovalKey,
    pub display_protocol: String,
}

impl ApprovalRequest {
    pub(crate) fn new(
        host: String,
        display_protocol: String,
        normalized_protocol: String,
        port: u16,
    ) -> Self {
        let id = format!("network#{normalized_protocol}#{host}#{port}");
        Self {
            id,
            key: ApprovalKey {
                host,
                protocol: normalized_protocol,
                port,
            },
            display_protocol,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalDecision {
    AllowOnce,
    AllowForSession,
    AlwaysAllow,
    Deny,
}

impl ApprovalDecision {
    pub(crate) fn from_external(value: &str) -> Result<Self> {
        match value {
            "allow_once" => Ok(Self::AllowOnce),
            "allow_for_session" => Ok(Self::AllowForSession),
            "always_allow" => Ok(Self::AlwaysAllow),
            "deny" => Ok(Self::Deny),
            other => bail!("invalid approval decision: {other}"),
        }
    }
}

#[async_trait]
pub(crate) trait ApprovalBroker: Send + Sync + 'static {
    async fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision>;

    fn cancellation(&self) -> Option<Arc<ExecutionCancellation>> {
        None
    }
}

#[derive(Default)]
pub(crate) struct ExecutionCancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

impl ExecutionCancellation {
    pub(crate) fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub(crate) async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }
}

#[derive(Default)]
pub(crate) struct PromptApprovalBroker;

#[async_trait]
impl ApprovalBroker for PromptApprovalBroker {
    async fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        let request = request.clone();
        tokio::task::spawn_blocking(move || prompt_for_approval_blocking(&request))
            .await
            .map_err(|err| anyhow!("approval prompt task failed: {err}"))?
    }
}

fn prompt_for_approval_blocking(request: &ApprovalRequest) -> Result<ApprovalDecision> {
    let prompt = format!(
        "Network access requested:\n  host: {}\n  protocol: {}\n  port: {}\n\nChoose:\n  [1] allow once\n  [2] allow for session\n  [3] always allow\n  [4] deny\n",
        request.key.host, request.display_protocol, request.key.port
    );

    let mut line = String::new();
    if let (Ok(mut tty_out), Ok(tty_in)) = (
        std::fs::OpenOptions::new().write(true).open("/dev/tty"),
        std::fs::OpenOptions::new().read(true).open("/dev/tty"),
    ) {
        tty_out
            .write_all(prompt.as_bytes())
            .context("failed to write approval prompt")?;
        tty_out.flush().ok();
        let mut reader = std::io::BufReader::new(tty_in);
        reader
            .read_line(&mut line)
            .context("failed to read approval choice")?;
    } else {
        eprint!("{prompt}");
        std::io::stderr().flush().ok();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read approval choice")?;
    }

    match line.trim() {
        "1" => Ok(ApprovalDecision::AllowOnce),
        "2" => Ok(ApprovalDecision::AllowForSession),
        "3" => Ok(ApprovalDecision::AlwaysAllow),
        "4" | "" => Ok(ApprovalDecision::Deny),
        other => bail!("invalid approval choice: {other}"),
    }
}

#[derive(Clone, Default)]
pub(crate) struct JsonlWriter {
    inner: Arc<std::sync::Mutex<()>>,
}

impl JsonlWriter {
    pub(crate) fn stdout() -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(())),
        }
    }

    pub(crate) async fn write_frame(&self, value: &Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        let lock = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let _guard = lock
                .lock()
                .map_err(|_| anyhow!("stdout JSONL writer lock poisoned"))?;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&bytes)?;
            stdout.flush()?;
            Ok(())
        })
        .await
        .map_err(|err| anyhow!("stdout JSONL write task failed: {err}"))??;
        Ok(())
    }
}

#[derive(Default)]
struct PendingResponse {
    decision: Mutex<Option<ApprovalDecision>>,
    notify: Notify,
}

#[derive(Clone)]
pub(crate) struct JsonlApprovalBroker {
    writer: JsonlWriter,
    pending: Arc<Mutex<HashMap<String, Arc<PendingResponse>>>>,
    cancellation: Arc<ExecutionCancellation>,
}

impl JsonlApprovalBroker {
    pub(crate) fn new(writer: JsonlWriter) -> Self {
        Self {
            writer,
            pending: Arc::new(Mutex::new(HashMap::new())),
            cancellation: Arc::new(ExecutionCancellation::default()),
        }
    }

    pub(crate) fn cancellation_token(&self) -> Arc<ExecutionCancellation> {
        Arc::clone(&self.cancellation)
    }

    pub(crate) async fn handle_response(&self, id: &str, decision: &str) {
        let decision = match ApprovalDecision::from_external(decision) {
            Ok(decision) => decision,
            Err(err) => {
                eprintln!("ignoring invalid approval_response decision for {id}: {err:#}");
                return;
            }
        };

        let pending = {
            let pending = self.pending.lock().await;
            pending.get(id).cloned()
        };

        let Some(pending) = pending else {
            eprintln!("ignoring unknown approval_response id: {id}");
            return;
        };

        let mut slot = pending.decision.lock().await;
        if slot.is_some() {
            eprintln!("ignoring duplicate approval_response id: {id}");
            return;
        }
        *slot = Some(decision);
        drop(slot);
        pending.notify.notify_waiters();
    }

    pub(crate) async fn controller_closed(&self) {
        self.cancellation.cancel();
        let pending = {
            let pending = self.pending.lock().await;
            pending.values().cloned().collect::<Vec<_>>()
        };
        for entry in pending {
            let mut slot = entry.decision.lock().await;
            if slot.is_none() {
                *slot = Some(ApprovalDecision::Deny);
                drop(slot);
                entry.notify.notify_waiters();
            }
        }
    }
}

#[async_trait]
impl ApprovalBroker for JsonlApprovalBroker {
    async fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        if self.cancellation.is_cancelled() {
            return Ok(ApprovalDecision::Deny);
        }

        let pending = Arc::new(PendingResponse::default());
        let previous = {
            let mut pending_map = self.pending.lock().await;
            pending_map.insert(request.id.clone(), Arc::clone(&pending))
        };

        if previous.is_some() {
            return Err(anyhow!("approval already pending for id {}", request.id));
        }

        if let Err(err) = self
            .writer
            .write_frame(&json!({
                "type": "approval_request",
                "id": request.id,
                "host": request.key.host,
                "protocol": request.display_protocol,
                "port": request.key.port,
            }))
            .await
        {
            let mut pending_map = self.pending.lock().await;
            pending_map.remove(&request.id);
            self.cancellation.cancel();
            return Err(err);
        }

        let decision = loop {
            if let Some(decision) = *pending.decision.lock().await {
                break decision;
            }
            pending.notify.notified().await;
        };

        let mut pending_map = self.pending.lock().await;
        pending_map.remove(&request.id);
        Ok(decision)
    }

    fn cancellation(&self) -> Option<Arc<ExecutionCancellation>> {
        Some(Arc::clone(&self.cancellation))
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StdinFrame {
    Start { payload: Value },
    ApprovalResponse { id: String, decision: String },
}

pub(crate) struct JsonlToolSession {
    payload_json: String,
    writer: JsonlWriter,
    broker: Arc<JsonlApprovalBroker>,
}

impl JsonlToolSession {
    pub(crate) async fn start_from_stdio() -> Result<Self> {
        let writer = JsonlWriter::stdout();
        let broker = Arc::new(JsonlApprovalBroker::new(writer.clone()));
        let (start_tx, start_rx) = oneshot::channel();
        let broker_for_thread = Arc::clone(&broker);
        let handle = tokio::runtime::Handle::current();

        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut lines = stdin.lock().lines();
            let start_result = match lines.next() {
                Some(Ok(line)) => match serde_json::from_str::<StdinFrame>(&line)
                    .context("invalid JSONL start frame")
                {
                    Ok(StdinFrame::Start { payload }) => {
                        serde_json::to_string(&payload).map_err(anyhow::Error::from)
                    }
                    Ok(StdinFrame::ApprovalResponse { .. }) => {
                        Err(anyhow!("first stdin frame must be start"))
                    }
                    Err(err) => Err(err),
                },
                Some(Err(err)) => Err(anyhow!(err).context("failed to read JSONL start frame")),
                None => Err(anyhow!("expected JSONL start frame on stdin")),
            };
            let _ = start_tx.send(start_result);

            for line in lines {
                match line {
                    Ok(line) => match serde_json::from_str::<StdinFrame>(&line) {
                        Ok(StdinFrame::ApprovalResponse { id, decision }) => {
                            handle.block_on(broker_for_thread.handle_response(&id, &decision));
                        }
                        Ok(StdinFrame::Start { .. }) => {
                            eprintln!("ignoring unexpected start frame after initialization");
                        }
                        Err(err) => {
                            eprintln!("ignoring invalid stdin JSONL frame: {err:#}");
                        }
                    },
                    Err(err) => {
                        eprintln!("stdin JSONL reader failed: {err:#}");
                        handle.block_on(broker_for_thread.controller_closed());
                        return;
                    }
                }
            }

            handle.block_on(broker_for_thread.controller_closed());
        });

        let payload_json = start_rx
            .await
            .map_err(|_| anyhow!("stdin JSONL reader thread exited before start frame"))??;

        Ok(Self {
            payload_json,
            writer,
            broker,
        })
    }

    pub(crate) fn payload_json(&self) -> &str {
        &self.payload_json
    }

    pub(crate) fn broker(&self) -> Arc<dyn ApprovalBroker> {
        Arc::clone(&self.broker) as Arc<dyn ApprovalBroker>
    }

    pub(crate) fn cancellation(&self) -> Arc<ExecutionCancellation> {
        self.broker.cancellation_token()
    }

    pub(crate) async fn write_result(&self, value: &Value) -> Result<()> {
        self.writer
            .write_frame(&json!({
                "type": "result",
                "value": value,
            }))
            .await
    }
}
