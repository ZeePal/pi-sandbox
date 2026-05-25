use crate::approval::JsonlToolSession;
use crate::config::load_effective_config;
use crate::internal_tools::{dispatch_internal_tool, InternalToolName};
use crate::sandbox::{
    is_linux_sandbox_helper_invocation, run_command, run_tool_bash, run_tool_via_internal,
};
use crate::types::{default_run_approval_mode, ApprovalMode, FsMode, NetMode, RuntimeOptions};
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{to_string, Value};
use std::io::Read;
use std::path::PathBuf;
use tokio::io::{self, AsyncReadExt};

#[derive(Parser, Debug)]
#[command(name = "pi-sandbox")]
#[command(about = "Linux-only sandbox sidecar for Pi")]
struct Cli {
    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Subcommand, Debug)]
enum TopLevel {
    #[command(about = "Run a command inside the sandbox.")]
    Run(RunCommand),
    #[command(about = "Run built-in tools over JSON stdin/stdout.")]
    Tool(ToolCommand),
    #[command(name = "__internal-tool", hide = true)]
    InternalTool(InternalToolCommand),
}

#[derive(Args, Debug)]
struct CommonArgs {
    #[arg(
        long = "fs",
        value_enum,
        value_name = "MODE",
        help = "Filesystem mode (defaults to .pi/sandbox.json)"
    )]
    fs: Option<FsMode>,
    #[arg(
        long = "net",
        value_enum,
        value_name = "MODE",
        help = "Network mode (defaults to .pi/sandbox.json)"
    )]
    net: Option<NetMode>,
    #[arg(
        long = "cwd",
        value_name = "DIR",
        help = "Working directory inside the sandbox (defaults to current working directory)"
    )]
    cwd: Option<PathBuf>,
    #[arg(
        long = "session",
        value_name = "ID",
        help = "Session id for session-scoped approvals"
    )]
    session: Option<String>,
    #[arg(long = "allow-once-host", hide = true)]
    allow_once_host: Vec<String>,
}

#[derive(Args, Debug)]
struct RunCommand {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(
        long = "approval",
        value_enum,
        value_name = "MODE",
        default_value_t = default_run_approval_mode(),
        help = "Approval mode"
    )]
    approval: ApprovalMode,
    #[arg(
        required = true,
        trailing_var_arg = true,
        help = "Command to execute inside the sandbox"
    )]
    command: Vec<String>,
}

#[derive(Args, Debug)]
struct ToolCommand {
    #[command(subcommand)]
    tool: ToolSubcommand,
}

#[derive(Args, Debug)]
struct ToolLeafCommand {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(
        long = "approval",
        value_enum,
        value_name = "MODE",
        default_value_t = ApprovalMode::External,
        help = "Approval mode"
    )]
    approval: ApprovalMode,
}

#[derive(Subcommand, Debug)]
enum ToolSubcommand {
    #[command(
        about = "Execute the bash tool.",
        long_about = "Execute the bash tool.\n\nReads a JSON request from stdin and writes a JSON response to stdout."
    )]
    Bash(ToolLeafCommand),
    #[command(
        about = "Read files or images.",
        long_about = "Read files or images.\n\nReads a JSON request from stdin and writes a JSON response to stdout."
    )]
    Read(ToolLeafCommand),
    #[command(
        about = "Write files.",
        long_about = "Write files.\n\nReads a JSON request from stdin and writes a JSON response to stdout."
    )]
    Write(ToolLeafCommand),
    #[command(
        about = "Edit files via exact text replacement.",
        long_about = "Edit files via exact text replacement.\n\nReads a JSON request from stdin and writes a JSON response to stdout."
    )]
    Edit(ToolLeafCommand),
    #[command(
        about = "List directory contents.",
        long_about = "List directory contents.\n\nReads a JSON request from stdin and writes a JSON response to stdout."
    )]
    Ls(ToolLeafCommand),
    #[command(
        about = "Find files by glob pattern.",
        long_about = "Find files by glob pattern.\n\nReads a JSON request from stdin and writes a JSON response to stdout."
    )]
    Find(ToolLeafCommand),
    #[command(
        about = "Search file contents.",
        long_about = "Search file contents.\n\nReads a JSON request from stdin and writes a JSON response to stdout."
    )]
    Grep(ToolLeafCommand),
}

#[derive(Args, Debug)]
struct InternalToolCommand {
    name: String,
}

pub fn run() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    if is_linux_sandbox_helper_invocation(&argv) {
        codex_linux_sandbox::run_main();
    }

    let cli = Cli::parse();
    if let TopLevel::InternalTool(cmd) = &cli.command {
        let payload = read_stdin_string_sync()?;
        let cwd = std::env::current_dir()?;
        let name = InternalToolName::parse(&cmd.name)?;
        let value = dispatch_internal_tool(name, &payload, &cwd);
        println!("{}", to_string(&value)?);
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(async move {
        match cli.command {
            TopLevel::Run(cmd) => {
                let runtime = resolve_runtime_options(&cmd.common, cmd.approval).await?;
                let exit_code = run_command(cmd.command, runtime).await?;
                std::process::exit(exit_code);
            }
            TopLevel::Tool(cmd) => run_tool_command(cmd.tool).await?,
            TopLevel::InternalTool(_) => unreachable!("handled before runtime init"),
        }

        Ok(())
    })
}

async fn run_tool_command(tool: ToolSubcommand) -> Result<()> {
    match tool {
        ToolSubcommand::Bash(cmd) => {
            let runtime = resolve_runtime_options(&cmd.common, cmd.approval).await?;
            if runtime.approval == ApprovalMode::External {
                run_tool_external_jsonl(runtime, |payload, runtime| async move {
                    run_tool_bash(&payload, runtime).await
                })
                .await?;
            } else {
                let payload = read_stdin_string().await?;
                let value = run_tool_bash(&payload, runtime).await?;
                println!("{}", to_string(&value)?);
            }
        }
        ToolSubcommand::Read(cmd) => {
            run_internal_tool_command(InternalToolName::Read, cmd).await?;
        }
        ToolSubcommand::Write(cmd) => {
            run_internal_tool_command(InternalToolName::Write, cmd).await?;
        }
        ToolSubcommand::Edit(cmd) => {
            run_internal_tool_command(InternalToolName::Edit, cmd).await?;
        }
        ToolSubcommand::Ls(cmd) => {
            run_internal_tool_command(InternalToolName::Ls, cmd).await?;
        }
        ToolSubcommand::Find(cmd) => {
            run_internal_tool_command(InternalToolName::Find, cmd).await?;
        }
        ToolSubcommand::Grep(cmd) => {
            run_internal_tool_command(InternalToolName::Grep, cmd).await?;
        }
    }

    Ok(())
}

async fn run_internal_tool_command(name: InternalToolName, cmd: ToolLeafCommand) -> Result<()> {
    let runtime = resolve_runtime_options(&cmd.common, cmd.approval).await?;
    if runtime.approval == ApprovalMode::External {
        run_tool_external_jsonl(runtime, move |payload, runtime| async move {
            run_tool_via_internal(name, &payload, runtime).await
        })
        .await?;
    } else {
        let payload = read_stdin_string().await?;
        let value = run_tool_via_internal(name, &payload, runtime).await?;
        println!("{}", to_string(&value)?);
    }
    Ok(())
}

async fn run_tool_external_jsonl<F, Fut>(mut runtime: RuntimeOptions, handler: F) -> Result<Value>
where
    F: FnOnce(String, RuntimeOptions) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let session = JsonlToolSession::start_from_stdio().await?;
    runtime.approval_broker = Some(session.broker());
    runtime.execution_cancellation = Some(session.cancellation());
    let value = handler(session.payload_json().to_string(), runtime).await?;
    session.write_result(&value).await?;
    Ok(value)
}

async fn resolve_runtime_options(
    common: &CommonArgs,
    approval: ApprovalMode,
) -> Result<RuntimeOptions> {
    let cwd = match &common.cwd {
        Some(cwd) => cwd.clone(),
        None => std::env::current_dir().context("failed to determine current directory")?,
    };
    let config = load_effective_config(&cwd).await?;
    let fs = common.fs.unwrap_or(config.fs.unwrap_or(FsMode::Write));
    let net = common.net.unwrap_or(config.net.unwrap_or(NetMode::None));

    Ok(RuntimeOptions {
        fs,
        net,
        cwd,
        session: common.session.clone(),
        approval,
        allow_once_hosts: common.allow_once_host.clone(),
        approval_broker: None,
        execution_cancellation: None,
    })
}

async fn read_stdin_string() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).await?;
    Ok(input)
}

fn read_stdin_string_sync() -> Result<String> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    Ok(input)
}
