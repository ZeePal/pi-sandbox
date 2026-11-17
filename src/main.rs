mod approval;
mod cli;
mod config;
mod denial_log;
mod internal_tools;
mod sandbox;
mod text;
mod tool_protection;
mod types;

fn main() -> anyhow::Result<()> {
    cli::run()
}
