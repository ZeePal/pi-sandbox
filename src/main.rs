mod approval;
mod cli;
mod config;
mod internal_tools;
mod sandbox;
mod text;
mod types;

fn main() -> anyhow::Result<()> {
    cli::run()
}
