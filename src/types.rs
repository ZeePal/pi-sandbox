use crate::approval::{ApprovalBroker, ExecutionCancellation};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum FsMode {
    #[value(alias = "r")]
    Readonly,
    #[value(alias = "w")]
    Write,
    #[value(alias = "u")]
    Unrestricted,
}

impl fmt::Display for FsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            self.to_possible_value()
                .expect("FsMode variants are always exposed")
                .get_name(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    #[value(alias = "n")]
    None,
    #[value(alias = "u", alias = "s", alias = "sandboxed")]
    Unrestricted,
    #[value(alias = "r")]
    Restricted,
}

impl fmt::Display for NetMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            self.to_possible_value()
                .expect("NetMode variants are always exposed")
                .get_name(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ApprovalMode {
    Prompt,
    External,
    Deny,
}

impl fmt::Display for ApprovalMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            self.to_possible_value()
                .expect("ApprovalMode variants are always exposed")
                .get_name(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyScope {
    Session,
    Persistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    #[allow(dead_code)]
    Deny,
}

#[derive(Clone)]
pub struct RuntimeOptions {
    pub fs: FsMode,
    pub net: NetMode,
    pub cwd: PathBuf,
    pub session: Option<String>,
    pub approval: ApprovalMode,
    pub allow_once_hosts: Vec<String>,
    pub approval_broker: Option<Arc<dyn ApprovalBroker>>,
    pub execution_cancellation: Option<Arc<ExecutionCancellation>>,
}

pub fn default_run_approval_mode() -> ApprovalMode {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        ApprovalMode::Prompt
    } else {
        ApprovalMode::Deny
    }
}
