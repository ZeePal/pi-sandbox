use crate::text::{
    relativize_tool_lines, truncate_head_text, MAX_TOOL_TEXT_BYTES, MAX_TOOL_TEXT_LINES,
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;

const DEFAULT_LS_LIMIT: usize = 500;
const DEFAULT_FIND_LIMIT: usize = 1000;
const DEFAULT_GREP_LIMIT: usize = 100;

#[derive(Debug, Deserialize)]
struct ReadToolInput {
    path: String,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct WriteToolInput {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ReplaceEditInput {
    #[serde(rename = "oldText")]
    old_text: String,
    #[serde(rename = "newText")]
    new_text: String,
}

#[derive(Debug, Deserialize)]
struct EditToolInput {
    path: String,
    edits: Vec<ReplaceEditInput>,
}

#[derive(Debug, Deserialize)]
struct LsToolInput {
    path: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindToolInput {
    pattern: String,
    path: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct GrepToolInput {
    pattern: String,
    path: Option<String>,
    glob: Option<String>,
    #[serde(default, rename = "ignoreCase")]
    ignore_case: Option<bool>,
    literal: Option<bool>,
    context: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub enum InternalToolName {
    Read,
    Write,
    Edit,
    Ls,
    Find,
    Grep,
}

impl InternalToolName {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "edit" => Ok(Self::Edit),
            "ls" => Ok(Self::Ls),
            "find" => Ok(Self::Find),
            "grep" => Ok(Self::Grep),
            other => bail!("unknown internal tool: {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Edit => "edit",
            Self::Ls => "ls",
            Self::Find => "find",
            Self::Grep => "grep",
        }
    }
}

#[derive(Debug)]
struct HelperCapture {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

pub fn dispatch_internal_tool(name: InternalToolName, payload_json: &str, cwd: &Path) -> Value {
    let result = match name {
        InternalToolName::Read => internal_tool_read(payload_json, cwd),
        InternalToolName::Write => internal_tool_write(payload_json, cwd),
        InternalToolName::Edit => internal_tool_edit(payload_json, cwd),
        InternalToolName::Ls => internal_tool_ls(payload_json, cwd),
        InternalToolName::Find => internal_tool_find(payload_json, cwd),
        InternalToolName::Grep => internal_tool_grep(payload_json, cwd),
    };

    match result {
        Ok(value) => value,
        Err(err) => tool_error_json(&err.to_string()),
    }
}

pub fn tool_error_json(message: &str) -> Value {
    json!({
        "ok": false,
        "error": {
            "kind": "tool_error",
            "message": message,
        }
    })
}

fn internal_tool_read(payload_json: &str, cwd: &Path) -> Result<Value> {
    let input: ReadToolInput =
        serde_json::from_str(payload_json).context("invalid read tool input")?;
    let path = resolve_input_path(cwd, &input.path);
    let content =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let text = String::from_utf8_lossy(&content).to_string();
    let all_lines: Vec<&str> = text.split('\n').collect();
    let total_lines = all_lines.len();
    let start = input
        .offset
        .map(|value| value.saturating_sub(1))
        .unwrap_or(0);

    if total_lines == 0 {
        return Ok(json!({
            "ok": true,
            "text": "",
            "truncated": false,
            "lineCount": 0,
        }));
    }
    if start >= total_lines {
        bail!("offset {} is beyond end of file", input.offset.unwrap_or(1));
    }

    let end = input
        .limit
        .map(|limit| start.saturating_add(limit).min(total_lines))
        .unwrap_or(total_lines);
    let selected = all_lines[start..end].join("\n");
    let truncated = truncate_head_text(&selected, MAX_TOOL_TEXT_LINES, MAX_TOOL_TEXT_BYTES);
    Ok(json!({
        "ok": true,
        "text": truncated.text,
        "truncated": truncated.truncated,
        "lineCount": total_lines,
    }))
}

fn internal_tool_write(payload_json: &str, cwd: &Path) -> Result<Value> {
    let input: WriteToolInput =
        serde_json::from_str(payload_json).context("invalid write tool input")?;
    let path = resolve_input_path(cwd, &input.path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&path, input.content.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(json!({
        "ok": true,
        "bytesWritten": input.content.len(),
    }))
}

fn internal_tool_edit(payload_json: &str, cwd: &Path) -> Result<Value> {
    let input: EditToolInput =
        serde_json::from_str(payload_json).context("invalid edit tool input")?;
    if input.edits.is_empty() {
        bail!("edits must contain at least one replacement")
    }

    let path = resolve_input_path(cwd, &input.path);
    let original = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let updated = apply_exact_edits(&original, &input.edits)?;
    std::fs::write(&path, updated.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(json!({
        "ok": true,
        "applied": input.edits.len(),
    }))
}

fn internal_tool_ls(payload_json: &str, cwd: &Path) -> Result<Value> {
    let input: LsToolInput = serde_json::from_str(payload_json).context("invalid ls tool input")?;
    let path = resolve_input_path(cwd, input.path.as_deref().unwrap_or("."));
    let mut entries = Vec::new();
    for entry in
        std::fs::read_dir(&path).with_context(|| format!("failed to list {}", path.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let mut name = entry.file_name().to_string_lossy().to_string();
        if file_type.is_dir() {
            name.push('/');
        }
        entries.push(name);
    }

    entries.sort_by_key(|entry| entry.to_lowercase());
    let limit = input.limit.unwrap_or(DEFAULT_LS_LIMIT);
    let limited: Vec<String> = entries.into_iter().take(limit).collect();
    let text = if limited.is_empty() {
        "(empty directory)".to_string()
    } else {
        limited.join("\n")
    };
    let truncated = truncate_head_text(&text, usize::MAX, MAX_TOOL_TEXT_BYTES);
    Ok(json!({
        "ok": true,
        "text": truncated.text,
        "truncated": truncated.truncated,
    }))
}

fn internal_tool_find(payload_json: &str, cwd: &Path) -> Result<Value> {
    let input: FindToolInput =
        serde_json::from_str(payload_json).context("invalid find tool input")?;
    let search_path = resolve_input_path(cwd, input.path.as_deref().unwrap_or("."));
    let limit = input.limit.unwrap_or(DEFAULT_FIND_LIMIT);
    let mut args = vec![
        "--glob".to_string(),
        "--color=never".to_string(),
        "--hidden".to_string(),
        "--no-require-git".to_string(),
        "--max-results".to_string(),
        limit.to_string(),
    ];
    let mut pattern = input.pattern.clone();
    if pattern.contains('/')
        && !pattern.starts_with('/')
        && !pattern.starts_with("**/")
        && pattern != "**"
    {
        args.push("--full-path".to_string());
        pattern = format!("**/{pattern}");
    }
    args.push("--".to_string());
    args.push(pattern);
    args.push(search_path.to_string_lossy().to_string());

    let capture = spawn_simple_capture_sync("fd", &args, cwd)?;
    if capture.exit_code != 0 && capture.exit_code != 1 {
        bail!(capture.stderr.trim().to_string())
    }

    let output = relativize_tool_lines(&capture.stdout, &search_path);
    let text = if output.trim().is_empty() {
        "No files found matching pattern".to_string()
    } else {
        output
    };
    let truncated = truncate_head_text(&text, usize::MAX, MAX_TOOL_TEXT_BYTES);
    Ok(json!({
        "ok": true,
        "text": truncated.text,
        "truncated": truncated.truncated,
    }))
}

fn internal_tool_grep(payload_json: &str, cwd: &Path) -> Result<Value> {
    let input: GrepToolInput =
        serde_json::from_str(payload_json).context("invalid grep tool input")?;
    let search_path = resolve_input_path(cwd, input.path.as_deref().unwrap_or("."));
    let limit = input.limit.unwrap_or(DEFAULT_GREP_LIMIT).max(1);
    let mut args = vec![
        "--line-number".to_string(),
        "--color=never".to_string(),
        "--hidden".to_string(),
        "-m".to_string(),
        limit.to_string(),
    ];
    if input.ignore_case.unwrap_or(false) {
        args.push("--ignore-case".to_string());
    }
    if input.literal.unwrap_or(false) {
        args.push("--fixed-strings".to_string());
    }
    if let Some(glob) = &input.glob {
        args.push("--glob".to_string());
        args.push(glob.clone());
    }
    if let Some(context) = input.context.filter(|value| *value > 0) {
        args.push("-C".to_string());
        args.push(context.to_string());
    }
    args.push("--".to_string());
    args.push(input.pattern.clone());
    args.push(search_path.to_string_lossy().to_string());

    let capture = spawn_simple_capture_sync("rg", &args, cwd)?;
    if capture.exit_code != 0 && capture.exit_code != 1 {
        bail!(capture.stderr.trim().to_string())
    }

    let text = if capture.stdout.trim().is_empty() {
        "No matches found".to_string()
    } else {
        relativize_tool_lines(&capture.stdout, &search_path)
    };
    let truncated = truncate_head_text(&text, usize::MAX, MAX_TOOL_TEXT_BYTES);
    Ok(json!({
        "ok": true,
        "text": truncated.text,
        "truncated": truncated.truncated,
    }))
}

fn spawn_simple_capture_sync(program: &str, args: &[String], cwd: &Path) -> Result<HelperCapture> {
    let output = std::process::Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to spawn {program}"))?;
    Ok(HelperCapture {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(1),
    })
}

fn resolve_input_path(cwd: &Path, input: &str) -> PathBuf {
    let path = PathBuf::from(input);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn apply_exact_edits(original: &str, edits: &[ReplaceEditInput]) -> Result<String> {
    #[derive(Debug)]
    struct Match<'a> {
        start: usize,
        end: usize,
        replacement: &'a str,
    }

    let mut matches = Vec::new();
    for edit in edits {
        let positions: Vec<usize> = original
            .match_indices(&edit.old_text)
            .map(|(idx, _)| idx)
            .collect();
        match positions.as_slice() {
            [] => bail!("oldText did not match: {:?}", edit.old_text),
            [start] => matches.push(Match {
                start: *start,
                end: *start + edit.old_text.len(),
                replacement: &edit.new_text,
            }),
            _ => bail!("oldText was not unique: {:?}", edit.old_text),
        }
    }

    matches.sort_by_key(|matched| matched.start);
    for pair in matches.windows(2) {
        let left = &pair[0];
        let right = &pair[1];
        if right.start < left.end {
            bail!("edits overlap in the original file")
        }
    }

    let mut result = String::with_capacity(original.len());
    let mut cursor = 0usize;
    for matched in matches {
        result.push_str(&original[cursor..matched.start]);
        result.push_str(matched.replacement);
        cursor = matched.end;
    }
    result.push_str(&original[cursor..]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after UNIX_EPOCH")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pi-sandbox-internal-tools-{nanos}"));
        std::fs::create_dir_all(&path).expect("temp test directory must be creatable");
        path
    }

    fn assert_error_schema(value: &Value) {
        assert_eq!(value.get("ok").and_then(Value::as_bool), Some(false));
        assert!(
            value.get("text").is_none(),
            "error wrappers must not provide fake tool text"
        );

        let error = value
            .get("error")
            .and_then(Value::as_object)
            .expect("error response must include an error object");
        assert_eq!(
            error.get("kind").and_then(Value::as_str),
            Some("tool_error")
        );
        assert!(error.get("message").and_then(Value::as_str).is_some());
    }

    fn assert_text_success_schema(value: &Value) {
        assert_eq!(value.get("ok").and_then(Value::as_bool), Some(true));
        assert!(value.get("text").and_then(Value::as_str).is_some());
        assert!(value.get("truncated").and_then(Value::as_bool).is_some());
    }

    #[test]
    fn tool_error_json_keeps_error_text_only_in_error_object() {
        let value = tool_error_json("example failure");

        assert_error_schema(&value);
        assert_eq!(value["error"]["message"], "example failure");
    }

    #[test]
    fn read_nonexistent_file_returns_complete_error_schema() {
        let cwd = temp_test_dir();
        let value = dispatch_internal_tool(
            InternalToolName::Read,
            r#"{"path":"does-not-exist.txt"}"#,
            &cwd,
        );

        assert_error_schema(&value);
        assert!(value["error"]["message"]
            .as_str()
            .expect("error message must be a string")
            .contains("failed to read"));
    }

    #[test]
    fn malformed_payload_errors_use_complete_schema_for_every_internal_tool() {
        let cwd = temp_test_dir();
        let tools = [
            InternalToolName::Read,
            InternalToolName::Write,
            InternalToolName::Edit,
            InternalToolName::Ls,
            InternalToolName::Find,
            InternalToolName::Grep,
        ];

        for tool in tools {
            let value = dispatch_internal_tool(tool, "not-json", &cwd);
            assert_error_schema(&value);
        }
    }

    #[test]
    fn text_output_successes_use_expected_schema() {
        let cwd = temp_test_dir();
        let file_path = cwd.join("sample.txt");
        std::fs::write(&file_path, "alpha\nbeta\n").expect("sample file must be writable");

        let read_value = dispatch_internal_tool(
            InternalToolName::Read,
            r#"{"path":"sample.txt","limit":1}"#,
            &cwd,
        );
        assert_text_success_schema(&read_value);
        assert!(read_value
            .get("lineCount")
            .and_then(Value::as_u64)
            .is_some());

        let ls_value = dispatch_internal_tool(InternalToolName::Ls, r#"{"path":"."}"#, &cwd);
        assert_text_success_schema(&ls_value);

        let find_value = dispatch_internal_tool(
            InternalToolName::Find,
            r#"{"pattern":"sample.txt","path":"."}"#,
            &cwd,
        );
        assert_text_success_schema(&find_value);

        let grep_value = dispatch_internal_tool(
            InternalToolName::Grep,
            r#"{"pattern":"alpha","path":"sample.txt"}"#,
            &cwd,
        );
        assert_text_success_schema(&grep_value);
    }
}
