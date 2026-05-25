pub const MAX_TOOL_TEXT_BYTES: usize = 50 * 1024;
pub const MAX_TOOL_TEXT_LINES: usize = 2000;

#[derive(Debug)]
pub struct TruncatedText {
    pub text: String,
    pub truncated: bool,
}

pub fn truncate_head_text(input: &str, max_lines: usize, max_bytes: usize) -> TruncatedText {
    if input.is_empty() {
        return TruncatedText {
            text: String::new(),
            truncated: false,
        };
    }

    let mut out = String::new();
    let mut truncated = false;

    for (idx, line) in input.split('\n').enumerate() {
        if idx >= max_lines {
            truncated = true;
            break;
        }
        let prefix = if idx == 0 { "" } else { "\n" };
        let addition = format!("{prefix}{line}");
        if out.len() + addition.len() > max_bytes {
            truncated = true;
            break;
        }
        out.push_str(&addition);
    }

    if !truncated && out.len() < input.len() {
        truncated = true;
    }

    TruncatedText {
        text: out,
        truncated,
    }
}

pub fn truncate_tail_text(input: &str, max_lines: usize, max_bytes: usize) -> (String, bool) {
    let lines: Vec<&str> = if input.is_empty() {
        Vec::new()
    } else {
        input.split('\n').collect()
    };
    let start = lines.len().saturating_sub(max_lines);
    let mut text = lines[start..].join("\n");
    let mut truncated = start > 0;
    if text.len() > max_bytes {
        truncated = true;
        let start_byte = text.len().saturating_sub(max_bytes);
        let boundary = next_char_boundary(&text, start_byte);
        text = text[boundary..].to_string();
    }
    (text, truncated)
}

pub fn relativize_tool_lines(output: &str, search_path: &std::path::Path) -> String {
    let search_prefix = search_path.to_string_lossy().to_string();
    output
        .lines()
        .map(|line| {
            if line.starts_with(&search_prefix) {
                line[search_prefix.len()..]
                    .trim_start_matches(std::path::MAIN_SEPARATOR)
                    .replace('\\', "/")
            } else {
                line.replace('\\', "/")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn next_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }

    let mut i = index;
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i
}
