//! Output boundary matching the Go MCP renderer. Call before embedding vault data.
use unicode_normalization::UnicodeNormalization;

pub fn sanitize_for_mcp(text: &str) -> String {
    let normalized: String = text.stream_safe().nfkc().collect();
    let stripped: String = normalized
        .chars()
        .filter(|c| !matches!(*c as u32, 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xfeff | 0xad | 0x34f))
        .collect();
    let bytes = stripped.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        if ch == 0x1b {
            match bytes.get(i + 1) {
                Some(b'[') => {
                    i += 2;
                    while i < bytes.len() && !(b'@'..=b'~').contains(&bytes[i]) {
                        i += 1;
                    }
                    i += usize::from(i < bytes.len());
                }
                Some(b']') => {
                    let start = i;
                    i += 2;
                    while i < bytes.len() {
                        if bytes[i] == 7
                            || (bytes[i] == b'\\' && i > start + 2 && bytes[i - 1] == 0x1b)
                        {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                }
                Some(_) => i += 2,
                None => i += 1,
            }
            continue;
        }
        if (ch < 0x20 && !matches!(ch, b'\t' | b'\n' | b'\r')) || ch == 0x7f {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"</")
            && bytes
                .get(i + 2)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
            && let Some(end) = bytes[i..].iter().position(|c| *c == b'>')
        {
            out.extend_from_slice(b"</ ");
            out.extend_from_slice(&bytes[i + 2..i + end]);
            out.extend_from_slice(b" >");
            i += end + 1;
            continue;
        }
        if bytes[i..].starts_with(b"-->") {
            out.extend_from_slice(b"-- >");
            i += 3;
            continue;
        }
        out.push(ch);
        i += 1;
    }
    // Go's byte scanner can remove the first byte of UTF-8 after a simple ESC.
    // JSON output replaces these invalid bytes with U+FFFD, as does this boundary.
    String::from_utf8_lossy(&out).into_owned()
}

/// Wrap untrusted data in independently randomized, sanitized boundaries.
/// Entropy failure is propagated: a predictable fallback marker is unsafe.
pub fn embed_as_data(label: &str, untrusted: &str) -> Result<String, getrandom::Error> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random)?;
    let marker = format!("{:016x}", u64::from_be_bytes(random));
    let label = sanitize_for_mcp(label)
        .replace("--", "-")
        .replace('\n', " ")
        .replace('\r', "");
    let safe = sanitize_for_mcp(untrusted);
    Ok(format!(
        "<!-- DATA_{marker} label={label} -->{safe}<!-- /DATA_{marker} -->"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn data_markers_are_fresh_and_content_cannot_close_them() {
        let first = embed_as_data("a--b\n\r", "--></data>").unwrap();
        let second = embed_as_data("a--b\n\r", "--></data>").unwrap();
        assert_ne!(first, second);
        let marker = &first[10..26];
        assert!(marker.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            first,
            format!("<!-- DATA_{marker} label=a-b  -->-- ></ data ><!-- /DATA_{marker} -->")
        );
    }
}
