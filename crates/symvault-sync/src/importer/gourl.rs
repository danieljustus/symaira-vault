//! The part of Go's `net/url` that `importer.ParseTOTP` observes.
//!
//! `ParseTOTP` hands the raw `otpauth://` text to `url.Parse` and then reads
//! `Scheme`, `Host` and `RawQuery` (via `ParseQuery`). The `url` crate accepts
//! and rejects different strings and words its errors differently, so the
//! warning text of a rejected URI (`parse "...": invalid URL escape "%zz"`)
//! could not match. This is a byte-level port of the Go 1.26 behavior: error
//! wording included, because pass and CSV imports surface it verbatim.

use symvault_core::go_quote;

/// `strconv.Quote` of a Go string that may hold invalid UTF-8.
pub(super) fn quote_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                push_quoted(&mut out, valid);
                break;
            }
            Err(error) => {
                let (valid, after) = rest.split_at(error.valid_up_to());
                push_quoted(
                    &mut out,
                    std::str::from_utf8(valid).expect("valid_up_to prefix is UTF-8"),
                );
                // Go quotes every invalid byte on its own as \xNN.
                out.push_str(&format!("\\x{:02x}", after[0]));
                rest = &after[1..];
            }
        }
    }
    out.push('"');
    out
}

fn push_quoted(out: &mut String, text: &str) {
    let quoted = go_quote(text);
    out.push_str(&quoted[1..quoted.len() - 1]);
}

pub(super) struct GoUrl {
    pub scheme: Vec<u8>,
    pub host: Vec<u8>,
    pub raw_query: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Host,
    Zone,
    Path,
    UserPassword,
    QueryComponent,
    Fragment,
}

fn find(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|byte| *byte == needle)
}

fn rfind(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().rposition(|byte| *byte == needle)
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn unhex(byte: u8) -> u8 {
    9 * (byte >> 6) + (byte & 15)
}

/// `shouldEscape` from net/url/gen_encoding_table.go.
fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, Mode::Host | Mode::Zone)
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::Path => return c == b'?',
            Mode::UserPassword => return matches!(c, b'@' | b'/' | b'?' | b':'),
            Mode::QueryComponent => return true,
            Mode::Fragment => return false,
            Mode::Host | Mode::Zone => {}
        },
        _ => {}
    }
    if mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
}

fn escape_error(bytes: &[u8]) -> String {
    format!("invalid URL escape {}", quote_bytes(bytes))
}

/// Go `unescape`: the error is the complete `net/url` error text.
fn unescape(s: &[u8], mode: Mode) -> Result<Vec<u8>, String> {
    let mut count = 0usize;
    let mut has_plus = false;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                count += 1;
                if i + 2 >= s.len() || !is_hex(s[i + 1]) || !is_hex(s[i + 2]) {
                    let tail = &s[i..];
                    return Err(escape_error(&tail[..tail.len().min(3)]));
                }
                if mode == Mode::Host && unhex(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                    return Err(escape_error(&s[i..i + 3]));
                }
                if mode == Mode::Zone {
                    let value = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    if &s[i..i + 3] != b"%25" && value != b' ' && should_escape(value, Mode::Host) {
                        return Err(escape_error(&s[i..i + 3]));
                    }
                }
                i += 3;
            }
            b'+' => {
                has_plus = mode == Mode::QueryComponent;
                i += 1;
            }
            byte => {
                if matches!(mode, Mode::Host | Mode::Zone)
                    && byte < 0x80
                    && should_escape(byte, mode)
                {
                    return Err(format!(
                        "invalid character {} in host name",
                        quote_bytes(&[byte])
                    ));
                }
                i += 1;
            }
        }
    }
    if count == 0 && !has_plus {
        return Ok(s.to_vec());
    }
    let plus = if mode == Mode::QueryComponent {
        b' '
    } else {
        b'+'
    };
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                out.push(unhex(s[i + 1]) << 4 | unhex(s[i + 2]));
                i += 3;
            }
            b'+' => {
                out.push(plus);
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// `url.Parse`; an error carries Go's complete `*url.Error` text.
pub(super) fn parse(raw: &[u8]) -> Result<GoUrl, String> {
    let (head, fragment) = match find(raw, b'#') {
        Some(index) => (&raw[..index], Some(&raw[index + 1..])),
        None => (raw, None),
    };
    let url = parse_inner(head).map_err(|error| url_error(head, &error))?;
    if let Some(fragment) = fragment.filter(|fragment| !fragment.is_empty()) {
        unescape(fragment, Mode::Fragment).map_err(|error| url_error(raw, &error))?;
    }
    Ok(url)
}

fn url_error(url: &[u8], error: &str) -> String {
    format!("parse {}: {error}", quote_bytes(url))
}

fn parse_inner(raw: &[u8]) -> Result<GoUrl, String> {
    if raw.iter().any(|byte| *byte < b' ' || *byte == 0x7f) {
        return Err("net/url: invalid control character in URL".into());
    }
    let mut url = GoUrl {
        scheme: Vec::new(),
        host: Vec::new(),
        raw_query: Vec::new(),
    };
    if raw == b"*" {
        return Ok(url);
    }
    let (scheme, mut rest) = get_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();

    if rest.ends_with(b"?") && rest.iter().filter(|byte| **byte == b'?').count() == 1 {
        rest = &rest[..rest.len() - 1];
    } else if let Some(index) = find(rest, b'?') {
        url.raw_query = rest[index + 1..].to_vec();
        rest = &rest[..index];
    }

    if !rest.starts_with(b"/") {
        if !url.scheme.is_empty() {
            // Rootless paths are opaque.
            return Ok(url);
        }
        let segment = rest.split(|byte| *byte == b'/').next().unwrap_or_default();
        if segment.contains(&b':') {
            return Err("first path segment in URL cannot contain colon".into());
        }
    }

    if (!url.scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
        let authority_and_path = &rest[2..];
        let (authority, path) = match find(authority_and_path, b'/') {
            Some(index) => (&authority_and_path[..index], &authority_and_path[index..]),
            None => (authority_and_path, &b""[..]),
        };
        url.host = parse_authority(authority)?;
        rest = path;
    }
    unescape(rest, Mode::Path)?;
    Ok(url)
}

fn get_scheme(raw: &[u8]) -> Result<(&[u8], &[u8]), String> {
    for (index, c) in raw.iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if index == 0 {
                    return Ok((&b""[..], raw));
                }
            }
            b':' => {
                if index == 0 {
                    return Err("missing protocol scheme".into());
                }
                return Ok((&raw[..index], &raw[index + 1..]));
            }
            _ => return Ok((&b""[..], raw)),
        }
    }
    Ok((&b""[..], raw))
}

fn parse_authority(authority: &[u8]) -> Result<Vec<u8>, String> {
    let (host_part, userinfo) = match rfind(authority, b'@') {
        Some(index) => (&authority[index + 1..], Some(&authority[..index])),
        None => (authority, None),
    };
    let host = parse_host(host_part)?;
    if let Some(userinfo) = userinfo {
        if !valid_userinfo(userinfo) {
            return Err("net/url: invalid userinfo".into());
        }
        match find(userinfo, b':') {
            None => {
                unescape(userinfo, Mode::UserPassword)?;
            }
            Some(index) => {
                unescape(&userinfo[..index], Mode::UserPassword)?;
                unescape(&userinfo[index + 1..], Mode::UserPassword)?;
            }
        }
    }
    Ok(host)
}

fn valid_userinfo(userinfo: &[u8]) -> bool {
    // Go ranges over runes: any non-ASCII rune is rejected, as is any byte
    // outside the allowed ASCII set (invalid UTF-8 decodes to U+FFFD).
    userinfo.iter().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

fn valid_optional_port(port: &[u8]) -> bool {
    match port.split_first() {
        None => true,
        Some((b':', digits)) => digits.iter().all(u8::is_ascii_digit),
        Some(_) => false,
    }
}

fn parse_host(host: &[u8]) -> Result<Vec<u8>, String> {
    match rfind(host, b'[') {
        Some(open) if open > 0 => return Err("invalid IP-literal".into()),
        Some(open) => {
            let close = rfind(host, b']').ok_or("missing ']' in host")?;
            let colon_port = &host[close + 1..];
            if !valid_optional_port(colon_port) {
                return Err(format!(
                    "invalid port {} after host",
                    quote_bytes(colon_port)
                ));
            }
            let unescaped_port = unescape(colon_port, Mode::Host)?;
            let hostname = &host[open + 1..close];
            let unescaped = match hostname.windows(3).position(|window| window == b"%25") {
                Some(zone) => {
                    let mut joined = unescape(&hostname[..zone], Mode::Host)?;
                    joined.extend(unescape(&hostname[zone..], Mode::Zone)?);
                    joined
                }
                None => unescape(hostname, Mode::Host)?,
            };
            match parse_addr(&unescaped)? {
                Addr::V4 => return Err("invalid IP-literal".into()),
                Addr::V6 => {}
            }
            let mut out = vec![b'['];
            out.extend(unescaped);
            out.push(b']');
            out.extend(unescaped_port);
            return Ok(out);
        }
        None => {}
    }
    if let Some(first) = find(host, b':') {
        let last = rfind(host, b':').unwrap_or(first);
        // Go keeps the permissive last-colon rule for every scheme but
        // http(s); otpauth is never one of those.
        let colon_port = &host[last..];
        if !valid_optional_port(colon_port) {
            return Err(format!(
                "invalid port {} after host",
                quote_bytes(colon_port)
            ));
        }
    }
    unescape(host, Mode::Host)
}

enum Addr {
    V4,
    V6,
}

fn addr_error(input: &[u8], message: &str, at: &[u8]) -> String {
    if at.is_empty() {
        format!("invalid host: ParseAddr({}): {message}", quote_bytes(input))
    } else {
        format!(
            "invalid host: ParseAddr({}): {message} (at {})",
            quote_bytes(input),
            quote_bytes(at)
        )
    }
}

/// `netip.ParseAddr`, reduced to what `parseHost` needs: the address family or
/// Go's error text (already prefixed with `invalid host: `).
fn parse_addr(input: &[u8]) -> Result<Addr, String> {
    for byte in input {
        match byte {
            b'.' => return parse_ipv4(input).map(|()| Addr::V4),
            b':' => return parse_ipv6(input).map(|()| Addr::V6),
            b'%' => return Err(addr_error(input, "missing IPv6 address", b"")),
            _ => {}
        }
    }
    Err(addr_error(input, "unable to parse IP", b""))
}

fn parse_ipv4_fields(
    input: &[u8],
    offset: usize,
    end: usize,
    fields: &mut [u8],
) -> Result<(), String> {
    let s = &input[offset..end];
    let (mut value, mut position, mut digits) = (0usize, 0usize, 0usize);
    for (index, byte) in s.iter().enumerate() {
        if byte.is_ascii_digit() {
            if digits == 1 && value == 0 {
                return Err(addr_error(
                    input,
                    "IPv4 field has octet with leading zero",
                    b"",
                ));
            }
            value = value * 10 + usize::from(byte - b'0');
            digits += 1;
            if value > 255 {
                return Err(addr_error(input, "IPv4 field has value >255", b""));
            }
        } else if *byte == b'.' {
            if index == 0 || index == s.len() - 1 || s[index - 1] == b'.' {
                return Err(addr_error(
                    input,
                    "IPv4 field must have at least one digit",
                    &s[index..],
                ));
            }
            if position == 3 {
                return Err(addr_error(input, "IPv4 address too long", b""));
            }
            fields[position] = value as u8;
            position += 1;
            value = 0;
            digits = 0;
        } else {
            return Err(addr_error(input, "unexpected character", &s[index..]));
        }
    }
    if position < 3 {
        return Err(addr_error(input, "IPv4 address too short", b""));
    }
    fields[3] = value as u8;
    Ok(())
}

fn parse_ipv4(input: &[u8]) -> Result<(), String> {
    let mut fields = [0u8; 4];
    parse_ipv4_fields(input, 0, input.len(), &mut fields)
}

fn parse_ipv6(input: &[u8]) -> Result<(), String> {
    let mut s = input;
    let mut zone: &[u8] = b"";
    if let Some(index) = find(s, b'%') {
        zone = &s[index + 1..];
        s = &s[..index];
        if zone.is_empty() {
            return Err(addr_error(input, "zone must be a non-empty string", b""));
        }
    }
    let mut ip = [0u8; 16];
    let mut ellipsis: Option<usize> = None;
    if s.len() >= 2 && s[0] == b':' && s[1] == b':' {
        ellipsis = Some(0);
        s = &s[2..];
        if s.is_empty() {
            return Ok(());
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let mut offset = 0usize;
        let mut acc = 0u32;
        while offset < s.len() {
            let c = s[offset];
            let digit = match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'a'..=b'f' => u32::from(c - b'a' + 10),
                b'A'..=b'F' => u32::from(c - b'A' + 10),
                _ => break,
            };
            acc = (acc << 4) + digit;
            if offset > 3 {
                return Err(addr_error(
                    input,
                    "each group must have 4 or less digits",
                    s,
                ));
            }
            if acc > 0xffff {
                return Err(addr_error(input, "IPv6 field has value >=2^16", s));
            }
            offset += 1;
        }
        if offset == 0 {
            return Err(addr_error(
                input,
                "each colon-separated field must have at least one digit",
                s,
            ));
        }
        if offset < s.len() && s[offset] == b'.' {
            if ellipsis.is_none() && i != 12 {
                return Err(addr_error(
                    input,
                    "embedded IPv4 address must replace the final 2 fields of the address",
                    s,
                ));
            }
            if i + 4 > 16 {
                return Err(addr_error(
                    input,
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                    s,
                ));
            }
            let mut end = input.len();
            if !zone.is_empty() {
                end -= zone.len() + 1;
            }
            parse_ipv4_fields(input, end - s.len(), end, &mut ip[i..i + 4])?;
            s = b"";
            i += 4;
            break;
        }
        ip[i] = (acc >> 8) as u8;
        ip[i + 1] = acc as u8;
        i += 2;
        s = &s[offset..];
        if s.is_empty() {
            break;
        }
        if s[0] != b':' {
            return Err(addr_error(input, "unexpected character, want colon", s));
        } else if s.len() == 1 {
            return Err(addr_error(
                input,
                "colon must be followed by more characters",
                s,
            ));
        }
        s = &s[1..];
        if s[0] == b':' {
            if ellipsis.is_some() {
                return Err(addr_error(input, "multiple :: in address", s));
            }
            ellipsis = Some(i);
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return Err(addr_error(input, "trailing garbage after address", s));
    }
    if i < 16 {
        if ellipsis.is_none() {
            return Err(addr_error(input, "address string too short", b""));
        }
    } else if ellipsis.is_some() {
        return Err(addr_error(
            input,
            "the :: must expand to at least one field of zeros",
            b"",
        ));
    }
    Ok(())
}

/// First value per key of Go's `url.ParseQuery`, ignoring its error exactly as
/// `URL.Query` does: pairs with a raw `;` or a bad escape are dropped.
pub(super) fn query_first_values(query: &[u8]) -> std::collections::HashMap<Vec<u8>, Vec<u8>> {
    let mut values = std::collections::HashMap::new();
    // urlParamsWithinMax: more than 10000 parameters empties the result.
    if query.iter().filter(|byte| **byte == b'&').count() + 1 > 10_000 {
        return values;
    }
    let mut remaining = query;
    while !remaining.is_empty() {
        let (pair, tail) = match find(remaining, b'&') {
            Some(index) => (&remaining[..index], &remaining[index + 1..]),
            None => (remaining, &b""[..]),
        };
        remaining = tail;
        if pair.contains(&b';') || pair.is_empty() {
            continue;
        }
        let (key, value) = match find(pair, b'=') {
            Some(index) => (&pair[..index], &pair[index + 1..]),
            None => (pair, &b""[..]),
        };
        let Ok(key) = unescape(key, Mode::QueryComponent) else {
            continue;
        };
        let Ok(value) = unescape(value, Mode::QueryComponent) else {
            continue;
        };
        values.entry(key).or_insert(value);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_bytes_matches_strconv_quote() {
        assert_eq!(quote_bytes(b"plain"), "\"plain\"");
        assert_eq!(quote_bytes(b"a\xffb"), "\"a\\xffb\"");
        assert_eq!(quote_bytes(b"\xe2\x82"), "\"\\xe2\\x82\"");
        assert_eq!(quote_bytes("é\u{a0}\n\"".as_bytes()), "\"é\\u00a0\\n\\\"\"");
    }

    #[test]
    fn parse_reports_go_error_text() {
        let error = |input: &str| parse(input.as_bytes()).err().expect("rejected");
        assert_eq!(
            error("otpauth://totp/%zz"),
            "parse \"otpauth://totp/%zz\": invalid URL escape \"%zz\""
        );
        assert_eq!(
            error("otpauth://totp/x#%"),
            "parse \"otpauth://totp/x#%\": invalid URL escape \"%\""
        );
        assert_eq!(
            error("otpauth://[zz]/"),
            "parse \"otpauth://[zz]/\": invalid host: ParseAddr(\"zz\"): unable to parse IP"
        );
        let ok = parse(b"OTPAUTH://tOtP/p?secret=x#f").expect("valid");
        assert_eq!(
            (ok.scheme, ok.host, ok.raw_query),
            (b"otpauth".to_vec(), b"tOtP".to_vec(), b"secret=x".to_vec())
        );
    }

    #[test]
    fn query_values_follow_parse_query() {
        let values = query_first_values(b"a=1&a=2&b=%zz&c=x;y&d=%41+b&=e&f");
        assert_eq!(values.get(&b"a"[..]), Some(&b"1".to_vec()));
        assert_eq!(values.get(&b"d"[..]), Some(&b"A b".to_vec()));
        assert_eq!(values.get(&b"f"[..]), Some(&Vec::new()));
        assert!(!values.contains_key(&b"b"[..]) && !values.contains_key(&b"c"[..]));
    }
}
