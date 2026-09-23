use serde::Deserialize;

#[derive(Deserialize)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
}

/// Validates the metadata accepted by Go's dynamic client registration handler.
/// Registration stays off the HTTP listener until Rust can persist and use it.
pub(super) fn validate_registration(
    content_type: &str,
    body: &str,
) -> Result<Vec<String>, &'static str> {
    if !super::http::is_json_content_type(content_type) {
        return Err("invalid_client_metadata");
    }
    let mut decoder = serde_json::Deserializer::from_str(body);
    let request =
        RegistrationRequest::deserialize(&mut decoder).map_err(|_| "invalid_client_metadata")?;
    if request.redirect_uris.is_empty()
        || !request
            .redirect_uris
            .iter()
            .all(|uri| allowed_redirect_uri(uri))
    {
        return Err("invalid_redirect_uri");
    }
    Ok(request.redirect_uris)
}

fn allowed_redirect_uri(value: &str) -> bool {
    if value.is_empty()
        || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
        || invalid_percent_escape(value)
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme_bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        || value
            .split_once('#')
            .is_some_and(|(_, fragment)| !fragment.is_empty())
    {
        return false;
    }

    if let Some(authority) = remainder.strip_prefix("//") {
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.contains('@') {
            return false;
        }
    }
    if scheme == "http" || scheme == "https" {
        let Some(authority) = remainder.strip_prefix("//") else {
            return false;
        };
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() {
            return false;
        }
        let hostname = if let Some(bracketed) = authority.strip_prefix('[') {
            let Some((host, tail)) = bracketed.split_once(']') else {
                return false;
            };
            if !tail.is_empty()
                && !tail.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
                })
            {
                return false;
            }
            host
        } else {
            let (host, port) = authority
                .split_once(':')
                .map_or((authority, None), |(host, port)| (host, Some(port)));
            if port.is_some_and(|port| {
                port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                return false;
            }
            host
        };
        matches!(hostname, "localhost" | "127.0.0.1" | "::1")
    } else {
        scheme.starts_with("symvault") || scheme.starts_with("symaira")
    }
}

fn invalid_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::validate_registration;

    #[test]
    fn validates_go_registration_metadata_and_custom_schemes() {
        let body = r#"{"redirect_uris":["http://localhost/callback","symvault:callback"]}"#;
        assert_eq!(
            validate_registration("application/json; charset=utf-8", body),
            Ok(vec![
                "http://localhost/callback".to_owned(),
                "symvault:callback".to_owned()
            ])
        );
    }

    #[test]
    fn rejects_invalid_metadata_and_userinfo_for_every_scheme() {
        let cases = [
            (
                "text/plain",
                r#"{"redirect_uris":["http://localhost/cb"]}"#,
                "invalid_client_metadata",
            ),
            ("application/json", "not json", "invalid_client_metadata"),
            ("application/json", "{}", "invalid_redirect_uri"),
            (
                "application/json",
                r#"{"redirect_uris":["https://example.com/cb"]}"#,
                "invalid_redirect_uri",
            ),
            (
                "application/json",
                r#"{"redirect_uris":["http://user@localhost/cb"]}"#,
                "invalid_redirect_uri",
            ),
            (
                "application/json",
                r#"{"redirect_uris":["http://user@localhost/cb"]} trailing"#,
                "invalid_redirect_uri",
            ),
            (
                "application/json",
                r#"{"redirect_uris":["symvault://user@vault/callback"]}"#,
                "invalid_redirect_uri",
            ),
        ];
        for (content_type, body, expected) in cases {
            assert_eq!(
                validate_registration(content_type, body).unwrap_err(),
                expected,
                "body={body}"
            );
        }
    }
}
