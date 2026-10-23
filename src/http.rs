// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! The few HTTP shapes the client needs over day-part-http: a JSON GET, a form POST that
//! answers JSON, and the error a provider puts in an error body.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::AuthError;

/// Percent-encode for a query or form field (RFC 3986 unreserved characters pass).
pub fn url_encode(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 15)] as char);
        }
    }
    out
}

/// Percent-decode a query or form value (`+` is a space).
pub fn url_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = (*bytes.get(i + 1)? as char).to_digit(16)?;
                let lo = (*bytes.get(i + 2)? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// `k=v&k=v` from pairs, both sides encoded.
pub fn form_encode(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The pairs of a query string or form body, decoded, in order.
pub fn form_decode(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|part| !part.is_empty())
        .filter_map(|part| {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            Some((url_decode(k)?, url_decode(v)?))
        })
        .collect()
}

/// The query of a URL (after `?`, before `#`), decoded.
pub fn query_of(url: &str) -> Vec<(String, String)> {
    let after = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let query = after.split('#').next().unwrap_or("");
    form_decode(query)
}

/// `url` with `fields` appended as its query.
pub fn with_query(url: &str, fields: &[(&str, &str)]) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{}", form_encode(fields))
}

/// What a provider answers when it refuses: `error` and, usually, `error_description`.
fn provider_error(status: u16, body: &[u8]) -> AuthError {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let error = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("http_{status}"));
    let description = parsed
        .as_ref()
        .and_then(|v| v.get("error_description"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            // A plain-text body is worth showing; a JSON body without a description is not.
            let text = String::from_utf8_lossy(body).trim().to_string();
            (parsed.is_none() && !text.is_empty() && text.len() < 400).then_some(text)
        });
    AuthError::Provider { error, description }
}

async fn send(request: day_part_http::Request) -> Result<day_part_http::Response, AuthError> {
    let response = day_part_http::fetch_future(request)
        .await
        .map_err(|e| AuthError::Network(e.to_string()))?;
    if response.status >= 400 {
        return Err(provider_error(response.status, &response.body));
    }
    Ok(response)
}

fn parse<T: DeserializeOwned>(response: &day_part_http::Response) -> Result<T, AuthError> {
    serde_json::from_slice(&response.body)
        .map_err(|e| AuthError::InvalidToken(format!("response body: {e}")))
}

/// GET `url` (with a bearer token when given) and parse the JSON body.
pub async fn get_json<T: DeserializeOwned>(
    url: &str,
    bearer: Option<&str>,
) -> Result<T, AuthError> {
    let mut request = day_part_http::Request::get(url).header("Accept", "application/json");
    if let Some(token) = bearer {
        request = request.bearer(token);
    }
    let response = send(request).await?;
    parse(&response)
}

/// POST `fields` as a form to `url` and parse the JSON body. `basic` sends the client's
/// credentials in the `Authorization` header (RFC 6749 §2.3.1).
pub async fn post_form_json<T: DeserializeOwned>(
    url: &str,
    fields: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> Result<T, AuthError> {
    let mut request = day_part_http::Request::post(url, form_encode(fields).into_bytes())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json");
    if let Some((user, password)) = basic {
        request = request.basic_auth(user, password);
    }
    let response = send(request).await?;
    parse(&response)
}

/// POST `fields` as a form to `url`, expecting no body worth reading (revocation).
pub async fn post_form(
    url: &str,
    fields: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> Result<(), AuthError> {
    let mut request = day_part_http::Request::post(url, form_encode(fields).into_bytes())
        .header("Content-Type", "application/x-www-form-urlencoded");
    if let Some((user, password)) = basic {
        request = request.basic_auth(user, password);
    }
    send(request).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trips_and_reserves_what_rfc3986_reserves() {
        assert_eq!(url_encode("a b&c=d/é~"), "a%20b%26c%3Dd%2F%C3%A9~");
        assert_eq!(url_decode("a%20b+c%26"), Some("a b c&".into()));
        assert_eq!(url_decode("%zz"), None);
        let fields = [
            ("redirect_uri", "myapp://auth?x=1"),
            ("scope", "openid email"),
        ];
        let encoded = form_encode(&fields);
        assert_eq!(
            encoded,
            "redirect_uri=myapp%3A%2F%2Fauth%3Fx%3D1&scope=openid%20email"
        );
        assert_eq!(
            form_decode(&encoded),
            vec![
                ("redirect_uri".to_string(), "myapp://auth?x=1".to_string()),
                ("scope".to_string(), "openid email".to_string())
            ]
        );
        assert_eq!(with_query("https://a/b", &[("c", "d")]), "https://a/b?c=d");
        assert_eq!(
            with_query("https://a/b?x=1", &[("c", "d")]),
            "https://a/b?x=1&c=d"
        );
        assert_eq!(
            query_of("myapp://cb?code=1&state=s#frag"),
            vec![
                ("code".to_string(), "1".to_string()),
                ("state".to_string(), "s".to_string())
            ]
        );
        assert!(query_of("myapp://cb").is_empty());
    }

    #[test]
    fn provider_errors_are_read_from_the_body() {
        let e = provider_error(
            400,
            br#"{"error":"invalid_grant","error_description":"expired"}"#,
        );
        assert_eq!(
            e,
            AuthError::Provider {
                error: "invalid_grant".into(),
                description: Some("expired".into())
            }
        );
        let e = provider_error(503, b"down");
        assert_eq!(
            e,
            AuthError::Provider {
                error: "http_503".into(),
                description: Some("down".into())
            }
        );
        let e = provider_error(401, br#"{"error":"invalid_token"}"#);
        assert_eq!(
            e,
            AuthError::Provider {
                error: "invalid_token".into(),
                description: None
            }
        );
    }
}
