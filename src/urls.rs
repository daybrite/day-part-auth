// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! URL validation at the authorization and transport boundaries.

use crate::AuthError;
use url::{Host, Url};

pub(crate) fn parse(value: &str) -> Result<Url, AuthError> {
    // URL parsers repair whitespace, backslashes and invalid percent escapes. A protocol
    // endpoint must not change identity as it crosses the browser/native HTTP boundary.
    let bytes = value.as_bytes();
    if bytes
        .iter()
        .any(|b| b.is_ascii_control() || *b == b' ' || *b == b'\\')
        || bytes.iter().enumerate().any(|(i, b)| {
            *b == b'%'
                && !bytes
                    .get(i + 1..i + 3)
                    .is_some_and(|s| s.iter().all(u8::is_ascii_hexdigit))
        })
    {
        return Err(invalid());
    }
    let parsed = Url::parse(value).map_err(|_| invalid())?;
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(invalid());
    }
    Ok(parsed)
}

pub(crate) fn endpoint(value: &str) -> Result<Url, AuthError> {
    let parsed = parse(value)?;
    let loopback = match parsed.host() {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if parsed.host().is_none()
        || !(parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback))
    {
        return Err(invalid());
    }
    Ok(parsed)
}

pub(crate) fn callback_matches(expected: &str, received: &str) -> bool {
    let (Ok(mut expected), Ok(mut received)) = (parse(expected), parse(received)) else {
        return false;
    };
    let fixed: Vec<_> = expected
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let actual: Vec<_> = received
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    expected.set_query(None);
    received.set_query(None);
    expected == received
        && fixed.iter().all(|pair| {
            actual.iter().filter(|(key, _)| key == &pair.0).count() == 1 && actual.contains(pair)
        })
}

fn invalid() -> AuthError {
    AuthError::InvalidRequest("invalid authentication URL".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_exceptions_do_not_match_remote_hosts_or_credentials() {
        for url in [
            "http://localhost.evil.test",
            "http://127.0.0.1.evil.test",
            "http://localhost@evil.test",
            "https://user:secret@provider.test",
            "https://provider.test/#fragment",
            " https://provider.test",
            "https://provider.test\\@evil.test",
            "https://provider.test/%zz",
        ] {
            assert!(endpoint(url).is_err(), "{url}");
        }
        for url in [
            "https://provider.test/token",
            "http://localhost:8123/token",
            "http://127.0.0.1:8123/token",
            "http://[::1]:8123/token",
        ] {
            assert!(endpoint(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn callbacks_match_the_endpoint_and_preserve_registered_query_fields() {
        let expected = "app://auth/callback?tenant=one";
        assert!(callback_matches(
            expected,
            "app://auth/callback?tenant=one&code=x&state=y"
        ));
        for url in [
            "app://auth/callback/extra?tenant=one",
            "app://auth/callback.evil?tenant=one",
            "app://auth.evil/callback?tenant=one",
            "app://auth/callback?tenant=two",
            "app://auth/callback?tenant=one&tenant=two",
            "app://auth/callback?tenant=one#code=x",
        ] {
            assert!(!callback_matches(expected, url), "{url}");
        }
    }
}
