// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! A provider's endpoints: the fields of an OpenID Connect discovery document this crate uses,
//! filled by hand for a plain OAuth 2.0 server, by [`Provider::discover`] for an OpenID Connect
//! one, or by the two built-in constants for Google and Apple.

use serde::Deserialize;

use crate::AuthError;
use crate::http::get_json;

/// Where a provider's requests go.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Provider {
    /// The issuer identifier every ID token must name. `None` for a plain OAuth 2.0 server.
    #[serde(default)]
    pub issuer: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// The scopes the provider advertises, when it does.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// The PKCE methods the provider advertises. Empty means "not stated".
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

impl Provider {
    /// A plain OAuth 2.0 server: the two endpoints every flow needs. Set the others as fields.
    pub fn new(
        authorization_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
    ) -> Provider {
        Provider {
            authorization_endpoint: authorization_endpoint.into(),
            token_endpoint: token_endpoint.into(),
            ..Provider::default()
        }
    }

    /// Google, as its discovery document publishes it.
    pub fn google() -> Provider {
        Provider {
            issuer: Some("https://accounts.google.com".into()),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_endpoint: "https://oauth2.googleapis.com/token".into(),
            userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo".into()),
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".into()),
            revocation_endpoint: Some("https://oauth2.googleapis.com/revoke".into()),
            end_session_endpoint: None,
            scopes_supported: vec!["openid".into(), "email".into(), "profile".into()],
            code_challenge_methods_supported: vec!["plain".into(), "S256".into()],
        }
    }

    /// Apple, for the web form of Sign in with Apple on platforms without the native sheet.
    pub fn apple() -> Provider {
        Provider {
            issuer: Some("https://appleid.apple.com".into()),
            authorization_endpoint: "https://appleid.apple.com/auth/authorize".into(),
            token_endpoint: "https://appleid.apple.com/auth/token".into(),
            userinfo_endpoint: None,
            jwks_uri: Some("https://appleid.apple.com/auth/keys".into()),
            revocation_endpoint: Some("https://appleid.apple.com/auth/revoke".into()),
            end_session_endpoint: None,
            scopes_supported: vec!["openid".into(), "email".into(), "name".into()],
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }

    /// Fetch `{issuer}/.well-known/openid-configuration` and check that it names `issuer`
    /// (OpenID Connect Discovery §4.3). The issuer must be `https`, or loopback for a local
    /// provider such as the demo one.
    pub async fn discover(issuer: &str) -> Result<Provider, AuthError> {
        let issuer = issuer.trim_end_matches('/');
        if !is_trusted_url(issuer) {
            return Err(AuthError::InvalidRequest(
                "the issuer must be an https URL".into(),
            ));
        }
        let document: Provider =
            get_json(&format!("{issuer}/.well-known/openid-configuration"), None).await?;
        match document.issuer.as_deref().map(|i| i.trim_end_matches('/')) {
            Some(named) if named == issuer => Ok(document),
            Some(named) => Err(AuthError::InvalidToken(format!(
                "the discovery document names issuer {named:?}, not {issuer:?}"
            ))),
            None => Err(AuthError::InvalidToken(
                "the discovery document names no issuer".into(),
            )),
        }
    }

    /// Whether the provider says it takes PKCE with S256. Unstated counts as yes: the client
    /// sends it either way, and a server that ignores it loses nothing.
    pub fn supports_s256(&self) -> bool {
        self.code_challenge_methods_supported.is_empty()
            || self
                .code_challenge_methods_supported
                .iter()
                .any(|m| m == "S256")
    }
}

/// `https://…`, or `http://` on the loopback interface.
pub(crate) fn is_trusted_url(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_providers_are_complete_and_discoverable_in_shape() {
        for p in [Provider::google(), Provider::apple()] {
            assert!(
                p.issuer
                    .as_deref()
                    .is_some_and(|i| i.starts_with("https://"))
            );
            assert!(p.authorization_endpoint.starts_with("https://"));
            assert!(p.token_endpoint.starts_with("https://"));
            assert!(
                p.jwks_uri
                    .as_deref()
                    .is_some_and(|j| j.starts_with("https://"))
            );
            assert!(p.supports_s256());
        }
        let plain = Provider::new("https://a/auth", "https://a/token");
        assert!(plain.issuer.is_none() && plain.supports_s256());
    }

    #[test]
    fn discovery_documents_parse_with_unknown_fields() {
        let doc: Provider = serde_json::from_str(r#"{"issuer":"https://x","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t","response_types_supported":["code"],"code_challenge_methods_supported":["plain"]}"#).expect("parse");
        assert_eq!(doc.issuer.as_deref(), Some("https://x"));
        assert!(!doc.supports_s256());
    }

    #[test]
    fn only_https_and_loopback_issuers_are_trusted() {
        assert!(is_trusted_url("https://accounts.google.com"));
        assert!(is_trusted_url("http://127.0.0.1:4000"));
        assert!(!is_trusted_url("http://example.com"));
        assert!(!is_trusted_url("ftp://x"));
    }
}
