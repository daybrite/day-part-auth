// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! What the token endpoint answers, and the requests that reach it: the code exchange
//! (RFC 6749 §4.1.3), refresh (§6), revocation (RFC 7009) and userinfo (OpenID Connect Core
//! §5.3). An ID token in an answer is verified before the answer is returned: signature against
//! the provider's keys, then the claims against this client and the request's nonce.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::Value;

use crate::AuthError;
use crate::authorize::{Authorization, Client};
use crate::http::{get_json, post_form, post_form_json};
use crate::jwt::{self, Claims, Expected, Jwks, Jws};

/// A verified ID token: the token as issued, and its claims.
#[derive(Clone, Debug, PartialEq)]
pub struct IdToken {
    /// The compact JWS, to send on to a server that wants it.
    pub raw: String,
    pub claims: Claims,
}

/// What a sign-in or a refresh produced.
#[derive(Clone, Debug, PartialEq)]
pub struct TokenSet {
    /// The access token, sent as a bearer to the provider's APIs.
    pub access_token: String,
    /// `Bearer`, nearly always.
    pub token_type: String,
    /// When the access token expires, from `expires_in`; `None` when the provider did not say.
    pub expires_at: Option<SystemTime>,
    /// The refresh token, when the provider issued one (and kept from the previous set when a
    /// refresh does not issue a new one).
    pub refresh_token: Option<String>,
    /// The verified ID token, when `openid` was asked for.
    pub id_token: Option<IdToken>,
    /// The scopes granted, as the provider stated them.
    pub scope: Option<String>,
    /// The whole answer, for anything a provider adds.
    pub raw: Value,
}

impl TokenSet {
    /// Whether the access token has expired, or will within `margin`. `false` when the provider
    /// gave no expiry.
    pub fn expires_within(&self, margin: Duration) -> bool {
        self.expires_at
            .is_some_and(|at| SystemTime::now() + margin >= at)
    }

    /// How long the access token is still good for; zero once expired, `None` when unknown.
    pub fn expires_in(&self) -> Option<Duration> {
        self.expires_at.map(|at| {
            at.duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
        })
    }

    /// The signed-in person's stable identifier, from the ID token.
    pub fn subject(&self) -> Option<&str> {
        self.id_token
            .as_ref()
            .and_then(|t| t.claims.subject.as_deref())
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<Value>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// The providers' key sets, kept for an hour; a verification that finds no key for the
/// token's `kid` fetches again once, which is how a rotated key is picked up.
static KEY_SETS: Mutex<Option<HashMap<String, (Jwks, SystemTime)>>> = Mutex::new(None);
const KEY_SET_LIFETIME: Duration = Duration::from_secs(3600);

async fn key_set(jwks_uri: &str, refresh: bool) -> Result<Jwks, AuthError> {
    if !refresh {
        let cached = KEY_SETS
            .lock()
            .ok()
            .and_then(|c| c.as_ref().and_then(|m| m.get(jwks_uri).cloned()));
        if let Some((jwks, fetched)) = cached
            && fetched.elapsed().unwrap_or(KEY_SET_LIFETIME) < KEY_SET_LIFETIME
        {
            return Ok(jwks);
        }
    }
    let jwks: Jwks = get_json(jwks_uri, None).await?;
    if let Ok(mut cache) = KEY_SETS.lock() {
        cache
            .get_or_insert_with(HashMap::new)
            .insert(jwks_uri.to_string(), (jwks.clone(), SystemTime::now()));
    }
    Ok(jwks)
}

/// Verify an ID token's signature and claims for `client`, with the `nonce` of the request it
/// answers and the access token issued beside it.
pub async fn verify_id_token(
    client: &Client,
    raw: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> Result<IdToken, AuthError> {
    let jws = Jws::decode(raw)?;
    let alg = jws.algorithm()?;
    let jwks_uri = client.provider.jwks_uri.as_deref().ok_or_else(|| {
        AuthError::InvalidToken("the provider publishes no keys (jwks_uri)".into())
    })?;
    let verified = match jws.verify(&key_set(jwks_uri, false).await?) {
        Ok(()) => Ok(()),
        // An unknown key may be a fresh one: fetch the set again, once.
        Err(_) => jws.verify(&key_set(jwks_uri, true).await?),
    };
    verified?;
    let claims = Claims::from_payload(&jws.payload);
    let mut expected = Expected::new(client.provider.issuer.clone(), client.client_id.clone());
    expected.nonce = nonce.map(str::to_string);
    expected.access_token = access_token.map(str::to_string);
    jwt::validate(&claims, alg, &expected)?;
    Ok(IdToken {
        raw: raw.to_string(),
        claims,
    })
}

async fn token_set_from(
    client: &Client,
    answer: Value,
    nonce: Option<&str>,
    previous_refresh: Option<&str>,
) -> Result<TokenSet, AuthError> {
    let response: TokenResponse = serde_json::from_value(answer.clone())
        .map_err(|e| AuthError::InvalidToken(format!("token response: {e}")))?;
    let expires_in = match response.expires_in {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    };
    let id_token = match response.id_token.as_deref() {
        Some(raw) => Some(verify_id_token(client, raw, nonce, Some(&response.access_token)).await?),
        None if client.is_openid() => {
            return Err(AuthError::InvalidToken(
                "openid was asked for but no ID token came back".into(),
            ));
        }
        None => None,
    };
    Ok(TokenSet {
        access_token: response.access_token,
        token_type: response.token_type.unwrap_or_else(|| "Bearer".into()),
        expires_at: expires_in.map(|s| SystemTime::now() + Duration::from_secs(s)),
        refresh_token: response
            .refresh_token
            .or_else(|| previous_refresh.map(str::to_string)),
        id_token,
        scope: response.scope,
        raw: answer,
    })
}

/// A confidential client's `Authorization` credentials, and the body fields a public client
/// sends instead.
type ClientAuth<'a> = (Option<(&'a str, &'a str)>, Vec<(&'a str, &'a str)>);

/// The client's credentials for a token request: a confidential client's secret in the
/// `Authorization` header, a public client's id in the body.
fn client_auth(client: &Client) -> ClientAuth<'_> {
    match client.client_secret.as_deref() {
        Some(secret) => (Some((client.client_id.as_str(), secret)), Vec::new()),
        None => (None, vec![("client_id", client.client_id.as_str())]),
    }
}

/// Exchange the callback's code for tokens, verifying the ID token against the request's
/// nonce. Consumes the request: a code is good once.
pub async fn exchange(
    client: &Client,
    request: Authorization,
    callback_url: &str,
) -> Result<TokenSet, AuthError> {
    let code = request.code_from(callback_url)?;
    let (basic, mut fields) = client_auth(client);
    fields.push(("grant_type", "authorization_code"));
    fields.push(("code", &code));
    fields.push(("redirect_uri", request.redirect_uri()));
    if let Some(verifier) = request.verifier() {
        fields.push(("code_verifier", verifier));
    }
    let answer: Value = post_form_json(&client.provider.token_endpoint, &fields, basic).await?;
    token_set_from(client, answer, request.nonce(), None).await
}

/// Trade a refresh token for a new set. The new set keeps the old refresh token when the
/// provider issues no new one; an ID token in the answer is verified without a nonce.
pub async fn refresh(client: &Client, refresh_token: &str) -> Result<TokenSet, AuthError> {
    let (basic, mut fields) = client_auth(client);
    fields.push(("grant_type", "refresh_token"));
    fields.push(("refresh_token", refresh_token));
    let answer: Value = post_form_json(&client.provider.token_endpoint, &fields, basic).await?;
    token_set_from(client, answer, None, Some(refresh_token)).await
}

/// Tell the provider a token is no longer in use (RFC 7009). `hint` is `access_token` or
/// `refresh_token`. A provider with no revocation endpoint answers `Unsupported`.
pub async fn revoke(client: &Client, token: &str, hint: &str) -> Result<(), AuthError> {
    let endpoint = client
        .provider
        .revocation_endpoint
        .as_deref()
        .ok_or(AuthError::Unsupported)?;
    let (basic, mut fields) = client_auth(client);
    fields.push(("token", token));
    fields.push(("token_type_hint", hint));
    post_form(endpoint, &fields, basic).await
}

/// The userinfo endpoint's answer for an access token. The `sub` must match the ID token's
/// when both are at hand (OpenID Connect Core §5.3.2); the caller compares.
pub async fn userinfo(client: &Client, access_token: &str) -> Result<Value, AuthError> {
    let endpoint = client
        .provider
        .userinfo_endpoint
        .as_deref()
        .ok_or(AuthError::Unsupported)?;
    get_json(endpoint, Some(access_token)).await
}

/// The URL that signs the person out at the provider too (OpenID Connect RP-Initiated Logout),
/// when the provider has an end-session endpoint.
pub fn end_session_url(
    client: &Client,
    id_token_hint: Option<&str>,
    post_logout_redirect_uri: Option<&str>,
) -> Option<String> {
    let endpoint = client.provider.end_session_endpoint.as_deref()?;
    let mut fields: Vec<(&str, &str)> = vec![("client_id", client.client_id.as_str())];
    if let Some(hint) = id_token_hint {
        fields.push(("id_token_hint", hint));
    }
    if let Some(redirect) = post_logout_redirect_uri {
        fields.push(("post_logout_redirect_uri", redirect));
    }
    Some(crate::http::with_query(endpoint, &fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;

    #[test]
    fn token_sets_report_expiry() {
        let mut set = TokenSet {
            access_token: "a".into(),
            token_type: "Bearer".into(),
            expires_at: Some(SystemTime::now() + Duration::from_secs(100)),
            refresh_token: None,
            id_token: None,
            scope: None,
            raw: Value::Null,
        };
        assert!(!set.expires_within(Duration::from_secs(10)));
        assert!(set.expires_within(Duration::from_secs(200)));
        assert!(set.expires_in().is_some_and(|d| d.as_secs() <= 100));
        set.expires_at = None;
        assert!(!set.expires_within(Duration::from_secs(10)));
        assert!(set.expires_in().is_none());
        assert!(set.subject().is_none());
    }

    #[test]
    fn end_session_urls_carry_the_hints() {
        let mut provider = Provider::new("https://p/a", "https://p/t");
        let client = Client::new(provider.clone(), "app");
        assert!(end_session_url(&client, None, None).is_none());
        provider.end_session_endpoint = Some("https://p/logout".into());
        let client = Client::new(provider, "app");
        assert_eq!(
            end_session_url(&client, Some("tok"), Some("myapp://out")),
            Some("https://p/logout?client_id=app&id_token_hint=tok&post_logout_redirect_uri=myapp%3A%2F%2Fout".into())
        );
    }

    #[test]
    fn a_confidential_client_sends_its_secret_as_basic_auth() {
        let public = Client::new(Provider::new("https://p/a", "https://p/t"), "app");
        assert_eq!(client_auth(&public), (None, vec![("client_id", "app")]));
        let confidential = public.clone().client_secret("s");
        assert_eq!(client_auth(&confidential), (Some(("app", "s")), Vec::new()));
    }
}
