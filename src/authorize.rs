// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! A client's identity and redirect, the authorization request it sends the provider's
//! authorization endpoint, and the callback it gets back: RFC 6749 §4.1.1 and §4.1.2 with
//! PKCE (RFC 7636) and the OpenID Connect `nonce`.
//!
//! [`Client`] holds what never changes between sign-ins (provider, client id, redirect, scopes).
//! [`Client::start`] draws the per-request secrets, resolves the redirect for this platform
//! (binding a loopback listener where that is the redirect) and returns an [`Authorization`]:
//! the URL to open, and the secrets to check the callback against. The crate's `flow` module
//! runs the browser and the token exchange; an app with its own browser uses these two halves
//! directly.

use crate::AuthError;
use crate::crypto;
use crate::http::{query_of, with_query};
use crate::provider::{Provider, is_trusted_url};
use crate::session::{Loopback, SessionOptions};

/// Where the provider sends the person back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Redirect {
    /// What fits this platform: the app's own scheme (`DAY_APP_SCHEME`, which `day build` sets
    /// from `Day.toml`) with the path `/auth/callback` on iOS, Android and HarmonyOS; a loopback
    /// listener on the desktops; the page's own URL (without its fragment) on the web.
    Auto,
    /// A custom-scheme URL the app registered (`myapp://auth/callback`). The platform's auth
    /// browser returns it on Apple; Android, the desktops and HarmonyOS receive it as a deep
    /// link.
    Scheme(String),
    /// A listener this crate opens on `127.0.0.1` for the flow (RFC 8252 §7.3). Port 0 lets
    /// the OS choose, which is what Google requires of desktop apps; a provider that registers
    /// one exact URL takes a fixed port.
    Loopback { port: u16, path: String },
    /// An `https://` URL the app owns: a universal link (iOS), an app link (Android), the page
    /// itself on the web.
    Https(String),
}

impl Redirect {
    /// A loopback redirect on any free port at `/callback`.
    pub fn loopback() -> Redirect {
        Redirect::Loopback {
            port: 0,
            path: "/callback".into(),
        }
    }
}

/// An OAuth 2.0 / OpenID Connect client: what never changes between sign-ins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub(crate) provider: Provider,
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
    pub(crate) redirect: Redirect,
    pub(crate) scopes: Vec<String>,
    pub(crate) extra: Vec<(String, String)>,
    pub(crate) session: SessionOptions,
    pub(crate) pkce: bool,
}

impl Client {
    /// A public client (no secret) asking for `openid`, with the platform's default redirect.
    pub fn new(provider: Provider, client_id: impl Into<String>) -> Client {
        Client {
            provider,
            client_id: client_id.into(),
            client_secret: None,
            redirect: Redirect::Auto,
            scopes: vec!["openid".into()],
            extra: Vec::new(),
            session: SessionOptions::default(),
            pkce: true,
        }
    }

    /// The provider this client talks to.
    pub fn provider(&self) -> &Provider {
        &self.provider
    }

    /// This client's id at the provider.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Where the provider sends the person back.
    pub fn redirect(mut self, redirect: Redirect) -> Self {
        self.redirect = redirect;
        self
    }

    /// The scopes to ask for, replacing the default `openid`.
    pub fn scopes<S: Into<String>>(mut self, scopes: impl IntoIterator<Item = S>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// A confidential client's secret, sent with every token request. A native app has none:
    /// a secret shipped inside an app is not one.
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// An extra parameter on the authorization request (`prompt`, `login_hint`, `access_type`,
    /// `hd`, a provider's own).
    pub fn param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push((name.into(), value.into()));
        self
    }

    /// How the browser session is shown.
    pub fn session(mut self, options: SessionOptions) -> Self {
        self.session = options;
        self
    }

    /// Whether to send a PKCE challenge. On by default; off only for a provider that rejects
    /// unknown parameters, which is rare and unsafe for a public client.
    pub fn pkce(mut self, on: bool) -> Self {
        self.pkce = on;
        self
    }

    /// Whether `openid` is among the scopes, which is what makes the answer an ID token.
    pub fn is_openid(&self) -> bool {
        self.scopes.iter().any(|s| s == "openid")
    }

    /// Draw this request's secrets, resolve the redirect, and build the authorization URL.
    pub fn start(&self) -> Result<Authorization, AuthError> {
        if self.client_id.is_empty() {
            return Err(AuthError::InvalidRequest("the client id is empty".into()));
        }
        if !is_trusted_url(&self.provider.authorization_endpoint) {
            return Err(AuthError::InvalidRequest(
                "the authorization endpoint must be an https URL".into(),
            ));
        }
        let (redirect_uri, loopback) = resolve_redirect(&self.redirect)?;
        let state = crypto::random_token(24)?;
        let nonce = if self.is_openid() {
            Some(crypto::random_token(24)?)
        } else {
            None
        };
        let verifier = if self.pkce {
            Some(crypto::random_token(48)?)
        } else {
            None
        };
        let scope = self.scopes.join(" ");
        let mut fields: Vec<(&str, &str)> = vec![
            ("response_type", "code"),
            ("client_id", &self.client_id),
            ("redirect_uri", &redirect_uri),
            ("scope", &scope),
            ("state", &state),
        ];
        if let Some(nonce) = &nonce {
            fields.push(("nonce", nonce));
        }
        let challenge = verifier
            .as_deref()
            .map(|v| crypto::base64url(&crypto::sha256(v.as_bytes())));
        if let Some(challenge) = &challenge {
            fields.push(("code_challenge", challenge));
            fields.push(("code_challenge_method", "S256"));
        }
        for (k, v) in &self.extra {
            fields.push((k, v));
        }
        let url = with_query(&self.provider.authorization_endpoint, &fields);
        Ok(Authorization {
            url,
            redirect_uri,
            state,
            nonce,
            verifier,
            loopback,
        })
    }
}

/// One authorization request in flight: the URL to open, and what the callback is checked
/// against. Consumed by `complete`.
pub struct Authorization {
    url: String,
    redirect_uri: String,
    state: String,
    nonce: Option<String>,
    verifier: Option<String>,
    loopback: Option<Loopback>,
}

impl Authorization {
    /// The URL to open in the auth browser.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The redirect URI this request named, resolved for this platform.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// The `state` the callback must echo.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// The `nonce` the ID token must echo, when `openid` was asked for.
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// The PKCE verifier the token request sends.
    pub fn verifier(&self) -> Option<&str> {
        self.verifier.as_deref()
    }

    /// The loopback listener, when the redirect is one. [`Client::sign_in`] awaits it itself;
    /// an app that opens the browser its own way (or a test that fetches the URL with an HTTP
    /// client, which follows the redirect to the listener) takes it here and awaits
    /// [`Loopback::wait`] before completing the request.
    pub fn take_loopback(&mut self) -> Option<Loopback> {
        self.loopback.take()
    }

    /// Check the callback URL's `state` and read its `code`, or the error the provider sent
    /// (RFC 6749 §4.1.2.1). The state comparison does not stop at the first difference.
    pub fn code_from(&self, callback_url: &str) -> Result<String, AuthError> {
        if !callback_url.starts_with(&self.redirect_uri) {
            return Err(AuthError::InvalidRequest(
                "the callback is not for this request's redirect".into(),
            ));
        }
        let query = query_of(callback_url);
        let get = |name: &str| {
            query
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        match get("state") {
            Some(state) if crypto::constant_time_eq(state.as_bytes(), self.state.as_bytes()) => {}
            _ => return Err(AuthError::StateMismatch),
        }
        if let Some(error) = get("error") {
            return Err(AuthError::Provider {
                error: error.to_string(),
                description: get("error_description").map(str::to_string),
            });
        }
        match get("code") {
            Some(code) if !code.is_empty() => Ok(code.to_string()),
            _ => Err(AuthError::InvalidRequest(
                "the callback carries no code".into(),
            )),
        }
    }
}

/// The redirect URI for this platform, and the loopback listener when the redirect is one.
fn resolve_redirect(redirect: &Redirect) -> Result<(String, Option<Loopback>), AuthError> {
    match redirect {
        Redirect::Scheme(url) => {
            if !url.contains("://") || url.starts_with("http://") || url.starts_with("https://") {
                return Err(AuthError::InvalidRequest(
                    "a scheme redirect is `<scheme>://<path>` with the app's own scheme".into(),
                ));
            }
            Ok((url.clone(), None))
        }
        Redirect::Https(url) => {
            if !url.starts_with("https://") {
                return Err(AuthError::InvalidRequest(
                    "an https redirect must start with https://".into(),
                ));
            }
            Ok((url.clone(), None))
        }
        Redirect::Loopback { port, path } => {
            let listener = Loopback::bind(*port, path)?;
            Ok((listener.redirect_uri().to_string(), Some(listener)))
        }
        Redirect::Auto => {
            if cfg!(target_arch = "wasm32") {
                // The page itself: the popup comes back to it and posts the URL to the opener.
                // A page served over plain http (local development) is accepted as the redirect
                // the provider sees; whether the provider takes it is the provider's rule.
                let page = crate::session::page_url().ok_or_else(|| {
                    AuthError::InvalidRequest(
                        "the page's URL is unknown; name a Redirect::Https".into(),
                    )
                })?;
                return Ok((page, None));
            }
            if cfg!(any(
                target_os = "ios",
                target_os = "android",
                target_env = "ohos"
            )) {
                let scheme = app_scheme().ok_or_else(|| {
                    AuthError::InvalidRequest(
                        "no app scheme is known (DAY_APP_SCHEME); name a Redirect::Scheme".into(),
                    )
                })?;
                return Ok((format!("{scheme}://auth/callback"), None));
            }
            resolve_redirect(&Redirect::loopback())
        }
    }
}

/// The app's URL scheme, which `day build` and `day launch` export as `DAY_APP_SCHEME`.
pub fn app_scheme() -> Option<String> {
    std::env::var("DAY_APP_SCHEME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| option_env!("DAY_APP_SCHEME").map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        Client::new(Provider::new("https://p/auth", "https://p/token"), "app")
            .redirect(Redirect::Scheme("myapp://auth/callback".into()))
            .scopes(["openid", "email"])
            .param("prompt", "consent")
    }

    #[test]
    fn the_request_carries_pkce_state_nonce_and_the_extras() {
        let a = client().start().expect("start");
        let query = query_of(a.url());
        let get = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert!(a.url().starts_with("https://p/auth?"));
        assert_eq!(get("response_type").as_deref(), Some("code"));
        assert_eq!(get("client_id").as_deref(), Some("app"));
        assert_eq!(
            get("redirect_uri").as_deref(),
            Some("myapp://auth/callback")
        );
        assert_eq!(get("scope").as_deref(), Some("openid email"));
        assert_eq!(get("state").as_deref(), Some(a.state()));
        assert_eq!(get("nonce").as_deref(), a.nonce());
        assert_eq!(get("code_challenge_method").as_deref(), Some("S256"));
        assert_eq!(get("prompt").as_deref(), Some("consent"));
        let expected =
            crypto::base64url(&crypto::sha256(a.verifier().expect("verifier").as_bytes()));
        assert_eq!(get("code_challenge").as_deref(), Some(expected.as_str()));
        // Two requests never share secrets.
        let b = client().start().expect("start");
        assert_ne!(a.state(), b.state());
        assert_ne!(a.verifier(), b.verifier());
    }

    #[test]
    fn plain_oauth_sends_no_nonce_and_pkce_can_be_turned_off() {
        let a = client()
            .scopes(["read"])
            .pkce(false)
            .start()
            .expect("start");
        assert!(a.nonce().is_none() && a.verifier().is_none());
        assert!(!a.url().contains("code_challenge"));
        assert!(!a.url().contains("nonce="));
    }

    #[test]
    fn callbacks_are_checked_for_redirect_state_error_and_code() {
        let a = client().start().expect("start");
        let good = format!("myapp://auth/callback?state={}&code=abc", a.state());
        assert_eq!(a.code_from(&good).as_deref(), Ok("abc"));
        assert_eq!(
            a.code_from("myapp://other?code=abc"),
            Err(AuthError::InvalidRequest(
                "the callback is not for this request's redirect".into()
            ))
        );
        assert_eq!(
            a.code_from("myapp://auth/callback?state=wrong&code=abc"),
            Err(AuthError::StateMismatch)
        );
        assert_eq!(
            a.code_from("myapp://auth/callback?code=abc"),
            Err(AuthError::StateMismatch)
        );
        let denied = format!(
            "myapp://auth/callback?state={}&error=access_denied&error_description=no",
            a.state()
        );
        assert_eq!(
            a.code_from(&denied),
            Err(AuthError::Provider {
                error: "access_denied".into(),
                description: Some("no".into())
            })
        );
        let empty = format!("myapp://auth/callback?state={}", a.state());
        assert!(matches!(
            a.code_from(&empty),
            Err(AuthError::InvalidRequest(_))
        ));
    }

    #[test]
    fn redirects_are_validated_and_loopback_binds() {
        assert!(
            Client::new(Provider::new("https://p/a", "https://p/t"), "app")
                .redirect(Redirect::Scheme("https://x".into()))
                .start()
                .is_err()
        );
        assert!(
            Client::new(Provider::new("https://p/a", "https://p/t"), "app")
                .redirect(Redirect::Https("http://x".into()))
                .start()
                .is_err()
        );
        assert!(
            Client::new(Provider::new("http://p/a", "https://p/t"), "app")
                .start()
                .is_err()
        );
        assert!(
            Client::new(Provider::new("https://p/a", "https://p/t"), "")
                .start()
                .is_err()
        );
        let mut a = Client::new(Provider::new("https://p/a", "https://p/t"), "app")
            .redirect(Redirect::loopback())
            .start()
            .expect("start");
        assert!(a.redirect_uri().starts_with("http://127.0.0.1:"));
        assert!(a.take_loopback().is_some());
        assert!(a.take_loopback().is_none());
    }
}
