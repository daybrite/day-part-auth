// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! day-part-auth: sign-in for Day apps, through the platform's own doors.
//!
//! ```no_run
//! use day_part_auth::{Client, Provider};
//!
//! let client = Client::new(Provider::google(), "1234.apps.googleusercontent.com")
//!     .scopes(["openid", "email", "profile"]);
//! # async fn run(client: Client) {
//! match client.sign_in().await {
//!     Ok(tokens) => println!("signed in as {:?}", tokens.subject()),
//!     Err(e) => println!("not signed in: {e}"),
//! }
//! # }
//! ```
//!
//! Three layers, each usable on its own:
//!
//! 1. [`session`]: the system's sign-in browser (`ASWebAuthenticationSession`, a Custom Tab,
//!    a same-origin popup, the default browser with a loopback listener), which returns the URL
//!    the provider redirected to.
//! 2. The OAuth 2.0 / OpenID Connect client: [`Provider`] (discovered or given),
//!    [`Client`] and [`Redirect`], the authorization request with PKCE, `state` and `nonce`
//!    ([`authorize`]), and the token requests ([`tokens`]) whose ID tokens are verified against
//!    the provider's keys ([`jwt`]). [`Client::sign_in`] runs the whole flow.
//! 3. The native credentials: [`apple`] (Sign in with Apple), [`google`] (Credential Manager on
//!    Android), and [`passkeys`] (WebAuthn JSON in, credential JSON out).
//!
//! Every future here is `Send` and resolves on the UI thread when awaited under `day::task`;
//! the calls that show a browser or a sheet start on the UI thread, which is where an action
//! runs. Nothing here posts to a main loop, so the crate works in a plain `main` and under
//! `cargo test`.
//!
//! The crate keeps no tokens. A [`TokenSet`] is the app's to store, and
//! [day-part-keychain](https://daybrite.dev/docs/reference/keychain) is where a refresh token
//! belongs.

use std::fmt;

pub use day_bridge::Support;

pub mod apple;
pub mod authorize;
pub mod crypto;
#[cfg(all(feature = "demo-provider", not(target_arch = "wasm32")))]
pub mod demo_provider;
mod flow;
pub mod google;
mod http;
pub mod jwt;
mod native;
pub mod passkeys;
pub mod provider;
pub mod session;
pub mod tokens;

pub use authorize::{Authorization, Client, Redirect};
pub use provider::Provider;
pub use session::SessionOptions;
pub use tokens::{IdToken, TokenSet};

/// Why a sign-in, a token request or a credential request did not succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// This platform has no implementation of what was asked.
    Unsupported,
    /// The person dismissed the browser or the dialog.
    Cancelled,
    /// The callback never arrived within the time allowed.
    Timeout,
    /// The request could not be built: a missing endpoint, an unusable redirect URI, a
    /// malformed URL. The text says which.
    InvalidRequest(String),
    /// The provider answered an authorization or token request with an error (`error`, and
    /// `error_description` when it gave one).
    Provider {
        error: String,
        description: Option<String>,
    },
    /// The callback's `state` did not match the request's, or arrived without one.
    StateMismatch,
    /// A token or a provider document failed validation. The text says what.
    InvalidToken(String),
    /// A network request failed before the provider answered.
    Network(String),
    /// A platform error outside the vocabulary above, with the platform's message.
    Platform(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Unsupported => write!(f, "not supported on this platform"),
            AuthError::Cancelled => write!(f, "cancelled"),
            AuthError::Timeout => write!(f, "the callback did not arrive in time"),
            AuthError::InvalidRequest(why) => write!(f, "invalid request: {why}"),
            AuthError::Provider { error, description } => match description {
                Some(d) => write!(f, "{error}: {d}"),
                None => write!(f, "{error}"),
            },
            AuthError::StateMismatch => write!(f, "the callback's state does not match"),
            AuthError::InvalidToken(why) => write!(f, "invalid token: {why}"),
            AuthError::Network(why) => write!(f, "network: {why}"),
            AuthError::Platform(why) => write!(f, "platform error: {why}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<day_bridge::Error> for AuthError {
    fn from(e: day_bridge::Error) -> Self {
        match e {
            day_bridge::Error::Unsupported => AuthError::Unsupported,
            day_bridge::Error::Foreign(message) => match message.as_str() {
                "cancelled" => AuthError::Cancelled,
                "unsupported" => AuthError::Unsupported,
                _ => AuthError::Platform(message),
            },
            day_bridge::Error::Encoding => AuthError::Platform("bridge encoding error".into()),
            day_bridge::Error::Runtime => {
                AuthError::Platform("platform runtime unavailable".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_display_and_convert() {
        for e in [
            AuthError::Unsupported,
            AuthError::Cancelled,
            AuthError::Timeout,
            AuthError::InvalidRequest("x".into()),
            AuthError::Provider {
                error: "e".into(),
                description: None,
            },
            AuthError::Provider {
                error: "e".into(),
                description: Some("d".into()),
            },
            AuthError::StateMismatch,
            AuthError::InvalidToken("x".into()),
            AuthError::Network("x".into()),
            AuthError::Platform("x".into()),
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(
            AuthError::from(day_bridge::Error::Foreign("cancelled".into())),
            AuthError::Cancelled
        );
        assert_eq!(
            AuthError::from(day_bridge::Error::Unsupported),
            AuthError::Unsupported
        );
    }
}
