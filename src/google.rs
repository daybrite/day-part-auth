// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! Google sign-in, the native way on Android: Credential Manager with the Google ID option,
//! through the Java arm in `native.rs`. The system sheet lists the device's Google accounts and
//! returns an ID token for the one chosen, with no browser involved.
//!
//! Everywhere else Google is an OpenID Connect provider like any other: the crate's client with
//! `Provider::google()` and the system's auth browser, which is also what the Showcase does on
//! the desktops. [`support`] says which of the two applies.
//!
//! The token is a JWS Google signs (RS256, keys at `https://www.googleapis.com/oauth2/v3/certs`)
//! with `aud` set to the **server** client id the request names and `nonce` echoed from the
//! request; a server verifies it, and [`crate::jwt`] can on the device.

use serde::Deserialize;

use crate::native::{google_sign_in_native_async, google_sign_in_native_support};
use crate::{AuthError, Support, crypto};

/// A Google sign-in request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoogleSignIn {
    server_client_id: String,
    nonce: Option<String>,
    filter_by_authorized_accounts: bool,
    auto_select: bool,
}

impl GoogleSignIn {
    /// A request whose token is for `server_client_id`: the OAuth client id of the **web
    /// application** type that the app's server owns (not the Android client id).
    pub fn new(server_client_id: impl Into<String>) -> Self {
        GoogleSignIn {
            server_client_id: server_client_id.into(),
            nonce: None,
            filter_by_authorized_accounts: false,
            auto_select: false,
        }
    }

    /// A value the ID token must echo, so a server can tie it to this request. One is generated
    /// when none is given.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Show only accounts that signed in to this app before (the "returning user" sheet).
    pub fn filter_by_authorized_accounts(mut self, filter: bool) -> Self {
        self.filter_by_authorized_accounts = filter;
        self
    }

    /// Sign in without a tap when exactly one authorized account exists.
    pub fn auto_select(mut self, auto: bool) -> Self {
        self.auto_select = auto;
        self
    }
}

/// A signed-in Google Account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoogleCredential {
    /// The ID token, a JWS Google signed: send it to the server.
    pub id_token: String,
    /// The account's email, which Google calls the id.
    pub id: String,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    /// The nonce given (or generated) for this request, which the token's `nonce` claim holds.
    pub nonce: String,
}

#[derive(Deserialize)]
struct Answer {
    #[serde(rename = "idToken")]
    id_token: String,
    id: String,
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(default, rename = "givenName")]
    given_name: Option<String>,
    #[serde(default, rename = "familyName")]
    family_name: Option<String>,
    #[serde(default, rename = "profilePictureUri")]
    picture: Option<String>,
}

/// Whether the native sheet exists here (Android with Google Play services).
pub fn support() -> Support {
    if cfg!(target_os = "android") {
        google_sign_in_native_support()
    } else {
        Support::Unsupported
    }
}

/// Show the Google sign-in sheet. [`AuthError::Provider`] with `no_credential` means no account
/// matched (with [`GoogleSignIn::filter_by_authorized_accounts`], none had signed in before).
pub fn sign_in(
    request: GoogleSignIn,
) -> impl std::future::Future<Output = Result<GoogleCredential, AuthError>> + Send {
    let (tx, rx) = day_async::oneshot();
    start(request, Box::new(move |answer| tx.send(answer)));
    async move { rx.await.unwrap_or(Err(AuthError::Cancelled)) }
}

fn start(
    request: GoogleSignIn,
    on_done: Box<dyn FnOnce(Result<GoogleCredential, AuthError>) + Send>,
) {
    if support() == Support::Unsupported {
        on_done(Err(AuthError::Unsupported));
        return;
    }
    if request.server_client_id.is_empty() {
        on_done(Err(AuthError::InvalidRequest(
            "the server client id is empty".into(),
        )));
        return;
    }
    let nonce = match request.nonce {
        Some(n) => n,
        None => match crypto::random_token(32) {
            Ok(n) => n,
            Err(e) => {
                on_done(Err(e));
                return;
            }
        },
    };
    let nonce_arg = nonce.clone();
    let _ = google_sign_in_native_async(
        &request.server_client_id,
        &nonce_arg,
        request.filter_by_authorized_accounts,
        request.auto_select,
        move |answer| {
            on_done(match answer {
                Ok(text) if text == "cancelled" => Err(AuthError::Cancelled),
                Ok(text) if text == "unsupported" => Err(AuthError::Unsupported),
                Ok(text) if text == "no_credential" => Err(AuthError::Provider {
                    error: "no_credential".into(),
                    description: Some("no Google Account matched the request".into()),
                }),
                Ok(text) if text.starts_with("error:") => {
                    Err(AuthError::Platform(text[6..].to_string()))
                }
                Ok(json) => match serde_json::from_str::<Answer>(&json) {
                    Ok(a) => Ok(GoogleCredential {
                        id_token: a.id_token,
                        id: a.id,
                        display_name: a.display_name.filter(|s| !s.is_empty()),
                        given_name: a.given_name.filter(|s| !s.is_empty()),
                        family_name: a.family_name.filter(|s| !s.is_empty()),
                        picture: a.picture.filter(|s| !s.is_empty()),
                        nonce: nonce.clone(),
                    }),
                    Err(e) => Err(AuthError::Platform(format!("credential JSON: {e}"))),
                },
                Err(e) => Err(AuthError::from(e)),
            })
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builder_keeps_what_it_is_given() {
        let r = GoogleSignIn::new("id")
            .nonce("n")
            .filter_by_authorized_accounts(true)
            .auto_select(true);
        assert_eq!(r.server_client_id, "id");
        assert_eq!(r.nonce.as_deref(), Some("n"));
        assert!(r.filter_by_authorized_accounts && r.auto_select);
    }

    #[test]
    fn unsupported_hosts_answer_through_the_callback() {
        if support() != Support::Unsupported {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        start(
            GoogleSignIn::new("id"),
            Box::new(move |a| {
                let _ = tx.send(a);
            }),
        );
        assert_eq!(rx.recv().ok(), Some(Err(AuthError::Unsupported)));
    }
}
