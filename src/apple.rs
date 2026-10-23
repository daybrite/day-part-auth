// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! Sign in with Apple, the native way: `ASAuthorizationAppleIDProvider` on iOS and macOS,
//! through the Swift arm in `native.rs`. The system sheet signs the person in with their Apple
//! Account (Face ID, Touch ID or the device passcode) and returns an identity token, an
//! authorization code, and, the first time only, the name and email they chose to share.
//!
//! On every other platform [`support`] reports `Unsupported`; Apple offers the web flow there,
//! which is an OpenID Connect authorization against `https://appleid.apple.com` with a Services
//! ID as the client and an `https://` redirect the app's server receives (`response_mode=form_post`).
//!
//! # Verify the identity token on the server
//!
//! The identity token is a JWS Apple signs (RS256, keys at `https://appleid.apple.com/auth/keys`)
//! whose `sub` is the person's stable identifier for this app; `email` and the `nonce` echoed
//! from [`SignInWithApple::nonce`] are inside. A server that accepts it verifies the signature,
//! the `iss` (`https://appleid.apple.com`), the `aud` (the app's bundle id), the expiry and the
//! nonce; [`crate::jwt`] does the same on the device.
//!
//! The `nonce` crosses to Apple as its SHA-256 (Apple's rule), and comes back in the token as
//! the hash too; compare against [`AppleCredential::hashed_nonce`].

use serde::Deserialize;

use crate::native::{
    apple_credential_state_native_async, apple_sign_in_native_async, apple_sign_in_native_support,
};
use crate::{AuthError, Support, crypto};

/// What the sheet asks the person to share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppleScope {
    /// The person's name (shared the first time only; keep it).
    FullName,
    /// The email, or Apple's private relay address.
    Email,
}

/// A Sign in with Apple request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInWithApple {
    scopes: Vec<AppleScope>,
    nonce: Option<String>,
    state: Option<String>,
}

impl SignInWithApple {
    /// A request for the name and email.
    pub fn new() -> Self {
        SignInWithApple {
            scopes: vec![AppleScope::FullName, AppleScope::Email],
            nonce: None,
            state: None,
        }
    }

    /// Which details to ask for. Empty asks for none: the token still carries `sub`.
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = AppleScope>) -> Self {
        self.scopes = scopes.into_iter().collect();
        self
    }

    /// A value the identity token must echo (as its SHA-256), so a server can tie the token
    /// to this request. One is generated when none is given.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// A value handed back untouched with the credential.
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }
}

impl Default for SignInWithApple {
    fn default() -> Self {
        Self::new()
    }
}

/// Apple's assessment of whether the person is likely real (iOS 14, macOS 11 and later).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealUserStatus {
    /// Apple does not know (an older device, or a Mac).
    Unsupported,
    /// Nothing said either way.
    Unknown,
    /// Likely a real person.
    LikelyReal,
}

/// A signed-in Apple Account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppleCredential {
    /// The person's stable identifier for this app (the token's `sub`).
    pub user: String,
    /// The identity token, a JWS Apple signed: send it to the server.
    pub identity_token: String,
    /// A short-lived code the server may exchange at Apple's token endpoint.
    pub authorization_code: String,
    /// The email or private relay address, the first time it is shared.
    pub email: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub real_user_status: RealUserStatus,
    /// The nonce given (or generated) for this request, in clear.
    pub nonce: String,
    /// The SHA-256 of the nonce as base64url: what the identity token's `nonce` claim holds.
    pub hashed_nonce: String,
    /// The `state` given, echoed.
    pub state: Option<String>,
}

#[derive(Deserialize)]
struct Answer {
    user: String,
    #[serde(rename = "identityToken")]
    identity_token: String,
    #[serde(rename = "authorizationCode")]
    authorization_code: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, rename = "givenName")]
    given_name: Option<String>,
    #[serde(default, rename = "familyName")]
    family_name: Option<String>,
    #[serde(default, rename = "realUserStatus")]
    real_user_status: i32,
    #[serde(default)]
    state: Option<String>,
}

/// Whether the native sheet exists here (iOS 13, macOS 10.15 and later).
pub fn support() -> Support {
    if cfg!(any(target_os = "ios", target_os = "macos")) {
        apple_sign_in_native_support()
    } else {
        Support::Unsupported
    }
}

/// Show the Sign in with Apple sheet.
pub fn sign_in(
    request: SignInWithApple,
) -> impl std::future::Future<Output = Result<AppleCredential, AuthError>> + Send {
    let (tx, rx) = day_async::oneshot();
    start(request, Box::new(move |answer| tx.send(answer)));
    async move { rx.await.unwrap_or(Err(AuthError::Cancelled)) }
}

fn start(
    request: SignInWithApple,
    on_done: Box<dyn FnOnce(Result<AppleCredential, AuthError>) + Send>,
) {
    if support() == Support::Unsupported {
        on_done(Err(AuthError::Unsupported));
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
    let hashed_nonce = crypto::base64url(&crypto::sha256(nonce.as_bytes()));
    // Apple wants the hex digest in the request; the token echoes the same digest.
    let request_nonce = crypto::hex(&crypto::sha256(nonce.as_bytes()));
    let scopes: Vec<&str> = request
        .scopes
        .iter()
        .map(|s| match s {
            AppleScope::FullName => "fullName",
            AppleScope::Email => "email",
        })
        .collect();
    let state = request.state.clone();
    let state_arg = state.clone().unwrap_or_default();
    let scopes = scopes.join(",");
    let _ = apple_sign_in_native_async(&scopes, &request_nonce, &state_arg, move |answer| {
        on_done(match answer {
            Ok(text) if text == "cancelled" => Err(AuthError::Cancelled),
            Ok(text) if text == "unsupported" => Err(AuthError::Unsupported),
            Ok(text) if text.starts_with("error:") => {
                Err(AuthError::Platform(text[6..].to_string()))
            }
            Ok(json) => match serde_json::from_str::<Answer>(&json) {
                Ok(a) => Ok(AppleCredential {
                    user: a.user,
                    identity_token: a.identity_token,
                    authorization_code: a.authorization_code,
                    email: a.email.filter(|e| !e.is_empty()),
                    given_name: a.given_name.filter(|e| !e.is_empty()),
                    family_name: a.family_name.filter(|e| !e.is_empty()),
                    real_user_status: match a.real_user_status {
                        1 => RealUserStatus::Unknown,
                        2 => RealUserStatus::LikelyReal,
                        _ => RealUserStatus::Unsupported,
                    },
                    nonce: nonce.clone(),
                    hashed_nonce: hashed_nonce.clone(),
                    state: a.state.filter(|s| !s.is_empty()).or(state.clone()),
                }),
                Err(e) => Err(AuthError::Platform(format!("credential JSON: {e}"))),
            },
            Err(e) => Err(AuthError::from(e)),
        })
    });
}

/// Whether the person is still signed in with Apple for this app, the state an app checks at
/// launch to decide whether to show its content or the sign-in sheet again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialState {
    /// The credential is good.
    Authorized,
    /// The person stopped using Apple to sign in to this app: sign them out.
    Revoked,
    /// Apple does not know this identifier.
    NotFound,
}

/// Ask Apple whether `user` (an [`AppleCredential::user`]) is still authorized.
pub fn credential_state(
    user: &str,
) -> impl std::future::Future<Output = Result<CredentialState, AuthError>> + Send {
    let (tx, rx) = day_async::oneshot();
    if support() == Support::Unsupported {
        tx.send(Err(AuthError::Unsupported));
    } else {
        let _ = apple_credential_state_native_async(user, move |answer| {
            tx.send(match answer {
                Ok(1) => Ok(CredentialState::Authorized),
                Ok(2) => Ok(CredentialState::Revoked),
                Ok(_) => Ok(CredentialState::NotFound),
                Err(e) => Err(AuthError::from(e)),
            })
        });
    }
    async move { rx.await.unwrap_or(Err(AuthError::Cancelled)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builder_keeps_what_it_is_given() {
        let r = SignInWithApple::new()
            .scopes([AppleScope::Email])
            .nonce("n")
            .state("s");
        assert_eq!(r.scopes, vec![AppleScope::Email]);
        assert_eq!(r.nonce.as_deref(), Some("n"));
        assert_eq!(r.state.as_deref(), Some("s"));
        assert_eq!(SignInWithApple::default().scopes.len(), 2);
    }

    /// Without the sheet, the answer is `Unsupported`, through the callback and the future alike.
    #[test]
    fn unsupported_hosts_answer_through_the_callback() {
        if support() != Support::Unsupported {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        start(
            SignInWithApple::new(),
            Box::new(move |a| {
                let _ = tx.send(a);
            }),
        );
        assert_eq!(rx.recv().ok(), Some(Err(AuthError::Unsupported)));
    }
}
