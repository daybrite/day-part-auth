// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! Passkeys: the platform's own WebAuthn client, with the standard JSON in and out.
//!
//! A relying party's server produces a `PublicKeyCredentialCreationOptionsJSON` (to register a
//! passkey) or a `PublicKeyCredentialRequestOptionsJSON` (to sign in with one), the shapes
//! `navigator.credentials` takes in a browser (WebAuthn Level 3 §5.1.8 and §5.1.9). This module
//! hands them to the platform's authenticator and returns the credential as
//! `PublicKeyCredential.toJSON()` would: `id`, `rawId`, `type`, `response` (with `clientDataJSON`
//! and either `attestationObject` or `authenticatorData` + `signature` + `userHandle`),
//! `authenticatorAttachment` and `clientExtensionResults`, every binary field base64url. The
//! server verifies it; nothing here interprets it.
//!
//! | Platform | Authenticator |
//! |---|---|
//! | iOS 16, macOS 13 and later | `ASAuthorizationPlatformPublicKeyCredentialProvider` (Swift arm) |
//! | Android 9 and later | Credential Manager (Java arm) |
//! | Windows 10 1903 and later | the platform WebAuthn API, `webauthn.dll` |
//! | Web | `navigator.credentials` (JavaScript arm) |
//! | Linux, HarmonyOS | no platform authenticator an app may call: `Unsupported` |
//!
//! The relying-party id in the options must be one the app is entitled to: an associated
//! domain on Apple (`webcredentials:`), a Digital Asset Links statement on Android, the page's
//! origin on the web. Windows takes the id as given and writes `https://<rp.id>` as the origin
//! of `clientDataJSON` unless the options carry an `origin` field, which the server must then
//! expect.

use serde_json::Value;

use crate::{AuthError, Support};

/// What this platform's passkey client can do.
pub fn support() -> Support {
    imp::support()
}

/// Whether a platform authenticator (Face ID, Touch ID, a screen lock, Windows Hello) can
/// make and use passkeys here, right now.
pub fn platform_authenticator_available() -> impl std::future::Future<Output = bool> + Send {
    let (tx, rx) = day_async::oneshot();
    imp::available(Box::new(move |available| tx.send(available)));
    async move { rx.await.unwrap_or(false) }
}

/// Register a passkey. `options` is a `PublicKeyCredentialCreationOptionsJSON`; the answer is
/// the registration credential as JSON. Fails with [`AuthError::Cancelled`] when the person
/// dismisses the dialog.
pub fn create(
    options: &Value,
) -> impl std::future::Future<Output = Result<Value, AuthError>> + Send {
    let request = check_creation_options(options);
    let (tx, rx) = day_async::oneshot();
    match request {
        Ok(json) => imp::create(json, Box::new(move |answer| tx.send(answer))),
        Err(e) => tx.send(Err(e)),
    }
    async move { rx.await.unwrap_or(Err(AuthError::Cancelled)) }
}

/// Sign in with a passkey. `options` is a `PublicKeyCredentialRequestOptionsJSON`; the answer
/// is the assertion credential as JSON.
pub fn get(options: &Value) -> impl std::future::Future<Output = Result<Value, AuthError>> + Send {
    let request = check_request_options(options);
    let (tx, rx) = day_async::oneshot();
    match request {
        Ok(json) => imp::get(json, Box::new(move |answer| tx.send(answer))),
        Err(e) => tx.send(Err(e)),
    }
    async move { rx.await.unwrap_or(Err(AuthError::Cancelled)) }
}

type OnDone = Box<dyn FnOnce(Result<Value, AuthError>) + Send>;

fn text(options: &Value, path: &[&str]) -> Option<String> {
    let mut cur = options;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str().map(str::to_string)
}

/// The fields a creation request cannot do without, checked before any platform sees it.
fn check_creation_options(options: &Value) -> Result<String, AuthError> {
    if !options.is_object() {
        return Err(AuthError::InvalidRequest(
            "the options must be a JSON object".into(),
        ));
    }
    for (path, what) in [
        (&["rp", "id"][..], "rp.id"),
        (&["rp", "name"][..], "rp.name"),
        (&["user", "id"][..], "user.id"),
        (&["user", "name"][..], "user.name"),
        (&["challenge"][..], "challenge"),
    ] {
        if text(options, path).unwrap_or_default().is_empty() {
            return Err(AuthError::InvalidRequest(format!(
                "the creation options need {what}"
            )));
        }
    }
    if options
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .is_none_or(|p| p.is_empty())
    {
        return Err(AuthError::InvalidRequest(
            "the creation options need pubKeyCredParams".into(),
        ));
    }
    serde_json::to_string(options).map_err(|e| AuthError::InvalidRequest(e.to_string()))
}

/// The fields an assertion request cannot do without.
fn check_request_options(options: &Value) -> Result<String, AuthError> {
    if !options.is_object() {
        return Err(AuthError::InvalidRequest(
            "the options must be a JSON object".into(),
        ));
    }
    if text(options, &["challenge"]).unwrap_or_default().is_empty() {
        return Err(AuthError::InvalidRequest(
            "the request options need a challenge".into(),
        ));
    }
    serde_json::to_string(options).map_err(|e| AuthError::InvalidRequest(e.to_string()))
}

/// The arm's answer: credential JSON, or one of the agreed failure words.
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "android",
    target_arch = "wasm32"
))]
fn read_answer(answer: Result<String, day_bridge::Error>) -> Result<Value, AuthError> {
    match answer {
        Ok(text) => match text.as_str() {
            "cancelled" => Err(AuthError::Cancelled),
            "unsupported" => Err(AuthError::Unsupported),
            "invalid_state" => Err(AuthError::Provider {
                error: "invalid_state".into(),
                description: Some(
                    "a passkey for this account already exists on this device".into(),
                ),
            }),
            "not_allowed" => Err(AuthError::Provider {
                error: "not_allowed".into(),
                description: Some("the authenticator refused the request".into()),
            }),
            other if other.starts_with("error:") => {
                Err(AuthError::Platform(other[6..].to_string()))
            }
            json => serde_json::from_str(json)
                .map_err(|e| AuthError::Platform(format!("credential JSON: {e}"))),
        },
        Err(e) => Err(AuthError::from(e)),
    }
}

// ---------------------------------------------------------------------------
// Per-platform clients. Each exposes:
//   fn support() -> Support
//   fn available(on_done: Box<dyn FnOnce(bool) + Send>)
//   fn create(options_json: String, on_done: OnDone)
//   fn get(options_json: String, on_done: OnDone)
// ---------------------------------------------------------------------------

/// Apple, Android and the web: the arms in `native.rs`.
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "android",
    target_arch = "wasm32"
))]
mod imp {
    use super::*;
    use crate::native::{
        create_passkey_native_async, get_passkey_native_async, passkeys_available_native_async,
        passkeys_available_native_support,
    };

    pub fn support() -> Support {
        passkeys_available_native_support()
    }

    pub fn available(on_done: Box<dyn FnOnce(bool) + Send>) {
        let _ = passkeys_available_native_async(move |answer| on_done(answer == Ok(1)));
    }

    pub fn create(options_json: String, on_done: OnDone) {
        let _ =
            create_passkey_native_async(&options_json, move |answer| on_done(read_answer(answer)));
    }

    pub fn get(options_json: String, on_done: OnDone) {
        let _ = get_passkey_native_async(&options_json, move |answer| on_done(read_answer(answer)));
    }
}

/// Windows: the platform WebAuthn API, in Rust.
#[cfg(target_os = "windows")]
#[path = "passkeys_windows.rs"]
mod imp;

/// Linux and HarmonyOS: no platform authenticator an application may call.
#[cfg(not(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "android",
    target_os = "windows",
    target_arch = "wasm32"
)))]
mod imp {
    use super::*;

    pub fn support() -> Support {
        Support::Unsupported
    }

    pub fn available(on_done: Box<dyn FnOnce(bool) + Send>) {
        on_done(false);
    }

    pub fn create(_options_json: String, on_done: OnDone) {
        on_done(Err(AuthError::Unsupported));
    }

    pub fn get(_options_json: String, on_done: OnDone) {
        on_done(Err(AuthError::Unsupported));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn creation_options_are_checked_before_any_platform_call() {
        let good = json!({
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"id": "dXNlcg", "name": "alice", "displayName": "Alice"},
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
        });
        assert!(check_creation_options(&good).is_ok());
        let mut missing = good.clone();
        missing["user"]["id"] = Value::Null;
        assert!(matches!(
            check_creation_options(&missing),
            Err(AuthError::InvalidRequest(_))
        ));
        let mut no_params = good.clone();
        no_params["pubKeyCredParams"] = json!([]);
        assert!(matches!(
            check_creation_options(&no_params),
            Err(AuthError::InvalidRequest(_))
        ));
        assert!(matches!(
            check_creation_options(&json!("x")),
            Err(AuthError::InvalidRequest(_))
        ));
    }

    #[test]
    fn request_options_need_a_challenge() {
        assert!(check_request_options(&json!({"challenge": "abc"})).is_ok());
        assert!(matches!(
            check_request_options(&json!({"rpId": "x"})),
            Err(AuthError::InvalidRequest(_))
        ));
    }

    /// The probes answer on every host; a target with no client reports so through both.
    #[test]
    fn support_and_availability_agree() {
        let s = support();
        let (tx, rx) = std::sync::mpsc::channel();
        imp::available(Box::new(move |a| {
            let _ = tx.send(a);
        }));
        let available = rx.recv().unwrap_or(false);
        if s == Support::Unsupported {
            assert!(!available);
        }
    }
}
