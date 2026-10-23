// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! Windows: the platform WebAuthn API (`webauthn.dll`, Windows 10 1903 and later), which shows
//! the Windows Hello and security-key dialogs owned by the app's window.
//!
//! The API takes C structures and returns the raw attestation object, authenticator data and
//! signature; this arm builds the `clientDataJSON` the structures want (WebAuthn §5.8.1: `type`,
//! `challenge`, `origin`, `crossOrigin`), with `https://<rp.id>` as the origin unless the
//! options name one in a top-level `origin` field, and packs the answer into the JSON shape the
//! other platforms return. Version-1 option structures are filled, so the oldest API the DLL
//! exports is enough; the later fields stay zero.
//!
//! The calls block for as long as the dialog is up, so they run on a worker thread; the window
//! handle is captured on the calling thread, where `GetActiveWindow` knows the app's window.

use serde_json::{Value, json};
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::Input::KeyboardAndMouse::GetActiveWindow;
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
use windows::core::{HSTRING, PCWSTR};

use super::OnDone;
use crate::crypto::{base64url, base64url_decode};
use crate::{AuthError, Support};

/// `ERROR_CANCELLED` as an HRESULT.
const HRESULT_CANCELLED: i32 = 0x8007_04C7_u32 as i32;
/// `NTE_EXISTS`: a credential for this user already exists on the authenticator.
const HRESULT_EXISTS: i32 = 0x8009_000F_u32 as i32;
/// `NTE_NOT_SUPPORTED`.
const HRESULT_NOT_SUPPORTED: i32 = 0x8009_0029_u32 as i32;
/// `NTE_INVALID_PARAMETER`.
const HRESULT_INVALID_PARAMETER: i32 = 0x8009_0027_u32 as i32;

pub fn support() -> Support {
    Support::Native
}

pub fn available(on_done: Box<dyn FnOnce(bool) + Send>) {
    // SAFETY: no arguments; the DLL answers whether a platform authenticator exists.
    let available = unsafe { WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() }
        .map(|b| b.as_bool())
        .unwrap_or(false);
    on_done(available);
}

/// A window handle that crosses to the worker thread.
#[derive(Clone, Copy)]
struct Window(isize);

fn owner_window() -> Option<Window> {
    // SAFETY: both calls take no arguments and return a handle or null; the process-id query
    // writes into the out-parameter it is given.
    unsafe {
        let active = GetActiveWindow();
        if !active.is_invalid() {
            return Some(Window(active.0 as isize));
        }
        let foreground = GetForegroundWindow();
        if foreground.is_invalid() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(foreground, Some(&mut pid));
        (pid == GetCurrentProcessId()).then_some(Window(foreground.0 as isize))
    }
}

fn on_worker(
    name: &'static str,
    on_done: OnDone,
    work: impl FnOnce() -> Result<Value, AuthError> + Send + 'static,
) {
    let spawned = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || on_done(work()));
    if let Err(e) = spawned {
        eprintln!("day-part-auth: could not start the passkey thread: {e}");
    }
}

pub fn create(options_json: String, on_done: OnDone) {
    let Some(window) = owner_window() else {
        on_done(Err(AuthError::Platform(
            "no window to show the passkey dialog from".into(),
        )));
        return;
    };
    on_worker("day-auth-passkey", on_done, move || {
        make_credential(window, &options_json)
    });
}

pub fn get(options_json: String, on_done: OnDone) {
    let Some(window) = owner_window() else {
        on_done(Err(AuthError::Platform(
            "no window to show the passkey dialog from".into(),
        )));
        return;
    };
    on_worker("day-auth-passkey", on_done, move || {
        get_assertion(window, &options_json)
    });
}

fn parse(options_json: &str) -> Result<Value, AuthError> {
    serde_json::from_str(options_json).map_err(|e| AuthError::InvalidRequest(e.to_string()))
}

fn text<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str()
}

fn bytes_field(v: &Value, path: &[&str]) -> Result<Vec<u8>, AuthError> {
    let text = text(v, path)
        .ok_or_else(|| AuthError::InvalidRequest(format!("missing {}", path.join("."))))?;
    base64url_decode(text)
        .ok_or_else(|| AuthError::InvalidRequest(format!("{} is not base64url", path.join("."))))
}

fn user_verification(v: Option<&str>) -> u32 {
    match v {
        Some("required") => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        Some("preferred") => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
        Some("discouraged") => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
        _ => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
    }
}

fn attachment(v: Option<&str>) -> u32 {
    match v {
        Some("platform") => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        Some("cross-platform") => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        _ => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
    }
}

fn timeout(v: &Value) -> u32 {
    v.get("timeout")
        .and_then(Value::as_u64)
        .and_then(|t| u32::try_from(t).ok())
        .filter(|t| *t > 0)
        .unwrap_or(120_000)
}

/// The `clientDataJSON` the authenticator signs over.
fn client_data(kind: &str, options: &Value, rp_id: &str) -> Result<Vec<u8>, AuthError> {
    let challenge = text(options, &["challenge"])
        .ok_or_else(|| AuthError::InvalidRequest("missing challenge".into()))?;
    let origin = text(options, &["origin"])
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{rp_id}"));
    let data = json!({
        "type": kind,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    });
    serde_json::to_vec(&data).map_err(|e| AuthError::Platform(e.to_string()))
}

/// Credential descriptors (`excludeCredentials` / `allowCredentials`) as the API's list. The
/// id buffers are returned too, so they outlive the structures that point into them.
fn credential_list(items: Option<&Vec<Value>>) -> (Vec<Vec<u8>>, Vec<WEBAUTHN_CREDENTIAL>) {
    let mut ids: Vec<Vec<u8>> = items
        .map(|list| {
            list.iter()
                .filter_map(|c| {
                    c.get("id")
                        .and_then(Value::as_str)
                        .and_then(base64url_decode)
                })
                .collect()
        })
        .unwrap_or_default();
    let creds = ids
        .iter_mut()
        .map(|id| WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: id.len() as u32,
            pbId: id.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        })
        .collect();
    (ids, creds)
}

fn platform_error(e: windows::core::Error) -> AuthError {
    match e.code().0 {
        HRESULT_CANCELLED => AuthError::Cancelled,
        HRESULT_EXISTS => AuthError::Provider {
            error: "invalid_state".into(),
            description: Some("a passkey for this account already exists on this device".into()),
        },
        HRESULT_NOT_SUPPORTED => AuthError::Unsupported,
        HRESULT_INVALID_PARAMETER => AuthError::InvalidRequest(e.message()),
        code => {
            // SAFETY: the DLL returns a static string for any HRESULT.
            let name = unsafe { WebAuthNGetErrorName(e.code()) };
            let name = if name.is_null() {
                String::new()
            } else {
                // SAFETY: a NUL-terminated wide string the DLL owns.
                unsafe { name.to_string() }.unwrap_or_default()
            };
            AuthError::Platform(format!("WebAuthn {name} ({code:#x}): {}", e.message()))
        }
    }
}

/// Copy `len` bytes from an API-owned buffer.
unsafe fn copy(ptr: *mut u8, len: u32) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: the caller passes a buffer the API reported as `len` bytes long.
    unsafe { std::slice::from_raw_parts(ptr, len as usize).to_vec() }
}

fn make_credential(window: Window, options_json: &str) -> Result<Value, AuthError> {
    let options = parse(options_json)?;
    let rp_id = text(&options, &["rp", "id"]).unwrap_or("").to_string();
    let rp_name = HSTRING::from(text(&options, &["rp", "name"]).unwrap_or(""));
    let rp_id_w = HSTRING::from(rp_id.as_str());
    let mut user_id = bytes_field(&options, &["user", "id"])?;
    let user_name = HSTRING::from(text(&options, &["user", "name"]).unwrap_or(""));
    let user_display = HSTRING::from(text(&options, &["user", "displayName"]).unwrap_or(""));
    let mut params: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> = options
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter(|p| p.get("type").and_then(Value::as_str) == Some("public-key"))
                .filter_map(|p| p.get("alg").and_then(Value::as_i64))
                .filter_map(|alg| i32::try_from(alg).ok())
                .map(|alg| WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                    dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                    pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                    lAlg: alg,
                })
                .collect()
        })
        .unwrap_or_default();
    if params.is_empty() {
        return Err(AuthError::InvalidRequest(
            "no usable pubKeyCredParams".into(),
        ));
    }
    let mut client = client_data("webauthn.create", &options, &rp_id)?;
    let (_exclude_ids, mut exclude) =
        credential_list(options.get("excludeCredentials").and_then(Value::as_array));
    let selection = options.get("authenticatorSelection");
    let resident = selection
        .and_then(|s| s.get("residentKey"))
        .and_then(Value::as_str)
        .is_some_and(|r| r == "required")
        || selection
            .and_then(|s| s.get("requireResidentKey"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let conveyance = match text(&options, &["attestation"]) {
        Some("direct") => WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        Some("none") => WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        _ => WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY,
    };

    let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId: PCWSTR(rp_id_w.as_ptr()),
        pwszName: PCWSTR(rp_name.as_ptr()),
        pwszIcon: PCWSTR::null(),
    };
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: user_id.len() as u32,
        pbId: user_id.as_mut_ptr(),
        pwszName: PCWSTR(user_name.as_ptr()),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: PCWSTR(user_display.as_ptr()),
    };
    let cose = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: params.len() as u32,
        pCredentialParameters: params.as_mut_ptr(),
    };
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: client.len() as u32,
        pbClientDataJSON: client.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    let make_options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1,
        dwTimeoutMilliseconds: timeout(&options),
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: exclude.len() as u32,
            pCredentials: exclude.as_mut_ptr(),
        },
        dwAuthenticatorAttachment: attachment(
            selection
                .and_then(|s| s.get("authenticatorAttachment"))
                .and_then(Value::as_str),
        ),
        bRequireResidentKey: resident.into(),
        dwUserVerificationRequirement: user_verification(
            selection
                .and_then(|s| s.get("userVerification"))
                .and_then(Value::as_str),
        ),
        dwAttestationConveyancePreference: conveyance,
        ..Default::default()
    };

    // SAFETY: every structure points into buffers that live until this function returns; the
    // handle is the app's window; the result is freed once below.
    let attestation = unsafe {
        WebAuthNAuthenticatorMakeCredential(
            HWND(window.0 as *mut core::ffi::c_void),
            &rp,
            &user,
            &cose,
            &client_data,
            Some(&make_options),
        )
    }
    .map_err(platform_error)?;
    let (credential_id, attestation_object) = unsafe {
        let a = &*attestation;
        (
            copy(a.pbCredentialId, a.cbCredentialId),
            copy(a.pbAttestationObject, a.cbAttestationObject),
        )
    };
    unsafe { WebAuthNFreeCredentialAttestation(Some(attestation)) };
    let id = base64url(&credential_id);
    Ok(json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": base64url(&client),
            "attestationObject": base64url(&attestation_object),
            "transports": ["internal"],
        }
    }))
}

fn get_assertion(window: Window, options_json: &str) -> Result<Value, AuthError> {
    let options = parse(options_json)?;
    let rp_id = text(&options, &["rpId"]).unwrap_or("").to_string();
    if rp_id.is_empty() {
        return Err(AuthError::InvalidRequest(
            "the request options need rpId".into(),
        ));
    }
    let rp_id_w = HSTRING::from(rp_id.as_str());
    let mut client = client_data("webauthn.get", &options, &rp_id)?;
    let (_allow_ids, mut allow) =
        credential_list(options.get("allowCredentials").and_then(Value::as_array));
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: client.len() as u32,
        pbClientDataJSON: client.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    let get_options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1,
        dwTimeoutMilliseconds: timeout(&options),
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: allow.len() as u32,
            pCredentials: allow.as_mut_ptr(),
        },
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        dwUserVerificationRequirement: user_verification(text(&options, &["userVerification"])),
        ..Default::default()
    };

    // SAFETY: as in `make_credential`.
    let assertion = unsafe {
        WebAuthNAuthenticatorGetAssertion(
            HWND(window.0 as *mut core::ffi::c_void),
            PCWSTR(rp_id_w.as_ptr()),
            &client_data,
            Some(&get_options),
        )
    }
    .map_err(platform_error)?;
    let (credential_id, authenticator_data, signature, user_handle) = unsafe {
        let a = &*assertion;
        (
            copy(a.Credential.pbId, a.Credential.cbId),
            copy(a.pbAuthenticatorData, a.cbAuthenticatorData),
            copy(a.pbSignature, a.cbSignature),
            copy(a.pbUserId, a.cbUserId),
        )
    };
    unsafe { WebAuthNFreeAssertion(assertion) };
    let id = base64url(&credential_id);
    Ok(json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": base64url(&client),
            "authenticatorData": base64url(&authenticator_data),
            "signature": base64url(&signature),
            "userHandle": if user_handle.is_empty() { Value::Null } else { Value::String(base64url(&user_handle)) },
        }
    }))
}
