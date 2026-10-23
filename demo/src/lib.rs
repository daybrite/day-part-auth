// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! Auth Demo: the demo and on-device test app for `day-part-auth`.
//!
//! One page, four sections: OpenID Connect against the demo provider the app starts on loopback,
//! passkeys, Sign in with Apple, and Google. Every element carries a stable id, so
//! `dayscript/auth.yaml` can drive the silent sign-in and the token lifecycle on every target CI
//! builds, which is how the crate proves that the client, the HTTP stack, the token verification
//! and the provider all meet inside a real app. The browser and the system sheets need a person.

use day::prelude::*;
use day_part_auth::apple::SignInWithApple;
use day_part_auth::google::GoogleSignIn;
use day_part_auth::{AuthError, Client, Support, TokenSet};
use serde_json::json;

// The mobile entry point; a plain cargo desktop build enters through src/main.rs.
day::day_start!(options: window(), root);

// Typed constants for everything under `resource/` (https://daybrite.dev/docs/how-to/resources).
day::resources!();

/// The window every entry point opens.
pub fn window() -> day::WindowOptions {
    res::window_options().size(560.0, 760.0)
}

/// The whole app: title, caption, and the four sections.
pub fn root() -> impl Piece {
    info!("Auth Demo starting");
    scroll(
        column((
            label(res::str::app_title())
                .font(Font::Title)
                .id(day::id!(auth_title)),
            label(res::str::caption()).font(Font::Footnote),
            oidc_section(),
            passkeys_section(),
            apple_section(),
            google_section(),
        ))
        .spacing(12.0)
        .padding(16.0),
    )
}

/// The three-way support label: what the part promises for this target.
fn support_text(support: Support) -> LocalizedText {
    match support {
        Support::Native => res::str::support_native(),
        Support::Emulated => res::str::support_emulated(),
        Support::Unsupported => res::str::support_unsupported(),
    }
}

/// The demo provider, started once for the life of the app, on native targets.
#[cfg(not(target_arch = "wasm32"))]
mod demo {
    use std::sync::OnceLock;

    use day_part_auth::demo_provider::{DemoConfig, DemoProvider, sign_in_headless};
    use day_part_auth::{AuthError, Client, TokenSet};

    static PROVIDER: OnceLock<Option<DemoProvider>> = OnceLock::new();

    pub fn provider() -> Option<&'static DemoProvider> {
        PROVIDER
            .get_or_init(|| match DemoProvider::start(DemoConfig::default()) {
                Ok(p) => Some(p),
                Err(e) => {
                    day::prelude::info!("the demo provider did not start: {e}");
                    None
                }
            })
            .as_ref()
    }

    /// The client every section of the page uses: the demo provider's one client id, the
    /// platform's default redirect, and the three scopes the provider knows.
    pub fn client() -> Option<Client> {
        let demo = provider()?;
        Some(Client::new(demo.provider(), demo.client_id()).scopes(["openid", "profile", "email"]))
    }

    /// The silent sign-in: `prompt=none` as the first demo account, no browser.
    pub async fn silent(client: Client) -> Result<TokenSet, AuthError> {
        let user = provider().and_then(|p| p.users().first().map(|u| u.sub.clone()));
        sign_in_headless(&client, user.as_deref()).await
    }
}

/// On the web there is no loopback server to run: the section shows why, and its buttons answer
/// `Unsupported`.
#[cfg(target_arch = "wasm32")]
mod demo {
    use day_part_auth::{AuthError, Client, TokenSet};

    pub fn client() -> Option<Client> {
        None
    }

    pub async fn silent(_client: Client) -> Result<TokenSet, AuthError> {
        Err(AuthError::Unsupported)
    }
}

/// The signed-in line for a token set, from its ID token when there is one.
fn signed_in_text(tokens: &TokenSet) -> String {
    let claims = tokens.id_token.as_ref().map(|t| &t.claims);
    res::str::oidc_signed_in(res::str::OidcSignedIn {
        name: claims
            .and_then(|c| c.name.clone())
            .unwrap_or_else(|| "?".into()),
        email: claims
            .and_then(|c| c.email.clone())
            .unwrap_or_else(|| "?".into()),
        sub: tokens.subject().unwrap_or("?").to_string(),
    })
    .format()
}

fn expiry_text(tokens: &TokenSet) -> String {
    res::str::oidc_expires(
        tokens
            .expires_in()
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|| "?".into()),
    )
    .format()
}

/// OpenID Connect against the demo provider: the browser sign-in, the silent one, and the token
/// lifecycle (refresh, userinfo, revocation, sign-out).
fn oidc_section() -> impl Piece {
    let status = Signal::new(res::str::oidc_idle().format());
    let detail = Signal::new(String::new());
    let tokens: Signal<Option<TokenSet>> = Signal::new(None);
    let caps = day_part_auth::session::capabilities();
    let client = demo::client();
    let issuer = client
        .as_ref()
        .and_then(|c| c.provider().issuer.clone())
        .unwrap_or_else(|| res::str::oidc_issuer_none().format());

    // Each action takes the outcome of one future and writes the three signals from it, on the
    // UI thread, which is where the continuation of `day::task` runs.
    let settle =
        move |outcome: Result<TokenSet, AuthError>, on_ok: fn(&TokenSet) -> String| match outcome {
            Ok(set) => {
                status.set(on_ok(&set));
                detail.set(expiry_text(&set));
                tokens.set(Some(set));
            }
            Err(e) => status.set(e.to_string()),
        };
    let with_client = {
        let client = client.clone();
        move || -> Option<Client> {
            if client.is_none() {
                status.set(AuthError::Unsupported.to_string());
            }
            client.clone()
        }
    };
    let access_token = move || tokens.with(|t| t.as_ref().map(|t| t.access_token.clone()));

    let sign_in = {
        let with_client = with_client.clone();
        move || {
            let Some(client) = with_client() else { return };
            status.set(res::str::oidc_working().format());
            day::task(async move {
                settle(client.sign_in().await, signed_in_text);
            });
        }
    };
    let sign_in_silent = {
        let with_client = with_client.clone();
        move || {
            let Some(client) = with_client() else { return };
            status.set(res::str::oidc_working().format());
            day::task(async move {
                settle(demo::silent(client).await, signed_in_text);
            });
        }
    };
    let refresh = {
        let with_client = with_client.clone();
        move || {
            let Some(client) = with_client() else { return };
            let Some(refresh_token) =
                tokens.with(|t| t.as_ref().and_then(|t| t.refresh_token.clone()))
            else {
                status.set(res::str::oidc_idle().format());
                return;
            };
            day::task(async move {
                settle(client.refresh(&refresh_token).await, |_| {
                    res::str::oidc_refreshed().format()
                });
            });
        }
    };
    let userinfo = {
        let with_client = with_client.clone();
        move || {
            let Some(client) = with_client() else { return };
            let Some(access) = access_token() else {
                status.set(res::str::oidc_idle().format());
                return;
            };
            day::task(async move {
                match client.userinfo(&access).await {
                    Ok(info) => {
                        let sub = info["sub"].as_str().unwrap_or("?").to_string();
                        status.set(res::str::oidc_userinfo_ok(sub).format());
                        detail.set(res::str::oidc_userinfo_value(info.to_string()).format());
                    }
                    Err(e) => status.set(e.to_string()),
                }
            });
        }
    };
    let revoke = {
        let with_client = with_client.clone();
        move || {
            let Some(client) = with_client() else { return };
            let Some(access) = access_token() else {
                status.set(res::str::oidc_idle().format());
                return;
            };
            day::task(async move {
                status.set(match client.revoke(&access, "access_token").await {
                    Ok(()) => res::str::oidc_revoked().format(),
                    Err(e) => e.to_string(),
                });
            });
        }
    };
    let sign_out = move || {
        tokens.set(None);
        detail.set(String::new());
        status.set(res::str::oidc_signed_out().format());
    };

    section((
        label(res::str::oidc_caption()).font(Font::Footnote),
        labeled(
            res::str::oidc_browser_label(),
            label(support_text(caps.support)).id(day::id!(oidc_browser_support)),
        ),
        label(format!(
            "{}: {issuer}",
            res::str::oidc_issuer_label().format()
        ))
        .font(Font::Footnote)
        .id(day::id!(oidc_issuer)),
        row((
            button(res::str::oidc_sign_in())
                .action(sign_in)
                .id(day::id!(oidc_sign_in)),
            button(res::str::oidc_sign_in_silent())
                .bordered()
                .action(sign_in_silent)
                .id(day::id!(oidc_sign_in_silent)),
        ))
        .spacing(8.0),
        adaptive((
            row((
                button(res::str::oidc_refresh())
                    .bordered()
                    .action(refresh)
                    .id(day::id!(oidc_refresh)),
                button(res::str::oidc_userinfo())
                    .bordered()
                    .action(userinfo)
                    .id(day::id!(oidc_userinfo)),
            ))
            .spacing(8.0),
            row((
                button(res::str::oidc_revoke())
                    .bordered()
                    .action(revoke)
                    .id(day::id!(oidc_revoke)),
                button(res::str::oidc_sign_out())
                    .bordered()
                    .action(sign_out)
                    .id(day::id!(oidc_sign_out)),
            ))
            .spacing(8.0),
        )),
        label(move || status.get())
            .font(Font::Footnote)
            .id(day::id!(oidc_status)),
        label(move || detail.get())
            .font(Font::Footnote)
            .id(day::id!(oidc_detail)),
    ))
    .title(res::str::oidc_title())
}

/// Passkeys: the authenticator probe, a relying party id, and the two ceremonies.
fn passkeys_section() -> impl Piece {
    let rp = Signal::new(String::new());
    let result = Signal::new(res::str::passkeys_idle().format());
    let available = Signal::new(String::new());
    let support = day_part_auth::passkeys::support();
    if support != Support::Unsupported {
        day::task(async move {
            let yes = day_part_auth::passkeys::platform_authenticator_available().await;
            available.set(
                if yes {
                    res::str::passkeys_available_yes()
                } else {
                    res::str::passkeys_available_no()
                }
                .format(),
            );
        });
    } else {
        available.set(res::str::passkeys_available_no().format());
    }
    let rp_id = move || {
        let typed = rp.with(|r| r.trim().to_string());
        if typed.is_empty() {
            DEFAULT_RP.to_string()
        } else {
            typed
        }
    };
    let create = move || {
        let rp_id = rp_id();
        let (Ok(challenge), Ok(user_id)) = (
            day_part_auth::crypto::random_token(32),
            day_part_auth::crypto::random_token(16),
        ) else {
            result.set(AuthError::Platform("no randomness".into()).to_string());
            return;
        };
        let options = json!({
            "rp": { "id": rp_id, "name": "Auth Demo" },
            "user": { "id": user_id, "name": "ada@example.com", "displayName": "Ada Lovelace" },
            "challenge": challenge,
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -7 },
                { "type": "public-key", "alg": -257 }
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "residentKey": "required",
                "userVerification": "preferred"
            },
            "attestation": "none",
            "timeout": 60000
        });
        day::task(async move {
            result.set(match day_part_auth::passkeys::create(&options).await {
                Ok(credential) => {
                    res::str::passkeys_created(credential["id"].as_str().unwrap_or("?").to_string())
                        .format()
                }
                Err(e) => e.to_string(),
            });
        });
    };
    let get = move || {
        let rp_id = rp_id();
        let Ok(challenge) = day_part_auth::crypto::random_token(32) else {
            result.set(AuthError::Platform("no randomness".into()).to_string());
            return;
        };
        let options = json!({
            "rpId": rp_id,
            "challenge": challenge,
            "userVerification": "preferred",
            "timeout": 60000
        });
        day::task(async move {
            result.set(match day_part_auth::passkeys::get(&options).await {
                Ok(credential) => res::str::passkeys_asserted(
                    credential["id"].as_str().unwrap_or("?").to_string(),
                )
                .format(),
                Err(e) => e.to_string(),
            });
        });
    };

    section((
        label(res::str::passkeys_caption()).font(Font::Footnote),
        labeled(
            res::str::passkeys_support_label(),
            label(support_text(support)).id(day::id!(passkeys_support)),
        ),
        labeled(
            res::str::passkeys_available_label(),
            label(move || available.get()).id(day::id!(passkeys_available)),
        ),
        labeled(
            res::str::passkeys_rp_label(),
            text_field(rp)
                .placeholder(DEFAULT_RP)
                .id(day::id!(passkeys_rp)),
        ),
        // Two long labels outgrow a phone-portrait row: side by side where they fit, stacked on
        // a Compact window.
        adaptive((
            button(res::str::passkeys_create())
                .action(create)
                .id(day::id!(passkeys_create)),
            button(res::str::passkeys_get())
                .bordered()
                .action(get)
                .id(day::id!(passkeys_get)),
        )),
        label(move || result.get())
            .font(Font::Footnote)
            .id(day::id!(passkeys_result)),
    ))
    .title(res::str::passkeys_title())
}

/// The relying party the passkey ceremonies name when the field is empty. On the web it must be
/// the page's own domain; on Apple and Android it must be a domain associated with the app.
#[cfg(target_arch = "wasm32")]
const DEFAULT_RP: &str = "localhost";
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_RP: &str = "daybrite.dev";

/// Sign in with Apple: the system sheet, where it exists.
fn apple_section() -> impl Piece {
    let result = Signal::new(String::new());
    let support = day_part_auth::apple::support();
    section((
        label(res::str::apple_caption()).font(Font::Footnote),
        labeled(
            res::str::support_label(),
            label(support_text(support)).id(day::id!(apple_support)),
        ),
        button(res::str::apple_sign_in())
            .action(move || {
                result.set(res::str::oidc_working().format());
                day::task(async move {
                    result.set(
                        match day_part_auth::apple::sign_in(SignInWithApple::new()).await {
                            Ok(credential) => res::str::apple_signed_in(credential.user).format(),
                            Err(e) => e.to_string(),
                        },
                    );
                });
            })
            .id(day::id!(apple_sign_in)),
        label(move || result.get())
            .font(Font::Footnote)
            .id(day::id!(apple_result)),
    ))
    .title(res::str::apple_title())
}

/// Google through Credential Manager, where it exists.
fn google_section() -> impl Piece {
    let server_client_id = Signal::new(String::new());
    let result = Signal::new(String::new());
    let support = day_part_auth::google::support();
    section((
        label(res::str::google_caption()).font(Font::Footnote),
        labeled(
            res::str::support_label(),
            label(support_text(support)).id(day::id!(google_support)),
        ),
        text_field(server_client_id)
            .placeholder(res::str::google_client_placeholder())
            .id(day::id!(google_client)),
        button(res::str::google_sign_in())
            .action(move || {
                let id = server_client_id.with(|s| s.trim().to_string());
                result.set(res::str::oidc_working().format());
                day::task(async move {
                    result.set(
                        match day_part_auth::google::sign_in(GoogleSignIn::new(id)).await {
                            Ok(credential) => res::str::google_signed_in(credential.id).format(),
                            Err(e) => e.to_string(),
                        },
                    );
                });
            })
            .id(day::id!(google_sign_in)),
        label(move || result.get())
            .font(Font::Footnote)
            .id(day::id!(google_result)),
    ))
    .title(res::str::google_title())
}
