<!--
Copyright © The Daybrite Project
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# day-part-auth

[![ci](https://github.com/daybrite/day-part-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/daybrite/day-part-auth/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MPL--2.0-green.svg)](LICENSE)

## Overview and capabilities

`day-part-auth` signs people in to Day apps through the platform's own doors: the system's auth
browser, OpenID Connect with PKCE and verified ID tokens, Sign in with Apple, Google, and passkeys.

[Day](https://github.com/daybrite/day) is a Rust framework for building applications from a shared
codebase using each platform's native UI toolkit. A **part** provides a capability without drawing
UI. This is a headless part: call it from a button action, `.await` the result under `day::task`,
and show what came back.

Three layers, each usable on its own:

| Layer | API | What it does |
|---|---|---|
| Auth browser | `session::open(url, callback_prefix, &options)` | Shows the system's sign-in browser and returns the URL the provider redirected to. |
| OAuth 2.0 / OpenID Connect | `Client::new(provider, client_id).sign_in()`, `Client::start` / `complete`, `refresh`, `revoke`, `userinfo`, `Provider::discover` | The authorization request with PKCE, `state` and `nonce`; the token exchange; ID tokens verified against the provider's keys. |
| Native credentials | `apple::sign_in`, `google::sign_in`, `passkeys::create` / `get` | Sign in with Apple, Google through Credential Manager, passkeys (WebAuthn JSON in, credential JSON out). |

The crate stores no tokens: a `TokenSet` is the app's to keep, and
[day-part-keychain](https://daybrite.dev/docs/reference/keychain) is where a refresh token belongs.
The `demo-provider` feature adds a small OpenID Connect provider on loopback, for demos and tests.

## Platform support

| Platform | Auth browser | Passkeys | Native sign-in |
|---|---|---|---|
| iOS, macOS | [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession) | [`ASAuthorizationPlatformPublicKeyCredentialProvider`](https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialprovider) (iOS 16, macOS 13) | Sign in with Apple |
| Android | a [Custom Tab](https://developer.chrome.com/docs/android/custom-tabs) and the deep-link rail | [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager) (Android 9) | Google, through Credential Manager |
| Web | a same-origin popup | [`navigator.credentials`](https://developer.mozilla.org/docs/Web/API/Web_Authentication_API) | OpenID Connect |
| Windows | the default browser with a loopback listener | [`webauthn.dll`](https://learn.microsoft.com/windows/win32/api/webauthn/) | OpenID Connect |
| Linux | the default browser with a loopback listener | `Unsupported` | OpenID Connect |
| HarmonyOS | the default browser and the deep-link rail (`Emulated`) | `Unsupported` | OpenID Connect |

[docs/auth.md](docs/auth.md) has the full reference: redirects per platform, what the ID-token
check covers, the error vocabulary, and what each platform needs from the app.

## Add it to a Day project

```toml
[dependencies]
day-part-auth = { git = "https://github.com/daybrite/day-part-auth.git" }
```

```rust
use day_part_auth::{Client, Provider};

let client = Client::new(Provider::google(), "1234.apps.googleusercontent.com")
    .scopes(["openid", "email", "profile"]);

day::task(async move {
    match client.sign_in().await {
        Ok(tokens) => println!("signed in as {:?}", tokens.subject()),
        Err(e) => println!("not signed in: {e}"),
    }
});
```

On iOS, Android and HarmonyOS the default redirect is the app's own scheme (`scheme` in
`Day.toml`) with `/auth/callback`; register that URL at the provider. On the desktops it is a
loopback listener on a free port, and on the web the page's own URL. Build through the Day CLI (`day build -p android-mdc`,
`day launch -p macos-appkit`) so the Swift, Java and JavaScript arms are generated and packaged.
The [demo](demo/) is a complete app with every layer on one page.

## Architecture and dependencies

[src/native.rs](src/native.rs) holds the crate's one `day_bridge::bridge!` declaration with the
Swift, Java and JavaScript arms and the Rust fallbacks; everything above it is Rust. Every
security decision (PKCE, `state`, `nonce`, the ID-token checks, the redirect rules) is made in
Rust, and the arms hand back a URL or a JSON document and decide nothing.

| Dependency | Role |
|---|---|
| [day-bridge](https://github.com/daybrite/day/tree/main/crates/day-bridge), [day-build](https://github.com/daybrite/day/tree/main/crates/day-build) | The bridge macros and the build-time generation of the foreign arms. |
| [day-core](https://github.com/daybrite/day/tree/main/crates/day-core), [day-reactive](https://github.com/daybrite/day/tree/main/crates/day-reactive), [day-async](https://github.com/daybrite/day/tree/main/crates/day-async) | `open_url`, the deep-link rail, scopes, oneshot futures. |
| [day-part-http](https://github.com/daybrite/day/tree/main/parts/day-part-http) | The token, discovery, JWKS and userinfo requests, through each platform's HTTP stack. |
| [serde](https://github.com/serde-rs/serde), [serde_json](https://github.com/serde-rs/json) | The JSON documents the protocol is made of. |
| [windows](https://github.com/microsoft/windows-rs) (Windows only) | `webauthn.dll` and `BCryptGenRandom`. |
| [day-android-runtime](https://github.com/daybrite/day/tree/main/crates/day-android-runtime) (Android only) | The cached JVM and application context for the Java arm. |
| Gradle (Android, declared by the part) | `androidx.browser`, `androidx.credentials`, `credentials-play-services-auth`, `googleid`. |

The signatures are verified by the crate's own `crypto` module (SHA-256, HMAC, RSA PKCS#1 v1.5,
ECDSA P-256), tested against the FIPS and RFC vectors and against OpenSSL fixtures; no TLS or
crypto library is linked for it.

## Compatibility and development

This crate declares compatibility with Day 0.6 in [Cargo.toml](Cargo.toml) and is consumed from
Git, not crates.io. Its Day dependencies use `https://github.com/daybrite/day.git` without a
branch, tag, or revision; use the same source in your app. No `Cargo.lock` is committed here or in
`demo/`: every build resolves day at the tip of `main`.

For a local framework checkout, run `day patch --local ../day` from this repository (and
`day patch --local ../../day` from `demo/`). Then:

```sh
cargo test --features demo-provider
cargo clippy --all-targets --features demo-provider -- -D warnings
cd demo && day launch -p macos-appkit --script dayscript/auth.yaml
```

The script signs in silently to the demo provider inside the app, with an HTTP client standing in
for the browser, and drives the token lifecycle. The browser and the system sheets need a person.
