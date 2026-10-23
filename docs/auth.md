---
title: "Sign-in"
description: "Sign-in for Day apps through the platform's own doors: the system's auth browser, OpenID Connect with PKCE and verified ID tokens, Sign in with Apple, Google, and passkeys."
---

<!--
Copyright © The Daybrite Project
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Sign-in (`day-part-auth`)

> **Status: shipped**, in its own repository. One Rust API, three layers that stand on their own,
> and foreign arms in Swift, Java, JavaScript and Rust-over-`webauthn.dll`. Verified by the crate's
> tests (standards vectors and OpenSSL fixtures for the signatures, an end-to-end sign-in against
> the demo provider over day-part-http), by the [demo app](../demo/) and by the Day Showcase's
> Sign-in page on macOS, the iOS Simulator and the Android emulator. HarmonyOS compiles and takes
> the default-browser path; its emulator is CI's business.

## Authoring

```rust
use day_part_auth::{Client, Provider};

let client = Client::new(Provider::google(), "1234.apps.googleusercontent.com")
    .scopes(["openid", "email", "profile"]);

day::task(async move {
    match client.sign_in().await {
        Ok(tokens) => signed_in.set(tokens.subject().map(str::to_string)),
        Err(e) => status.set(e.to_string()),
    }
});
```

`sign_in` opens the system's auth browser on the provider's authorization page, takes the
callback, exchanges the code, verifies the ID token and resolves with a `TokenSet`. Call it on the
UI thread (a button's action) and `.await` it under `day::task`; the continuation runs on the UI
thread again. The person dismissing the browser resolves with `AuthError::Cancelled`.

The crate stores nothing. A `TokenSet` is the app's to keep, and
[day-part-keychain](https://daybrite.dev/docs/reference/keychain) is where a refresh token belongs.

## The three layers

| Layer | Module | What it does |
|---|---|---|
| 1. Auth browser | `session` | Shows the system's sign-in browser on a URL and returns the URL the provider redirected to. |
| 2. OAuth 2.0 / OpenID Connect | `provider`, `authorize`, `tokens`, `jwt` | Builds the authorization request (PKCE, `state`, `nonce`), exchanges the code, verifies the ID token, refreshes, revokes, reads userinfo. |
| 3. Native credentials | `apple`, `google`, `passkeys` | The platform's own sheets: Sign in with Apple, Google through Credential Manager, passkeys. |

Each layer is usable alone: an app with its own browser takes `Client::start` and
`Client::complete`; an app that wants only the browser takes `session::open`.

## The auth browser

| Platform | Browser | How the callback comes back |
|---|---|---|
| iOS, macOS | [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession) | The session returns it. A custom scheme on every version; an `https://` callback on iOS 17.4 and macOS 14.4 and later. |
| Android | a [Custom Tab](https://developer.chrome.com/docs/android/custom-tabs) | The app's custom scheme, delivered as a deep link. |
| Web | a popup of the same origin | The popup, back on the page's own URL, posts the URL to the opener and closes. |
| Windows, Linux | the default browser | A loopback listener (`Redirect::Loopback`), or the custom scheme through the deep-link rail. |
| HarmonyOS | the default browser | The custom scheme through the deep-link rail. `Emulated`: nothing closes the browser tab. |

`session::capabilities()` says which callbacks a platform takes and whether the browser can be
ephemeral. `SessionOptions` sets `ephemeral` (no shared cookies, so no single sign-on either),
`timeout` (five minutes by default) and the page the loopback listener answers with.

No platform gets an embedded web view. Providers refuse them ([RFC 8252
§8.12](https://www.rfc-editor.org/rfc/rfc8252#section-8.12)), and the person has no address bar to
check who is asking.

### Callbacks on the deep-link rail

A custom-scheme redirect arrives like any other URL the OS hands the app, through
`day::on_open_url`. The session registers a handler in a scope of its own for the one URL it
expects and declines everything else, so the app's own handler keeps seeing the rest; the
registration goes when the session ends. Registering needs the UI thread, which is where a sign-in
starts.

### The loopback listener

`session::Loopback` binds `127.0.0.1` (port 0 lets the OS pick, [RFC 8252
§7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)), answers the one request the browser
makes with a short "you can return to the app" page, and hands the request URL back. A sandboxed
macOS app needs `network-server = true` in its `Day.toml` sandbox table to bind it.

## The client

### Providers

```rust
let google = Provider::google();                       // built in
let apple = Provider::apple();                         // the web form of Sign in with Apple
let own = Provider::discover("https://id.example.com").await?;   // OpenID Connect Discovery
let plain = Provider::new("https://a/authorize", "https://a/token"); // any OAuth 2.0 server
```

`discover` fetches `/.well-known/openid-configuration` and refuses a document whose `issuer` is
not the one asked for. Issuers and endpoints must be `https://`, or `http://` on loopback for a
local provider such as the demo one.

### Redirects

| `Redirect` | Where it works | Notes |
|---|---|---|
| `Auto` | everywhere | The app's scheme with `/auth/callback` on iOS, Android and HarmonyOS (from `DAY_APP_SCHEME`, which `day build` sets from `Day.toml`); a loopback listener on the desktops; the page's own URL, without its fragment, on the web. |
| `Scheme("myapp://auth/callback")` | everywhere but the web | The scheme must be the app's own. Register the exact URL at the provider. |
| `Loopback { port, path }` | desktops | Port 0 for a free port, which Google requires of desktop apps; a fixed port for a provider that registers one exact URL. |
| `Https("https://…")` | iOS 17.4+, macOS 14.4+, Android (app links), web | A universal link or app link the app owns, or the page itself on the web. The safest kind: another app cannot claim it. |

A custom scheme can be claimed by another app on the same device. Where the provider and the
platform allow it, prefer `Https`; where they do not, keep the scheme long and specific.

### The request and the callback

`Client::start` draws the per-request secrets and builds the URL:

- `response_type=code`, the client id, the resolved redirect URI, the scopes;
- `state`, 24 random bytes, compared on return without stopping at the first difference;
- `nonce`, when `openid` is among the scopes, echoed by the ID token;
- `code_challenge` and `code_challenge_method=S256` ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), always,
  unless `.pkce(false)`;
- anything added with `.param(name, value)`: `prompt`, `login_hint`, `access_type`, a provider's own.

`Authorization::code_from(callback_url)` checks that the callback is for this request's redirect,
that `state` matches, reports the provider's `error` and `error_description` when it refused, and
returns the code. `Client::complete(request, callback_url)` does that and the exchange.

### Tokens

A `TokenSet` carries the access token and its type, `expires_at` (from `expires_in`), the refresh
token, the verified `IdToken` when `openid` was asked for, the granted scope and the whole answer
as JSON. `expires_within(margin)` and `expires_in()` answer the scheduling question; `subject()` is
the person's stable identifier.

`Client::refresh(token)` keeps the old refresh token when the provider issues no new one.
`Client::revoke(token, hint)` is [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009); a provider
without a revocation endpoint answers `Unsupported`. `Client::userinfo(access_token)` returns the
JSON; compare its `sub` with the ID token's. `Client::end_session_url(id_token_hint,
post_logout_redirect_uri)` is the URL that signs the person out at the provider too, when it has an
end-session endpoint.

A confidential client's secret, set with `.client_secret`, goes in the `Authorization` header of
every token request ([RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)). A
native app has none: a secret shipped inside an app is not one.

### What the ID token check covers

An ID token in a token answer is verified before the answer is returned:

1. The compact JWS is decoded; `alg` must be `RS256` or `ES256`. `none` and the HMAC family are
   refused.
2. The signature is checked against the key the token's `kid` names in the provider's JWKS, which
   is fetched once an hour. A token whose key is unknown fetches the set again, once: that is how a
   rotated key is picked up.
3. `iss` must be the provider's issuer; `aud` must contain the client id, and `azp`, when present,
   must be the client id; `exp`, `iat` and `nbf` are checked with a leeway of two minutes; `nonce`
   must be the request's; `at_hash`, when present, must match the access token issued beside it.

The signatures are verified by the crate's own `crypto` module: RSASSA-PKCS1-v1_5 with SHA-256 and
ECDSA over P-256, with the arithmetic tested against the FIPS and RFC vectors and against OpenSSL
fixtures committed beside the tests. Nothing links a TLS or crypto library for it.

### Errors

| `AuthError` | Meaning |
|---|---|
| `Unsupported` | This platform has no implementation of what was asked. |
| `Cancelled` | The person dismissed the browser or the sheet. |
| `Timeout` | The callback never arrived within `SessionOptions::timeout`. |
| `InvalidRequest(why)` | The request could not be built: a missing endpoint, an unusable redirect, an empty client id. |
| `Provider { error, description }` | The provider refused (`access_denied`, `invalid_grant`, `login_required`, …). |
| `StateMismatch` | The callback's `state` is not this request's, or is missing. |
| `InvalidToken(why)` | A token or a discovery document failed a check; `why` names it. |
| `Network(why)` | A request failed before the provider answered. |
| `Platform(why)` | A platform error outside the vocabulary above, with the platform's message. |

## Native credentials

### Sign in with Apple

```rust
let credential = day_part_auth::apple::sign_in(SignInWithApple::new()).await?;
// credential.user, credential.identity_token, credential.authorization_code,
// credential.email / given_name / family_name (the first time only), credential.nonce
```

iOS 13 and macOS 10.15 and later, through
[`ASAuthorizationAppleIDProvider`](https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidprovider).
The app needs the Sign in with Apple capability on its identifier; without it the sheet reports an
error, which comes back as `Platform`. The `nonce` crosses to Apple as its SHA-256, as Apple
requires, and the identity token echoes that hash: a server compares the token's `nonce` with
`credential.hashed_nonce`. `apple::credential_state(user)` is the launch-time check for a revoked
account. On every other platform `apple::support()` is `Unsupported`; the web form is
`Client::new(Provider::apple(), services_id)` with an `https://` redirect the app's server
receives.

### Google

```rust
let credential = day_part_auth::google::sign_in(GoogleSignIn::new(server_client_id)).await?;
// credential.id_token, credential.id (the email), display_name, picture, nonce
```

Android with Google Play services, through
[Credential Manager](https://developer.android.com/identity/sign-in/credential-manager-siwg) and
the Google ID library; the system sheet lists the device's accounts, with no browser. The request
names the **server** client id (the OAuth client of the web application type), and the ID token's
`aud` is that id. `filter_by_authorized_accounts(true)` shows only accounts that signed in before;
`auto_select(true)` signs in without a tap when exactly one did. No matching account is
`Provider { error: "no_credential" }`. Everywhere else `google::support()` is `Unsupported` and
Google is `Provider::google()` in the client above.

### Passkeys

```rust
let credential = day_part_auth::passkeys::create(&creation_options_json).await?;
let assertion = day_part_auth::passkeys::get(&request_options_json).await?;
```

WebAuthn JSON in (`PublicKeyCredentialCreationOptionsJSON`, `PublicKeyCredentialRequestOptionsJSON`
as a server sends them, with base64url fields), credential JSON out (`id`, `rawId`, `type`,
`response.clientDataJSON`, `response.attestationObject` or `response.authenticatorData`,
`response.signature`, `response.userHandle`), ready to post back to the server, which verifies it.
`passkeys::platform_authenticator_available()` says whether the device has one.

| Platform | API | Relying party rule |
|---|---|---|
| iOS 16, macOS 13 | [`ASAuthorizationPlatformPublicKeyCredentialProvider`](https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialprovider) | `rp.id` must be an associated domain of the app (`webcredentials:`). |
| Android 9 | [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager) | `rp.id` must publish an `assetlinks.json` naming the app. |
| Web | [`navigator.credentials`](https://developer.mozilla.org/docs/Web/API/Web_Authentication_API) | `rp.id` must be the page's domain or a registrable suffix of it. |
| Windows 10 1903 | [`webauthn.dll`](https://learn.microsoft.com/windows/win32/api/webauthn/) | Any `rp.id`; the `clientDataJSON` origin is `https://<rp.id>` unless the options carry a top-level `origin`. |
| Linux, HarmonyOS | | `Unsupported`. |

A failed ceremony is `Cancelled` when the person dismissed the sheet, `Provider { error:
"invalid_state" }` when a credential for that user exists already, `Provider { error:
"not_allowed" }` when the platform refused the relying party.

## The demo provider

The `demo-provider` feature adds `demo_provider`: a small OpenID Connect provider on loopback with
discovery, an authorization page that lets the person pick one of a few demo accounts, PKCE
(required), tokens signed with ES256 by a key generated at start, userinfo, refresh with rotation,
revocation and a logout endpoint. It is what the demo app and the Showcase sign in to with no
account anywhere, and what the crate's own end-to-end test runs against.

```rust
let demo = DemoProvider::start(DemoConfig::default())?;        // binds 127.0.0.1:0
let client = Client::new(demo.provider(), demo.client_id()).scopes(["openid", "profile", "email"]);
let tokens = client.sign_in().await?;                         // the browser, the consent page
let tokens = sign_in_headless(&client, Some("ada")).await?;   // no browser: prompt=none
```

`prompt=none` with a `login_hint` naming a demo account is approved silently, the way a provider
treats a signed-in session (OpenID Connect Core §3.1.2.1); `DemoConfig::auto_approve` approves
every request as one account. It accepts loopback and app-scheme redirects without registration
and `https://` ones listed in `DemoConfig::redirect_uris`. It keeps everything in memory, binds
loopback only, and is not for production. A browser page cannot run it, so the web build of a demo
signs in to a provider it is pointed at instead.

## Platform notes

| Platform | What the app needs |
|---|---|
| iOS | `scheme` in `Day.toml` (the scaffold's `CFBundleURLTypes` carries it). An `https://` redirect needs the associated domain. Sign in with Apple needs its capability. |
| Android | `scheme` in `Day.toml` (the scaffold's intent filter carries it). The part declares `androidx.browser`, `androidx.credentials` and the Google ID library as Gradle dependencies and the `INTERNET` permission. A loopback provider over plain HTTP needs `cleartext-domains = ["127.0.0.1"]`. |
| macOS | Loopback by default. A sandboxed app needs `network-client = true` and `network-server = true`. |
| Windows, Linux | Loopback by default; `Redirect::Scheme` works where `url_schemes` is registered. |
| Web | `Redirect::Auto` is the page's own URL (`session::page_url()`); register it at the provider. The popup must not be blocked, so start the sign-in from a click. |
| HarmonyOS | `scheme` in `Day.toml`. The browser tab stays open after the callback. |

## Trying it

```sh
cargo test --features demo-provider              # 49 tests: crypto vectors, JOSE, the client, the provider, end to end
cd demo && day launch -p macos-appkit --script dayscript/auth.yaml
```

The script signs in silently, checks the verified claims on the status line, reads userinfo,
refreshes, revokes and signs out. Press **Sign in** yourself for the browser.

## The shape of the crate

| File | Contents |
|---|---|
| `src/lib.rs` | `AuthError`, the re-exports, the crate's overview. |
| `src/session.rs` | Layer one: the auth browser per platform, the deep-link rail watch, `Loopback`. |
| `src/provider.rs`, `src/authorize.rs`, `src/tokens.rs`, `src/flow.rs` | Layer two: providers and discovery, the authorization request and callback, the token requests, `Client::sign_in`. |
| `src/jwt.rs`, `src/crypto.rs` | JWS and claims validation; SHA-256, HMAC, base64url, big integers, RSA PKCS#1 v1.5 and ECDSA P-256 verification (and ES256 signing for the demo provider). |
| `src/apple.rs`, `src/google.rs`, `src/passkeys.rs`, `src/passkeys_windows.rs` | Layer three. |
| `src/native.rs` | The one `bridge!` of the crate: the Swift, Java and JavaScript arms and the Rust fallbacks. |
| `src/http.rs` | Form encoding and the JSON requests over day-part-http. |
| `src/demo_provider.rs` | The demo provider and `sign_in_headless`. |
| `tests/e2e.rs` | The client against the demo provider over the host's HTTP stack. |
