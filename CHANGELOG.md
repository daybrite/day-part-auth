<!--
Copyright © The Daybrite Project
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Changelog

## Unreleased

The first version.

- New: the web auth session (`session`): `ASWebAuthenticationSession` on iOS and macOS, a Custom
  Tab with the deep-link rail on Android, a same-origin popup on the web, the default browser with
  a loopback listener or the deep-link rail on Windows, Linux and HarmonyOS.
- New: the OAuth 2.0 / OpenID Connect client: `Provider` (discovery, Google, Apple, or endpoints by
  hand), `Client` with PKCE, `state` and `nonce` on every request, `Redirect` resolved per
  platform, the token exchange, refresh, revocation, userinfo and the end-session URL. ID tokens
  are verified against the provider's keys (RS256 and ES256, hand-rolled in `crypto`) and their
  claims against the client and the request.
- New: Sign in with Apple (`apple`) through `ASAuthorizationController`, with the credential state
  check; Google (`google`) through Credential Manager and the Google ID library on Android.
- New: passkeys (`passkeys`): WebAuthn JSON in, credential JSON out, on iOS 16 and macOS 13, Android
  (Credential Manager), the web (`navigator.credentials`) and Windows (`webauthn.dll`).
- New: the demo provider (`demo_provider`, feature `demo-provider`): a small OpenID Connect
  provider on loopback with a consent page, PKCE, ES256 tokens, refresh with rotation, revocation,
  `prompt=none`, for demos and tests; `sign_in_headless` runs a whole sign-in with no browser.
- New: the `demo/` app and its `dayscript/auth.yaml`, run by CI on every target.
- Needs day with stacked `on_open_url` handlers (2026-10): the session registers its own handler
  for the one callback it expects and declines everything else.
