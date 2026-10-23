# Auth Demo UI strings (https://daybrite.dev/docs/how-to/localization). Add a locale by dropping a
# sibling folder (e.g. locales/fr/app.ftl) and translating.

app_title = Auth Demo
caption = Sign-in through the platform's own doors: the system's auth browser, OpenID Connect with PKCE, Sign in with Apple, Google, and passkeys.

support_native = Native
support_emulated = Emulated (partial)
support_unsupported = Unsupported on this host

# The OpenID Connect section, against the demo provider the app starts on loopback.
oidc_title = OpenID Connect
oidc_caption = A provider runs inside this app on 127.0.0.1 and signs in two demo accounts. Sign in opens the system's browser on its consent page; the silent sign-in uses prompt=none, with an HTTP client standing in for the browser.
oidc_issuer_label = Issuer
oidc_issuer_none = The demo provider needs a native build.
oidc_browser_label = Auth browser
oidc_sign_in = Sign in
oidc_sign_in_silent = Sign in silently
oidc_refresh = Refresh
oidc_userinfo = Userinfo
oidc_revoke = Revoke
oidc_sign_out = Sign out
oidc_idle = Not signed in
oidc_working = Waiting for the provider…
oidc_signed_in = Signed in as { $name } ({ $email }), subject { $sub }
oidc_expires = The access token expires in { $secs } s
oidc_refreshed = Refreshed: a new access token was issued
oidc_userinfo_ok = Userinfo answered for { $sub }
oidc_userinfo_value = Userinfo: { $json }
oidc_revoked = The access token was revoked
oidc_signed_out = Signed out

# Passkeys.
passkeys_title = Passkeys
passkeys_caption = WebAuthn through the platform authenticator: the options JSON a server would send, the credential JSON it gets back.
passkeys_support_label = Support here
passkeys_available_label = Platform authenticator
passkeys_available_yes = available
passkeys_available_no = not available
passkeys_rp_label = Relying party
passkeys_create = Create a passkey
passkeys_get = Sign in with a passkey
passkeys_idle = No credential yet
passkeys_created = Created credential { $id }
passkeys_asserted = Signed in with credential { $id }

# Sign in with Apple and Google.
apple_title = Sign in with Apple
apple_caption = The system sheet on iOS and macOS. It needs the Sign in with Apple capability on the app's identifier; without it the sheet reports an error, which is shown here.
apple_sign_in = Sign in with Apple
apple_signed_in = Apple user { $user }
google_title = Google
google_caption = Credential Manager on Android, with the OAuth client id of the web application type your server owns. Elsewhere Google is an OpenID Connect provider for the section above.
google_client_placeholder = Server client id
google_sign_in = Sign in with Google
google_signed_in = Google account { $id }
support_label = Support here
