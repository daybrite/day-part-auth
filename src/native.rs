// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! The one daybridge declaration every foreign arm of this crate implements, and the arms
//! themselves (https://daybrite.dev/contributing/backend-contracts/bridge). day-build generates
//! one module per crate from the `bridge!` block, so every platform entry point this crate asks
//! a foreign language for is declared here once: Swift for AuthenticationServices on iOS and
//! macOS, Java for Custom Tabs and Credential Manager on Android, JavaScript for the popup and
//! `navigator.credentials` on the web. The Rust files around this one read the answers.
//!
//! # The wire
//!
//! An enum cannot cross the bridge, so answers are strings, bytes and small integers:
//!
//! - A web auth session completes with the callback URL, or fails with `cancelled` (the person
//!   dismissed the browser), `unsupported`, or the platform's message.
//! - Sign in with Apple completes with a JSON object (`user`, `identityToken`,
//!   `authorizationCode`, `email`, `fullName`, `realUserStatus`), or fails with `cancelled` or
//!   the platform's message.
//! - Google completes with a JSON object (`idToken`, `id`, `displayName`, `givenName`,
//!   `familyName`, `profilePictureUri`), or fails with `cancelled`, `no_credential` or the
//!   platform's message.
//! - Passkeys take WebAuthn JSON (a `PublicKeyCredentialCreationOptionsJSON` or
//!   `PublicKeyCredentialRequestOptionsJSON`) and complete with the credential's JSON
//!   (`PublicKeyCredential.toJSON()`), or fail with `cancelled`, `unsupported`,
//!   `invalid_state` (a credential already exists), `not_allowed`, or the platform's message.
//!
//! Every arm completes on its platform's own thread; the Rust side's futures bring the answer
//! back to the UI thread.

day_bridge::bridge! {
    #[day_bridge::declare]
    extern "day" {
        /// `n` random bytes from the browser (`crypto.getRandomValues`), as lowercase hex,
        /// completed before the call returns (a string crosses the JavaScript bridge through a
        /// completion only).
        fn random_hex_native(n: i32, done: day_bridge::Done<String>) -> Result<(), day_bridge::Error>;
        /// The page's own URL without its fragment, on the web: the redirect a popup flow returns
        /// to. Unsupported elsewhere.
        fn page_url_native(done: day_bridge::Done<String>) -> Result<(), day_bridge::Error>;
        /// Open the system's sign-in browser on `url` and complete with the URL the provider
        /// redirected to (one starting with `callback_prefix`, whose scheme is
        /// `callback_scheme`), with `cancelled`, or with `error:<message>`. Android completes
        /// with an empty string when the tab closes: the callback itself arrives as a deep link.
        fn open_session_native(url: &str, callback_scheme: &str, callback_prefix: &str, ephemeral: bool, done: day_bridge::Done<String>) -> Result<(), day_bridge::Error>;
        /// Dismiss the session on screen, if any.
        fn close_session_native() -> Result<(), day_bridge::Error>;
        /// Whether a platform authenticator can make and use passkeys now: 1 or 0.
        fn passkeys_available_native(done: day_bridge::Done<i32>) -> Result<(), day_bridge::Error>;
        /// Register a passkey from `PublicKeyCredentialCreationOptionsJSON`; completes with the
        /// credential JSON, or `cancelled`, `unsupported`, `invalid_state`, `not_allowed`,
        /// `error:<message>`.
        fn create_passkey_native(options_json: &str, done: day_bridge::Done<String>) -> Result<(), day_bridge::Error>;
        /// Sign in with a passkey from `PublicKeyCredentialRequestOptionsJSON`; completes as
        /// `create_passkey_native` does.
        fn get_passkey_native(options_json: &str, done: day_bridge::Done<String>) -> Result<(), day_bridge::Error>;
        /// Sign in with Apple: `scopes` is `fullName`/`email` joined by commas, `nonce` the hex
        /// SHA-256 Apple expects. Completes with the credential JSON (`user`, `identityToken`,
        /// `authorizationCode`, `email`, `givenName`, `familyName`, `realUserStatus`, `state`),
        /// `cancelled`, or `error:<message>`.
        fn apple_sign_in_native(scopes: &str, nonce: &str, state: &str, done: day_bridge::Done<String>) -> Result<(), day_bridge::Error>;
        /// Apple's credential state for a user identifier: 1 authorized, 2 revoked, 3 not found.
        fn apple_credential_state_native(user: &str, done: day_bridge::Done<i32>) -> Result<(), day_bridge::Error>;
        /// Google through Credential Manager. Completes with the credential JSON (`idToken`,
        /// `id`, `displayName`, `givenName`, `familyName`, `profilePictureUri`), `cancelled`,
        /// `no_credential`, or `error:<message>`.
        fn google_sign_in_native(server_client_id: &str, nonce: &str, filter_by_authorized: bool, auto_select: bool, done: day_bridge::Done<String>) -> Result<(), day_bridge::Error>;
    }

    // Apple: ASWebAuthenticationSession. A strong reference to the session and to its
    // presentation-context provider is kept for the session's life (the session holds the
    // provider weakly), anchored to the key window. An https callback uses the iOS 17.4 /
    // macOS 14.4 form, which needs an associated domain; a custom scheme works everywhere.
    #[day_bridge::impl(swift, platforms = [ios, macos])]
    swift!(
        prelude = r#"
            import AuthenticationServices
            #if os(macOS)
            import AppKit
            #else
            import UIKit
            #endif
        "#,
        body = r#"
            private final class DayAuthAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {
                func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
                    #if os(macOS)
                    return NSApplication.shared.keyWindow ?? NSApplication.shared.mainWindow ?? ASPresentationAnchor()
                    #else
                    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
                    let windows = scenes.flatMap { $0.windows }
                    return windows.first { $0.isKeyWindow } ?? windows.first ?? ASPresentationAnchor()
                    #endif
                }
            }

            private let dayAuthAnchor = DayAuthAnchor()
            private var dayAuthSession: ASWebAuthenticationSession? = nil

            func open_session_native(url: String, callback_scheme callbackScheme: String, callback_prefix callbackPrefix: String,
                                     ephemeral: Bool, done: UInt64) throws {
                DispatchQueue.main.async {
                    guard let target = URL(string: url) else {
                        open_session_native_complete(done, "error:the sign-in URL is not a URL")
                        return
                    }
                    dayAuthSession?.cancel()
                    let handler: ASWebAuthenticationSession.CompletionHandler = { callback, error in
                        dayAuthSession = nil
                        if let callback = callback {
                            open_session_native_complete(done, callback.absoluteString)
                        } else if let error = error as? ASWebAuthenticationSessionError,
                                  error.code == .canceledLogin {
                            open_session_native_complete(done, "cancelled")
                        } else {
                            open_session_native_complete(done, "error:" + (error?.localizedDescription ?? "the session failed"))
                        }
                    }
                    let session: ASWebAuthenticationSession
                    if callbackPrefix.hasPrefix("https://"),
                       let callback = URL(string: callbackPrefix), let host = callback.host,
                       #available(iOS 17.4, macOS 14.4, *) {
                        session = ASWebAuthenticationSession(url: target,
                                                             callback: .https(host: host, path: callback.path),
                                                             completionHandler: handler)
                    } else {
                        session = ASWebAuthenticationSession(url: target, callbackURLScheme: callbackScheme,
                                                             completionHandler: handler)
                    }
                    session.presentationContextProvider = dayAuthAnchor
                    session.prefersEphemeralWebBrowserSession = ephemeral
                    dayAuthSession = session
                    if !session.start() {
                        dayAuthSession = nil
                        open_session_native_complete(done, "error:the session could not start")
                    }
                }
            }

            func close_session_native() throws {
                DispatchQueue.main.async {
                    dayAuthSession?.cancel()
                    dayAuthSession = nil
                }
            }

            // Passkeys: ASAuthorizationController over the platform credential provider (iOS 16,
            // macOS 13). The controller and its delegate are kept alive until it answers.

            private func dayB64u(_ data: Data) -> String {
                return data.base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
            }

            private func dayB64uDecode(_ text: String) -> Data? {
                var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                while s.count % 4 != 0 { s += "=" }
                return Data(base64Encoded: s)
            }

            private func dayJson(_ object: Any) -> String {
                if let data = try? JSONSerialization.data(withJSONObject: object),
                   let text = String(data: data, encoding: .utf8) {
                    return text
                }
                return "error:could not serialize the credential"
            }

            @available(iOS 16.0, macOS 13.0, *)
            private final class DayPasskeyDelegate: NSObject, ASAuthorizationControllerDelegate,
                                                     ASAuthorizationControllerPresentationContextProviding {
                let done: UInt64
                let complete: (UInt64, String) -> Void
                var controller: ASAuthorizationController? = nil

                init(done: UInt64, complete: @escaping (UInt64, String) -> Void) {
                    self.done = done
                    self.complete = complete
                }

                func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
                    return dayAuthAnchor.presentationAnchor(for: ASWebAuthenticationSession(url: URL(string: "https://daybrite.dev")!, callbackURLScheme: nil) { _, _ in })
                }

                func authorizationController(controller: ASAuthorizationController,
                                             didCompleteWithAuthorization authorization: ASAuthorization) {
                    dayPasskeyDelegates.removeValue(forKey: done)
                    if let reg = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
                        let id = dayB64u(reg.credentialID)
                        complete(done, dayJson([
                            "id": id, "rawId": id, "type": "public-key",
                            "authenticatorAttachment": "platform", "clientExtensionResults": [:],
                            "response": [
                                "clientDataJSON": dayB64u(reg.rawClientDataJSON),
                                "attestationObject": dayB64u(reg.rawAttestationObject ?? Data()),
                                "transports": ["internal"],
                            ],
                        ]))
                    } else if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
                        let id = dayB64u(assertion.credentialID)
                        complete(done, dayJson([
                            "id": id, "rawId": id, "type": "public-key",
                            "authenticatorAttachment": "platform", "clientExtensionResults": [:],
                            "response": [
                                "clientDataJSON": dayB64u(assertion.rawClientDataJSON),
                                "authenticatorData": dayB64u(assertion.rawAuthenticatorData),
                                "signature": dayB64u(assertion.signature),
                                "userHandle": dayB64u(assertion.userID),
                            ],
                        ]))
                    } else {
                        complete(done, "error:unexpected credential type")
                    }
                }

                func authorizationController(controller: ASAuthorizationController,
                                             didCompleteWithError error: Error) {
                    dayPasskeyDelegates.removeValue(forKey: done)
                    if let e = error as? ASAuthorizationError {
                        switch e.code {
                        case .canceled: complete(done, "cancelled")
                        case .notInteractive: complete(done, "not_allowed")
                        default: complete(done, "error:" + e.localizedDescription)
                        }
                    } else {
                        complete(done, "error:" + error.localizedDescription)
                    }
                }
            }

            private var dayPasskeyDelegates: [UInt64: AnyObject] = [:]

            private func dayUserVerification(_ text: String?) -> ASAuthorizationPublicKeyCredentialUserVerificationPreference {
                switch text {
                case "required": return .required
                case "discouraged": return .discouraged
                default: return .preferred
                }
            }

            func passkeys_available_native(done: UInt64) throws {
                if #available(iOS 16.0, macOS 13.0, *) {
                    passkeys_available_native_complete(done, 1)
                } else {
                    passkeys_available_native_complete(done, 0)
                }
            }

            func create_passkey_native(options_json optionsJson: String, done: UInt64) throws {
                DispatchQueue.main.async {
                    guard #available(iOS 16.0, macOS 13.0, *) else {
                        create_passkey_native_complete(done, "unsupported")
                        return
                    }
                    guard let data = optionsJson.data(using: .utf8),
                          let options = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                          let rp = options["rp"] as? [String: Any], let rpId = rp["id"] as? String,
                          let user = options["user"] as? [String: Any], let userName = user["name"] as? String,
                          let userIdText = user["id"] as? String, let userId = dayB64uDecode(userIdText),
                          let challengeText = options["challenge"] as? String, let challenge = dayB64uDecode(challengeText) else {
                        create_passkey_native_complete(done, "error:the creation options are incomplete")
                        return
                    }
                    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
                    let request = provider.createCredentialRegistrationRequest(challenge: challenge, name: userName, userID: userId)
                    if let selection = options["authenticatorSelection"] as? [String: Any] {
                        request.userVerificationPreference = dayUserVerification(selection["userVerification"] as? String)
                    }
                    if let exclude = options["excludeCredentials"] as? [[String: Any]], #available(iOS 17.4, macOS 14.4, *) {
                        request.excludedCredentials = exclude.compactMap { entry in
                            (entry["id"] as? String).flatMap(dayB64uDecode).map {
                                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
                            }
                        }
                    }
                    let delegate = DayPasskeyDelegate(done: done, complete: create_passkey_native_complete)
                    let controller = ASAuthorizationController(authorizationRequests: [request])
                    controller.delegate = delegate
                    controller.presentationContextProvider = delegate
                    delegate.controller = controller
                    dayPasskeyDelegates[done] = delegate
                    controller.performRequests()
                }
            }

            func get_passkey_native(options_json optionsJson: String, done: UInt64) throws {
                DispatchQueue.main.async {
                    guard #available(iOS 16.0, macOS 13.0, *) else {
                        get_passkey_native_complete(done, "unsupported")
                        return
                    }
                    guard let data = optionsJson.data(using: .utf8),
                          let options = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                          let rpId = options["rpId"] as? String,
                          let challengeText = options["challenge"] as? String, let challenge = dayB64uDecode(challengeText) else {
                        get_passkey_native_complete(done, "error:the request options are incomplete")
                        return
                    }
                    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
                    let request = provider.createCredentialAssertionRequest(challenge: challenge)
                    request.userVerificationPreference = dayUserVerification(options["userVerification"] as? String)
                    if let allow = options["allowCredentials"] as? [[String: Any]] {
                        request.allowedCredentials = allow.compactMap { entry in
                            (entry["id"] as? String).flatMap(dayB64uDecode).map {
                                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
                            }
                        }
                    }
                    let delegate = DayPasskeyDelegate(done: done, complete: get_passkey_native_complete)
                    let controller = ASAuthorizationController(authorizationRequests: [request])
                    controller.delegate = delegate
                    controller.presentationContextProvider = delegate
                    delegate.controller = controller
                    dayPasskeyDelegates[done] = delegate
                    controller.performRequests()
                }
            }

            // Sign in with Apple: the Apple ID provider through the same controller.

            private final class DayAppleDelegate: NSObject, ASAuthorizationControllerDelegate,
                                                   ASAuthorizationControllerPresentationContextProviding {
                let done: UInt64
                var controller: ASAuthorizationController? = nil

                init(done: UInt64) {
                    self.done = done
                }

                func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
                    return dayAuthAnchor.presentationAnchor(for: ASWebAuthenticationSession(url: URL(string: "https://daybrite.dev")!, callbackURLScheme: nil) { _, _ in })
                }

                func authorizationController(controller: ASAuthorizationController,
                                             didCompleteWithAuthorization authorization: ASAuthorization) {
                    dayPasskeyDelegates.removeValue(forKey: done)
                    guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential else {
                        apple_sign_in_native_complete(done, "error:unexpected credential type")
                        return
                    }
                    var status = 0
                    if #available(iOS 14.0, macOS 11.0, *) {
                        switch credential.realUserStatus {
                        case .unknown: status = 1
                        case .likelyReal: status = 2
                        default: status = 0
                        }
                    }
                    apple_sign_in_native_complete(done, dayJson([
                        "user": credential.user,
                        "identityToken": credential.identityToken.flatMap { String(data: $0, encoding: .utf8) } ?? "",
                        "authorizationCode": credential.authorizationCode.flatMap { String(data: $0, encoding: .utf8) } ?? "",
                        "email": credential.email ?? "",
                        "givenName": credential.fullName?.givenName ?? "",
                        "familyName": credential.fullName?.familyName ?? "",
                        "realUserStatus": status,
                        "state": credential.state ?? "",
                    ]))
                }

                func authorizationController(controller: ASAuthorizationController,
                                             didCompleteWithError error: Error) {
                    dayPasskeyDelegates.removeValue(forKey: done)
                    if let e = error as? ASAuthorizationError, e.code == .canceled {
                        apple_sign_in_native_complete(done, "cancelled")
                    } else {
                        apple_sign_in_native_complete(done, "error:" + error.localizedDescription)
                    }
                }
            }

            func apple_sign_in_native(scopes: String, nonce: String, state: String, done: UInt64) throws {
                DispatchQueue.main.async {
                    let request = ASAuthorizationAppleIDProvider().createRequest()
                    var requested: [ASAuthorization.Scope] = []
                    for scope in scopes.split(separator: ",") {
                        if scope == "fullName" { requested.append(.fullName) }
                        if scope == "email" { requested.append(.email) }
                    }
                    request.requestedScopes = requested
                    request.nonce = nonce
                    if !state.isEmpty { request.state = state }
                    let delegate = DayAppleDelegate(done: done)
                    let controller = ASAuthorizationController(authorizationRequests: [request])
                    controller.delegate = delegate
                    controller.presentationContextProvider = delegate
                    delegate.controller = controller
                    dayPasskeyDelegates[done] = delegate
                    controller.performRequests()
                }
            }

            func apple_credential_state_native(user: String, done: UInt64) throws {
                ASAuthorizationAppleIDProvider().getCredentialState(forUserID: user) { state, _ in
                    switch state {
                    case .authorized: apple_credential_state_native_complete(done, 1)
                    case .revoked: apple_credential_state_native_complete(done, 2)
                    default: apple_credential_state_native_complete(done, 3)
                    }
                }
            }

            // The declarations the other arms own. Randomness comes from the Security framework
            // (Rust reads /dev/urandom here, so this is reached only by a caller that asks for it);
            // the page URL and Google's sheet do not exist on Apple platforms.

            func random_hex_native(n: Int32, done: UInt64) throws {
                var bytes = [UInt8](repeating: 0, count: Int(max(n, 0)))
                let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
                if status != errSecSuccess {
                    random_hex_native_complete(done, "error:SecRandomCopyBytes \(status)")
                    return
                }
                random_hex_native_complete(done, bytes.map { String(format: "%02x", $0) }.joined())
            }

            func page_url_native(done: UInt64) throws {
                page_url_native_complete(done, "unsupported")
            }

            func google_sign_in_native(server_client_id: String, nonce: String, filter_by_authorized: Bool,
                                       auto_select: Bool, done: UInt64) throws {
                google_sign_in_native_complete(done, "unsupported")
            }
        "#,
    );

    // Android: a Custom Tab from the activity. The provider's redirect to the app's scheme
    // relaunches the activity (singleTask) and reaches the deep-link rail; this arm reports the
    // activity resuming, which is the tab closing, so the Rust side can tell a dismissal from a
    // callback still on its way. Plain Java so it compiles in any Android project.
    #[day_bridge::impl(java, platforms = [android])]
    java!(
        prelude = r#"
            import android.app.Activity;
            import android.app.Application;
            import android.content.Context;
            import android.net.Uri;
            import android.os.Build;
            import android.os.Bundle;
            import android.os.CancellationSignal;
            import androidx.browser.customtabs.CustomTabsIntent;
            import androidx.credentials.CreateCredentialResponse;
            import androidx.credentials.CreatePublicKeyCredentialRequest;
            import androidx.credentials.CreatePublicKeyCredentialResponse;
            import androidx.credentials.Credential;
            import androidx.credentials.CredentialManager;
            import androidx.credentials.CredentialManagerCallback;
            import androidx.credentials.GetCredentialRequest;
            import androidx.credentials.GetCredentialResponse;
            import androidx.credentials.GetPublicKeyCredentialOption;
            import androidx.credentials.PublicKeyCredential;
            import androidx.credentials.exceptions.CreateCredentialCancellationException;
            import androidx.credentials.exceptions.CreateCredentialException;
            import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException;
            import androidx.credentials.exceptions.GetCredentialCancellationException;
            import androidx.credentials.exceptions.GetCredentialException;
            import androidx.credentials.exceptions.GetCredentialProviderConfigurationException;
            import androidx.credentials.exceptions.NoCredentialException;
            import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException;
            import androidx.credentials.CustomCredential;
            import com.google.android.libraries.identity.googleid.GetGoogleIdOption;
            import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential;
            import dev.daybrite.day.bridge.DayBridge;
            import org.json.JSONObject;
        "#,
        body = r#"
            private static long daySessionDone = 0;
            private static Application.ActivityLifecycleCallbacks dayResumeWatch = null;

            private static void daySessionSettle(String answer) {
                long done = daySessionDone;
                daySessionDone = 0;
                if (dayResumeWatch != null) {
                    Context ctx = DayBridge.ctx;
                    if (ctx instanceof Activity) {
                        ((Activity) ctx).getApplication().unregisterActivityLifecycleCallbacks(dayResumeWatch);
                    }
                    dayResumeWatch = null;
                }
                if (done != 0) {
                    open_session_native_complete(done, answer);
                }
            }

            public static void open_session_native(final String url, String callbackScheme, String callbackPrefix,
                                                   boolean ephemeral, final long done) {
                final Context ctx = DayBridge.ctx;
                if (!(ctx instanceof Activity)) {
                    open_session_native_complete(done, "error:no activity to open the browser from");
                    return;
                }
                final Activity activity = (Activity) ctx;
                DayBridge.main.post(new Runnable() {
                    @Override
                    public void run() {
                        daySessionSettle("cancelled");
                        daySessionDone = done;
                        dayResumeWatch = new Application.ActivityLifecycleCallbacks() {
                            @Override public void onActivityCreated(Activity a, Bundle b) {}
                            @Override public void onActivityStarted(Activity a) {}
                            @Override public void onActivityResumed(Activity a) {
                                if (a == activity) {
                                    daySessionSettle("");
                                }
                            }
                            @Override public void onActivityPaused(Activity a) {}
                            @Override public void onActivityStopped(Activity a) {}
                            @Override public void onActivitySaveInstanceState(Activity a, Bundle b) {}
                            @Override public void onActivityDestroyed(Activity a) {}
                        };
                        activity.getApplication().registerActivityLifecycleCallbacks(dayResumeWatch);
                        try {
                            CustomTabsIntent tab = new CustomTabsIntent.Builder().build();
                            tab.launchUrl(activity, Uri.parse(url));
                        } catch (Throwable t) {
                            daySessionSettle("error:" + t);
                        }
                    }
                });
            }

            public static void close_session_native() {
                DayBridge.main.post(new Runnable() {
                    @Override
                    public void run() {
                        daySessionSettle("cancelled");
                    }
                });
            }

            // Passkeys: Credential Manager, which takes and returns the WebAuthn JSON as is.

            private static String dayCredentialFailure(Throwable t) {
                String name = t.getClass().getSimpleName();
                if (t instanceof CreateCredentialCancellationException || t instanceof GetCredentialCancellationException) {
                    return "cancelled";
                }
                if (t instanceof NoCredentialException) {
                    return "not_allowed";
                }
                if (t instanceof CreateCredentialProviderConfigurationException
                    || t instanceof GetCredentialProviderConfigurationException) {
                    return "unsupported";
                }
                if (t instanceof CreatePublicKeyCredentialDomException) {
                    String type = ((CreatePublicKeyCredentialDomException) t).getDomError().getType();
                    if ("androidx.credentials.TYPE_INVALID_STATE_ERROR".equals(type)) {
                        return "invalid_state";
                    }
                    if ("androidx.credentials.TYPE_NOT_ALLOWED_ERROR".equals(type)) {
                        return "not_allowed";
                    }
                }
                return "error:" + name + ": " + t.getMessage();
            }

            public static void passkeys_available_native(long done) {
                passkeys_available_native_complete(done, Build.VERSION.SDK_INT >= 28 ? 1 : 0);
            }

            public static void create_passkey_native(final String optionsJson, final long done) {
                final Context ctx = DayBridge.ctx;
                if (!(ctx instanceof Activity) || Build.VERSION.SDK_INT < 28) {
                    create_passkey_native_complete(done, "unsupported");
                    return;
                }
                final Activity activity = (Activity) ctx;
                DayBridge.main.post(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            CredentialManager manager = CredentialManager.create(ctx);
                            CreatePublicKeyCredentialRequest request = new CreatePublicKeyCredentialRequest(optionsJson);
                            manager.createCredentialAsync(activity, request, new CancellationSignal(),
                                ctx.getMainExecutor(),
                                new CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException>() {
                                    @Override
                                    public void onResult(CreateCredentialResponse response) {
                                        if (response instanceof CreatePublicKeyCredentialResponse) {
                                            create_passkey_native_complete(done,
                                                ((CreatePublicKeyCredentialResponse) response).getRegistrationResponseJson());
                                        } else {
                                            create_passkey_native_complete(done, "error:unexpected credential type");
                                        }
                                    }

                                    @Override
                                    public void onError(CreateCredentialException e) {
                                        create_passkey_native_complete(done, dayCredentialFailure(e));
                                    }
                                });
                        } catch (Throwable t) {
                            create_passkey_native_complete(done, dayCredentialFailure(t));
                        }
                    }
                });
            }

            public static void google_sign_in_native(final String serverClientId, final String nonce,
                                                     final boolean filterByAuthorized, final boolean autoSelect,
                                                     final long done) {
                final Context ctx = DayBridge.ctx;
                if (!(ctx instanceof Activity) || Build.VERSION.SDK_INT < 28) {
                    google_sign_in_native_complete(done, "unsupported");
                    return;
                }
                final Activity activity = (Activity) ctx;
                DayBridge.main.post(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            GetGoogleIdOption option = new GetGoogleIdOption.Builder()
                                .setServerClientId(serverClientId)
                                .setFilterByAuthorizedAccounts(filterByAuthorized)
                                .setAutoSelectEnabled(autoSelect)
                                .setNonce(nonce)
                                .build();
                            GetCredentialRequest request = new GetCredentialRequest.Builder()
                                .addCredentialOption(option)
                                .build();
                            CredentialManager.create(ctx).getCredentialAsync(activity, request, new CancellationSignal(),
                                ctx.getMainExecutor(),
                                new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                                    @Override
                                    public void onResult(GetCredentialResponse response) {
                                        try {
                                            Credential credential = response.getCredential();
                                            if (!(credential instanceof CustomCredential)
                                                || !GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL.equals(credential.getType())) {
                                                google_sign_in_native_complete(done, "error:unexpected credential type");
                                                return;
                                            }
                                            GoogleIdTokenCredential google = GoogleIdTokenCredential.createFrom(credential.getData());
                                            JSONObject out = new JSONObject();
                                            out.put("idToken", google.getIdToken());
                                            out.put("id", google.getId());
                                            out.put("displayName", google.getDisplayName() == null ? "" : google.getDisplayName());
                                            out.put("givenName", google.getGivenName() == null ? "" : google.getGivenName());
                                            out.put("familyName", google.getFamilyName() == null ? "" : google.getFamilyName());
                                            out.put("profilePictureUri", google.getProfilePictureUri() == null ? "" : google.getProfilePictureUri().toString());
                                            google_sign_in_native_complete(done, out.toString());
                                        } catch (Throwable t) {
                                            google_sign_in_native_complete(done, "error:" + t);
                                        }
                                    }

                                    @Override
                                    public void onError(GetCredentialException e) {
                                        if (e instanceof NoCredentialException) {
                                            google_sign_in_native_complete(done, "no_credential");
                                        } else {
                                            google_sign_in_native_complete(done, dayCredentialFailure(e));
                                        }
                                    }
                                });
                        } catch (Throwable t) {
                            google_sign_in_native_complete(done, "error:" + t);
                        }
                    }
                });
            }

            // The declarations the other arms own: Apple's sheet and the page URL do not exist on
            // Android. Randomness comes from SecureRandom (Rust reads /dev/urandom here).

            public static void random_hex_native(int n, long done) {
                byte[] bytes = new byte[Math.max(n, 0)];
                new java.security.SecureRandom().nextBytes(bytes);
                StringBuilder hex = new StringBuilder(bytes.length * 2);
                for (byte b : bytes) {
                    hex.append(String.format("%02x", b));
                }
                random_hex_native_complete(done, hex.toString());
            }

            public static void page_url_native(long done) {
                page_url_native_complete(done, "unsupported");
            }

            public static void apple_sign_in_native(String scopes, String nonce, String state, long done) {
                apple_sign_in_native_complete(done, "unsupported");
            }

            public static void apple_credential_state_native(String user, long done) {
                apple_credential_state_native_complete(done, 3);
            }

            public static void get_passkey_native(final String optionsJson, final long done) {
                final Context ctx = DayBridge.ctx;
                if (!(ctx instanceof Activity) || Build.VERSION.SDK_INT < 28) {
                    get_passkey_native_complete(done, "unsupported");
                    return;
                }
                final Activity activity = (Activity) ctx;
                DayBridge.main.post(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            CredentialManager manager = CredentialManager.create(ctx);
                            GetCredentialRequest request = new GetCredentialRequest.Builder()
                                .addCredentialOption(new GetPublicKeyCredentialOption(optionsJson))
                                .build();
                            manager.getCredentialAsync(activity, request, new CancellationSignal(),
                                ctx.getMainExecutor(),
                                new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                                    @Override
                                    public void onResult(GetCredentialResponse response) {
                                        Credential credential = response.getCredential();
                                        if (credential instanceof PublicKeyCredential) {
                                            get_passkey_native_complete(done,
                                                ((PublicKeyCredential) credential).getAuthenticationResponseJson());
                                        } else {
                                            get_passkey_native_complete(done, "error:unexpected credential type");
                                        }
                                    }

                                    @Override
                                    public void onError(GetCredentialException e) {
                                        get_passkey_native_complete(done, dayCredentialFailure(e));
                                    }
                                });
                        } catch (Throwable t) {
                            get_passkey_native_complete(done, dayCredentialFailure(t));
                        }
                    }
                });
            }
        "#,
    );

    // The web: a popup of the same origin. The redirect lands the app's own page in the popup;
    // this module, loaded there too, sees it is the popup and posts its URL to the opener, which
    // completes the session and closes it. A popup closed any other way is a dismissal.
    #[day_bridge::impl(js, platforms = [web])]
    js!(r#"
        const DAY_AUTH_POPUP = 'day-part-auth-callback';
        let dayAuthPopup = null;
        let dayAuthDone = 0;
        let dayAuthPrefix = '';
        let dayAuthPoll = 0;

        if (window.opener && window.name === DAY_AUTH_POPUP) {
            try {
                window.opener.postMessage({ dayPartAuth: window.location.href }, window.location.origin);
            } catch (e) {}
            window.close();
        }

        function dayAuthSettle(answer) {
            const done = dayAuthDone;
            dayAuthDone = 0;
            if (dayAuthPoll) {
                clearInterval(dayAuthPoll);
                dayAuthPoll = 0;
            }
            dayAuthPopup = null;
            if (done) {
                open_session_native_complete(done, answer);
            }
        }

        window.addEventListener('message', (event) => {
            if (event.origin !== window.location.origin || !event.data || typeof event.data.dayPartAuth !== 'string') {
                return;
            }
            const url = event.data.dayPartAuth;
            if (dayAuthDone && url.startsWith(dayAuthPrefix)) {
                dayAuthSettle(url);
            }
        });

        export function open_session_native(url, callbackScheme, callbackPrefix, ephemeral, done) {
            dayAuthSettle('cancelled');
            dayAuthDone = done;
            dayAuthPrefix = callbackPrefix;
            const popup = window.open(url, DAY_AUTH_POPUP, 'popup=yes,width=520,height=680');
            if (!popup) {
                dayAuthSettle('error:the browser blocked the sign-in window');
                return;
            }
            dayAuthPopup = popup;
            dayAuthPoll = setInterval(() => {
                if (dayAuthPopup && dayAuthPopup.closed) {
                    dayAuthSettle('cancelled');
                }
            }, 400);
        }

        export function close_session_native() {
            if (dayAuthPopup) {
                try { dayAuthPopup.close(); } catch (e) {}
            }
            dayAuthSettle('cancelled');
        }

        export function page_url_native(done) {
            page_url_native_complete(done, String(window.location.href).split('#')[0]);
        }

        export function random_hex_native(n, done) {
            const bytes = new Uint8Array(n);
            crypto.getRandomValues(bytes);
            random_hex_native_complete(done, Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''));
        }

        // Passkeys: navigator.credentials with the WebAuthn JSON forms. Browsers from 2023 on
        // parse and serialize the JSON themselves; the two helpers below are the fallback for
        // the ones that take and give ArrayBuffers.
        function dayB64uToBytes(text) {
            const b64 = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4);
            const bin = atob(b64);
            const out = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
            return out;
        }

        function dayBytesToB64u(buffer) {
            const bytes = new Uint8Array(buffer);
            let bin = '';
            for (const b of bytes) bin += String.fromCharCode(b);
            return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }

        function dayCreationOptions(json) {
            if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
                return PublicKeyCredential.parseCreationOptionsFromJSON(json);
            }
            const out = Object.assign({}, json);
            out.challenge = dayB64uToBytes(json.challenge);
            out.user = Object.assign({}, json.user, { id: dayB64uToBytes(json.user.id) });
            if (Array.isArray(json.excludeCredentials)) {
                out.excludeCredentials = json.excludeCredentials.map((c) => Object.assign({}, c, { id: dayB64uToBytes(c.id) }));
            }
            return out;
        }

        function dayRequestOptions(json) {
            if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
                return PublicKeyCredential.parseRequestOptionsFromJSON(json);
            }
            const out = Object.assign({}, json);
            out.challenge = dayB64uToBytes(json.challenge);
            if (Array.isArray(json.allowCredentials)) {
                out.allowCredentials = json.allowCredentials.map((c) => Object.assign({}, c, { id: dayB64uToBytes(c.id) }));
            }
            return out;
        }

        function dayCredentialJson(cred) {
            if (typeof cred.toJSON === 'function') {
                return JSON.stringify(cred.toJSON());
            }
            const r = cred.response;
            const response = { clientDataJSON: dayBytesToB64u(r.clientDataJSON) };
            if (r.attestationObject) {
                response.attestationObject = dayBytesToB64u(r.attestationObject);
                if (typeof r.getTransports === 'function') response.transports = r.getTransports();
            } else {
                response.authenticatorData = dayBytesToB64u(r.authenticatorData);
                response.signature = dayBytesToB64u(r.signature);
                response.userHandle = r.userHandle ? dayBytesToB64u(r.userHandle) : null;
            }
            return JSON.stringify({
                id: cred.id,
                rawId: dayBytesToB64u(cred.rawId),
                type: cred.type,
                authenticatorAttachment: cred.authenticatorAttachment || null,
                clientExtensionResults: typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {},
                response,
            });
        }

        function dayPasskeyFailure(e) {
            const name = e && e.name ? e.name : '';
            if (name === 'NotAllowedError' || name === 'AbortError') return 'cancelled';
            if (name === 'InvalidStateError') return 'invalid_state';
            if (name === 'NotSupportedError') return 'unsupported';
            if (name === 'SecurityError') return 'not_allowed';
            return 'error:' + (e && e.message ? e.message : String(e));
        }

        // The declarations the other arms own: the system sheets do not exist in a browser.
        export function apple_sign_in_native(scopes, nonce, state, done) {
            apple_sign_in_native_complete(done, 'unsupported');
        }

        export function apple_credential_state_native(user, done) {
            apple_credential_state_native_complete(done, 3);
        }

        export function google_sign_in_native(serverClientId, nonce, filterByAuthorized, autoSelect, done) {
            google_sign_in_native_complete(done, 'unsupported');
        }

        export function passkeys_available_native(done) {
            if (typeof PublicKeyCredential === 'undefined') {
                passkeys_available_native_complete(done, 0);
                return;
            }
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                .then((ok) => passkeys_available_native_complete(done, ok ? 1 : 0),
                      () => passkeys_available_native_complete(done, 0));
        }

        export function create_passkey_native(optionsJson, done) {
            if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials) {
                create_passkey_native_complete(done, 'unsupported');
                return;
            }
            let options;
            try {
                options = dayCreationOptions(JSON.parse(optionsJson));
            } catch (e) {
                create_passkey_native_complete(done, 'error:' + e);
                return;
            }
            navigator.credentials.create({ publicKey: options })
                .then((cred) => create_passkey_native_complete(done, dayCredentialJson(cred)),
                      (e) => create_passkey_native_complete(done, dayPasskeyFailure(e)));
        }

        export function get_passkey_native(optionsJson, done) {
            if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials) {
                get_passkey_native_complete(done, 'unsupported');
                return;
            }
            let options;
            try {
                options = dayRequestOptions(JSON.parse(optionsJson));
            } catch (e) {
                get_passkey_native_complete(done, 'error:' + e);
                return;
            }
            navigator.credentials.get({ publicKey: options })
                .then((cred) => get_passkey_native_complete(done, dayCredentialJson(cred)),
                      (e) => get_passkey_native_complete(done, dayPasskeyFailure(e)));
        }
    "#);

    #[day_bridge::impl(rust, platforms = [other])]
    fn random_hex_native(_n: i32, _done: day_bridge::Done<String>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn page_url_native(_done: day_bridge::Done<String>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn open_session_native(_url: &str, _callback_scheme: &str, _callback_prefix: &str, _ephemeral: bool, _done: day_bridge::Done<String>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn close_session_native() -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn passkeys_available_native(_done: day_bridge::Done<i32>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn create_passkey_native(_options_json: &str, _done: day_bridge::Done<String>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn get_passkey_native(_options_json: &str, _done: day_bridge::Done<String>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn apple_sign_in_native(_scopes: &str, _nonce: &str, _state: &str, _done: day_bridge::Done<String>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn apple_credential_state_native(_user: &str, _done: day_bridge::Done<i32>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }

    #[day_bridge::impl(rust, platforms = [other])]
    fn google_sign_in_native(_server_client_id: &str, _nonce: &str, _filter_by_authorized: bool, _auto_select: bool, _done: day_bridge::Done<String>) -> Result<(), day_bridge::Error> {
        Err(day_bridge::Error::Unsupported)
    }
}

/// What a synchronous arm completes with before it returns.
fn settled<T: Send + 'static>(
    call: impl FnOnce(
        Box<dyn FnOnce(Result<T, day_bridge::Error>) + Send>,
    ) -> Result<(), day_bridge::Error>,
) -> Result<T, day_bridge::Error> {
    use std::sync::{Arc, Mutex};
    let slot: Arc<Mutex<Option<Result<T, day_bridge::Error>>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&slot);
    call(Box::new(move |answer| {
        if let Ok(mut s) = sink.lock() {
            *s = Some(answer);
        }
    }))?;
    let taken = slot.lock().ok().and_then(|mut s| s.take());
    taken.unwrap_or(Err(day_bridge::Error::Runtime))
}

/// `n` random bytes as hex, from the browser. Used by `crypto::random_bytes` on the web.
#[allow(dead_code)] // reached on wasm32 only
pub(crate) fn random_hex(n: i32) -> Result<String, day_bridge::Error> {
    settled(|cb| random_hex_native_async(n, cb).map(|_| ()))
}

/// The page's own URL without its fragment, on the web. Used by `session::page_url`.
#[allow(dead_code)] // reached on wasm32 only
pub(crate) fn page_url() -> Result<String, day_bridge::Error> {
    settled(|cb| page_url_native_async(cb).map(|_| ()))
}

/// Dismiss the session on screen (`close_session_native`), for `session.rs`.
#[allow(dead_code)] // reached on the platforms with a session arm
pub(crate) fn close_session() -> Result<(), day_bridge::Error> {
    close_session_native()
}
