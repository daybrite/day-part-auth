// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! The crate's client against its own demo provider, end to end over day-part-http: discovery,
//! the sign-in with an HTTP client standing in for the browser, the verified ID token, userinfo,
//! refresh, revocation, and the ways a sign-in is refused.

#![cfg(feature = "demo-provider")]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use day_part_auth::demo_provider::{DemoConfig, DemoProvider, sign_in_headless};
use day_part_auth::{AuthError, Client, Provider, Redirect};

/// Run a future to completion on this thread, parking between polls.
fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        std::thread::park();
    }
}

fn http_available() -> bool {
    day_part_http::tier() != day_part_http::Tier::Unavailable
}

#[test]
fn discovery_matches_the_provider_description() {
    if !http_available() {
        eprintln!("skipped: no HTTP stack on this host");
        return;
    }
    let demo = DemoProvider::start(DemoConfig::default()).expect("start");
    let discovered = block_on(Provider::discover(demo.issuer())).expect("discover");
    assert_eq!(discovered, demo.provider());
    // A trailing slash is tolerated; another issuer is not.
    assert!(block_on(Provider::discover(&format!("{}/", demo.issuer()))).is_ok());
    assert!(matches!(
        block_on(Provider::discover("http://example.com")),
        Err(AuthError::InvalidRequest(_))
    ));
}

#[test]
fn a_headless_sign_in_yields_verified_tokens_and_the_rest_of_the_lifecycle_works() {
    if !http_available() {
        eprintln!("skipped: no HTTP stack on this host");
        return;
    }
    let demo = DemoProvider::start(DemoConfig::default()).expect("start");
    let client =
        Client::new(demo.provider(), demo.client_id()).scopes(["openid", "profile", "email"]);

    // `prompt=none` with a hint: the standard silent sign-in, which the demo provider honors.
    let tokens = block_on(sign_in_headless(&client, Some("grace"))).expect("sign in");
    assert_eq!(tokens.subject(), Some("grace"));
    let id = tokens.id_token.as_ref().expect("id token");
    assert_eq!(id.claims.email.as_deref(), Some("grace@example.com"));
    assert_eq!(id.claims.name.as_deref(), Some("Grace Hopper"));
    assert!(tokens.expires_in().is_some_and(|d| d.as_secs() > 3000));
    assert!(!tokens.expires_within(std::time::Duration::from_secs(60)));
    let refresh_token = tokens.refresh_token.clone().expect("refresh token");

    let info = block_on(client.userinfo(&tokens.access_token)).expect("userinfo");
    assert_eq!(info["sub"], serde_json::Value::String("grace".into()));
    assert_eq!(
        info["email"],
        serde_json::Value::String("grace@example.com".into())
    );

    let refreshed = block_on(client.refresh(&refresh_token)).expect("refresh");
    assert_ne!(refreshed.access_token, tokens.access_token);
    assert_ne!(
        refreshed.refresh_token.as_deref(),
        Some(refresh_token.as_str())
    );
    assert_eq!(refreshed.subject(), Some("grace"));
    // The old refresh token was rotated out.
    assert!(matches!(
        block_on(client.refresh(&refresh_token)),
        Err(AuthError::Provider { error, .. }) if error == "invalid_grant"
    ));

    block_on(client.revoke(&refreshed.access_token, "access_token")).expect("revoke");
    assert!(matches!(
        block_on(client.userinfo(&refreshed.access_token)),
        Err(AuthError::Provider { .. })
    ));

    let logout = client
        .end_session_url(Some(&id.raw), Some("http://127.0.0.1:1/bye"))
        .expect("logout url");
    assert!(logout.starts_with(&format!("{}/logout?", demo.issuer())));
}

#[test]
fn a_plain_oauth_sign_in_has_no_id_token() {
    if !http_available() {
        eprintln!("skipped: no HTTP stack on this host");
        return;
    }
    let demo = DemoProvider::start(DemoConfig {
        auto_approve: Some("ada".into()),
        ..DemoConfig::default()
    })
    .expect("start");
    let client = Client::new(demo.provider(), demo.client_id()).scopes(["profile"]);
    // No hint: the server-side `auto_approve` account signs in.
    let tokens = block_on(sign_in_headless(&client, None)).expect("sign in");
    assert!(tokens.id_token.is_none());
    assert!(tokens.subject().is_none());
    assert_eq!(tokens.scope.as_deref(), Some("profile"));
}

#[test]
fn the_wrong_client_and_a_tampered_callback_are_refused() {
    if !http_available() {
        eprintln!("skipped: no HTTP stack on this host");
        return;
    }
    let demo = DemoProvider::start(DemoConfig {
        auto_approve: Some("ada".into()),
        ..DemoConfig::default()
    })
    .expect("start");
    // An unknown client id: the authorization endpoint refuses before any redirect.
    let wrong = Client::new(demo.provider(), "someone-else");
    assert!(matches!(
        block_on(sign_in_headless(&wrong, Some("ada"))),
        Err(AuthError::Provider { .. })
    ));
    // `prompt=none` for an account the provider does not know: `login_required` comes back
    // through the callback, as the specification says.
    let client = Client::new(demo.provider(), demo.client_id());
    assert!(matches!(
        block_on(sign_in_headless(&client, Some("nobody"))),
        Err(AuthError::Provider { error, .. }) if error == "login_required"
    ));
    // A callback whose state is not this request's.
    let client = Client::new(demo.provider(), demo.client_id())
        .redirect(Redirect::Scheme("demo://cb".into()));
    let request = client.start().expect("start");
    assert_eq!(
        block_on(client.complete(request, "demo://cb?code=x&state=forged")),
        Err(AuthError::StateMismatch)
    );
    // A code the provider never issued.
    let request = client.start().expect("start");
    let callback = format!("demo://cb?code=never-issued&state={}", request.state());
    assert!(matches!(
        block_on(client.complete(request, &callback)),
        Err(AuthError::Provider { error, .. }) if error == "invalid_grant"
    ));
}
