// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! A whole sign-in: the authorization request, the system's auth browser, the callback, and
//! the token exchange, as one future on [`Client`].

use crate::AuthError;
use crate::authorize::{Authorization, Client};
use crate::session;
use crate::tokens::{self, TokenSet};

impl Client {
    /// Sign the person in: open the system's auth browser on the provider's authorization
    /// page, take the callback, exchange the code, verify the ID token, and resolve with the
    /// tokens. Call it on the UI thread (a button's action) and `.await` it under `day::task`;
    /// the continuation runs on the UI thread again. The person dismissing the browser resolves
    /// with [`AuthError::Cancelled`].
    pub fn sign_in(&self) -> impl std::future::Future<Output = Result<TokenSet, AuthError>> + Send {
        let client = self.clone();
        let started = self.start();
        async move {
            let mut request = started?;
            let callback = match request.take_loopback() {
                Some(listener) => {
                    // The default browser, and the listener the redirect points at.
                    let waiting = listener.wait(&client.session);
                    day_core::open_url(request.url());
                    waiting.await?
                }
                None => {
                    session::open(request.url(), request.redirect_uri(), &client.session).await?
                }
            };
            tokens::exchange(&client, request, &callback).await
        }
    }

    /// Finish a sign-in whose browser the app drove itself: `request` from [`Client::start`],
    /// `callback_url` from wherever the app received it.
    pub fn complete(
        &self,
        request: Authorization,
        callback_url: &str,
    ) -> impl std::future::Future<Output = Result<TokenSet, AuthError>> + Send {
        let client = self.clone();
        let callback = callback_url.to_string();
        async move { tokens::exchange(&client, request, &callback).await }
    }

    /// Trade a refresh token for a new set; see [`tokens::refresh`].
    pub fn refresh(
        &self,
        refresh_token: &str,
    ) -> impl std::future::Future<Output = Result<TokenSet, AuthError>> + Send {
        let client = self.clone();
        let token = refresh_token.to_string();
        async move { tokens::refresh(&client, &token).await }
    }

    /// Tell the provider a token is no longer in use; see [`tokens::revoke`].
    pub fn revoke(
        &self,
        token: &str,
        hint: &str,
    ) -> impl std::future::Future<Output = Result<(), AuthError>> + Send {
        let client = self.clone();
        let token = token.to_string();
        let hint = hint.to_string();
        async move { tokens::revoke(&client, &token, &hint).await }
    }

    /// The userinfo endpoint's answer; see [`tokens::userinfo`].
    pub fn userinfo(
        &self,
        access_token: &str,
    ) -> impl std::future::Future<Output = Result<serde_json::Value, AuthError>> + Send {
        let client = self.clone();
        let token = access_token.to_string();
        async move { tokens::userinfo(&client, &token).await }
    }

    /// The URL that signs the person out at the provider too; see [`tokens::end_session_url`].
    pub fn end_session_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
    ) -> Option<String> {
        tokens::end_session_url(self, id_token_hint, post_logout_redirect_uri)
    }
}
