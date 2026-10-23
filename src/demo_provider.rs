// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! A small OpenID Connect provider on loopback, for demos and tests: discovery, an
//! authorization page that lets the person pick one of a few demo accounts, PKCE, tokens signed
//! with ES256, userinfo, refresh with rotation, revocation and a logout endpoint. It is what
//! the demo app and the Day Showcase sign in to with no account anywhere, and what this crate's
//! own end-to-end tests run against.
//!
//! It is not for production. It keeps everything in memory, binds `127.0.0.1` only, generates
//! its signing key when it starts, and knows the accounts it is given. Its one concession to
//! automation is [`DemoConfig::auto_approve`]: with an account named there, the authorization
//! page is skipped and the request is approved as that account, so a scripted run (a dayscript,
//! a test) completes a sign-in with an HTTP client standing in for the browser.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::AuthError;
use crate::authorize::{Client, Redirect};
use crate::crypto::{self, BigUint, P256};
use crate::http::{form_decode, query_of, url_encode};
use crate::jwt::{self, Jwk, Jwks};
use crate::provider::Provider;
use crate::session::SessionOptions;
use crate::tokens::TokenSet;

/// One account the demo provider can sign in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DemoUser {
    /// The stable identifier (`sub`).
    pub sub: String,
    pub name: String,
    pub email: String,
}

/// What the provider accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DemoConfig {
    /// The one client id it knows.
    pub client_id: String,
    /// `https://` redirect URIs it accepts, by prefix. Loopback URLs and app-scheme URLs
    /// (`myapp://…`) are accepted without an entry, so a listener on a port chosen at run time
    /// and a mobile app's own scheme need none.
    pub redirect_uris: Vec<String>,
    /// The accounts shown on the authorization page.
    pub users: Vec<DemoUser>,
    /// Skip the page and approve every request as this account (a `sub` from `users`).
    pub auto_approve: Option<String>,
    /// Honor `prompt=none` with a `login_hint` naming one of `users`: approve silently as that
    /// account, the way a provider does for a signed-in session (OpenID Connect Core §3.1.2.1).
    /// On by default; [`sign_in_headless`] relies on it. Without a usable hint the request
    /// fails with `login_required`, as the specification says.
    pub allow_prompt_none: bool,
    /// How long access tokens live.
    pub access_token_lifetime: Duration,
}

impl Default for DemoConfig {
    fn default() -> Self {
        DemoConfig {
            client_id: "day-demo".into(),
            redirect_uris: Vec::new(),
            users: vec![
                DemoUser {
                    sub: "ada".into(),
                    name: "Ada Lovelace".into(),
                    email: "ada@example.com".into(),
                },
                DemoUser {
                    sub: "grace".into(),
                    name: "Grace Hopper".into(),
                    email: "grace@example.com".into(),
                },
            ],
            auto_approve: None,
            allow_prompt_none: true,
            access_token_lifetime: Duration::from_secs(3600),
        }
    }
}

/// A pending authorization: what the page's decision completes.
struct Pending {
    redirect_uri: String,
    state: Option<String>,
    nonce: Option<String>,
    scope: String,
    code_challenge: String,
    issued: Instant,
}

/// A code waiting to be exchanged.
struct Code {
    sub: String,
    redirect_uri: String,
    nonce: Option<String>,
    scope: String,
    code_challenge: String,
    issued: Instant,
}

/// A live access token.
struct Access {
    sub: String,
    scope: String,
    expires: Instant,
}

struct State {
    config: DemoConfig,
    issuer: String,
    private_key: BigUint,
    jwks: Jwks,
    stop: AtomicBool,
    pending: Mutex<HashMap<String, Pending>>,
    codes: Mutex<HashMap<String, Code>>,
    access: Mutex<HashMap<String, Access>>,
    refresh: Mutex<HashMap<String, (String, String)>>,
}

/// A running demo provider. Dropping it stops the listener.
pub struct DemoProvider {
    state: Arc<State>,
    addr: SocketAddr,
}

impl DemoProvider {
    /// Bind a free loopback port and start serving.
    pub fn start(config: DemoConfig) -> Result<DemoProvider, AuthError> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| AuthError::Platform(e.to_string()))?;
        let addr = listener
            .local_addr()
            .map_err(|e| AuthError::Platform(e.to_string()))?;
        let curve = P256::new();
        let private_key = BigUint::from_be_bytes(&crypto::random_bytes(32)?)
            .rem(&curve.n)
            .filter(|d| !d.is_zero())
            .ok_or_else(|| AuthError::Platform("could not draw a signing key".into()))?;
        let (x, y) = curve
            .public_key(&private_key)
            .ok_or_else(|| AuthError::Platform("could not derive the public key".into()))?;
        let jwks = Jwks {
            keys: vec![Jwk {
                kty: "EC".into(),
                kid: Some("demo".into()),
                alg: Some("ES256".into()),
                use_: Some("sig".into()),
                n: None,
                e: None,
                crv: Some("P-256".into()),
                x: Some(crypto::base64url(&x.to_be_bytes(32))),
                y: Some(crypto::base64url(&y.to_be_bytes(32))),
            }],
        };
        let state = Arc::new(State {
            config,
            issuer: format!("http://127.0.0.1:{}", addr.port()),
            private_key,
            jwks,
            stop: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            access: Mutex::new(HashMap::new()),
            refresh: Mutex::new(HashMap::new()),
        });
        let accept = state.clone();
        std::thread::Builder::new()
            .name("day-auth-demo-provider".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if accept.stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let conn = accept.clone();
                    let _ = std::thread::Builder::new()
                        .name("day-auth-demo-connection".into())
                        .spawn(move || serve(stream, &conn));
                }
            })
            .map_err(|e| AuthError::Platform(e.to_string()))?;
        Ok(DemoProvider { state, addr })
    }

    /// The issuer: `http://127.0.0.1:<port>`.
    pub fn issuer(&self) -> &str {
        &self.state.issuer
    }

    /// The provider's endpoints, as discovery would describe them.
    pub fn provider(&self) -> Provider {
        let i = &self.state.issuer;
        Provider {
            issuer: Some(i.clone()),
            authorization_endpoint: format!("{i}/authorize"),
            token_endpoint: format!("{i}/token"),
            userinfo_endpoint: Some(format!("{i}/userinfo")),
            jwks_uri: Some(format!("{i}/jwks")),
            revocation_endpoint: Some(format!("{i}/revoke")),
            end_session_endpoint: Some(format!("{i}/logout")),
            scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }

    /// The signing key set.
    pub fn jwks(&self) -> Jwks {
        self.state.jwks.clone()
    }

    /// The client id the provider accepts.
    pub fn client_id(&self) -> &str {
        &self.state.config.client_id
    }

    /// The accounts it signs in.
    pub fn users(&self) -> &[DemoUser] {
        &self.state.config.users
    }

    /// The port it listens on.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for DemoProvider {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Relaxed);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect(self.addr);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// One HTTP/1.1 request, as far as this server reads it.
struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                if buf.len() > 64 * 1024 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < length.min(1 << 20) {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let (path, query) = match target.split_once('?') {
        Some((p, _)) => (p.to_string(), query_of(&target)),
        None => (target.clone(), Vec::new()),
    };
    Some(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) {
    let reason = match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nPragma: no-cache\r\n",
        body.len()
    );
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn json(stream: &mut TcpStream, status: u16, value: &Value) {
    respond(
        stream,
        status,
        "application/json",
        value.to_string().as_bytes(),
        &[],
    );
}

fn error(stream: &mut TcpStream, status: u16, code: &str, description: &str) {
    json(
        stream,
        status,
        &json!({"error": code, "error_description": description}),
    );
}

fn redirect(stream: &mut TcpStream, location: &str) {
    respond(stream, 302, "text/plain", b"", &[("Location", location)]);
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn serve(mut stream: TcpStream, state: &State) {
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/.well-known/openid-configuration") => discovery(&mut stream, state),
        ("GET", "/jwks") => json(&mut stream, 200, &jwks_json(state)),
        ("GET", "/authorize") => authorize(&mut stream, state, &request.query),
        ("POST", "/decision") => decision(
            &mut stream,
            state,
            &form_decode(&String::from_utf8_lossy(&request.body)),
        ),
        ("POST", "/token") => token(
            &mut stream,
            state,
            &form_decode(&String::from_utf8_lossy(&request.body)),
        ),
        ("GET", "/userinfo") => userinfo(&mut stream, state, &request.headers),
        ("POST", "/revoke") => revoke(
            &mut stream,
            state,
            &form_decode(&String::from_utf8_lossy(&request.body)),
        ),
        ("GET", "/logout") => logout(&mut stream, &request.query),
        ("GET", "/") => respond(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            page_home(state).as_bytes(),
            &[],
        ),
        (_, "/token" | "/decision" | "/revoke") => {
            error(&mut stream, 405, "invalid_request", "POST only")
        }
        _ => respond(&mut stream, 404, "text/plain", b"not found", &[]),
    }
}

fn discovery(stream: &mut TcpStream, state: &State) {
    let i = &state.issuer;
    json(
        stream,
        200,
        &json!({
            "issuer": i,
            "authorization_endpoint": format!("{i}/authorize"),
            "token_endpoint": format!("{i}/token"),
            "userinfo_endpoint": format!("{i}/userinfo"),
            "jwks_uri": format!("{i}/jwks"),
            "revocation_endpoint": format!("{i}/revoke"),
            "end_session_endpoint": format!("{i}/logout"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "claims_supported": ["sub", "name", "email", "email_verified", "iss", "aud", "exp", "iat", "nonce", "at_hash"],
        }),
    );
}

fn jwks_json(state: &State) -> Value {
    let keys: Vec<Value> = state
        .jwks
        .keys
        .iter()
        .map(|k| {
            json!({"kty": k.kty, "kid": k.kid, "alg": k.alg, "use": k.use_, "crv": k.crv, "x": k.x, "y": k.y})
        })
        .collect();
    json!({ "keys": keys })
}

/// Loopback and app-scheme redirects are accepted as such: on every platform this crate runs
/// on, a custom scheme belongs to the app that registered it. `http(s)://` elsewhere must be
/// listed in the configuration.
fn redirect_allowed(state: &State, uri: &str) -> bool {
    let Some((scheme, _)) = uri.split_once("://") else {
        return false;
    };
    let web = scheme == "http" || scheme == "https";
    (!web && !scheme.is_empty())
        || uri.starts_with("http://127.0.0.1")
        || uri.starts_with("http://localhost")
        || uri.starts_with("http://[::1]")
        || state
            .config
            .redirect_uris
            .iter()
            .any(|r| uri.starts_with(r))
}

fn token_string() -> String {
    crypto::random_token(32).unwrap_or_default()
}

fn authorize(stream: &mut TcpStream, state: &State, query: &[(String, String)]) {
    let client_id = param(query, "client_id").unwrap_or("");
    let redirect_uri = param(query, "redirect_uri").unwrap_or("").to_string();
    if client_id != state.config.client_id {
        error(stream, 400, "unauthorized_client", "unknown client_id");
        return;
    }
    if redirect_uri.is_empty() || !redirect_allowed(state, &redirect_uri) {
        error(
            stream,
            400,
            "invalid_request",
            "redirect_uri is not registered",
        );
        return;
    }
    let state_param = param(query, "state").map(str::to_string);
    let back = |stream: &mut TcpStream, code: &str, description: &str| {
        let mut location = format!(
            "{redirect_uri}{}error={code}&error_description={}",
            if redirect_uri.contains('?') { "&" } else { "?" },
            url_encode(description)
        );
        if let Some(s) = &state_param {
            location.push_str(&format!("&state={}", url_encode(s)));
        }
        redirect(stream, &location);
    };
    if param(query, "response_type") != Some("code") {
        back(
            stream,
            "unsupported_response_type",
            "only code is supported",
        );
        return;
    }
    let scope = param(query, "scope").unwrap_or("openid").to_string();
    let Some(challenge) = param(query, "code_challenge") else {
        back(
            stream,
            "invalid_request",
            "PKCE is required: send code_challenge",
        );
        return;
    };
    if param(query, "code_challenge_method") != Some("S256") {
        back(
            stream,
            "invalid_request",
            "code_challenge_method must be S256",
        );
        return;
    }
    let pending = Pending {
        redirect_uri: redirect_uri.clone(),
        state: state_param.clone(),
        nonce: param(query, "nonce").map(str::to_string),
        scope,
        code_challenge: challenge.to_string(),
        issued: Instant::now(),
    };
    let id = token_string();
    if param(query, "prompt") == Some("none") {
        let hinted = param(query, "login_hint")
            .filter(|_| state.config.allow_prompt_none)
            .filter(|sub| state.config.users.iter().any(|u| u.sub == *sub));
        match hinted {
            Some(sub) => {
                let location = approve(state, pending, sub);
                redirect(stream, &location);
            }
            None => back(
                stream,
                "login_required",
                "prompt=none needs a login_hint naming a demo account",
            ),
        }
        return;
    }
    if let Some(sub) = state.config.auto_approve.clone() {
        if state.config.users.iter().any(|u| u.sub == sub) {
            let location = approve(state, pending, &sub);
            redirect(stream, &location);
        } else {
            back(
                stream,
                "access_denied",
                "the auto-approve account is unknown",
            );
        }
        return;
    }
    lock(&state.pending).retain(|_, p| p.issued.elapsed() < Duration::from_secs(600));
    lock(&state.pending).insert(id.clone(), pending);
    respond(
        stream,
        200,
        "text/html; charset=utf-8",
        page_authorize(state, &id).as_bytes(),
        &[],
    );
}

/// Issue a code for `sub` and build the callback URL.
fn approve(state: &State, pending: Pending, sub: &str) -> String {
    let code = token_string();
    let mut location = format!(
        "{}{}code={}",
        pending.redirect_uri,
        if pending.redirect_uri.contains('?') {
            "&"
        } else {
            "?"
        },
        url_encode(&code)
    );
    if let Some(s) = &pending.state {
        location.push_str(&format!("&state={}", url_encode(s)));
    }
    lock(&state.codes).retain(|_, c| c.issued.elapsed() < Duration::from_secs(120));
    lock(&state.codes).insert(
        code,
        Code {
            sub: sub.to_string(),
            redirect_uri: pending.redirect_uri,
            nonce: pending.nonce,
            scope: pending.scope,
            code_challenge: pending.code_challenge,
            issued: Instant::now(),
        },
    );
    location
}

fn decision(stream: &mut TcpStream, state: &State, form: &[(String, String)]) {
    let id = param(form, "request").unwrap_or("");
    let Some(pending) = lock(&state.pending).remove(id) else {
        respond(
            stream,
            400,
            "text/html; charset=utf-8",
            page_message(
                "This sign-in request has expired.",
                "Go back to the app and try again.",
            )
            .as_bytes(),
            &[],
        );
        return;
    };
    let sub = param(form, "user").unwrap_or("");
    let allowed =
        param(form, "decision") == Some("allow") && state.config.users.iter().any(|u| u.sub == sub);
    if !allowed {
        let mut location = format!(
            "{}{}error=access_denied&error_description={}",
            pending.redirect_uri,
            if pending.redirect_uri.contains('?') {
                "&"
            } else {
                "?"
            },
            url_encode("the person did not approve the request")
        );
        if let Some(s) = &pending.state {
            location.push_str(&format!("&state={}", url_encode(s)));
        }
        redirect(stream, &location);
        return;
    }
    let location = approve(state, pending, sub);
    redirect(stream, &location);
}

fn user(state: &State, sub: &str) -> Option<DemoUser> {
    state.config.users.iter().find(|u| u.sub == sub).cloned()
}

fn mint(state: &State, sub: &str, scope: &str, nonce: Option<&str>) -> Result<Value, AuthError> {
    let Some(account) = user(state, sub) else {
        return Err(AuthError::Provider {
            error: "invalid_grant".into(),
            description: Some("unknown account".into()),
        });
    };
    let access_token = token_string();
    let refresh_token = token_string();
    let lifetime = state.config.access_token_lifetime;
    lock(&state.access).retain(|_, a| a.expires > Instant::now());
    lock(&state.access).insert(
        access_token.clone(),
        Access {
            sub: sub.to_string(),
            scope: scope.to_string(),
            expires: Instant::now() + lifetime,
        },
    );
    lock(&state.refresh).insert(refresh_token.clone(), (sub.to_string(), scope.to_string()));
    let mut answer = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": lifetime.as_secs(),
        "refresh_token": refresh_token,
        "scope": scope,
    });
    if scope.split(' ').any(|s| s == "openid") {
        let now = jwt::now_secs();
        let mut claims = json!({
            "iss": state.issuer,
            "sub": sub,
            "aud": state.config.client_id,
            "exp": now + lifetime.as_secs(),
            "iat": now,
            "auth_time": now,
            "at_hash": jwt::access_token_hash(&access_token, jwt::Algorithm::Es256),
        });
        if let Some(n) = nonce {
            claims["nonce"] = Value::String(n.to_string());
        }
        if scope.split(' ').any(|s| s == "profile") {
            claims["name"] = Value::String(account.name.clone());
        }
        if scope.split(' ').any(|s| s == "email") {
            claims["email"] = Value::String(account.email.clone());
            claims["email_verified"] = Value::Bool(true);
        }
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": "demo"});
        answer["id_token"] = Value::String(jwt::sign_es256(&header, &claims, &state.private_key)?);
    }
    Ok(answer)
}

fn token(stream: &mut TcpStream, state: &State, form: &[(String, String)]) {
    if param(form, "client_id").is_some_and(|c| c != state.config.client_id) {
        error(stream, 401, "invalid_client", "unknown client_id");
        return;
    }
    match param(form, "grant_type") {
        Some("authorization_code") => {
            let code = param(form, "code").unwrap_or("");
            let Some(issued) = lock(&state.codes).remove(code) else {
                error(stream, 400, "invalid_grant", "unknown or used code");
                return;
            };
            if issued.issued.elapsed() > Duration::from_secs(120) {
                error(stream, 400, "invalid_grant", "the code expired");
                return;
            }
            if param(form, "redirect_uri") != Some(issued.redirect_uri.as_str()) {
                error(stream, 400, "invalid_grant", "redirect_uri does not match");
                return;
            }
            let verifier = param(form, "code_verifier").unwrap_or("");
            let expected = crypto::base64url(&crypto::sha256(verifier.as_bytes()));
            if verifier.is_empty()
                || !crypto::constant_time_eq(expected.as_bytes(), issued.code_challenge.as_bytes())
            {
                error(
                    stream,
                    400,
                    "invalid_grant",
                    "the PKCE verifier does not match",
                );
                return;
            }
            match mint(state, &issued.sub, &issued.scope, issued.nonce.as_deref()) {
                Ok(answer) => json(stream, 200, &answer),
                Err(e) => error(stream, 500, "server_error", &e.to_string()),
            }
        }
        Some("refresh_token") => {
            let refresh = param(form, "refresh_token").unwrap_or("");
            let Some((sub, scope)) = lock(&state.refresh).remove(refresh) else {
                error(
                    stream,
                    400,
                    "invalid_grant",
                    "unknown or used refresh token",
                );
                return;
            };
            match mint(state, &sub, &scope, None) {
                Ok(answer) => json(stream, 200, &answer),
                Err(e) => error(stream, 500, "server_error", &e.to_string()),
            }
        }
        _ => error(
            stream,
            400,
            "unsupported_grant_type",
            "authorization_code or refresh_token",
        ),
    }
}

fn userinfo(stream: &mut TcpStream, state: &State, headers: &[(String, String)]) {
    let bearer = headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .and_then(|(_, v)| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let found = lock(&state.access)
        .get(bearer)
        .filter(|a| a.expires > Instant::now())
        .map(|a| (a.sub.clone(), a.scope.clone()));
    let Some((sub, scope)) = found else {
        respond(
            stream,
            401,
            "application/json",
            br#"{"error":"invalid_token"}"#,
            &[("WWW-Authenticate", "Bearer error=\"invalid_token\"")],
        );
        return;
    };
    let Some(account) = user(state, &sub) else {
        error(stream, 401, "invalid_token", "unknown account");
        return;
    };
    let mut out = json!({ "sub": sub });
    if scope.split(' ').any(|s| s == "profile") {
        out["name"] = Value::String(account.name);
    }
    if scope.split(' ').any(|s| s == "email") {
        out["email"] = Value::String(account.email);
        out["email_verified"] = Value::Bool(true);
    }
    json(stream, 200, &out);
}

fn revoke(stream: &mut TcpStream, state: &State, form: &[(String, String)]) {
    let token = param(form, "token").unwrap_or("");
    lock(&state.access).remove(token);
    lock(&state.refresh).remove(token);
    // RFC 7009 §2.2: an unknown token is still a 200.
    respond(stream, 200, "application/json", b"{}", &[]);
}

fn logout(stream: &mut TcpStream, query: &[(String, String)]) {
    match param(query, "post_logout_redirect_uri") {
        Some(back) => redirect(stream, back),
        None => respond(
            stream,
            200,
            "text/html; charset=utf-8",
            page_message("Signed out.", "You can close this window.").as_bytes(),
            &[],
        ),
    }
}

const STYLE: &str = "body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#eef1f5;color:#1f2933;display:flex;align-items:center;justify-content:center;min-height:100vh}main{background:#fff;border-radius:16px;box-shadow:0 10px 40px rgba(31,41,51,.12);padding:2rem;width:min(92vw,420px)}h1{font-size:1.3rem;margin:0 0 .25rem}p{margin:0 0 1.25rem;color:#52606d;line-height:1.45}form{display:flex;flex-direction:column;gap:.6rem}button{appearance:none;border:1px solid #d9dee5;border-radius:12px;background:#fff;padding:.8rem 1rem;font:inherit;text-align:left;cursor:pointer;display:flex;align-items:center;gap:.8rem}button:hover{border-color:#3a7bd5;background:#f5f9ff}button span{display:block}button small{color:#52606d}button.deny{justify-content:center;color:#52606d;margin-top:.5rem}.avatar{width:36px;height:36px;border-radius:50%;background:#3a7bd5;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:600}.scope{font-size:.85rem;color:#52606d;margin-top:1rem}";

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn page_authorize(state: &State, request_id: &str) -> String {
    let scope = lock(&state.pending)
        .get(request_id)
        .map(|p| p.scope.clone())
        .unwrap_or_default();
    let mut buttons = String::new();
    for u in &state.config.users {
        let initial = u.name.chars().next().unwrap_or('?');
        buttons.push_str(&format!(
            "<button type=\"submit\" name=\"user\" value=\"{}\"><span class=\"avatar\">{}</span><span>{}<br><small>{}</small></span></button>",
            escape(&u.sub),
            initial,
            escape(&u.name),
            escape(&u.email)
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Day demo provider</title><style>{STYLE}</style></head><body><main><h1>Sign in to the demo</h1><p>The app asks for <code>{}</code>. Choose an account; nothing here is real.</p><form method=\"post\" action=\"/decision\"><input type=\"hidden\" name=\"request\" value=\"{}\"><input type=\"hidden\" name=\"decision\" value=\"allow\">{buttons}</form><form method=\"post\" action=\"/decision\"><input type=\"hidden\" name=\"request\" value=\"{}\"><input type=\"hidden\" name=\"decision\" value=\"deny\"><button type=\"submit\" class=\"deny\">Cancel</button></form></main></body></html>",
        escape(&scope),
        escape(request_id),
        escape(request_id)
    )
}

fn page_message(title: &str, text: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><style>{STYLE}</style></head><body><main><h1>{}</h1><p>{}</p></main></body></html>",
        escape(title),
        escape(title),
        escape(text)
    )
}

fn page_home(state: &State) -> String {
    page_message(
        "Day demo provider",
        &format!(
            "An OpenID Connect provider for demos, issuer {}. It signs in {} demo accounts and keeps nothing.",
            state.issuer,
            state.config.users.len()
        ),
    )
}

/// A whole sign-in against the demo provider with an HTTP client standing in for the browser:
/// the authorization URL is fetched with `prompt=none` and `login_hint=<user>` (or relying on
/// [`DemoConfig::auto_approve`] when `user` is `None`), so the provider redirects straight back;
/// the redirect lands on a loopback listener this call binds, and the code is exchanged as
/// [`Client::sign_in`] would. Nothing opens on screen, which is what a dayscript or a CI leg
/// needs; the `client`'s redirect is replaced by a loopback one for the call.
pub async fn sign_in_headless(client: &Client, user: Option<&str>) -> Result<TokenSet, AuthError> {
    let mut client = client.clone().redirect(Redirect::loopback());
    if let Some(user) = user {
        client = client.param("prompt", "none").param("login_hint", user);
    }
    let mut request = client.start()?;
    let listener = request
        .take_loopback()
        .ok_or_else(|| AuthError::InvalidRequest("no loopback listener".into()))?;
    let options = SessionOptions::default();
    let waiting = listener.wait(&options);
    // The browser's step: GET the authorization URL and follow the redirect to the listener.
    let page = day_part_http::fetch_future(day_part_http::Request::get(request.url()))
        .await
        .map_err(|e| AuthError::Network(e.to_string()))?;
    if page.status >= 400 {
        return Err(AuthError::Provider {
            error: format!("http_{}", page.status),
            description: Some(String::from_utf8_lossy(&page.body).trim().to_string()),
        });
    }
    let callback = waiting.await?;
    client.complete(request, &callback).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::Jws;

    fn fetch(url: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let (host, path) = url
            .trim_start_matches("http://")
            .split_once('/')
            .expect("path");
        let mut s = TcpStream::connect(host).expect("connect");
        write!(
            s,
            "GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .expect("write");
        let mut out = Vec::new();
        s.read_to_end(&mut out).expect("read");
        parse_response(out)
    }

    fn post(url: &str, body: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let (host, path) = url
            .trim_start_matches("http://")
            .split_once('/')
            .expect("path");
        let mut s = TcpStream::connect(host).expect("connect");
        write!(s, "POST /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write");
        let mut out = Vec::new();
        s.read_to_end(&mut out).expect("read");
        parse_response(out)
    }

    fn parse_response(raw: Vec<u8>) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.lines();
        let status: u16 = lines
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok())
            .expect("status");
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        (status, headers, raw[split + 4..].to_vec())
    }

    #[test]
    fn discovery_jwks_and_home_answer() {
        let demo = DemoProvider::start(DemoConfig::default()).expect("start");
        let (status, _, body) = fetch(&format!(
            "{}/.well-known/openid-configuration",
            demo.issuer()
        ));
        assert_eq!(status, 200);
        let doc: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(doc["issuer"], Value::String(demo.issuer().to_string()));
        assert_eq!(
            doc["token_endpoint"],
            Value::String(demo.provider().token_endpoint)
        );
        let (status, _, body) = fetch(&format!("{}/jwks", demo.issuer()));
        assert_eq!(status, 200);
        assert_eq!(
            Jwks::parse(&String::from_utf8_lossy(&body)).expect("jwks"),
            demo.jwks()
        );
        let (status, _, _) = fetch(&format!("{}/", demo.issuer()));
        assert_eq!(status, 200);
        let (status, _, _) = fetch(&format!("{}/nothing", demo.issuer()));
        assert_eq!(status, 404);
    }

    /// The whole protocol with an HTTP client standing in for the browser: the client's
    /// authorization URL, auto-approved; the code; the exchange; a verified ID token; userinfo;
    /// refresh with rotation; revocation.
    #[test]
    fn a_full_sign_in_round_trip_with_the_crate_client() {
        let demo = DemoProvider::start(DemoConfig {
            auto_approve: Some("ada".into()),
            ..DemoConfig::default()
        })
        .expect("start");
        let client = Client::new(demo.provider(), demo.client_id())
            .redirect(Redirect::Scheme("demoapp://auth/callback".into()))
            .scopes(["openid", "profile", "email"]);
        let request = client.start().expect("start");
        // The browser's step, by hand: the authorization endpoint redirects straight back.
        let (status, headers, _) = fetch(request.url());
        assert_eq!(status, 302);
        let callback = headers
            .iter()
            .find(|(k, _)| k == "location")
            .map(|(_, v)| v.clone())
            .expect("location");
        assert!(callback.starts_with("demoapp://auth/callback?code="));
        let code = request.code_from(&callback).expect("code");
        // The exchange, through the token endpoint, with the PKCE verifier.
        let body = crate::http::form_encode(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", request.redirect_uri()),
            ("client_id", demo.client_id()),
            ("code_verifier", request.verifier().expect("verifier")),
        ]);
        let (status, _, answer) = post(&demo.provider().token_endpoint, &body);
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
        let tokens: Value = serde_json::from_slice(&answer).expect("json");
        let id_token = tokens["id_token"].as_str().expect("id token");
        let jws = Jws::decode(id_token).expect("decode");
        jws.verify(&demo.jwks()).expect("signature");
        let claims = crate::jwt::Claims::from_payload(&jws.payload);
        let mut expected =
            crate::jwt::Expected::new(Some(demo.issuer().to_string()), demo.client_id());
        expected.nonce = request.nonce().map(str::to_string);
        expected.access_token = tokens["access_token"].as_str().map(str::to_string);
        crate::jwt::validate(&claims, crate::jwt::Algorithm::Es256, &expected).expect("claims");
        assert_eq!(claims.subject.as_deref(), Some("ada"));
        assert_eq!(claims.email.as_deref(), Some("ada@example.com"));
        // A second exchange of the same code fails.
        let (status, _, _) = post(&demo.provider().token_endpoint, &body);
        assert_eq!(status, 400);
        // Userinfo with the access token.
        let access = tokens["access_token"].as_str().expect("access");
        let (host, _) = demo
            .issuer()
            .trim_start_matches("http://")
            .split_once('/')
            .unwrap_or((demo.issuer().trim_start_matches("http://"), ""));
        let mut s = TcpStream::connect(host).expect("connect");
        write!(s, "GET /userinfo HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {access}\r\nConnection: close\r\n\r\n").expect("write");
        let mut out = Vec::new();
        s.read_to_end(&mut out).expect("read");
        let (status, _, info) = parse_response(out);
        assert_eq!(status, 200);
        let info: Value = serde_json::from_slice(&info).expect("json");
        assert_eq!(info["sub"], Value::String("ada".into()));
        assert_eq!(info["name"], Value::String("Ada Lovelace".into()));
        // Refresh rotates the refresh token.
        let refresh = tokens["refresh_token"].as_str().expect("refresh");
        let body = crate::http::form_encode(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", demo.client_id()),
        ]);
        let (status, _, answer) = post(&demo.provider().token_endpoint, &body);
        assert_eq!(status, 200);
        let refreshed: Value = serde_json::from_slice(&answer).expect("json");
        assert_ne!(refreshed["refresh_token"], tokens["refresh_token"]);
        let (status, _, _) = post(&demo.provider().token_endpoint, &body);
        assert_eq!(status, 400, "a used refresh token is gone");
        // Revocation answers 200 and the token stops working.
        let body = crate::http::form_encode(&[
            ("token", refreshed["access_token"].as_str().expect("access")),
            ("client_id", demo.client_id()),
        ]);
        let (status, _, _) = post(
            &demo.provider().revocation_endpoint.clone().expect("revoke"),
            &body,
        );
        assert_eq!(status, 200);
    }

    #[test]
    fn the_authorization_endpoint_checks_the_request() {
        let demo = DemoProvider::start(DemoConfig::default()).expect("start");
        let base = demo.provider().authorization_endpoint;
        let (status, _, _) = fetch(&format!(
            "{base}?client_id=other&redirect_uri=http://127.0.0.1:1/cb"
        ));
        assert_eq!(status, 400);
        let (status, _, _) = fetch(&format!(
            "{base}?client_id={}&redirect_uri=https://evil.example/cb",
            demo.client_id()
        ));
        assert_eq!(status, 400);
        // No PKCE: the error goes back to the app.
        let (status, headers, _) = fetch(&format!(
            "{base}?client_id={}&redirect_uri=http://127.0.0.1:1/cb&response_type=code&state=s",
            demo.client_id()
        ));
        assert_eq!(status, 302);
        let location = headers
            .iter()
            .find(|(k, _)| k == "location")
            .map(|(_, v)| v.clone())
            .expect("location");
        assert!(location.contains("error=invalid_request") && location.contains("state=s"));
        // A proper request shows the page with both accounts.
        let (status, _, body) = fetch(&format!(
            "{base}?client_id={}&redirect_uri=http://127.0.0.1:1/cb&response_type=code&state=s&code_challenge=abc&code_challenge_method=S256",
            demo.client_id()
        ));
        assert_eq!(status, 200);
        let page = String::from_utf8_lossy(&body);
        assert!(page.contains("Ada Lovelace") && page.contains("Grace Hopper"));
    }
}
