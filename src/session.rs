// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! The web auth session: the system's own sign-in browser, which returns the URL the provider
//! redirected to. Layer one of the crate; everything above it takes the callback URL from here.
//!
//! | Platform | Browser | Callback |
//! |---|---|---|
//! | iOS, macOS | `ASWebAuthenticationSession` (Swift arm) | returned by the session itself |
//! | Android | a Custom Tab (Java arm) | the app's custom scheme, through the deep-link rail |
//! | Web | a popup of the same origin (JavaScript arm) | the popup posts its URL to the opener |
//! | Windows, Linux | the default browser | a loopback listener, or the deep-link rail |
//! | HarmonyOS | the default browser | the deep-link rail |
//!
//! Embedded web views are not offered on any platform: providers refuse them (RFC 8252 §8.12),
//! and the person has no address bar to check who is asking.
//!
//! # Callbacks on the deep-link rail
//!
//! A custom-scheme redirect arrives like any other URL the OS hands the app: through
//! `day::on_open_url`. The session registers a handler in a scope of its own for the one URL it
//! expects and declines everything else, so the app's handler keeps seeing the rest; the
//! registration goes when the session ends. Registering needs the UI thread, which is where a
//! sign-in starts (a button's action).
//!
//! # The loopback listener
//!
//! [`Loopback`] binds `127.0.0.1` (port 0 lets the OS pick, RFC 8252 §7.3), answers the one
//! request the browser makes with a short "you can return to the app" page, and hands the
//! request URL back. It accepts one connection, on a thread of its own, within the timeout.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(any(
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_env = "ohos"
))]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::AuthError;

/// How the browser session is shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOptions {
    /// Ask for a browsing session that shares no cookies with the person's browser, so the
    /// provider does not know them from an earlier sign-in. Honored by Apple
    /// (`prefersEphemeralWebBrowserSession`); the other platforms cannot and ignore it.
    pub ephemeral: bool,
    /// How long a loopback listener waits for the browser's request before giving up with
    /// [`AuthError::Timeout`]. The interactive sessions have no timeout of their own: the
    /// person closes them.
    pub timeout: Duration,
    /// The page the loopback listener answers the browser with. HTML; the default says the
    /// sign-in is done and the window can be closed.
    pub completion_page: Option<String>,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions {
            ephemeral: false,
            timeout: Duration::from_secs(300),
            completion_page: None,
        }
    }
}

/// What this platform's session can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionCapabilities {
    /// Whether a session can be opened at all.
    pub support: day_bridge::Support,
    /// Whether an `https://` callback is received without leaving the browser (Apple from
    /// iOS 17.4 and macOS 14.4 with an associated domain; the web).
    pub https_callback: bool,
    /// Whether [`SessionOptions::ephemeral`] is honored.
    pub ephemeral: bool,
    /// Whether a custom-scheme callback is received (every platform with a deep-link rail).
    pub scheme_callback: bool,
    /// Whether a loopback listener can serve as the callback (the desktops).
    pub loopback: bool,
}

/// What this platform's session can do.
pub fn capabilities() -> SessionCapabilities {
    let apple = cfg!(any(target_os = "ios", target_os = "macos"));
    let desktop = cfg!(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos"))
    ));
    let web = cfg!(target_arch = "wasm32");
    let support = if cfg!(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "android",
        target_os = "windows",
        target_os = "linux",
        target_env = "ohos",
        target_arch = "wasm32"
    )) {
        day_bridge::Support::Native
    } else {
        day_bridge::Support::Unsupported
    };
    SessionCapabilities {
        support,
        https_callback: apple || web,
        ephemeral: apple,
        scheme_callback: !web,
        loopback: desktop || apple,
    }
}

/// Open `url` in the system's sign-in browser and resolve with the callback URL once the
/// provider redirects to `callback_prefix` (compared by prefix, case-sensitively). The person
/// dismissing the browser resolves with [`AuthError::Cancelled`].
///
/// Call it on the UI thread: the custom-scheme platforms register for the callback on the
/// deep-link rail, which lives there. The future is `Send`; awaited under `day::task` the
/// continuation runs on the UI thread again.
pub fn open(
    url: &str,
    callback_prefix: &str,
    options: &SessionOptions,
) -> impl std::future::Future<Output = Result<String, AuthError>> + Send {
    let (tx, rx) = day_async::oneshot();
    start(
        url,
        callback_prefix,
        options,
        Box::new(move |answer| tx.send(answer)),
    );
    async move { rx.await.unwrap_or(Err(AuthError::Cancelled)) }
}

/// The page's own URL without its fragment, on the web: the redirect the popup flow returns to,
/// and what [`crate::Redirect::Auto`] resolves to there. `None` everywhere else.
pub fn page_url() -> Option<String> {
    if cfg!(target_arch = "wasm32") {
        crate::native::page_url()
            .ok()
            .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
    } else {
        None
    }
}

/// Dismiss the session on screen, if any. Its caller resolves with [`AuthError::Cancelled`].
pub fn cancel() {
    imp::cancel();
}

type OnDone = Box<dyn FnOnce(Result<String, AuthError>) + Send>;

fn start(url: &str, callback_prefix: &str, options: &SessionOptions, on_done: OnDone) {
    if callback_prefix.is_empty() || !callback_prefix.contains(':') {
        on_done(Err(AuthError::InvalidRequest(
            "the callback must be an absolute URL".into(),
        )));
        return;
    }
    if !(url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost"))
    {
        on_done(Err(AuthError::InvalidRequest(
            "the sign-in URL must be https (or loopback for a local provider)".into(),
        )));
        return;
    }
    imp::start(url, callback_prefix, options, on_done);
}

/// Wrap a one-shot completion so it can be called from two places and fire once.
#[cfg(any(
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_env = "ohos"
))]
fn once(cb: OnDone) -> Arc<dyn Fn(Result<String, AuthError>) + Send + Sync> {
    let cell = Mutex::new(Some(cb));
    Arc::new(move |answer| {
        let taken = match cell.lock() {
            Ok(mut g) => g.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(cb) = taken {
            cb(answer);
        }
    })
}

// ---------------------------------------------------------------------------
// The deep-link rail: a custom-scheme callback through `day::on_open_url`
// ---------------------------------------------------------------------------

// The scope of the rail watch in flight on this (the UI) thread. One at a time: a new session
// replaces the last, and a delivered callback removes its own.
#[cfg(any(
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_env = "ohos"
))]
thread_local! {
    static WATCH: std::cell::RefCell<Option<day_reactive::Scope>> = const { std::cell::RefCell::new(None) };
}

/// Watch the deep-link rail for one URL starting with `prefix`, in a scope of its own, from the
/// UI thread. The handler delivers the URL and removes itself; a session that ends another way
/// leaves the watch until the next session replaces it, which is harmless, since the completion
/// it would deliver to fires once.
#[cfg(any(
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_env = "ohos"
))]
fn watch_rail(prefix: String, deliver: Arc<dyn Fn(Result<String, AuthError>) + Send + Sync>) {
    unwatch_rail();
    let scope = day_reactive::Scope::child();
    scope.enter(|| {
        day_core::on_open_url(move |url| {
            if url.starts_with(&prefix) {
                deliver(Ok(url.to_string()));
                unwatch_rail();
                true
            } else {
                false
            }
        });
    });
    WATCH.with(|w| *w.borrow_mut() = Some(scope));
}

/// Dispose the rail watch in flight, if any.
#[cfg(any(
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_env = "ohos"
))]
fn unwatch_rail() {
    let taken = WATCH.with(|w| w.borrow_mut().take());
    if let Some(scope) = taken {
        scope.dispose();
    }
}

// ---------------------------------------------------------------------------
// The loopback listener (desktops, and any platform with a browser to open)
// ---------------------------------------------------------------------------

/// A listener on `127.0.0.1` for the provider's redirect.
pub struct Loopback {
    listener: TcpListener,
    redirect_uri: String,
}

impl Loopback {
    /// Bind `127.0.0.1:port` (0 for any free port) and build the redirect URI with the port
    /// the OS gave and `path` (`/callback` by default).
    pub fn bind(port: u16, path: &str) -> Result<Loopback, AuthError> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| AuthError::Platform(format!("loopback listener: {e}")))?;
        let bound = listener
            .local_addr()
            .map_err(|e| AuthError::Platform(format!("loopback listener: {e}")))?;
        let path = if path.is_empty() { "/callback" } else { path };
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        Ok(Loopback {
            listener,
            redirect_uri: format!("http://127.0.0.1:{}{}", bound.port(), path),
        })
    }

    /// The redirect URI to send the provider: `http://127.0.0.1:<port><path>`.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Wait on a thread of its own for the browser's request and resolve with its full URL.
    /// Any request to another path is answered 404 and ignored.
    pub fn wait(
        self,
        options: &SessionOptions,
    ) -> impl std::future::Future<Output = Result<String, AuthError>> + Send {
        let (tx, rx) = day_async::oneshot();
        let timeout = options.timeout;
        let page = options
            .completion_page
            .clone()
            .unwrap_or_else(|| DEFAULT_COMPLETION_PAGE.to_string());
        let spawned = std::thread::Builder::new()
            .name("day-auth-loopback".into())
            .spawn(move || tx.send(self.serve(timeout, &page)));
        let started = spawned.is_ok();
        async move {
            if !started {
                return Err(AuthError::Platform(
                    "could not start the loopback thread".into(),
                ));
            }
            rx.await.unwrap_or(Err(AuthError::Cancelled))
        }
    }

    fn serve(self, timeout: Duration, page: &str) -> Result<String, AuthError> {
        let deadline = Instant::now() + timeout;
        self.listener
            .set_nonblocking(true)
            .map_err(|e| AuthError::Platform(format!("loopback listener: {e}")))?;
        let path = self
            .redirect_uri
            .splitn(4, '/')
            .nth(3)
            .map(|p| format!("/{p}"))
            .unwrap_or_else(|| "/".to_string());
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    if let Some(url) = self.answer(stream, &path, page) {
                        return Ok(url);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(AuthError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(AuthError::Platform(format!("loopback listener: {e}"))),
            }
        }
    }

    /// Read one request line, answer it, and return the full URL when it is the callback.
    fn answer(&self, mut stream: TcpStream, path: &str, page: &str) -> Option<String> {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let request_line = head.lines().next().unwrap_or("");
        let mut parts = request_line.split(' ');
        let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
            let _ = respond(&mut stream, 400, "text/plain", "bad request");
            return None;
        };
        let target_path = target.split('?').next().unwrap_or("");
        if method != "GET" || target_path != path {
            let _ = respond(&mut stream, 404, "text/plain", "not found");
            return None;
        }
        let _ = respond(&mut stream, 200, "text/html; charset=utf-8", page);
        let base = self.redirect_uri.trim_end_matches(path);
        Some(format!("{base}{target}"))
    }
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// The page the browser shows once the provider has redirected back.
const DEFAULT_COMPLETION_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Signed in</title><style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f4f5f7;color:#1f2933}main{text-align:center;padding:2rem}h1{font-size:1.4rem;margin:0 0 .5rem}p{margin:0;color:#52606d}</style></head><body><main><h1>Signed in</h1><p>You can close this window and return to the app.</p></main></body></html>";

// ---------------------------------------------------------------------------
// Per-platform sessions
// ---------------------------------------------------------------------------

/// Apple: `ASWebAuthenticationSession`, through the Swift arm. It returns the callback URL
/// itself, custom scheme or (iOS 17.4, macOS 14.4) https.
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod imp {
    use super::*;
    use crate::native::{close_session, open_session_native_async};

    pub fn start(url: &str, callback_prefix: &str, options: &SessionOptions, on_done: OnDone) {
        let scheme = callback_prefix.split(':').next().unwrap_or("").to_string();
        let _ = open_session_native_async(
            url,
            &scheme,
            callback_prefix,
            options.ephemeral,
            move |answer| on_done(super::read_answer(answer)),
        );
    }

    pub fn cancel() {
        let _ = close_session();
    }
}

/// Android: a Custom Tab through the Java arm; the callback arrives on the deep-link rail. The
/// arm reports when the app's activity resumes, which is the tab closing: a callback that has
/// not arrived shortly after that is a dismissal.
#[cfg(target_os = "android")]
mod imp {
    use super::*;
    use crate::native::{close_session, open_session_native_async};

    pub fn start(url: &str, callback_prefix: &str, options: &SessionOptions, on_done: OnDone) {
        let deliver = once(on_done);
        watch_rail(callback_prefix.to_string(), deliver.clone());
        let scheme = callback_prefix.split(':').next().unwrap_or("").to_string();
        let resumed = deliver.clone();
        let _ = open_session_native_async(
            url,
            &scheme,
            callback_prefix,
            options.ephemeral,
            move |answer| match answer {
                // The tab closed. The deep link, when there is one, is delivered on the UI thread
                // as the activity resumes; give it a moment before calling this a dismissal.
                Ok(_) => {
                    let resumed = resumed.clone();
                    let _ = std::thread::Builder::new()
                        .name("day-auth-resume".into())
                        .spawn(move || {
                            std::thread::sleep(Duration::from_millis(700));
                            resumed(Err(AuthError::Cancelled));
                        });
                }
                Err(e) => resumed(Err(AuthError::from(e))),
            },
        );
    }

    pub fn cancel() {
        let _ = close_session();
    }
}

/// The web: a popup of the same origin through the JavaScript arm, which posts the callback
/// URL to its opener and closes.
#[cfg(target_arch = "wasm32")]
mod imp {
    use super::*;
    use crate::native::{close_session, open_session_native_async};

    pub fn start(url: &str, callback_prefix: &str, options: &SessionOptions, on_done: OnDone) {
        let _ =
            open_session_native_async(url, "", callback_prefix, options.ephemeral, move |answer| {
                on_done(super::read_answer(answer))
            });
    }

    pub fn cancel() {
        let _ = close_session();
    }
}

/// Windows, Linux and HarmonyOS: the default browser, and the callback on the deep-link rail
/// (desktop single-instance forwarding or the HarmonyOS want). A loopback redirect does not come
/// through here: [`Loopback`] serves it.
#[cfg(not(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "android",
    target_arch = "wasm32"
)))]
mod imp {
    use super::*;

    type Deliver = Arc<dyn Fn(Result<String, AuthError>) + Send + Sync>;
    static ACTIVE: Mutex<Option<Deliver>> = Mutex::new(None);

    pub fn start(url: &str, callback_prefix: &str, _options: &SessionOptions, on_done: OnDone) {
        let deliver = once(on_done);
        watch_rail(callback_prefix.to_string(), deliver.clone());
        if let Ok(mut slot) = ACTIVE.lock() {
            *slot = Some(deliver);
        }
        day_core::open_url(url);
    }

    pub fn cancel() {
        let taken = ACTIVE.lock().ok().and_then(|mut s| s.take());
        if let Some(deliver) = taken {
            deliver(Err(AuthError::Cancelled));
        }
    }
}

/// The arm's completion: a URL, `cancelled`, or `error:<message>`.
#[cfg(any(target_os = "ios", target_os = "macos", target_arch = "wasm32"))]
fn read_answer(answer: Result<String, day_bridge::Error>) -> Result<String, AuthError> {
    match answer {
        Ok(text) if text == "cancelled" => Err(AuthError::Cancelled),
        Ok(text) if text == "unsupported" => Err(AuthError::Unsupported),
        Ok(text) if text.starts_with("error:") => Err(AuthError::Platform(text[6..].to_string())),
        Ok(url) if url.contains(':') => Ok(url),
        Ok(other) => Err(AuthError::Platform(format!(
            "unexpected session answer {other:?}"
        ))),
        Err(e) => Err(AuthError::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_answer_for_this_host() {
        let caps = capabilities();
        if cfg!(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "windows"
        )) {
            assert_eq!(caps.support, day_bridge::Support::Native);
            assert!(caps.loopback);
        }
    }

    #[test]
    fn loopback_binds_builds_the_redirect_and_returns_the_request_url() {
        let loopback = Loopback::bind(0, "/callback").expect("bind");
        let redirect = loopback.redirect_uri().to_string();
        assert!(redirect.starts_with("http://127.0.0.1:"));
        assert!(redirect.ends_with("/callback"));
        let options = SessionOptions {
            timeout: Duration::from_secs(5),
            ..SessionOptions::default()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let answer = loopback.serve(options.timeout, "done");
            let _ = tx.send(answer);
        });
        // A request to another path is ignored; the callback is answered and returned.
        let port: u16 = redirect
            .trim_start_matches("http://127.0.0.1:")
            .split('/')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("port");
        let mut other = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        other
            .write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("write");
        let mut reply = String::new();
        let _ = other.read_to_string(&mut reply);
        assert!(reply.starts_with("HTTP/1.1 404"));
        let mut browser = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        browser
            .write_all(b"GET /callback?code=abc&state=xyz HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("write");
        let mut reply = String::new();
        let _ = browser.read_to_string(&mut reply);
        assert!(reply.starts_with("HTTP/1.1 200"));
        assert!(reply.ends_with("done"));
        let answer = rx.recv().expect("answer");
        assert_eq!(answer, Ok(format!("{redirect}?code=abc&state=xyz")));
        server.join().expect("join");
    }

    #[test]
    fn loopback_times_out_without_a_request() {
        let loopback = Loopback::bind(0, "cb").expect("bind");
        assert!(loopback.redirect_uri().ends_with("/cb"));
        assert_eq!(
            loopback.serve(Duration::from_millis(120), "done"),
            Err(AuthError::Timeout)
        );
    }

    #[test]
    fn open_rejects_unusable_arguments_through_the_callback() {
        let (tx, rx) = std::sync::mpsc::channel();
        start(
            "https://x",
            "",
            &SessionOptions::default(),
            Box::new(move |a| {
                let _ = tx.send(a);
            }),
        );
        assert!(matches!(rx.recv(), Ok(Err(AuthError::InvalidRequest(_)))));
        let (tx, rx) = std::sync::mpsc::channel();
        start(
            "ftp://x",
            "myapp://cb",
            &SessionOptions::default(),
            Box::new(move |a| {
                let _ = tx.send(a);
            }),
        );
        assert!(matches!(rx.recv(), Ok(Err(AuthError::InvalidRequest(_)))));
    }
}
