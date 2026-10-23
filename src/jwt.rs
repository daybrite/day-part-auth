// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! JSON Web Signatures, JSON Web Keys and OpenID Connect ID-token claims (RFC 7515, RFC 7517,
//! OpenID Connect Core 1.0 §3.1.3.7).
//!
//! An ID token is accepted only when its signature verifies under one of the provider's
//! published keys (`jwks_uri`) with the algorithm the header names (RS256 or ES256; `none` and
//! everything else is refused) AND its claims pass [`validate`]: issuer, audience, expiry,
//! issue time, nonce, `azp` when several audiences, and `at_hash` when an access token was
//! issued alongside. Keys are matched by `kid` where the header carries one, else every key of
//! the right type is tried.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

use crate::AuthError;
use crate::crypto::{self, BigUint, P256, RsaPublicKey};

/// One key of a JWK set (RFC 7517 §4, RFC 7518 §6).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    /// RSA modulus, base64url.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent, base64url.
    #[serde(default)]
    pub e: Option<String>,
    /// EC curve name.
    #[serde(default)]
    pub crv: Option<String>,
    /// EC coordinates, base64url.
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

/// A JWK set, as a provider's `jwks_uri` serves it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Parse a JWK set document.
    pub fn parse(json: &str) -> Result<Jwks, AuthError> {
        serde_json::from_str(json).map_err(|e| AuthError::InvalidToken(format!("JWK set: {e}")))
    }
}

/// A signing algorithm this crate verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// ECDSA on P-256 with SHA-256.
    Es256,
}

impl Algorithm {
    fn parse(name: &str) -> Option<Algorithm> {
        match name {
            "RS256" => Some(Algorithm::Rs256),
            "ES256" => Some(Algorithm::Es256),
            _ => None,
        }
    }

    /// The JOSE name.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Rs256 => "RS256",
            Algorithm::Es256 => "ES256",
        }
    }
}

/// A decoded compact JWS: the header and payload as JSON, and what the signature covers.
#[derive(Clone, Debug)]
pub struct Jws {
    pub header: Value,
    pub payload: Value,
    signing_input: String,
    signature: Vec<u8>,
}

impl Jws {
    /// Split and decode `header.payload.signature`. Nothing is verified yet.
    pub fn decode(token: &str) -> Result<Jws, AuthError> {
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AuthError::InvalidToken("not a compact JWS".into()));
        };
        let header_bytes = crypto::base64url_decode(h)
            .ok_or_else(|| AuthError::InvalidToken("header is not base64url".into()))?;
        let payload_bytes = crypto::base64url_decode(p)
            .ok_or_else(|| AuthError::InvalidToken("payload is not base64url".into()))?;
        let signature = crypto::base64url_decode(s)
            .ok_or_else(|| AuthError::InvalidToken("signature is not base64url".into()))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::InvalidToken(format!("header: {e}")))?;
        let payload: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AuthError::InvalidToken(format!("payload: {e}")))?;
        if !header.is_object() || !payload.is_object() {
            return Err(AuthError::InvalidToken(
                "header and payload must be objects".into(),
            ));
        }
        Ok(Jws {
            header,
            payload,
            signing_input: format!("{h}.{p}"),
            signature,
        })
    }

    /// The header's `alg`, when it is one this crate verifies.
    pub fn algorithm(&self) -> Result<Algorithm, AuthError> {
        let alg = self.header.get("alg").and_then(Value::as_str).unwrap_or("");
        Algorithm::parse(alg)
            .ok_or_else(|| AuthError::InvalidToken(format!("unsupported alg {alg:?}")))
    }

    /// The header's `kid`.
    pub fn key_id(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }

    /// Verify the signature against `jwks`. The key is the one whose `kid` matches the
    /// header's; without a `kid`, every key of the algorithm's type is tried.
    pub fn verify(&self, jwks: &Jwks) -> Result<(), AuthError> {
        let alg = self.algorithm()?;
        let kid = self.key_id();
        let candidates: Vec<&Jwk> = jwks
            .keys
            .iter()
            .filter(|k| match kid {
                Some(kid) => k.kid.as_deref() == Some(kid),
                None => true,
            })
            .filter(|k| match alg {
                Algorithm::Rs256 => k.kty == "RSA",
                Algorithm::Es256 => k.kty == "EC",
            })
            .filter(|k| k.alg.as_deref().is_none_or(|a| a == alg.name()))
            .filter(|k| k.use_.as_deref().is_none_or(|u| u == "sig"))
            .collect();
        if candidates.is_empty() {
            return Err(AuthError::InvalidToken(match kid {
                Some(kid) => format!("no {} key {kid:?} in the provider's key set", alg.name()),
                None => format!("no {} key in the provider's key set", alg.name()),
            }));
        }
        for key in candidates {
            if self.verify_with(alg, key) {
                return Ok(());
            }
        }
        Err(AuthError::InvalidToken("signature does not verify".into()))
    }

    fn verify_with(&self, alg: Algorithm, key: &Jwk) -> bool {
        let input = self.signing_input.as_bytes();
        match alg {
            Algorithm::Rs256 => {
                let (Some(n), Some(e)) = (
                    key.n.as_deref().and_then(crypto::base64url_decode),
                    key.e.as_deref().and_then(crypto::base64url_decode),
                ) else {
                    return false;
                };
                crypto::rsa_pkcs1_sha256_verify(&RsaPublicKey { n, e }, input, &self.signature)
            }
            Algorithm::Es256 => {
                if key.crv.as_deref() != Some("P-256") || self.signature.len() != 64 {
                    return false;
                }
                let (Some(x), Some(y)) = (
                    key.x.as_deref().and_then(crypto::base64url_decode),
                    key.y.as_deref().and_then(crypto::base64url_decode),
                ) else {
                    return false;
                };
                let curve = P256::new();
                let hash = crypto::sha256(input);
                curve.ecdsa_verify(
                    &BigUint::from_be_bytes(&x),
                    &BigUint::from_be_bytes(&y),
                    &hash,
                    &BigUint::from_be_bytes(&self.signature[..32]),
                    &BigUint::from_be_bytes(&self.signature[32..]),
                )
            }
        }
    }
}

/// The claims an ID token carries (OpenID Connect Core §2 and §5.1), plus the whole payload.
#[derive(Clone, Debug, PartialEq)]
pub struct Claims {
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub audience: Vec<String>,
    pub expires_at: Option<u64>,
    pub issued_at: Option<u64>,
    pub not_before: Option<u64>,
    pub auth_time: Option<u64>,
    pub nonce: Option<String>,
    pub authorized_party: Option<String>,
    pub access_token_hash: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    /// Every claim, as the token carried it.
    pub raw: Value,
}

impl Claims {
    /// Read the claims out of a decoded payload.
    pub fn from_payload(payload: &Value) -> Claims {
        let s = |k: &str| payload.get(k).and_then(Value::as_str).map(str::to_string);
        let u = |k: &str| payload.get(k).and_then(Value::as_u64);
        let audience = match payload.get("aud") {
            Some(Value::String(a)) => vec![a.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        // Some providers send `email_verified` as the string "true".
        let email_verified = match payload.get("email_verified") {
            Some(Value::Bool(b)) => Some(*b),
            Some(Value::String(s)) => Some(s == "true"),
            _ => None,
        };
        Claims {
            issuer: s("iss"),
            subject: s("sub"),
            audience,
            expires_at: u("exp"),
            issued_at: u("iat"),
            not_before: u("nbf"),
            auth_time: u("auth_time"),
            nonce: s("nonce"),
            authorized_party: s("azp"),
            access_token_hash: s("at_hash"),
            email: s("email"),
            email_verified,
            name: s("name"),
            given_name: s("given_name"),
            family_name: s("family_name"),
            preferred_username: s("preferred_username"),
            picture: s("picture"),
            raw: payload.clone(),
        }
    }

    /// A claim by name, for anything not listed above.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.raw.get(name)
    }
}

/// What an ID token is checked against.
#[derive(Clone, Debug)]
pub struct Expected {
    /// The provider's issuer identifier; `None` skips the check (a provider with no discovery
    /// document).
    pub issuer: Option<String>,
    /// This client's id, which must be among the audiences.
    pub client_id: String,
    /// The nonce sent with the authorization request, which the token must echo.
    pub nonce: Option<String>,
    /// The access token issued alongside, for `at_hash`.
    pub access_token: Option<String>,
    /// Clock skew tolerated on `exp`, `iat` and `nbf`, in seconds.
    pub leeway_secs: u64,
    /// The time to check against, seconds since the epoch; `None` is now.
    pub now: Option<u64>,
}

impl Expected {
    /// The checks for one client, with sixty seconds of leeway.
    pub fn new(issuer: Option<String>, client_id: impl Into<String>) -> Expected {
        Expected {
            issuer,
            client_id: client_id.into(),
            nonce: None,
            access_token: None,
            leeway_secs: 60,
            now: None,
        }
    }
}

/// Seconds since the epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// OpenID Connect Core §3.1.3.7, the client's part: steps 2 through 11, the ones that do not
/// depend on the signature already checked by [`Jws::verify`].
pub fn validate(claims: &Claims, alg: Algorithm, expected: &Expected) -> Result<(), AuthError> {
    let now = expected.now.unwrap_or_else(now_secs);
    let leeway = expected.leeway_secs;
    if let Some(issuer) = &expected.issuer {
        match &claims.issuer {
            Some(iss) if iss == issuer => {}
            Some(iss) => {
                return Err(AuthError::InvalidToken(format!(
                    "issuer {iss:?} is not {issuer:?}"
                )));
            }
            None => return Err(AuthError::InvalidToken("no issuer".into())),
        }
    }
    if claims.subject.as_deref().unwrap_or("").is_empty() {
        return Err(AuthError::InvalidToken("no subject".into()));
    }
    if !claims.audience.iter().any(|a| a == &expected.client_id) {
        return Err(AuthError::InvalidToken(
            "this client is not an audience".into(),
        ));
    }
    if claims.audience.len() > 1 {
        match &claims.authorized_party {
            Some(azp) if azp == &expected.client_id => {}
            Some(_) => return Err(AuthError::InvalidToken("azp is another client".into())),
            None => {
                return Err(AuthError::InvalidToken(
                    "several audiences and no azp".into(),
                ));
            }
        }
    } else if let Some(azp) = &claims.authorized_party
        && azp != &expected.client_id
    {
        return Err(AuthError::InvalidToken("azp is another client".into()));
    }
    match claims.expires_at {
        Some(exp) if exp + leeway > now => {}
        Some(_) => return Err(AuthError::InvalidToken("expired".into())),
        None => return Err(AuthError::InvalidToken("no expiry".into())),
    }
    match claims.issued_at {
        Some(iat) if iat <= now + leeway => {}
        Some(_) => return Err(AuthError::InvalidToken("issued in the future".into())),
        None => return Err(AuthError::InvalidToken("no issue time".into())),
    }
    if let Some(nbf) = claims.not_before
        && nbf > now + leeway
    {
        return Err(AuthError::InvalidToken("not yet valid".into()));
    }
    match (&expected.nonce, &claims.nonce) {
        (None, _) => {}
        (Some(want), Some(got)) if crypto::constant_time_eq(want.as_bytes(), got.as_bytes()) => {}
        (Some(_), Some(_)) => return Err(AuthError::InvalidToken("nonce does not match".into())),
        (Some(_), None) => return Err(AuthError::InvalidToken("no nonce".into())),
    }
    if let Some(access_token) = &expected.access_token
        && let Some(at_hash) = &claims.access_token_hash
    {
        let want = access_token_hash(access_token, alg);
        if !crypto::constant_time_eq(want.as_bytes(), at_hash.as_bytes()) {
            return Err(AuthError::InvalidToken(
                "at_hash does not match the access token".into(),
            ));
        }
    }
    Ok(())
}

/// The `at_hash` of an access token: the left half of its SHA-256, base64url (both RS256 and
/// ES256 hash with SHA-256).
pub fn access_token_hash(access_token: &str, _alg: Algorithm) -> String {
    let digest = crypto::sha256(access_token.as_bytes());
    crypto::base64url(&digest[..16])
}

/// Build a compact JWS signed with ES256: the demo provider's token mint.
pub fn sign_es256(
    header: &Value,
    payload: &Value,
    private_key: &BigUint,
) -> Result<String, AuthError> {
    let h = crypto::base64url(
        serde_json::to_string(header)
            .map_err(|e| AuthError::Platform(e.to_string()))?
            .as_bytes(),
    );
    let p = crypto::base64url(
        serde_json::to_string(payload)
            .map_err(|e| AuthError::Platform(e.to_string()))?
            .as_bytes(),
    );
    let input = format!("{h}.{p}");
    let curve = P256::new();
    let (r, s) = curve
        .ecdsa_sign(private_key, &crypto::sha256(input.as_bytes()))
        .ok_or_else(|| AuthError::Platform("ECDSA signing failed".into()))?;
    let mut sig = r.to_be_bytes(32);
    sig.extend(s.to_be_bytes(32));
    Ok(format!("{input}.{}", crypto::base64url(&sig)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn demo_key() -> (BigUint, Jwks) {
        let curve = P256::new();
        let d = BigUint::from_be_bytes(
            &crypto::hex_decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .expect("hex"),
        );
        let (x, y) = curve.public_key(&d).expect("public key");
        let jwks = Jwks {
            keys: vec![Jwk {
                kty: "EC".into(),
                kid: Some("demo-1".into()),
                alg: Some("ES256".into()),
                use_: Some("sig".into()),
                n: None,
                e: None,
                crv: Some("P-256".into()),
                x: Some(crypto::base64url(&x.to_be_bytes(32))),
                y: Some(crypto::base64url(&y.to_be_bytes(32))),
            }],
        };
        (d, jwks)
    }

    #[test]
    fn es256_token_round_trips_through_sign_decode_verify() {
        let (d, jwks) = demo_key();
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": "demo-1"});
        let payload = json!({"iss": "https://demo.example", "sub": "alice", "aud": "app", "exp": 4_000_000_000u64, "iat": 1_700_000_000u64, "nonce": "n1"});
        let token = sign_es256(&header, &payload, &d).expect("sign");
        let jws = Jws::decode(&token).expect("decode");
        assert_eq!(jws.algorithm(), Ok(Algorithm::Es256));
        assert_eq!(jws.key_id(), Some("demo-1"));
        jws.verify(&jwks).expect("verifies");
        // A tampered payload fails.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = crypto::base64url(br#"{"iss":"https://demo.example","sub":"mallory","aud":"app","exp":4000000000,"iat":1700000000}"#);
        parts[1] = &forged;
        let forged_token = parts.join(".");
        assert!(
            Jws::decode(&forged_token)
                .expect("decode")
                .verify(&jwks)
                .is_err()
        );
        // Claims validate against what was requested.
        let claims = Claims::from_payload(&jws.payload);
        let mut expected = Expected::new(Some("https://demo.example".into()), "app");
        expected.nonce = Some("n1".into());
        expected.now = Some(1_700_000_010);
        validate(&claims, Algorithm::Es256, &expected).expect("valid");
        expected.nonce = Some("other".into());
        assert!(validate(&claims, Algorithm::Es256, &expected).is_err());
    }

    #[test]
    fn key_selection_follows_kid_alg_and_use() {
        let (d, mut jwks) = demo_key();
        let header = json!({"alg": "ES256", "kid": "missing"});
        let token = sign_es256(&header, &json!({"sub": "a"}), &d).expect("sign");
        assert!(Jws::decode(&token).expect("decode").verify(&jwks).is_err());
        // Without a kid every EC key is tried.
        let token = sign_es256(&json!({"alg": "ES256"}), &json!({"sub": "a"}), &d).expect("sign");
        Jws::decode(&token)
            .expect("decode")
            .verify(&jwks)
            .expect("any key");
        // An encryption key is never a signing key.
        jwks.keys[0].use_ = Some("enc".into());
        assert!(Jws::decode(&token).expect("decode").verify(&jwks).is_err());
    }

    #[test]
    fn none_and_unknown_algorithms_are_refused() {
        let h = crypto::base64url(br#"{"alg":"none"}"#);
        let p = crypto::base64url(br#"{"sub":"a"}"#);
        let jws = Jws::decode(&format!("{h}.{p}.")).expect("decode");
        assert!(jws.algorithm().is_err());
        assert!(jws.verify(&Jwks::default()).is_err());
        let h = crypto::base64url(br#"{"alg":"HS256"}"#);
        let jws = Jws::decode(&format!("{h}.{p}.AAAA")).expect("decode");
        assert!(jws.verify(&Jwks::default()).is_err());
        assert!(Jws::decode("a.b").is_err());
        assert!(Jws::decode("a.b.c.d").is_err());
    }

    #[test]
    fn claim_checks_cover_the_core_rules() {
        let payload = json!({"iss": "i", "sub": "s", "aud": ["app", "other"], "azp": "app", "exp": 2000, "iat": 1000, "nbf": 900, "email_verified": "true"});
        let claims = Claims::from_payload(&payload);
        assert_eq!(claims.email_verified, Some(true));
        let mut expected = Expected::new(Some("i".into()), "app");
        expected.now = Some(1500);
        expected.leeway_secs = 0;
        validate(&claims, Algorithm::Rs256, &expected).expect("valid");
        expected.now = Some(2001);
        assert!(validate(&claims, Algorithm::Rs256, &expected).is_err());
        expected.now = Some(999);
        assert!(validate(&claims, Algorithm::Rs256, &expected).is_err());
        expected.now = Some(1500);
        expected.client_id = "other".into();
        assert!(
            validate(&claims, Algorithm::Rs256, &expected).is_err(),
            "azp names another client"
        );
        expected.client_id = "app".into();
        expected.issuer = Some("j".into());
        assert!(validate(&claims, Algorithm::Rs256, &expected).is_err());
        expected.issuer = None;
        expected.access_token = Some("tok".into());
        let with_hash = Claims::from_payload(
            &json!({"iss": "i", "sub": "s", "aud": "app", "exp": 2000, "iat": 1000, "at_hash": access_token_hash("tok", Algorithm::Rs256)}),
        );
        validate(&with_hash, Algorithm::Rs256, &expected).expect("at_hash matches");
        expected.access_token = Some("other".into());
        assert!(validate(&with_hash, Algorithm::Rs256, &expected).is_err());
    }

    /// OpenID Connect Core §3.3.2.11's example: the at_hash of "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y".
    #[test]
    fn at_hash_matches_the_specification_example() {
        assert_eq!(
            access_token_hash(
                "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
                Algorithm::Rs256
            ),
            "77QmUPtjPfzWtF2AnpK9RQ"
        );
    }

    #[test]
    fn jwks_parse_tolerates_unknown_fields() {
        let jwks = Jwks::parse(r#"{"keys":[{"kty":"RSA","kid":"a","n":"AQAB","e":"AQAB","x5c":["..."]},{"kty":"OKP","crv":"Ed25519","x":"AA"}]}"#).expect("parse");
        assert_eq!(jwks.keys.len(), 2);
        assert!(Jwks::parse("{").is_err());
    }
}
