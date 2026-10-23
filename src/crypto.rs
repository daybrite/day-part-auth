// Copyright © The Daybrite Project
// SPDX-License-Identifier: MPL-2.0

//! The arithmetic a sign-in client needs, written here rather than taken from a crate: SHA-256
//! and HMAC-SHA256 (PKCE, `at_hash`, deterministic ECDSA nonces), base64url (every JOSE field),
//! an unsigned big integer with the division RSA needs, RSA PKCS#1 v1.5 verification (RS256),
//! and the P-256 curve with ECDSA verification (ES256) and, for the demo provider, signing.
//!
//! Every algorithm is checked below against published test vectors (FIPS 180-4, RFC 4231,
//! RFC 4648, RFC 6979) and against signatures OpenSSL produced for a fixed message. None of it
//! is constant-time: a client verifies public signatures and signs nothing but the demo
//! provider's tokens, whose key lives for one run.

use std::cmp::Ordering;

use crate::AuthError;

// ---------------------------------------------------------------------------
// SHA-256 and HMAC
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = H0;
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for block in message.as_chunks::<64>().0 {
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

// ---------------------------------------------------------------------------
// base64url (RFC 4648 §5, no padding) and hex
// ---------------------------------------------------------------------------

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `bytes` as base64url without padding, the JOSE spelling.
pub fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(URL_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(URL_ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(URL_ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(URL_ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

fn url_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'-' | b'+' => Some(62),
        b'_' | b'/' => Some(63),
        _ => None,
    }
}

/// Decode base64url (padding optional; the standard alphabet is accepted too). `None` for
/// anything malformed.
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = text
        .bytes()
        .filter(|b| *b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | url_value(c)?;
        }
        n <<= 6 * (4 - chunk.len() as u32);
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 15)] as char);
    }
    s
}

/// Bytes from hex of either case. `None` for an odd length or a non-hex character.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Randomness: the OS's own source, never a userland generator
// ---------------------------------------------------------------------------

/// `n` bytes from the operating system's random source.
pub fn random_bytes(n: usize) -> Result<Vec<u8>, AuthError> {
    #[cfg(any(unix, target_env = "ohos"))]
    {
        use std::io::Read;
        let mut out = vec![0u8; n];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut out))
            .map_err(|e| AuthError::Platform(format!("random: {e}")))?;
        Ok(out)
    }
    #[cfg(windows)]
    {
        use windows::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };
        let mut out = vec![0u8; n];
        // SAFETY: the buffer is live for the call; the system-preferred RNG needs no handle.
        unsafe { BCryptGenRandom(None, &mut out, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
            .ok()
            .map_err(|e| AuthError::Platform(format!("random: {e}")))?;
        Ok(out)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let text = crate::native::random_hex(n as i32)
            .map_err(|e| AuthError::Platform(format!("random: {e}")))?;
        hex_decode(&text)
            .filter(|b| b.len() == n)
            .ok_or_else(|| AuthError::Platform("random: bad answer".into()))
    }
    #[cfg(not(any(unix, target_env = "ohos", windows, target_arch = "wasm32")))]
    {
        let _ = n;
        Err(AuthError::Unsupported)
    }
}

/// A base64url string of `n` random bytes: `state`, `nonce`, a PKCE verifier.
pub fn random_token(n: usize) -> Result<String, AuthError> {
    random_bytes(n).map(|b| base64url(&b))
}

// ---------------------------------------------------------------------------
// Unsigned big integers: little-endian u32 limbs, no leading zero limbs
// ---------------------------------------------------------------------------

/// An arbitrary-precision unsigned integer, as much of one as RSA and P-256 need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    /// Least significant limb first; never ends in a zero limb; empty is zero.
    limbs: Vec<u32>,
}

impl BigUint {
    pub fn zero() -> BigUint {
        BigUint { limbs: Vec::new() }
    }

    pub fn from_u32(v: u32) -> BigUint {
        let mut b = BigUint { limbs: vec![v] };
        b.trim();
        b
    }

    pub fn from_u64(v: u64) -> BigUint {
        let mut b = BigUint {
            limbs: vec![v as u32, (v >> 32) as u32],
        };
        b.trim();
        b
    }

    pub fn from_be_bytes(bytes: &[u8]) -> BigUint {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(4));
        for chunk in bytes.rchunks(4) {
            let mut limb = 0u32;
            for &b in chunk {
                limb = (limb << 8) | u32::from(b);
            }
            limbs.push(limb);
        }
        let mut b = BigUint { limbs };
        b.trim();
        b
    }

    /// Big-endian bytes, left-padded with zeros to `len` (or longer when the value needs it).
    pub fn to_be_bytes(&self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.limbs.len() * 4);
        for limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        let used = out.iter().position(|b| *b != 0).unwrap_or(out.len());
        let mut out = out.split_off(used);
        if out.len() < len {
            let mut padded = vec![0u8; len - out.len()];
            padded.append(&mut out);
            out = padded;
        }
        out
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|l| l & 1 == 1)
    }

    pub fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    pub fn bit(&self, i: usize) -> bool {
        self.limbs
            .get(i / 32)
            .is_some_and(|l| (l >> (i % 32)) & 1 == 1)
    }

    pub fn add(&self, other: &BigUint) -> BigUint {
        let (long, short) = if self.limbs.len() >= other.limbs.len() {
            (self, other)
        } else {
            (other, self)
        };
        let mut limbs = Vec::with_capacity(long.limbs.len() + 1);
        let mut carry = 0u64;
        for i in 0..long.limbs.len() {
            let sum = u64::from(long.limbs[i])
                + u64::from(short.limbs.get(i).copied().unwrap_or(0))
                + carry;
            limbs.push(sum as u32);
            carry = sum >> 32;
        }
        if carry > 0 {
            limbs.push(carry as u32);
        }
        let mut b = BigUint { limbs };
        b.trim();
        b
    }

    /// `self - other`; `None` when the result would be negative.
    pub fn sub(&self, other: &BigUint) -> Option<BigUint> {
        if self.cmp(other) == Ordering::Less {
            return None;
        }
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let diff = i64::from(self.limbs[i])
                - i64::from(other.limbs.get(i).copied().unwrap_or(0))
                - borrow;
            if diff < 0 {
                limbs.push((diff + (1i64 << 32)) as u32);
                borrow = 1;
            } else {
                limbs.push(diff as u32);
                borrow = 0;
            }
        }
        let mut b = BigUint { limbs };
        b.trim();
        Some(b)
    }

    pub fn mul(&self, other: &BigUint) -> BigUint {
        if self.is_zero() || other.is_zero() {
            return BigUint::zero();
        }
        let mut limbs = vec![0u32; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let t = u64::from(a) * u64::from(b) + u64::from(limbs[i + j]) + carry;
                limbs[i + j] = t as u32;
                carry = t >> 32;
            }
            let mut k = i + other.limbs.len();
            while carry > 0 {
                let t = u64::from(limbs[k]) + carry;
                limbs[k] = t as u32;
                carry = t >> 32;
                k += 1;
            }
        }
        let mut b = BigUint { limbs };
        b.trim();
        b
    }

    fn shl_limbs(&self, bits: u32) -> Vec<u32> {
        // A left shift by less than 32 bits, with one extra limb for the overflow.
        let mut out = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u32;
        for &l in &self.limbs {
            if bits == 0 {
                out.push(l);
            } else {
                out.push((l << bits) | carry);
                carry = l >> (32 - bits);
            }
        }
        out.push(carry);
        out
    }

    /// `(self / other, self % other)`; `None` when `other` is zero.
    pub fn divrem(&self, other: &BigUint) -> Option<(BigUint, BigUint)> {
        if other.is_zero() {
            return None;
        }
        if self.cmp(other) == Ordering::Less {
            return Some((BigUint::zero(), self.clone()));
        }
        if other.limbs.len() == 1 {
            let d = u64::from(other.limbs[0]);
            let mut q = vec![0u32; self.limbs.len()];
            let mut rem = 0u64;
            for i in (0..self.limbs.len()).rev() {
                let cur = (rem << 32) | u64::from(self.limbs[i]);
                q[i] = (cur / d) as u32;
                rem = cur % d;
            }
            let mut q = BigUint { limbs: q };
            q.trim();
            return Some((q, BigUint::from_u64(rem)));
        }
        // Knuth, TAOCP vol. 2, Algorithm D, with 32-bit digits.
        let n = other.limbs.len();
        let m = self.limbs.len() - n;
        let shift = other.limbs[n - 1].leading_zeros();
        let v = other.shl_limbs(shift);
        let mut u = self.shl_limbs(shift);
        // `u` has m + n + 1 limbs after the shift (the extra one may be zero).
        let b: u64 = 1 << 32;
        let mut q = vec![0u32; m + 1];
        for j in (0..=m).rev() {
            let num = (u64::from(u[j + n]) << 32) | u64::from(u[j + n - 1]);
            let mut qhat = num / u64::from(v[n - 1]);
            let mut rhat = num % u64::from(v[n - 1]);
            while qhat >= b || qhat * u64::from(v[n - 2]) > ((rhat << 32) | u64::from(u[j + n - 2]))
            {
                qhat -= 1;
                rhat += u64::from(v[n - 1]);
                if rhat >= b {
                    break;
                }
            }
            // Multiply and subtract.
            let mut borrow = 0i64;
            let mut carry = 0u64;
            for i in 0..n {
                let p = qhat * u64::from(v[i]) + carry;
                carry = p >> 32;
                let t = i64::from(u[i + j]) - borrow - i64::from(p as u32);
                u[i + j] = t as u32;
                borrow = if t < 0 { 1 } else { 0 };
            }
            let t = i64::from(u[j + n]) - borrow - carry as i64;
            u[j + n] = t as u32;
            q[j] = qhat as u32;
            if t < 0 {
                // Add back.
                q[j] -= 1;
                let mut carry = 0u64;
                for i in 0..n {
                    let t = u64::from(u[i + j]) + u64::from(v[i]) + carry;
                    u[i + j] = t as u32;
                    carry = t >> 32;
                }
                u[j + n] = u[j + n].wrapping_add(carry as u32);
            }
        }
        // The remainder is u[0..n] shifted back.
        let mut r = vec![0u32; n];
        for i in 0..n {
            r[i] = if shift == 0 {
                u[i]
            } else {
                (u[i] >> shift) | (u[i + 1] << (32 - shift))
            };
        }
        let mut q = BigUint { limbs: q };
        q.trim();
        let mut r = BigUint { limbs: r };
        r.trim();
        Some((q, r))
    }

    pub fn rem(&self, modulus: &BigUint) -> Option<BigUint> {
        self.divrem(modulus).map(|(_, r)| r)
    }

    /// `self^exp mod modulus` by square-and-multiply. `None` for a zero modulus.
    pub fn modpow(&self, exp: &BigUint, modulus: &BigUint) -> Option<BigUint> {
        if modulus.is_zero() {
            return None;
        }
        let mut result = BigUint::from_u32(1).rem(modulus)?;
        let mut base = self.rem(modulus)?;
        for i in 0..exp.bit_len() {
            if exp.bit(i) {
                result = result.mul(&base).rem(modulus)?;
            }
            if i + 1 < exp.bit_len() {
                base = base.mul(&base).rem(modulus)?;
            }
        }
        Some(result)
    }

    /// The inverse of `self` modulo a prime, by Fermat's little theorem. `None` when `self` is
    /// zero modulo the prime.
    pub fn mod_inverse_prime(&self, prime: &BigUint) -> Option<BigUint> {
        let reduced = self.rem(prime)?;
        if reduced.is_zero() {
            return None;
        }
        let exp = prime.sub(&BigUint::from_u32(2))?;
        reduced.modpow(&exp, prime)
    }

    /// `(a + b) mod m`.
    pub fn add_mod(a: &BigUint, b: &BigUint, m: &BigUint) -> Option<BigUint> {
        a.add(b).rem(m)
    }

    /// `(a - b) mod m`, for `a` and `b` already reduced.
    pub fn sub_mod(a: &BigUint, b: &BigUint, m: &BigUint) -> Option<BigUint> {
        match a.sub(b) {
            Some(d) => Some(d),
            None => a.add(m).sub(b),
        }
    }

    /// `(a * b) mod m`.
    pub fn mul_mod(a: &BigUint, b: &BigUint, m: &BigUint) -> Option<BigUint> {
        a.mul(b).rem(m)
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for i in (0..self.limbs.len()).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// RSA PKCS#1 v1.5 with SHA-256 (JWS "RS256")
// ---------------------------------------------------------------------------

/// The DER prefix of a SHA-256 `DigestInfo` (RFC 8017 §9.2 note 1).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// An RSA public key: modulus and exponent as big-endian bytes (a JWK's `n` and `e`).
pub struct RsaPublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

/// Whether `signature` is the RSASSA-PKCS1-v1_5 SHA-256 signature of `message` under `key`.
pub fn rsa_pkcs1_sha256_verify(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let n = BigUint::from_be_bytes(&key.n);
    let e = BigUint::from_be_bytes(&key.e);
    let k = n.to_be_bytes(0).len();
    if k < 11 + SHA256_DIGEST_INFO.len() + 32 || signature.len() != k {
        return false;
    }
    let s = BigUint::from_be_bytes(signature);
    if s.cmp(&n) != Ordering::Less {
        return false;
    }
    let Some(em) = s.modpow(&e, &n) else {
        return false;
    };
    let em = em.to_be_bytes(k);
    // EM = 0x00 || 0x01 || PS (0xff, at least 8) || 0x00 || DigestInfo || hash
    let t_len = SHA256_DIGEST_INFO.len() + 32;
    if em.len() != k || em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let ps_end = k - t_len - 1;
    if ps_end < 10 || em[ps_end] != 0x00 || em[2..ps_end].iter().any(|b| *b != 0xff) {
        return false;
    }
    let digest = sha256(message);
    let mut t = Vec::with_capacity(t_len);
    t.extend_from_slice(&SHA256_DIGEST_INFO);
    t.extend_from_slice(&digest);
    constant_time_eq(&em[ps_end + 1..], &t)
}

/// Equality that does not stop at the first difference.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// P-256 (secp256r1) and ECDSA (JWS "ES256")
// ---------------------------------------------------------------------------

/// The curve constants, from FIPS 186-4 D.1.2.3.
pub struct P256 {
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub n: BigUint,
    pub gx: BigUint,
    pub gy: BigUint,
}

fn from_hex(text: &str) -> BigUint {
    BigUint::from_be_bytes(&hex_decode(text).unwrap_or_default())
}

impl P256 {
    pub fn new() -> P256 {
        P256 {
            p: from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            a: from_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
            b: from_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
            n: from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            gx: from_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            gy: from_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        }
    }

    fn generator(&self) -> Jacobian {
        Jacobian {
            x: self.gx.clone(),
            y: self.gy.clone(),
            z: BigUint::from_u32(1),
        }
    }

    fn field_mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        BigUint::mul_mod(a, b, &self.p).unwrap_or_else(BigUint::zero)
    }

    fn field_add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        BigUint::add_mod(a, b, &self.p).unwrap_or_else(BigUint::zero)
    }

    fn field_sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        BigUint::sub_mod(a, b, &self.p).unwrap_or_else(BigUint::zero)
    }

    /// Whether `(x, y)` lies on the curve.
    pub fn is_on_curve(&self, x: &BigUint, y: &BigUint) -> bool {
        if x.cmp(&self.p) != Ordering::Less || y.cmp(&self.p) != Ordering::Less {
            return false;
        }
        let lhs = self.field_mul(y, y);
        let x2 = self.field_mul(x, x);
        let x3 = self.field_mul(&x2, x);
        let rhs = self.field_add(&self.field_add(&x3, &self.field_mul(&self.a, x)), &self.b);
        lhs == rhs
    }

    /// Point doubling in Jacobian coordinates (a = -3 form).
    fn double(&self, pt: &Jacobian) -> Jacobian {
        if pt.is_infinity() {
            return pt.clone();
        }
        let p = &self.p;
        let three = BigUint::from_u32(3);
        let two = BigUint::from_u32(2);
        let four = BigUint::from_u32(4);
        let eight = BigUint::from_u32(8);
        let zz = self.field_mul(&pt.z, &pt.z);
        // M = 3 (X - Z^2)(X + Z^2)
        let m = self.field_mul(
            &three,
            &self.field_mul(&self.field_sub(&pt.x, &zz), &self.field_add(&pt.x, &zz)),
        );
        let yy = self.field_mul(&pt.y, &pt.y);
        // S = 4 X Y^2
        let s = self.field_mul(&four, &self.field_mul(&pt.x, &yy));
        let x3 = self.field_sub(&self.field_mul(&m, &m), &self.field_mul(&two, &s));
        // Y3 = M (S - X3) - 8 Y^4
        let y3 = self.field_sub(
            &self.field_mul(&m, &self.field_sub(&s, &x3)),
            &self.field_mul(&eight, &self.field_mul(&yy, &yy)),
        );
        let z3 = self.field_mul(&two, &self.field_mul(&pt.y, &pt.z));
        let _ = p;
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Point addition in Jacobian coordinates.
    fn add(&self, a: &Jacobian, b: &Jacobian) -> Jacobian {
        if a.is_infinity() {
            return b.clone();
        }
        if b.is_infinity() {
            return a.clone();
        }
        let z1z1 = self.field_mul(&a.z, &a.z);
        let z2z2 = self.field_mul(&b.z, &b.z);
        let u1 = self.field_mul(&a.x, &z2z2);
        let u2 = self.field_mul(&b.x, &z1z1);
        let s1 = self.field_mul(&a.y, &self.field_mul(&b.z, &z2z2));
        let s2 = self.field_mul(&b.y, &self.field_mul(&a.z, &z1z1));
        if u1 == u2 {
            if s1 == s2 {
                return self.double(a);
            }
            return Jacobian::infinity();
        }
        let h = self.field_sub(&u2, &u1);
        let r = self.field_sub(&s2, &s1);
        let hh = self.field_mul(&h, &h);
        let hhh = self.field_mul(&hh, &h);
        let u1hh = self.field_mul(&u1, &hh);
        let two = BigUint::from_u32(2);
        let x3 = self.field_sub(
            &self.field_sub(&self.field_mul(&r, &r), &hhh),
            &self.field_mul(&two, &u1hh),
        );
        let y3 = self.field_sub(
            &self.field_mul(&r, &self.field_sub(&u1hh, &x3)),
            &self.field_mul(&s1, &hhh),
        );
        let z3 = self.field_mul(&h, &self.field_mul(&a.z, &b.z));
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `k * pt`, double-and-add from the top bit.
    fn mul(&self, k: &BigUint, pt: &Jacobian) -> Jacobian {
        let mut acc = Jacobian::infinity();
        for i in (0..k.bit_len()).rev() {
            acc = self.double(&acc);
            if k.bit(i) {
                acc = self.add(&acc, pt);
            }
        }
        acc
    }

    /// Affine coordinates of a Jacobian point; `None` for the point at infinity.
    fn to_affine(&self, pt: &Jacobian) -> Option<(BigUint, BigUint)> {
        if pt.is_infinity() {
            return None;
        }
        let zi = pt.z.mod_inverse_prime(&self.p)?;
        let zi2 = self.field_mul(&zi, &zi);
        let zi3 = self.field_mul(&zi2, &zi);
        Some((self.field_mul(&pt.x, &zi2), self.field_mul(&pt.y, &zi3)))
    }

    /// The public point of a scalar: `d * G` as affine `(x, y)`.
    pub fn public_key(&self, d: &BigUint) -> Option<(BigUint, BigUint)> {
        self.to_affine(&self.mul(d, &self.generator()))
    }

    /// Whether `(r, s)` is a valid ECDSA signature over `hash` (already SHA-256) for the public
    /// point `(qx, qy)`.
    pub fn ecdsa_verify(
        &self,
        qx: &BigUint,
        qy: &BigUint,
        hash: &[u8; 32],
        r: &BigUint,
        s: &BigUint,
    ) -> bool {
        let one = BigUint::from_u32(1);
        if !self.is_on_curve(qx, qy) {
            return false;
        }
        if r.cmp(&one) == Ordering::Less
            || r.cmp(&self.n) != Ordering::Less
            || s.cmp(&one) == Ordering::Less
            || s.cmp(&self.n) != Ordering::Less
        {
            return false;
        }
        let e = BigUint::from_be_bytes(hash);
        let Some(w) = s.mod_inverse_prime(&self.n) else {
            return false;
        };
        let (Some(u1), Some(u2)) = (
            BigUint::mul_mod(&e, &w, &self.n),
            BigUint::mul_mod(r, &w, &self.n),
        ) else {
            return false;
        };
        let q = Jacobian {
            x: qx.clone(),
            y: qy.clone(),
            z: one,
        };
        let point = self.add(&self.mul(&u1, &self.generator()), &self.mul(&u2, &q));
        match self.to_affine(&point) {
            Some((x, _)) => x.rem(&self.n).as_ref() == Some(r),
            None => false,
        }
    }

    /// Sign `hash` with the private scalar `d`, deterministically (RFC 6979). Returns `(r, s)`.
    pub fn ecdsa_sign(&self, d: &BigUint, hash: &[u8; 32]) -> Option<(BigUint, BigUint)> {
        let one = BigUint::from_u32(1);
        if d.is_zero() || d.cmp(&self.n) != Ordering::Less {
            return None;
        }
        let e = BigUint::from_be_bytes(hash);
        let mut k_source = Rfc6979::new(&d.to_be_bytes(32), &e.rem(&self.n)?.to_be_bytes(32));
        loop {
            let k = k_source.next_candidate();
            if k.is_zero() || k.cmp(&self.n) != Ordering::Less {
                continue;
            }
            let Some((x, _)) = self.to_affine(&self.mul(&k, &self.generator())) else {
                continue;
            };
            let r = x.rem(&self.n)?;
            if r.is_zero() {
                continue;
            }
            let kinv = k.mod_inverse_prime(&self.n)?;
            let s = BigUint::mul_mod(
                &kinv,
                &BigUint::add_mod(&e, &BigUint::mul_mod(&r, d, &self.n)?, &self.n)?,
                &self.n,
            )?;
            if s.is_zero() {
                continue;
            }
            let _ = one;
            return Some((r, s));
        }
    }
}

impl Default for P256 {
    fn default() -> Self {
        P256::new()
    }
}

#[derive(Clone)]
struct Jacobian {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl Jacobian {
    fn infinity() -> Jacobian {
        Jacobian {
            x: BigUint::from_u32(1),
            y: BigUint::from_u32(1),
            z: BigUint::zero(),
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }
}

/// RFC 6979 §3.2: deterministic nonce candidates for ECDSA with HMAC-SHA256.
struct Rfc6979 {
    k: [u8; 32],
    v: [u8; 32],
}

impl Rfc6979 {
    fn new(private_key: &[u8], hash_mod_n: &[u8]) -> Rfc6979 {
        let mut k = [0u8; 32];
        let mut v = [1u8; 32];
        let mut material = Vec::with_capacity(33 + private_key.len() + hash_mod_n.len());
        material.extend_from_slice(&v);
        material.push(0x00);
        material.extend_from_slice(private_key);
        material.extend_from_slice(hash_mod_n);
        k = hmac_sha256(&k, &material);
        v = hmac_sha256(&k, &v);
        let mut material = Vec::with_capacity(33 + private_key.len() + hash_mod_n.len());
        material.extend_from_slice(&v);
        material.push(0x01);
        material.extend_from_slice(private_key);
        material.extend_from_slice(hash_mod_n);
        k = hmac_sha256(&k, &material);
        v = hmac_sha256(&k, &v);
        Rfc6979 { k, v }
    }

    fn next_candidate(&mut self) -> BigUint {
        // One HMAC output covers the 256-bit order.
        self.v = hmac_sha256(&self.k, &self.v);
        let candidate = BigUint::from_be_bytes(&self.v);
        // Prepare the next candidate, in case this one is rejected.
        let mut material = Vec::with_capacity(33);
        material.extend_from_slice(&self.v);
        material.push(0x00);
        self.k = hmac_sha256(&self.k, &material);
        self.v = hmac_sha256(&self.k, &self.v);
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha256(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        // Lengths around the padding boundary.
        for len in 54..70 {
            let _ = sha256(&vec![0x61; len]);
        }
    }

    /// RFC 4231 test cases 1, 2 and 6 (a key longer than the block).
    #[test]
    fn hmac_vectors() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// RFC 4648 §10 vectors, in the url-safe alphabet without padding.
    #[test]
    fn base64url_vectors() {
        for (plain, text) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(plain.as_bytes()), text);
            assert_eq!(base64url_decode(text).as_deref(), Some(plain.as_bytes()));
        }
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url_decode("Zg==").as_deref(), Some(&b"f"[..]));
        assert_eq!(base64url_decode("+/8").as_deref(), Some(&[0xfb, 0xff][..]));
        assert_eq!(base64url_decode("Z"), None);
        assert_eq!(base64url_decode("Zm9!"), None);
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base64url_decode(&base64url(&all)), Some(all));
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0, 15, 255]), "000fff");
        assert_eq!(hex_decode("000FfF"), Some(vec![0, 15, 255]));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn random_bytes_come_from_the_os() {
        let a = random_bytes(32).expect("random");
        let b = random_bytes(32).expect("random");
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert_eq!(random_token(32).expect("token").len(), 43);
    }

    /// A simple generator for arithmetic cross-checks (not for keys).
    fn lcg(seed: &mut u64) -> u32 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 33) as u32
    }

    fn random_big(seed: &mut u64, limbs: usize) -> BigUint {
        let mut b = BigUint {
            limbs: (0..limbs).map(|_| lcg(seed)).collect(),
        };
        b.trim();
        b
    }

    #[test]
    fn bigint_round_trips_and_identities() {
        let mut seed = 42u64;
        for _ in 0..200 {
            let a_len = (lcg(&mut seed) % 9) as usize + 1;
            let a = random_big(&mut seed, a_len);
            let b_len = (lcg(&mut seed) % 5) as usize + 1;
            let b = random_big(&mut seed, b_len);
            // Bytes round trip.
            assert_eq!(BigUint::from_be_bytes(&a.to_be_bytes(0)), a);
            // (a + b) - b == a
            assert_eq!(a.add(&b).sub(&b), Some(a.clone()));
            if b.is_zero() {
                assert!(a.divrem(&b).is_none());
                continue;
            }
            // a == q*b + r with r < b
            let (q, r) = a.divrem(&b).expect("division");
            assert!(r.cmp(&b) == Ordering::Less);
            assert_eq!(q.mul(&b).add(&r), a);
            // (a * b) / b == a
            assert_eq!(a.mul(&b).divrem(&b).map(|(q, _)| q), Some(a.clone()));
        }
        assert_eq!(
            BigUint::from_u32(4).modpow(&BigUint::from_u32(13), &BigUint::from_u32(497)),
            Some(BigUint::from_u32(445))
        );
        assert_eq!(BigUint::from_u64(1 << 40).bit_len(), 41);
        assert!(BigUint::zero().is_zero());
        assert_eq!(
            BigUint::from_u32(7).mod_inverse_prime(&BigUint::from_u32(13)),
            Some(BigUint::from_u32(2))
        );
    }

    /// The division edge cases Algorithm D is known to get wrong when ported carelessly: the
    /// add-back step and a divisor whose top limb needs normalizing.
    #[test]
    fn bigint_division_edge_cases() {
        let a = from_hex("8000000000000000000000000000000000000000");
        let b = from_hex("800000000000000000000001");
        let (q, r) = a.divrem(&b).expect("division");
        assert_eq!(q.mul(&b).add(&r), a);
        assert!(r.cmp(&b) == Ordering::Less);
        let a = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffff");
        let b = from_hex("ffffffffffffffff0000000000000001");
        let (q, r) = a.divrem(&b).expect("division");
        assert_eq!(q.mul(&b).add(&r), a);
        assert!(r.cmp(&b) == Ordering::Less);
        let a = from_hex("7fffffff80000000000000007fffffff");
        let b = from_hex("7fffffff80000000");
        let (q, r) = a.divrem(&b).expect("division");
        assert_eq!(q.mul(&b).add(&r), a);
    }

    const FIXTURE_MESSAGE: &[u8] = b"day-part-auth signature fixture";
    const RSA_N: &str = "A0844CA4902D3C9063073DCF4BCFF5A8A5A907F978B48C3B3493A96D3EA957AA831A1BD2999F915840D85E972928E13BC17866E92BAB5257EBFD2DD004F656DA470A6C44841526D129062E6BC9BC97F703BF33CE2FB8546D51030F43EAFB4DDE58E793B027C2C06B6B854322789EBE131371AFAB2E21F8BD2E7AEB49B8FD42A17FEE5B00776E27EAA6B6005C5E35DD168CE0EF040CE32404E75B64011529D31A235246DD7DA31E78D562E9F133954C56DC05708A7DDC1036BF170B391716EB6662DD1312205C8BB9D9DCD799AB02A2C5EC2EE24E122EFB54AA2C1F4255A8885BA75AB335D75C764EFC20DE825146C174BAD13D9F332C606124493A38485935A3";
    const RSA_SIG: &str = "9820d0e9bcbcf7452877b7e8d21e4c7623108c61fdedccb9b5d1e03910d3529d072958b247ab6685caa5f662f7d46e2fc48545c9eaeb4ff32b68df0f28c883742a55f25ff65e76108f567af2c538c25a771e01317c71fa260b0e8b2a34bd2a7c5e6b354b339604a405350a56acd53f90f69e3d4f2598b794a512c16e06d2950b58677e0a0a02ddc49c9b19ea70e975c805b6769b86c3f91f6adbb2400a72931a4f39cc492bdb16928218b38bc17575a7bd7c38f3104755aaa8a8fddbddcf79ed8253b6279b9d1b70dcad1b6cc202d96c6df66aa9c31d89848ec048b47be40aa4284314cd68614ee0330d4f55a441f39c3a0377c337e9e865d866831852f58463";

    /// A 2048-bit key and signature OpenSSL produced (`openssl dgst -sha256 -sign`).
    #[test]
    fn rsa_verifies_an_openssl_signature() {
        let key = RsaPublicKey {
            n: hex_decode(RSA_N).expect("n"),
            e: vec![1, 0, 1],
        };
        let sig = hex_decode(RSA_SIG).expect("sig");
        assert!(rsa_pkcs1_sha256_verify(&key, FIXTURE_MESSAGE, &sig));
        assert!(!rsa_pkcs1_sha256_verify(&key, b"another message", &sig));
        let mut flipped = sig.clone();
        flipped[100] ^= 1;
        assert!(!rsa_pkcs1_sha256_verify(&key, FIXTURE_MESSAGE, &flipped));
        assert!(!rsa_pkcs1_sha256_verify(&key, FIXTURE_MESSAGE, &sig[1..]));
    }

    /// A P-256 key and signature OpenSSL produced (`openssl pkeyutl -sign` over the SHA-256).
    #[test]
    fn ecdsa_verifies_an_openssl_signature() {
        let curve = P256::new();
        let qx = from_hex("e896739e62ebb61b1d5e19b054e67e7ba6adfdcae179fe7cce1bcdd1aa5a21e7");
        let qy = from_hex("6d31816b9dba48bad45eedbfcccb1280e18f852e77dab619d6094c17ed761b54");
        let r = from_hex("94d1fc52af8151e5519a56e865d0b3f20a8d86f12e3a7cfc1afac581f956c79f");
        let s = from_hex("f77b59dbeca970d4278bd26351b80cdd3871b8c937d16703b3355f7121f3f07b");
        assert!(curve.is_on_curve(&qx, &qy));
        let hash = sha256(FIXTURE_MESSAGE);
        assert!(curve.ecdsa_verify(&qx, &qy, &hash, &r, &s));
        assert!(!curve.ecdsa_verify(&qx, &qy, &sha256(b"other"), &r, &s));
        assert!(!curve.ecdsa_verify(&qx, &qy, &hash, &s, &r));
        assert!(!curve.ecdsa_verify(&qy, &qx, &hash, &r, &s));
    }

    /// RFC 6979 A.2.5: P-256 with SHA-256, the "sample" and "test" messages.
    #[test]
    fn ecdsa_signs_the_rfc6979_vectors() {
        let curve = P256::new();
        let d = from_hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let (qx, qy) = curve.public_key(&d).expect("public key");
        assert_eq!(
            hex(&qx.to_be_bytes(32)),
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        );
        assert_eq!(
            hex(&qy.to_be_bytes(32)),
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        );
        let (r, s) = curve.ecdsa_sign(&d, &sha256(b"sample")).expect("signature");
        assert_eq!(
            hex(&r.to_be_bytes(32)),
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        );
        assert_eq!(
            hex(&s.to_be_bytes(32)),
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        );
        assert!(curve.ecdsa_verify(&qx, &qy, &sha256(b"sample"), &r, &s));
        let (r, s) = curve.ecdsa_sign(&d, &sha256(b"test")).expect("signature");
        assert_eq!(
            hex(&r.to_be_bytes(32)),
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
        );
        assert_eq!(
            hex(&s.to_be_bytes(32)),
            "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
        );
    }

    /// A fresh key signs and verifies; the signature does not verify under another key or hash.
    #[test]
    fn ecdsa_round_trip_with_a_random_key() {
        let curve = P256::new();
        let d = BigUint::from_be_bytes(&random_bytes(32).expect("random"))
            .rem(&curve.n)
            .expect("reduce");
        let (qx, qy) = curve.public_key(&d).expect("public key");
        let hash = sha256(b"round trip");
        let (r, s) = curve.ecdsa_sign(&d, &hash).expect("signature");
        assert!(curve.ecdsa_verify(&qx, &qy, &hash, &r, &s));
        assert!(!curve.ecdsa_verify(&qx, &qy, &sha256(b"other"), &r, &s));
        let (ox, oy) = curve
            .public_key(&BigUint::from_u32(12345))
            .expect("other key");
        assert!(!curve.ecdsa_verify(&ox, &oy, &hash, &r, &s));
    }
}
