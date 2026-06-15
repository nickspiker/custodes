//! custodes — K-of-N social recovery for TOKEN identities.
//!
//! Lose every device and normal attestation is impossible: there is no surviving device left to vouch for a new one.
//! custodes is the layer TOKEN invokes for exactly that case.
//! It splits a recovery secret into `N` shards under a threshold `K` (Shamir secret sharing over GF(2⁸)); any `K` custodians cooperating reconstruct the secret on new hardware, and fewer than `K` learn nothing — information-theoretically, not merely computationally.
//!
//! # What this crate is, and is not
//!
//! This crate is the *pure mathematical core* plus the value types that name the recovery model.
//! It does exactly one thing: turn a bytestring into shards, and back.
//! By deliberate design it does NOT store shards (distribution is Photon's job), transmit anything (transport is Photon's job), manage device attestation (that is TOKEN's bootstrap), or know what the secret *is* (it is an opaque bytestring; semantics live above).
//!
//! Two boundaries are therefore left as integration seams: per-custodian encryption binds to TOKEN's KEM (see [`Shard::encrypt_to`]), and the out-of-band verification phrase binds to the `voca` wordlist crate (see [`notify_custodians`]).
//! The split/reconstruct math below is complete and tested; those two seams are not — calling them panics with a descriptive `todo!`.
//!
//! # Honesty note
//!
//! The GF(2⁸) arithmetic here is textbook and correct, but not yet hardened: [`gf_mul`]/[`gf_inv`] are not constant-time, so any deployment where `split`/`reconstruct` timing is observable to an attacker needs a constant-time pass first.
//! Reconstruction also performs no integrity check of its own — a custodian who returns a corrupted shard silently corrupts the output.
//! Bind a MAC/AEAD at the encryption seam so a tampered shard is rejected before it ever reaches [`reconstruct`].
//!
//! # Shape
//!
//! ```ignore
//! let policy = RecoveryPolicy::new().threshold(3).custodians(vec![/* ... */]).build()?;
//! let shards = custodes::split(&identity_secret, &policy, &mut rng)?; // rng = caller's CSPRNG
//! // ... Photon delivers each shard to its custodian; later, after total loss, K come back ...
//! let mut collector = ShardCollector::new(&policy);
//! for shard in returned { collector.add(shard)?; if collector.threshold_met() { break; } }
//! let recovered = custodes::reconstruct(collector.shards())?;
//! ```

#![forbid(unsafe_code)]

/// Result alias for the crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong building a policy, splitting, or reconstructing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `RecoveryPolicyBuilder::build` was called without a threshold set.
    ThresholdUnset,
    /// Threshold `K` was zero; a zero-of-N policy can never reconstruct.
    ZeroThreshold,
    /// Threshold `K` exceeds the custodian count `N`; the secret could never be reassembled.
    ThresholdExceedsCustodians { k: u8, n: usize },
    /// More than 255 custodians; GF(2⁸) Shamir admits at most 255 distinct shares (x ∈ 1..=255).
    TooManyCustodians(usize),
    /// A policy with no custodians was built.
    NoCustodians,
    /// `split` was handed an empty secret; there is nothing to share.
    EmptySecret,
    /// Reconstruction was attempted with fewer than `need` distinct shards.
    NotEnoughShards { have: usize, need: u8 },
    /// Shards disagree on body length or recorded threshold — they are not from one split.
    MismatchedShards,
    /// Two shards carry the same x-coordinate; one is a duplicate or a forgery.
    DuplicateShardIndex(u8),
    /// A shard carries index 0, the reserved secret coordinate — never a valid share.
    ZeroShardIndex,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::ThresholdUnset => write!(f, "recovery policy has no threshold set"),
            Error::ZeroThreshold => write!(f, "threshold K must be at least 1"),
            Error::ThresholdExceedsCustodians { k, n } => {
                write!(f, "threshold K={k} exceeds custodian count N={n}")
            }
            Error::TooManyCustodians(n) => {
                write!(f, "{n} custodians — GF(2⁸) Shamir admits at most 255")
            }
            Error::NoCustodians => write!(f, "recovery policy has no custodians"),
            Error::EmptySecret => write!(f, "cannot split an empty secret"),
            Error::NotEnoughShards { have, need } => {
                write!(f, "have {have} shards, need {need} to reconstruct")
            }
            Error::MismatchedShards => write!(f, "shards are not from the same split"),
            Error::DuplicateShardIndex(i) => write!(f, "duplicate shard index {i}"),
            Error::ZeroShardIndex => write!(f, "shard index 0 is the reserved secret coordinate"),
        }
    }
}

impl std::error::Error for Error {}

/// A cryptographically secure source of randomness, injected by the caller so the crate stays pure — no OS entropy, no dependencies.
/// `split` draws `K-1` random field elements per secret byte from it.
///
/// Production callers wire their platform CSPRNG here; tests use a deterministic stub, which must NEVER be used for real splits.
pub trait Rng {
    /// Fill `out` with random bytes.
    fn fill(&mut self, out: &mut [u8]);
}

/// A person you trust, addressed by their TOKEN identity.
///
/// custodes never contacts them — it only records who a shard is *for*; Photon delivers it.
/// Their `pubkey` is a TOKEN pubkey, the same identity substrate the rest of the stack uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Custodian {
    /// The custodian's TOKEN handle.
    pub handle: String,
    /// The custodian's 32-byte TOKEN public key (a shard is sealed to this at the encryption seam).
    pub pubkey: [u8; 32],
}

impl Custodian {
    /// Name a custodian by handle and TOKEN pubkey.
    pub fn new(handle: impl Into<String>, pubkey: [u8; 32]) -> Self {
        Self { handle: handle.into(), pubkey }
    }
}

/// The user-set recovery policy: a threshold `K` and the `N` custodians it distributes to.
///
/// Built thru [`RecoveryPolicy::new`] so the `K ≤ N`, `K ≥ 1`, `N ≤ 255` invariants are checked once and then carried by the type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPolicy {
    threshold: u8,
    custodians: Vec<Custodian>,
}

impl RecoveryPolicy {
    /// Start building a policy.
    pub fn new() -> RecoveryPolicyBuilder {
        RecoveryPolicyBuilder::default()
    }
    /// The threshold `K`: how many custodians must cooperate.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
    /// The `N` custodians the secret is distributed to.
    pub fn custodians(&self) -> &[Custodian] {
        &self.custodians
    }
}

/// Builder for [`RecoveryPolicy`]; validates the threshold/custodian invariants in [`build`](Self::build).
#[derive(Default, Clone, Debug)]
pub struct RecoveryPolicyBuilder {
    threshold: Option<u8>,
    custodians: Vec<Custodian>,
}

impl RecoveryPolicyBuilder {
    /// Set the threshold `K` — how many of the `N` custodians must cooperate to reconstruct.
    pub fn threshold(mut self, k: u8) -> Self {
        self.threshold = Some(k);
        self
    }
    /// Replace the custodian list wholesale.
    pub fn custodians(mut self, custodians: Vec<Custodian>) -> Self {
        self.custodians = custodians;
        self
    }
    /// Append one custodian.
    pub fn custodian(mut self, custodian: Custodian) -> Self {
        self.custodians.push(custodian);
        self
    }
    /// Validate and finalize: `K ≥ 1`, at least one custodian, `K ≤ N`, `N ≤ 255`.
    pub fn build(self) -> Result<RecoveryPolicy> {
        let threshold = self.threshold.ok_or(Error::ThresholdUnset)?;
        if threshold == 0 {
            return Err(Error::ZeroThreshold);
        }
        let n = self.custodians.len();
        if n == 0 {
            return Err(Error::NoCustodians);
        }
        if n > 255 {
            return Err(Error::TooManyCustodians(n));
        }
        if threshold as usize > n {
            return Err(Error::ThresholdExceedsCustodians { k: threshold, n });
        }
        Ok(RecoveryPolicy { threshold, custodians: self.custodians })
    }
}

/// One Shamir share.
///
/// `index` is the x-coordinate (1..=N, never 0 — that is the secret's own coordinate); `body` holds one GF(2⁸) evaluation per secret byte; `threshold` is carried so [`reconstruct`] can refuse with too few shards rather than silently return garbage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shard {
    /// The Shamir x-coordinate of this share (1..=N).
    pub index: u8,
    threshold: u8,
    body: Vec<u8>,
}

impl Shard {
    /// The threshold `K` recorded at split time.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
    /// The secret length this shard reconstructs to (its body length).
    pub fn len(&self) -> usize {
        self.body.len()
    }
    /// Whether the shard's body is empty.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
    /// PENDING (TOKEN integration): seal this shard to a custodian's pubkey so Photon can deliver it, and so a tampered shard is rejected before [`reconstruct`].
    ///
    /// Binds to TOKEN's KEM plus an AEAD whose tag is the integrity check the bare math lacks.
    /// Not yet implemented — see the crate-level honesty note.
    pub fn encrypt_to(&self, _recipient_pubkey: &[u8; 32]) -> Vec<u8> {
        todo!("seal-to-pubkey binds to TOKEN's KEM + AEAD (integration phase)")
    }
}

/// Accumulates shards as custodians respond, deduped by index, until the policy threshold is met.
///
/// Pure bookkeeping: it does NO cryptographic verification — feed it already-verified, already-decrypted shards (the AEAD tag check is the encryption seam's job, not the collector's).
#[derive(Clone, Debug)]
pub struct ShardCollector {
    threshold: u8,
    shards: Vec<Shard>,
}

impl ShardCollector {
    /// A fresh collector targeting `policy`'s threshold.
    pub fn new(policy: &RecoveryPolicy) -> Self {
        Self { threshold: policy.threshold, shards: Vec::new() }
    }
    /// Add a shard; rejects index 0, duplicate indices, and shards whose body length disagrees with those already held.
    pub fn add(&mut self, shard: Shard) -> Result<()> {
        if shard.index == 0 {
            return Err(Error::ZeroShardIndex);
        }
        if let Some(first) = self.shards.first() {
            if first.body.len() != shard.body.len() || first.threshold != shard.threshold {
                return Err(Error::MismatchedShards);
            }
        }
        if self.shards.iter().any(|s| s.index == shard.index) {
            return Err(Error::DuplicateShardIndex(shard.index));
        }
        self.shards.push(shard);
        Ok(())
    }
    /// Whether enough distinct shards have arrived to reconstruct.
    pub fn threshold_met(&self) -> bool {
        self.shards.len() as u8 >= self.threshold
    }
    /// The shards collected so far, ready to hand to [`reconstruct`] once [`threshold_met`](Self::threshold_met).
    pub fn shards(&self) -> &[Shard] {
        &self.shards
    }
}

/// A request to reconstitute an identity on new hardware after total device loss.
///
/// Pure data — Photon delivers it to the custodians; the per-custodian `voca` phrase derived from it (see [`notify_custodians`]) is what they verify out of band.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRequest {
    /// The handle being recovered.
    pub handle: String,
    /// The fresh device's 32-byte TOKEN pubkey the identity will move to.
    pub new_device_pubkey: [u8; 32],
    /// When the request was raised, in eagle-time oscillations (vsf's clock).
    pub at: u64,
}

impl RecoveryRequest {
    /// Raise a recovery request for `handle`, targeting `new_device_pubkey`, stamped at eagle-time `at`.
    pub fn new(handle: impl Into<String>, new_device_pubkey: [u8; 32], at: u64) -> Self {
        Self { handle: handle.into(), new_device_pubkey, at }
    }
}

/// PENDING (voca integration): derive one human-readable verification phrase per custodian from the request content, fresh per request.
///
/// Binds to the `voca` wordlist crate; the phrase is what the custodian reads back to you over a channel an attacker cannot intercept — the out-of-band step that defeats a remote attacker who intercepted the TOKEN request but cannot phone your mother.
/// Not yet implemented.
pub fn notify_custodians(_request: &RecoveryRequest, _policy: &RecoveryPolicy) -> Vec<String> {
    todo!("voca-phrase derivation binds to the voca crate (integration phase)")
}

/// Split `secret` into one shard per custodian under `policy`'s threshold, drawing the polynomial's random coefficients from `rng`.
///
/// Each secret byte becomes an independent degree-`K-1` polynomial whose constant term is the byte; every custodian's shard records that polynomial evaluated at the custodian's x-coordinate.
/// Any `K` shards reconstruct via [`reconstruct`]; any `K-1` reveal nothing.
pub fn split(secret: &[u8], policy: &RecoveryPolicy, rng: &mut impl Rng) -> Result<Vec<Shard>> {
    if secret.is_empty() {
        return Err(Error::EmptySecret);
    }
    let k = policy.threshold;
    let n = policy.custodians.len();
    let mut shards: Vec<Shard> = (1..=n)
        .map(|x| Shard { index: x as u8, threshold: k, body: Vec::with_capacity(secret.len()) })
        .collect();
    let mut coeffs = vec![0u8; k as usize];
    for &byte in secret {
        coeffs[0] = byte;
        if k > 1 {
            rng.fill(&mut coeffs[1..]);
        }
        for shard in &mut shards {
            shard.body.push(gf_eval(&coeffs, shard.index));
        }
    }
    Ok(shards)
}

/// Reconstruct the secret from `shards` via Lagrange interpolation at x=0 over GF(2⁸).
///
/// Requires at least the recorded threshold of mutually consistent, distinct-indexed shards; uses the first `K` of them.
/// Returns [`Error::NotEnoughShards`] rather than silently producing garbage when too few are supplied — but note this is a usability guard, not integrity: a corrupted-but-well-formed shard still corrupts the output (see the crate honesty note).
pub fn reconstruct(shards: &[Shard]) -> Result<Vec<u8>> {
    let first = shards.first().ok_or(Error::NotEnoughShards { have: 0, need: 1 })?;
    let need = first.threshold;
    let len = first.body.len();
    for (i, s) in shards.iter().enumerate() {
        if s.index == 0 {
            return Err(Error::ZeroShardIndex);
        }
        if s.threshold != need || s.body.len() != len {
            return Err(Error::MismatchedShards);
        }
        if shards[..i].iter().any(|p| p.index == s.index) {
            return Err(Error::DuplicateShardIndex(s.index));
        }
    }
    if (shards.len() as u8) < need {
        return Err(Error::NotEnoughShards { have: shards.len(), need });
    }
    let used = &shards[..need as usize];
    let xs: Vec<u8> = used.iter().map(|s| s.index).collect();
    let mut secret = vec![0u8; len];
    for (pos, out) in secret.iter_mut().enumerate() {
        let mut acc = 0u8;
        for i in 0..used.len() {
            // Lagrange basis L_i(0) = ∏_{j≠i} (0 − x_j)/(x_i − x_j); in GF(2ⁿ), −v = v, so 0 − x_j = x_j and x_i − x_j = x_i ^ x_j.
            let xi = xs[i];
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, &xj) in xs.iter().enumerate() {
                if j != i {
                    num = gf_mul(num, xj);
                    den = gf_mul(den, xi ^ xj);
                }
            }
            let basis = gf_mul(num, gf_inv(den));
            acc ^= gf_mul(used[i].body[pos], basis);
        }
        *out = acc;
    }
    Ok(secret)
}

/// Multiply in GF(2⁸) modulo the AES reduction polynomial x⁸+x⁴+x³+x+1 (0x11b), via the carryless Russian-peasant loop.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b; // reduce by the low byte of 0x11b
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(2⁸): a⁻¹ = a²⁵⁴ (since a²⁵⁵ = 1 for a ≠ 0), by square-and-multiply. `gf_inv(0)` is 0 and is never called with 0 — x-coordinates are distinct and nonzero, so every `x_i ^ x_j` is nonzero.
fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u32;
    while exp > 0 {
        if exp & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Evaluate a polynomial (coefficients low-degree-first) at `x` in GF(2⁸) by Horner's method.
fn gf_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ c;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic counter "RNG" — TEST ONLY, never cryptographically secure.
    struct CountRng(u8);
    impl Rng for CountRng {
        fn fill(&mut self, out: &mut [u8]) {
            for b in out {
                self.0 = self.0.wrapping_add(0x53);
                *b = self.0;
            }
        }
    }

    fn policy(k: u8, n: usize) -> RecoveryPolicy {
        let custodians = (0..n)
            .map(|i| Custodian::new(format!("c{i}"), [i as u8; 32]))
            .collect();
        RecoveryPolicy::new().threshold(k).custodians(custodians).build().unwrap()
    }

    #[test]
    fn round_trip_any_k_of_n() {
        let secret = b"the identity recovery secret \x00\xff\x80 bytes";
        let pol = policy(3, 5);
        let mut rng = CountRng(0);
        let shards = split(secret, &pol, &mut rng).unwrap();
        assert_eq!(shards.len(), 5);
        // Every 3-of-5 subset reconstructs the original.
        for combo in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
            let subset: Vec<Shard> = combo.iter().map(|&i| shards[i].clone()).collect();
            assert_eq!(reconstruct(&subset).unwrap(), secret);
        }
    }

    #[test]
    fn below_threshold_is_refused_not_garbage() {
        let pol = policy(3, 5);
        let mut rng = CountRng(7);
        let shards = split(b"secret", &pol, &mut rng).unwrap();
        let two: Vec<Shard> = shards[..2].to_vec();
        assert_eq!(reconstruct(&two), Err(Error::NotEnoughShards { have: 2, need: 3 }));
    }

    #[test]
    fn threshold_one_is_trivial_share() {
        let pol = policy(1, 3);
        let mut rng = CountRng(1);
        let shards = split(b"x", &pol, &mut rng).unwrap();
        // K=1: any single shard reconstructs (no secrecy — valid but pointless).
        assert_eq!(reconstruct(&shards[1..2]).unwrap(), b"x");
    }

    #[test]
    fn collector_dedups_and_gates() {
        let pol = policy(2, 4);
        let mut rng = CountRng(9);
        let shards = split(b"hello", &pol, &mut rng).unwrap();
        let mut c = ShardCollector::new(&pol);
        c.add(shards[0].clone()).unwrap();
        assert!(!c.threshold_met());
        assert_eq!(c.add(shards[0].clone()), Err(Error::DuplicateShardIndex(shards[0].index)));
        c.add(shards[2].clone()).unwrap();
        assert!(c.threshold_met());
        assert_eq!(reconstruct(c.shards()).unwrap(), b"hello");
    }

    #[test]
    fn policy_invariants() {
        assert_eq!(RecoveryPolicy::new().custodians(vec![]).build().unwrap_err(), Error::ThresholdUnset);
        assert_eq!(RecoveryPolicy::new().threshold(0).custodian(Custodian::new("a", [0; 32])).build().unwrap_err(), Error::ZeroThreshold);
        assert_eq!(RecoveryPolicy::new().threshold(2).custodian(Custodian::new("a", [0; 32])).build().unwrap_err(), Error::ThresholdExceedsCustodians { k: 2, n: 1 });
    }
}
