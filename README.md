# custodes

**Lose all your devices? Call a custodian.**

*Quis custodiet ipsos custodes?* Each other. Any K of N must cooperate before
your identity reconstitutes. No single custodian can act alone. No central
authority holds pieces. No corporation gets asked.

The TOKEN social recovery layer: Shamir secret sharing across user-designated
human guardians, threshold-gated, zero-knowledge, no plaintext ever leaves
the user's device.

---

## What a custodian is

A person you trust. Mom. Spouse. Oldest friend. Colleague.

They don't need to understand cryptography. They hold an encrypted shard —
a VSF blob stored in their Photon vault, keyed to their TOKEN identity. They
cannot read it. They cannot use it alone. If K of your N custodians cooperate,
your identity can be reconstructed on new hardware. That's it.

The shard content is opaque to them because the underlying secret is already
encrypted. Custodians cannot collude usefully below threshold. Above threshold
they cooperate deliberately — because you asked them to.

---

## The recovery model

```
Normal:         single device → tap new device → existing device attests
                new device added, old device remains, no recovery needed

Partial loss:   some devices lost, one remains → tap new device
                same as normal, custodes not involved

Total loss:     all devices gone → no existing device to attest from
                → invoke custodes
```

Total loss invokes the social graph. You obtain new hardware, claim your handle,
and request recovery. Your custodians are notified. Each is shown a voca
verification phrase — human-readable, unambiguous, generated fresh per request.
They verify out of band (phone call, in person — however you trust), confirm
the phrase, and release their shard. Once K shards arrive, Lagrange interpolation
reconstructs the secret. Your identity moves to the new device.

The out-of-band step is not a weakness. It is the point. Humans verify humans.
The math handles the rest.

---

## Recovery policy

The user sets it. The system enforces it. No defaults that create hidden
dependencies on any party.

```rust
let policy = RecoveryPolicy::new()
    .threshold(3)                    // any 3 of N must cooperate
    .custodians(vec![
        Custodian::new(brittany_handle, brittany_pubkey),
        Custodian::new(mom_handle,      mom_pubkey),
        Custodian::new(sibling_handle,  sibling_pubkey),
        Custodian::new(friend_handle,   friend_pubkey),
        Custodian::new(colleague_handle, colleague_pubkey),
    ])
    .build()?;
```

N is how many people you distribute to. K is how many must respond.
Choose based on your threat model. Higher K: harder for attackers to collude.
Lower K: easier to recover if some custodians become unreachable.
~5-of-40 is a reasonable default for most people's social graph depth.

---

## API shape

```rust
// Split — on a working device, distribute shards to custodians
let shards = custodes::split(&identity_secret, &policy, &mut rng)?; // rng: caller's CSPRNG — the crate stays pure (no OS entropy, no deps)
for (custodian, shard) in policy.custodians().zip(shards) {
    photon::send(&custodian.handle, shard.encrypt_to(&custodian.pubkey))?;
}

// Request — on new hardware, after total loss
let request = RecoveryRequest::new(handle, new_device_pubkey, eagle_time::now());
let phrases = custodes::notify_custodians(&request, &policy)?;
// phrases: voca-encoded, one per custodian, for out-of-band verification

// Collect — as custodians respond
let mut collector = ShardCollector::new(&policy);
for response in incoming_responses {
    collector.add(response.verify_and_decrypt(&new_device_key)?)?;
    if collector.threshold_met() { break; }
}

// Reconstruct
let recovered_secret = custodes::reconstruct(collector.shards())?;
// → identity reconstitutes on new hardware
```

---

## What custodes does not do

- Does not store shards. Distribution is Photon's job.
- Does not transmit anything. Network is Photon's job.
- Does not manage device attestation. That's TOKEN's bootstrap.
- Does not know what the secret is. It's a bytestring. Semantics are above.
- Does not require custodians to be online simultaneously. Shards collect
  asynchronously until threshold is met.

---

## Relationship to TOKEN

custodes is the recovery layer TOKEN calls when normal device attestation
is impossible. TOKEN handles everything above: handle namespace, device
binding, ihi derivation, billing attestation. custodes handles exactly
one thing: what happens when every device is gone.

Custodians are themselves TOKEN identities. Their pubkeys are TOKEN pubkeys.
Shard delivery is a Photon message. The machinery composes because it's all
the same identity substrate.

---

## Verification codes

Recovery requests generate voca phrases — human-readable, wordlist-derived,
unambiguous. One phrase per custodian, fresh per request, derived from the
request content. The custodian reads it to you over the phone. You confirm
it matches what the UI shows. This step defeats remote attackers who could
intercept the TOKEN recovery request but cannot intercept a phone call to
your mother.

See `voca` crate for wordlist encoding.

---

## Status

Core implemented and tested: Shamir split/reconstruct over GF(2⁸) (Lagrange at x=0), the policy / custodian / shard value types, and async shard collection (`ShardCollector`).

Two integration seams are stubbed (`todo!`) until the TOKEN/voca phase: per-custodian encryption (`Shard::encrypt_to`, binds TOKEN's KEM + an AEAD) and the out-of-band verification phrases (`notify_custodians`, binds the `voca` crate).

Honesty note in the crate docs: the GF(2⁸) arithmetic is textbook-correct but not yet constant-time, and `reconstruct` has no integrity check of its own — a corrupted shard corrupts the output until the AEAD tag at the encryption seam rejects it. Both are deliberate, documented, and gated on integration.

## License

MIT OR Apache-2.0, at your option.