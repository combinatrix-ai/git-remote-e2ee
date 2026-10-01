# Design

This document summarizes the implemented v5 architecture. [`spec.md`](spec.md)
defines the protocol invariants and security claims in detail.

## Goal

Provide ordinary Git synchronization while an untrusted storage provider cannot
read the inner repository contents, refs, commit IDs, paths, authors, or
messages. Users keep independent device private keys. A one-time leaked content
key reveals a bounded repository snapshot, not perpetual future updates.

## Generation key regression

Every successful `HEAD` publication samples a fresh random generation root key
`K_t`. The manifest header HPKE-wraps that key once to every active reader. The
manifest body and packs created in that generation use distinct HKDF-derived
subkeys.

For `t > 0`, the encrypted body contains a backward link:

```text
K_t --authenticated encryption--> K_(t-1)
```

The recovered predecessor key must match the commitment in the parent
manifest's signed header. A current reader can walk to genesis; a revoked
reader holding `K_(t-1)` cannot derive `K_t`.

This deliberately makes `K_t` a snapshot capability for all history through
generation `t`. Future access still requires a later generation key or the
private key of a device that remains active.

## Immutable object model

```text
objects/<ciphertext hash>      encrypted incremental Git pack
manifests/<object hash>        plaintext discovery header + encrypted sealed header and body
HEAD                           opaque newest-manifest pointer
```

Only `HEAD` is mutable. Updating it requires compare-and-swap against the exact
value observed by the publisher.

The manifest body contains complete current refs, only packs introduced by its
generation, the predecessor-key link, and the complete signed policy when that
manifest introduces one. Historical pack descriptors are not copied into
every new manifest. The signed manifest chain is the append-only pack delta
log; there are no separate `policies/` objects.

## Cryptography

- Ed25519 exact-byte signatures
- X25519/HKDF-SHA-256/ChaCha20-Poly1305 HPKE generation-key envelopes
- HKDF-SHA-256 domain-separated object subkeys
- XChaCha20-Poly1305 authenticated encryption, using the STREAM construction
  for Git packs
- SHA-256 content IDs and generation-key commitments

The plaintext header contains only format version, repository root, generation,
previous manifest ID, generation-key commitment, anonymous padded envelopes,
and the digests of the encrypted body and sealed-header content. The
K_t-encrypted sealed header contains policy ID and generation, signer device
ID, transition type, cumulative pack count, envelope audit, and Ed25519
signature. The signature covers the exact plaintext header bytes, the sealed
header content without the signature, and the encrypted body digest.

Each envelope hides its recipient ID. Publishers pad the envelope list to the
next power of two with a minimum of four, sort by encapsulated-key bytes, and
make each dummy a genuine HPKE seal of a random key to a throwaway X25519
recipient, so its encapsulated key is a real curve point. A device trial
decrypts only the head list; predecessor links provide older keys. Every
verifier uses each audited seed with `rand_chacha` 0.9.0 `ChaCha20Rng` to
re-seal K_t and check byte equality, then requires exactly one real envelope
for each active reader in the encrypted policy.

Subkey contexts use the repository root, fixed-width generation, object kind,
and dense generation-local ordinal. Pack AAD binds the same identity. Keys are
zeroized on drop where practical and never written to continuity state.

## Policy and roles

Each repository has per-device Ed25519 signing and HPKE recipient keys. Policy
roles are independent, with two liveness constraints:

- a writer must also be a reader;
- an administrator must also be a reader.

Readers receive generation envelopes. Writers sign ordinary manifest updates.
Administrators sign direct child policies and policy-transition manifests.
The signed policy bytes travel only in the encrypted body of the manifest that
introduces them. Later manifests name the current policy in their sealed header.

The repository root is derived from the genesis owner's two public keys.
Genesis contains exactly that active owner with reader, writer, and
administrator roles and is self-signed. Child policies are authorized by an
administrator in the parent policy.

The format retains an administrator threshold and signature array, but v5
accepts threshold 1 and one signature only. Unsupported thresholds fail closed.

## Device operations

- **Add:** create a child policy and a membership-only generation whose fresh
  key is wrapped to the new active-reader set. The new reader walks backward for
  full history. No historical object changes.
- **Revoke:** create a child policy and immediately publish a fresh generation
  excluding the device. The device keeps the parent snapshot but cannot derive
  the child key. No historical object changes.
- **Rotate:** add a replacement identity and revoke the old one in one policy
  transition.

Administrative changes contain no Git pack delta and preserve refs. A lost
administrative CAS is never automatically rebased.

## Git semantics

- New data is generated with `git pack-objects --stdout --revs`.
- Pack output is encrypted as 1 MiB authenticated segments directly into a
  backend-owned stage; it is never collected into a whole-pack Rust buffer.
- Existing remote tips present locally are pack exclusions.
- Packs are decrypted segment by segment directly into `git index-pack`
  oldest-first.
- After import, every advertised ref must resolve to a complete local Git
  object graph before pins or remote-tracking refs move.
- Client-side `git merge-base --is-ancestor` enforces fast-forward updates.
- Explicit force pushes append a normal encrypted delta.
- Push destinations are limited to `refs/heads/*`; tags and deletion fail
  before publication.

A fresh clone traverses the manifest/key chain to genesis. A returning client
traverses to its pinned manifest and imports only unseen pack IDs. The client
pin records IDs and generations, never decryption keys.

## Storage contract

The backend-neutral trait uses staged immutable writes:

```text
begin_object(kind) -> writable stage; stage.finish(id)
open_object(kind, id) -> reader
read_head()
compare_and_swap_head(expected, next)
```

The ciphertext digest is computed during the write. `finish(id)` validates the
digest and publishes the staged object by hard-linking it from `.staging` into
`objects/<prefix>/`. Those are different directories on the same filesystem.
An existing object id is not replaced. Filesystem storage serializes CAS with
an advisory lock and publishes `HEAD` by renaming a temporary file in the
storage root. File contents are flushed before the name is published. A
directory created for that publication is flushed through the preexisting
ancestor, and the parent directory is flushed again after the new name is
published. A flush error fails the call. Immutable objects are durable before
the pointer moves, within the limits in [`durability.md`](durability.md).
Abandoned `.stage-*` files are unreachable; automatic cleanup is deferred to
future GC.
Manifest objects still use bounded buffered parsing with a 16 MiB hard limit;
large pack objects always use the streaming path. Policy bytes are parsed from
the decrypted manifest body and are not separate storage objects.

An S3 backend can use create-if-absent immutable writes and a conditional HEAD
write, but requires a provider capability test; the label "S3 compatible" does
not guarantee correct compare-and-swap behavior.

## Carrier Git mapping

The carrier backend maps protocol objects to normal blobs under `e2ee/`, split
into a dense canonical sequence of 32 MiB chunks, on the dedicated branch
`refs/heads/git-remote-e2ee`. Each protocol publication creates an outer commit.
A normal fast-forward push is the CAS: two candidates from the same parent
cannot both win.

The host sees outer commit timing, chunk sizes/counts, update frequency, padded
reader count, and total growth. Public keys, device IDs, roles, signer identity,
and membership changes are encrypted; object-size patterns can still suggest
that a membership transition occurred. Inner Git metadata remains encrypted.

Each helper process fetches the carrier branch into a persistent bare object
cache, then creates a disposable checkout that borrows the cache's objects.
Fetches transfer only objects missing from the cache. The cache is keyed by the
SHA-256 of a normalized remote URL; a file lock serializes updates across helper
processes, and automatic garbage collection is disabled so borrowed objects
remain available. The carrier branch is fetched again immediately before each
CAS, and the CAS remains a normal fast-forward push. A stale cache therefore
cannot authorize a write against an outdated branch tip.

Recovery publishes a fresh cache generation instead of replacing objects that
an in-flight temporary checkout may still borrow. Obsolete generations are
retained so those checkouts remain valid; repeated cache corruption can therefore
consume additional local disk space.

The cache contains carrier Git objects and metadata only. It never stores keys,
plaintext, or decrypted repository data. Its default location and the
`GIT_REMOTE_E2EE_CACHE_DIR` override are documented in the [user guide](guide.md#git-host-as-storage-carrier-git-backend).

## Concurrency

Race detection uses the opaque outer `HEAD`, not encrypted inner commit
parents. A losing writer fetches and decrypts the winner, then uses the inner
Git DAG to decide whether to retry, merge, or rebase.

Losing candidates can leave unreachable ciphertext. They are integrity-inert
but not always confidentiality-inert: a push racing revocation can have valid
envelopes to the old reader set. This is part of the revocation race window and
motivates future garbage collection.

## Continuity and limits

Returning clients pin repository root, manifest ID/generation, and policy
generation. They reject rollback, non-descendant state, policy rollback, and
root substitution.

Storage alone still cannot prevent:

- a fresh client receiving an old valid chain without an invitation checkpoint;
- different valid forks shown to isolated clients;
- freeze, deletion, or denial of service;
- destructive history authored by an authorized writer;
- plaintext or snapshot-key export by an authorized reader.

Old manifest headers retain device envelopes. Later compromise of a device
private key can retroactively expose every generation addressed to that device.
There is no forward secrecy for stored history.

## Anonymous recipients (v5)

v4 let storage see each device's per-repository public keys, its roles, and
every membership change. The reason was structural: envelopes carried a
recipient device ID so a device could find its own, and verifiers compared
that ID set with a plaintext policy. v5 removes that exposure so storage learns
only the padded reader count, the same class of leak as `gpg --throw-keyids` in
git-remote-gcrypt.

### What changes

1. **Anonymous, padded envelopes.** The plaintext header carries a list of
   HPKE envelopes with no recipient ID. The list is padded with dummy
   envelopes to the next power of two, with a minimum of four. A dummy is a
   genuine HPKE seal of a random key to a throwaway X25519 recipient, so it is
   indistinguishable from a real envelope without the recipient private key.
   Uniformly random bytes would not do: a real encapsulated key is an X25519
   public key whose top bit is always clear.
   The list is sorted by encapsulated-key bytes, so position carries no
   identity across generations. The HPKE AAD still binds the repository root,
   format, generation, `C_t`, and the recipient's device ID. The recipient
   knows its own ID, and the AAD is not transmitted.
2. **Trial decryption, once per fetch.** A device tries its HPKE key against
   each envelope of the newest manifest until one opens and the result matches
   `C_t`. Older generation keys come from the backward link chain as in v4, so
   only the head generation costs trial decryption: O(padded reader count)
   X25519 operations per fetch, not per generation. The list length is capped
   (4096) to bound work on malicious input. If nothing opens, the client
   reports that this device is not an active reader of the current generation:
   it was revoked, was never added, or its envelope is malformed.
3. **Sealed header.** Everything that identifies devices stays out of the
   plaintext header and inside a sealed header, encrypted under a `K_t`-derived
   subkey: policy ID and policy generation, signer device ID, transition type,
   cumulative pack count, the envelope audit (item 5), and the Ed25519
   signature. The signature covers the plaintext header bytes, the sealed
   header content without the signature, and the encrypted body digest. The
   plaintext header keeps only the format version, repository root,
   generation, previous manifest ID, `C_t`, the envelope list, and the digests
   needed to locate and authenticate the sealed parts.
4. **Policy inside the transition manifest.** v5 removes the separate
   plaintext `policies/` objects. A policy travels inside the encrypted body of
   the manifest that introduces it: genesis, device add, revoke, or rotate.
   Later manifests reference it by policy ID inside their sealed header, and
   readers reach it through the backward key chain. Storage can no longer tell
   a membership change from a content push, except by size.
5. **Envelope audit.** Without visible recipient IDs, verifiers cannot compare
   an envelope ID set with the active-reader set, so a malicious writer could
   corrupt one reader's envelope unnoticed by everyone else. The sealed header
   therefore records, for each envelope, either the recipient device ID and a
   fresh 32-byte seed that initializes the HPKE encapsulation RNG, or a dummy marker. After
   opening its own envelope, every verifier deterministically re-seals `K_t`
   for each real entry with that seed and the recipient's public key from the
   policy. It requires byte equality with the stored envelope and exactly one
   envelope per active reader. Dummy entries only need to be absent from the
   reader mapping. A seed reveals only the shared secret for that envelope,
   which yields `K_t`, and every verifier already holds `K_t`. The seed is
   never reused.

### What storage still learns

The padded envelope count (an upper bound on active readers), object sizes,
upload timing, generation count, total growth, and the opaque repository root.
Device public keys and IDs, roles, signer identity, and membership data are
encrypted, though size patterns can still suggest a transition.

### Costs and limits

- Format break: v5 does not read v4 repositories and ships no migration, which
  is acceptable for a prototype.
- For four or more active readers, padding adds fewer than 2x envelope metadata;
  one to three readers use the four-entry minimum.
- A device that cannot open any envelope cannot tell revocation from
  corruption. Continuity pins still reject rollback for returning clients.
- A reader can still see the complete policy after decryption, exactly as in
  v4.
- The revocation race window, retroactive exposure on device-key compromise,
  and the absence of forward secrecy are unchanged.

## Cost model

For new encrypted pack bytes `S`, padded reader count `P`, and a small envelope
`G`:

```text
content push delta       S + P*G + O(1)
membership change       P*G + O(policy size)
large content storage   sum(pack ciphertext sizes), independent of N
```

Envelope metadata remains linear in padded readers per generation. A policy
transition also carries the signed policy history in its encrypted body. Fresh
clone time is linear in generations until checkpoint compaction exists. The v5
wire format reserves a checkpoint transition, but current clients reject it as
unimplemented.
