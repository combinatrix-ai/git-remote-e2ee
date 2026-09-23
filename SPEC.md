# Protocol specification

> [!WARNING]
> This document specifies the experimental v4 format implemented by the current
> prototype. The format is incompatible with v2 and v3. There is no automatic
> migration; keep an independent plaintext copy and every device key.

## 1. Requirements

The protocol keeps Git semantics on trusted clients and reduces an untrusted
storage provider to immutable object storage plus one compare-and-swap pointer.

It is designed to satisfy all of the following:

1. Every user has a repository-specific device private key. Collaborators
   exchange public device records, not private keys.
2. Disclosing one content capability does not grant perpetual future access.
   Future leakage requires either compromise/disclosure of an active device
   private key or continued cooperation that releases each later generation
   key or plaintext.
3. A publication never rewrites or retransmits historical Git packs.
4. Pack ciphertext is stored once, independent of reader count. Only small key
   envelopes scale with the active-reader set.
5. A newly admitted reader receives full history by default.
6. Concurrent publications have exactly one visible winner.

The protocol provides confidentiality, authenticity, integrity, and continuity
from state pinned by the same client. It does not provide global freshness or
prevent an authorized reader from exporting plaintext.

## 2. Terminology

- **Inner repository**: the decrypted Git repository used locally.
- **Carrier**: an ordinary Git repository used to transport protocol objects.
- **Generation**: one successful `HEAD` publication. Every content push and
  every membership-only transition advances the generation exactly once.
- **Generation root key**, `K_t`: a fresh random 256-bit secret for generation
  `t`.
- **Generation envelope**: an HPKE encryption of `K_t` to one active reader.
- **Object subkey**: an HKDF-derived key used for one manifest body, pack, or
  predecessor-key link.
- **Predecessor link**: authenticated encryption of `K_(t-1)` under a dedicated
  subkey derived from `K_t`.
- **Policy**: the signed device registry and role assignment.
- **Manifest**: the signed generation transition, containing an encrypted body.
- **Repository root**: the stable identity derived from the genesis owner's
  Ed25519 and HPKE public keys.
- **Device ID**: a domain-separated digest of one device's two public keys.

## 3. Cryptographic construction

The v4 format uses:

- Ed25519 signatures;
- X25519/HKDF-SHA-256/ChaCha20-Poly1305 HPKE Base mode;
- HKDF-SHA-256 for object subkeys;
- XChaCha20-Poly1305 for manifest and predecessor-link encryption;
- XChaCha20-Poly1305 STREAM with a big-endian 32-bit counter for packs;
- SHA-256 for content IDs and generation-key commitments.

Every successful publisher samples `K_t` independently from the operating
system CSPRNG. Repository content, commit IDs, previous keys, timestamps, or a
forward KDF MUST NOT be used as the entropy source. In particular, a holder of
`K_(t-1)` must not be able to compute `K_t`.

The publisher derives distinct subkeys using an injective, fixed-width context:

```text
HKDF-SHA-256(
  input_key = K_t,
  salt = protocol-specific v4 domain,
  info = repository_root || generation_u64_le || kind_u8 || ordinal_u64_le
)
```

The defined kinds are `manifest-body`, `pack`, and `predecessor-link`. A key is
used for one logical message only. Manifest and predecessor-link envelopes each
carry a fresh random 24-byte nonce. Pack streams carry a fresh random 19-byte
nonce prefix; the STREAM counter and final-segment marker complete the nonce.
Associated data binds the v4 domain, repository root, generation, object kind,
ordinal or parent manifest ID as applicable, and the complete pack-stream
header.

The signed header contains the full, untruncated commitment:

```text
C_t = SHA-256("git-remote-e2ee generation key commitment v4" || K_t)
```

Commitments are compared in constant time before the corresponding key is used
for AEAD decryption. XChaCha20-Poly1305 itself is not treated as key-committing.

## 4. Backward key chain

For every `t > 0`, the manifest body contains:

```text
Enc(derive(K_t, predecessor-link), K_(t-1))
```

The encryption direction is normative. `K_t` opens `K_(t-1)`; `K_(t-1)` never
opens or derives `K_t`.

After decrypting a predecessor link, a client MUST compare the recovered key
against `C_(t-1)` in the parent manifest's signed header before using it. The
link AAD binds the repository root, current generation, and exact parent
manifest ID. A missing link, extra link, wrong parent, or commitment mismatch is
fatal.

Consequences:

- `K_t` is a transferable snapshot capability for all history through `t`.
- A disclosed `K_t` grants no access to `t+1`.
- Continued future leakage requires disclosure of each later key/plaintext or
  compromise of a device private key that remains an active recipient.
- A new reader given `K_t` can traverse to genesis and therefore always gets
  full history.
- Future-only onboarding is not supported by v4 because the predecessor link is
  available to every reader of the current generation.

## 5. Stored objects

All objects except `HEAD` are immutable and named by SHA-256 of their exact
stored bytes:

```text
objects/<hash>       encrypted incremental Git packs
manifests/<hash>     signed header plus inline encrypted delta body
policies/<hash>      signed plaintext device registry and roles
HEAD                 opaque newest-manifest ID
```

Private device keys and decrypted generation keys are never stored remotely or
in client continuity pins.

Policies and manifest headers are plaintext-structured to avoid a key-discovery
cycle. This intentionally exposes reader count, repository-specific public
keys, roles, policy changes, ciphertext size, and update timing. Inner refs,
Git object IDs, paths, authors, messages, pack contents, generation keys, and
predecessor-link plaintext remain encrypted.

## 6. Policy

A policy contains:

- format version, repository root, generation, and previous policy ID;
- administrator threshold and signature array;
- immutable historical device records with public keys, roles, and optional
  revocation generation.

Roles are:

- **reader**: receives generation-key envelopes;
- **writer**: signs ordinary manifests;
- **administrator**: signs direct child policies and policy-transition
  manifests.

Every active writer and administrator MUST also be an active reader because a
publisher needs the current generation key to construct the next predecessor
link. A policy must retain at least one active reader and administrator.

Genesis has exactly one active owner with all three roles and is self-signed.
Every child policy is signed by an administrator in its direct parent, never
solely by authority introduced in the child. v4 supports threshold 1 and one
signature; other thresholds fail closed. A future M-of-N format must count
distinct parent administrators under the parent's threshold.

## 7. Manifest

### 7.1 Signed plaintext header

The header binds at least:

- format version and repository root;
- generation and exact previous manifest ID;
- selected policy ID and policy generation;
- cumulative pack count;
- `C_t`;
- the complete, sorted generation-envelope list;
- signer device ID and transition type.

The Ed25519 signature covers the exact stored header bytes and the SHA-256
digest of the exact encrypted body bytes. Verifiers never sign or verify a
re-serialized interpretation.

The envelope for one recipient uses HPKE AAD that binds the repository root,
format, generation, policy ID, recipient device ID, and `C_t`. HPKE Base mode
does not authenticate the sender by itself; sender authenticity comes from the
manifest signature covering the complete envelope list.

Every verifier MUST compare the envelope device-ID set with the selected
policy's active-reader set. The relationship is bijective: no omissions,
extras, or duplicates. A recipient unwraps its envelope and checks `C_t` before
decrypting the body.

### 7.2 Encrypted delta body

The body contains:

- complete current inner refs;
- only pack descriptors introduced by this generation;
- exactly one predecessor-key link, except at genesis.

A pack descriptor contains ciphertext ID, plaintext size, creation generation,
and a dense generation-local ordinal beginning at zero. Its subkey and AAD bind
that generation and ordinal. Descriptor IDs must be unique within the delta and
plaintext size must be nonzero.

The manifest chain is the append-only pack inventory. Manifests do not repeat
historical descriptors, avoiding quadratic cumulative-inventory metadata.

### 7.3 Pack stream framing

Each pack is encoded as:

```text
"E2EEPK4\0" || chunk_size_u32_le || nonce_prefix_19 || segments...
```

`chunk_size` MUST equal 1,048,576 bytes. Every non-final plaintext segment is
exactly that size; the final segment is 1 through 1,048,576 bytes. Each stored
segment adds a 16-byte Poly1305 tag. The signed descriptor plaintext size
determines the exact segment count and ciphertext geometry. There must be at
least one and fewer than `2^32-1` segments.

The decoder MUST authenticate every segment, invoke the STREAM final operation
exactly once, consume the exact computed ciphertext length, reject trailing
bytes, and verify SHA-256 of the complete stored stream against the descriptor
ID. A malformed header, size mismatch, counter overflow, short read, reordered
or duplicated segment, authentication failure, trailing byte, or hash mismatch
is fatal. Plaintext may stream into `git index-pack` before the final object hash
is known, but no ref or continuity pin may move until all cryptographic,
content-address, process, and Git-connectivity checks succeed.

Immutable writes MUST be staged within the storage backend and become visible
under their ciphertext ID only after the complete streamed hash matches that
ID. A process killed before finalization can leave an unreachable `.stage-*`
artifact; an implementation may delete stale stages only when it can establish
that no live writer owns them. Stage cleanup never changes a published object
or `HEAD`.

### 7.4 Transition types

Every successor is exactly one of:

1. **Ordinary**: selected policy is unchanged; signer is an active writer in
   that policy; refs may change; zero or more new pack deltas may be added.
2. **Policy transition**: selected policy is the direct authorized child of the
   parent's policy; signer is an administrator in the parent policy; refs and
   cumulative pack count are unchanged; the delta contains no packs.
3. **Checkpoint**: reserved for future compaction and garbage collection.
   Current implementations MUST reject it as unsupported.

For every successor:

- generation equals parent generation plus one;
- `previous` equals the parent's content-addressed manifest ID;
- cumulative pack count equals parent count plus delta length;
- policy never moves backward or sideways;
- the predecessor link recovers the key committed by the parent header.

Genesis is generation 0, uses the defined null previous value, selects the
genesis policy, contains empty refs and no packs, and has no predecessor link.

## 8. Repository lifecycle

### 8.1 Normal content publication

1. Fetch and validate the current manifest/policy chain to the local pin or
   genesis.
2. Enforce Git fast-forward rules locally unless force was explicit.
3. Create only the incremental Git pack needed for the update.
4. Sample `K_t`, derive the pack and body subkeys, and encrypt the new data.
5. Encrypt the previous generation key under the predecessor-link subkey.
6. HPKE-wrap `K_t` once to every active reader.
7. Upload the immutable pack and manifest.
8. Compare-and-swap `HEAD` from the observed parent ID to the new manifest ID.

### 8.2 Add a device

The new device sends only its repository-specific public record to an
administrator. The administrator creates a child policy and a membership-only
generation whose envelopes include the new active reader. No historical pack
or manifest is rewritten. The new device unwraps the newest generation key and
walks the predecessor chain for full history.

### 8.3 Revoke a device

Revocation immediately publishes a membership-only generation selecting a
child policy without the device. The revoked device retains plaintext and keys
through the parent generation but receives no envelope for the child key and
cannot derive it from the parent key. Historical objects are unchanged.

The departing administrator necessarily knows the child key it publishes. A
revocation racing another valid push has an inherent race window: a losing CAS
candidate can contain content encrypted to the pre-revocation reader set. It is
unreachable from `HEAD` but not confidentiality-inert if storage colludes with
that reader. Garbage collection should remove losing candidates when safe.

### 8.4 Rotate a device key

Rotation is one administrative transition that adds the replacement device and
revokes the old record. Other users keep their device private keys. No pack is
rewritten.

## 9. Delta traversal and Git connectivity

A fresh clone traverses manifest and key links from `HEAD` to genesis,
validates each hop, collects pack deltas, decrypts packs with their creation
generation keys, and imports them oldest-first.

A returning client traverses from `HEAD` to its pinned manifest, validates each
new hop, and imports only unseen pack IDs. Imported pack IDs are local cache
state, not an authorization source.

After importing the required deltas, the client MUST verify that every current
ref resolves to a complete local Git object graph before moving remote-tracking
refs, pinning the new head, or publishing a successor. A signed ref advance
whose required pack delta is absent is invalid even when every cryptographic
check succeeds.

Force pushes append a normal pack delta and new ref state. Older packs remain
in historical manifests and may become unreachable in the inner Git graph.

## 10. Concurrency

The server does not inspect encrypted inner commit parents. Two writers read
the same opaque `HEAD`, create immutable candidates, and attempt the same CAS.
Exactly one wins.

- Filesystem storage uses locking. `HEAD` is published by rename inside the
  storage root. Immutable objects are hard-linked from `.staging` into
  `objects/<prefix>/` on the same filesystem and are not replaced. New
  directories and the parent of a published name are flushed; a flush error
  fails the operation. Limits are in `docs/durability.md`.
- Carrier Git uses a normal fast-forward push of
  `refs/heads/git-remote-e2ee`; receive-pack ref update is the CAS.

The losing client fetches/decrypts the winner and uses the inner Git DAG to
decide whether to retry, merge, or rebase. Administrative CAS failures are
never automatically rebased; authorization and membership must be reevaluated.
Unreachable losing objects require later GC.

## 11. Continuity and invitations

Returning clients pin at least repository root, manifest ID and generation,
and policy ID and generation. They reject rollback, a non-descendant manifest,
policy rollback/sideways movement, root substitution, and generation gaps.

A fresh device should receive an administrator-authorized invitation checkpoint
through an authenticated channel containing:

```text
repository_root
minimum_manifest_id
minimum_manifest_generation
minimum_policy_id
minimum_policy_generation
recipient_device_id
signing_administrator_device_id
signature
```

The repository root delivered through that channel is the bootstrap trust
anchor. The signature provides authorization and accountability. Storage alone
cannot prevent freeze, present different valid forks to isolated clients, or
prove global freshness; gossip or transparency anchoring is a separate layer.

## 12. Cost model

Let `N` be active readers, `G` one small HPKE envelope, and `S` newly encrypted
pack bytes.

| Operation | Upload delta | Remote storage delta |
| --- | ---: | ---: |
| Content push | `S + N*G + O(1)` | `S + N*G + O(1)` |
| Add/revoke/rotate | `N*G + O(1)` | `N*G + O(1)` |

Large-content storage is `sum(pack ciphertext sizes)`, independent of `N`.
Envelope metadata is still linear in readers per generation and accumulates as
approximately `O(generations * readers * G)`. Fresh clone work is linear in
manifest generations until checkpoint compaction exists.

## 13. Security limits

- An authorized reader can export plaintext or the current snapshot key.
- Disclosure of `K_t` exposes all repository history through `t`, not only one
  pack. It exposes no later generation.
- Compromise of an active device private key is stronger: the attacker can
  unwrap later generation keys while the device remains active.
- Old immutable headers retain envelopes. Later device-key compromise can
  retroactively expose every generation addressed to that device. v4 has no
  forward secrecy for stored history.
- Full-history onboarding is mandatory; future-only access requires a new
  format or an explicit compartment.
- Storage observes sizes, timing, generation count, reader count, public keys,
  roles, and membership changes.
- Storage can delete, freeze, or deny service.
- Writers can author destructive Git history; force remains explicit.
- Global rollback/equivocation detection requires an external anchor.

## 14. Migration and future work

v4 is intentionally wire-incompatible with v2 and v3. Migration must occur on
a trusted client able to decrypt the older repository and republish under a new
v4 repository boundary. Automatic migration is not implemented. The local key
file remains format 3 because its stable repository/device identity material did
not change; manifest, policy, signature, KDF, HPKE, and AEAD domains changed and
therefore fail closed across wire versions.

Planned extensions:

1. checkpoint/compaction and garbage collection with explicit authority;
2. M-of-N administrator authorization and recovery;
3. automatic stale-push retry with explicit merge behavior;
4. persistent partial-clone carrier cache;
5. S3 backend with conditional-write compatibility tests;
6. optional gossip or transparency-log anchoring.
