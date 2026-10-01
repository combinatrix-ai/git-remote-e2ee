# Protocol specification

> [!WARNING]
> This document specifies the experimental v5 format implemented by the current
> prototype. The format is incompatible with v2, v3, and v4. There is no
> automatic migration; keep an independent plaintext copy and every device key.

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
   envelopes scale with the padded reader count; a policy transition also
   carries its encrypted policy body.
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
- **Sealed header**: Kₜ-encrypted manifest metadata, including policy selection,
  signer, transition type, pack count, envelope audit, and signature.
- **Padded reader count**: the number of envelopes after padding to the next
  power of two, with a minimum of four.
- **Repository root**: the stable identity derived from the genesis owner's
  Ed25519 and HPKE public keys.
- **Device ID**: a domain-separated digest of one device's two public keys.

## 3. Cryptographic construction

The v5 format uses:

- Ed25519 signatures;
- X25519/HKDF-SHA-256/ChaCha20-Poly1305 HPKE Base mode;
- HKDF-SHA-256 for object subkeys, including a distinct sealed-header subkey;
- XChaCha20-Poly1305 for manifest and predecessor-link encryption;
- XChaCha20-Poly1305 STREAM with a big-endian 32-bit counter for packs;
- SHA-256 for content IDs and generation-key commitments.

The v5 domain strings are `git-remote-e2ee subkey derivation v5\0`,
`git-remote-e2ee generation key commitment v5\0`,
`git-remote-e2ee manifest v5\0`, and `git-remote-e2ee policy v5\0`.
`sign_domain` signs `domain || SHA-256(exact_bytes)` with Ed25519. Symmetric
XChaCha20-Poly1305 envelopes are encoded as
`E2EES05\0 || nonce_24 || ciphertext`. Subkey kind values are
`manifest-body=1`, `pack=2`, `predecessor-link=3`, and `sealed-header=4`.

Every successful publisher samples `K_t` independently from the operating
system CSPRNG. Repository content, commit IDs, previous keys, timestamps, or a
forward KDF MUST NOT be used as the entropy source. In particular, a holder of
`K_(t-1)` must not be able to compute `K_t`.

The publisher derives distinct subkeys using an injective, fixed-width context:

```text
HKDF-SHA-256(
  input_key = K_t,
  salt = protocol-specific v5 domain,
  info = repository_root || generation_u64_le || kind_u8 || ordinal_u64_le
)
```

The defined kinds are `manifest-body`, `pack`, `predecessor-link`, and
`sealed-header`. A key is used for one logical message only. Manifest,
predecessor-link, and sealed-header envelopes each carry a fresh random 24-byte
nonce. Pack streams carry a fresh random 19-byte nonce prefix; the STREAM
counter and final-segment marker complete the nonce. Associated data binds the
v5 domain, repository root, generation, object kind, ordinal or parent manifest
ID as applicable, and the complete pack-stream header. Sealed-header AAD is the
exact plaintext header bytes.

The signed manifest header contains the full, untruncated commitment:

```text
C_t = SHA-256("git-remote-e2ee generation key commitment v5\0" || K_t)
```

Generation envelopes use HPKE Base mode with info
`git-remote-e2ee generation key v5`. Their AAD binds the repository root,
format version, generation, `C_t`, and recipient device ID. The recipient ID
and AAD are not transmitted. AAD encoding is the v5 envelope domain string,
then a little-endian `u32` length and bytes for repository root, format version
as little-endian `u32`, generation as little-endian `u64`, then a length and
bytes for the ASCII `C_t` and ASCII recipient device ID. Each real envelope uses an independent random
32-byte seed to initialize `rand_chacha` 0.9.0 `ChaCha20Rng`; this seeded RNG is
passed to HPKE 0.13 `single_shot_seal`. The seed is recorded only in the sealed
header audit. Commitments are compared in constant time before the corresponding
key is used for AEAD decryption. XChaCha20-Poly1305 itself is not treated as
key-committing.

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
- Future-only onboarding is not supported by v5 because the predecessor link is
  available to every reader of the current generation.

## 5. Stored objects

All objects except `HEAD` are immutable and named by SHA-256 of their exact
stored bytes:

```text
objects/<hash>       encrypted incremental Git packs
manifests/<hash>     plaintext discovery header plus encrypted sealed header and body
HEAD                 opaque newest-manifest ID
```

Private device keys and decrypted generation keys are never stored remotely or
in client continuity pins. A policy is included in the encrypted body of the
manifest that introduces it; there are no separate `policies/` objects.

The plaintext manifest header contains only format version, repository root,
generation, previous manifest ID, `C_t`, the anonymous padded envelope list, and
digests for the encrypted body and sealed-header content. Policy data, device
public keys and IDs, roles, signer, authorization type, pack count, audit, and
signature are encrypted. Inner refs, Git object IDs, paths, authors, messages,
pack contents, generation keys, and predecessor-link plaintext remain
encrypted.

## 6. Policy

A policy contains:

- format version 5, repository root, generation, and previous policy ID;
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
link. A policy must retain at least one active reader and administrator. The
complete signed policy bytes are carried inside the encrypted manifest body
that introduces them: genesis and each add, revoke, or rotate transition.
Ordinary manifests do not repeat the policy; their sealed header names its
policy ID and generation.

Genesis has exactly one active owner with all three roles and is self-signed.
Every child policy is signed by an administrator in its direct parent, never
solely by authority introduced in the child. v5 supports threshold 1 and one
signature; other thresholds fail closed. A future M-of-N format must count
distinct parent administrators under the parent's threshold.

## 7. Manifest

### 7.1 Plaintext and sealed headers

The plaintext header contains only:

- format version 5, repository root, generation, and exact previous manifest
  ID;
- `C_t`;
- the generation-envelope list, with no recipient IDs;
- the SHA-256 digest of the encrypted body;
- the SHA-256 digest of the sealed-header content without its signature.

The envelope list length MUST be a power of two from 4 through 4096. Publishers
wrap `K_t` once for each active reader, add indistinguishable dummy entries
(each a genuine HPKE Base-mode seal of a fresh random 32-byte key, under a
random AAD, to a freshly generated throwaway X25519 recipient; uniformly random
bytes MUST NOT be used because a real encapsulated key is an X25519 public key
with its top bit clear) until the list
reaches the next power of two, with a minimum of four, then sort by raw
encapsulated-key bytes. Encapsulated keys and ciphertexts MUST have their
protocol-defined lengths. Duplicate or non-increasing encapsulated keys are
invalid. If padding would exceed 4096 entries, publication fails.

A reader tries its private key against each envelope in the current head until
HPKE opens a 32-byte key matching `C_t`. This is the only trial-decryption pass;
older keys come from predecessor links. If no envelope opens to a key matching
`C_t`, the client MUST report that it is not an active reader of the current
generation, which may mean revoked, never added, or a malformed envelope.

The sealed header is encrypted under a `K_t`-derived `sealed-header` subkey.
Its content contains policy ID and generation, signer device ID, transition
type, cumulative pack count, and one audit entry per envelope. The entry is
either `(recipient device ID, 32-byte encapsulation seed)` or a dummy marker.
The sealed header also contains the Ed25519 signature. Every real entry's seed
MUST be sampled freshly from the operating system CSPRNG and MUST NOT be reused.
Audit entries correspond position-for-position to the sorted envelope list.

The signature covers the exact plaintext header bytes, the exact sealed-header
content bytes without the signature, and the encrypted body digest. The signed
encoding length-prefixes each value. The encrypted body digest and sealed
content digest MUST match their exact bytes. Verifiers MUST NOT verify a
re-serialized interpretation.

After opening its own envelope, every verifier MUST validate the complete
sealed audit. For each real entry it initializes `rand_chacha` 0.9.0
`ChaCha20Rng` from the 32-byte seed, deterministically seals `K_t` to that
device's HPKE public key using the v5 envelope AAD, and requires byte equality
with the corresponding stored envelope. Real audit device IDs MUST equal the
policy's active-reader set exactly: no missing, duplicate, extra, or revoked
readers. Dummy entries MUST have no reader mapping. HPKE Base mode does not
authenticate the sender itself; signer authorization and the signature provide
that property.

### 7.2 Encrypted delta body

The body contains:

- complete current inner refs;
- only pack descriptors introduced by this generation;
- exactly one predecessor-key link, except at genesis;
- the complete signed policy bytes when this manifest introduces a policy.

Genesis and policy-transition manifests MUST contain exactly one introduced
policy. Ordinary writer manifests MUST contain none. The policy ID in the
sealed header is SHA-256 of the exact policy object bytes. Verifiers MUST check
that the introduced policy matches this ID and validate its signature and
direct-parent relationship before accepting the manifest.

A pack descriptor contains ciphertext ID, plaintext size, creation generation,
and a dense generation-local ordinal beginning at zero. Its subkey and AAD bind
that generation and ordinal. Descriptor IDs must be unique within the delta and
plaintext size must be nonzero.

The manifest chain is the append-only pack inventory. Manifests do not repeat
historical descriptors, avoiding quadratic cumulative-inventory metadata.

### 7.3 Pack stream framing

Each pack is encoded as:

```text
"E2EEPK5\0" || chunk_size_u32_le || nonce_prefix_19 || segments...
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
is known, but no imported-state pin or remote ref may move until all
cryptographic, content-address, process, and Git-connectivity checks succeed.
Listing an authenticated manifest does not advance the continuity floor. A
publisher advances its own floor only after its compare-and-swap succeeds.

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
4. Sample `K_t`, derive the pack, body, and sealed-header subkeys, and encrypt
   the new data.
5. Encrypt the previous generation key under the predecessor-link subkey.
6. HPKE-wrap `K_t` once to every active reader using a fresh audit seed, add
   dummy envelopes sealed to throwaway recipients up to the padded count, sort by encapsulated-key bytes,
   and put the corresponding audit entries in the sealed header.
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

### 8.5 Inner Git refs

The remote helper advertises refs in `refs/heads/*` and `refs/tags/*`. All other
namespaces MUST be rejected before publication. Branch refs MUST resolve to
commits and retain the fast-forward check unless the writer explicitly forces
the update. Lightweight and annotated tags MAY point to any Git object; their
complete object graphs, including annotated tag objects, MUST be included in
the encrypted pack and verified by receiving clients. An existing tag MUST
remain unchanged unless the update is forced.

Deleting an existing branch or tag publishes a signed writer manifest with the
complete ref map minus that ref. A deletion introduces no pack and does not
increase the cumulative pack count. The helper advertises `refs/heads/main` as
the remote `HEAD` when present and MUST refuse to delete it while it is
advertised as the default branch. Returning clones can remove stale local
tracking refs with Git's `--prune` and `--prune-tags` fetch options.

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

Authenticating a manifest alone MUST NOT advance the continuity floor. A
helper client's head, generation, repository root, and policy-generation floor
advances only when the complete-ref connectivity check succeeds for that
manifest's refs, either after pack import or, during listing, because every
advertised ref is already connected locally; or after that client successfully
publishes its own successor with compare-and-swap. A client MUST NOT rely on
receiving a fetch command to pin a state, because Git omits it when no objects
need to be transferred. A failed or incomplete
import leaves the previous floor intact, so an authenticated but unusable
publication cannot make a later valid successor look like rollback.

Client-state updates for one repository and remote MUST serialize their
read-modify-write operation across helper processes. The merge MUST preserve
the greatest recorded manifest and policy generations and MUST reject a
same-generation head-ID conflict. The durable state-file replacement remains
atomic; the lock is held while an import or publication checks and advances
the floor.

A client MAY satisfy that requirement incrementally. After a successful full
or incremental connectivity check, it records the exact checked ref tips as a
verified frontier. On a later fetch it first requires every frontier tip to
still exist locally, then walks the current tips while excluding objects
reachable from the verified frontier. Content-addressed Git objects reachable
from that frontier were already checked and cannot be changed in place, so an
inductive check of only the newly reachable range establishes completeness of
the new state. The frontier advances only after pack authentication, import,
and the incremental connectivity check all succeed.

A missing frontier in a v5 client state requires a full connectivity walk. A
client state from another wire version is not accepted. The incremental rule assumes the trusted
client's existing object database has not been corrupted outside this
protocol; explicit full verification remains available to check local storage.

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
  fails the operation. Limits are in [durability.md](durability.md).
- Carrier Git uses a normal fast-forward push of
  `refs/heads/git-remote-e2ee`; receive-pack ref update is the CAS.

The losing client fetches/decrypts the winner and uses the inner Git DAG to
decide whether to retry, merge, or rebase. Administrative CAS failures are
never automatically rebased; authorization and membership must be reevaluated.
Unreachable losing objects require later GC.

## 11. Continuity and invitations

Returning clients pin at least repository root, manifest ID and generation,
and policy ID and generation. Helper continuity pins advance after a complete
successful fetch/import or a successful own publication, never from listing
alone. They reject rollback, a non-descendant manifest, policy
rollback/sideways movement, root substitution, and generation gaps. Local
client-state updates are serialized and monotonic across concurrent helpers.

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

Let `N` be active readers, `P` the padded envelope count, `G` one small HPKE
envelope, and `S` newly encrypted pack bytes. `P` is the next power of two at
least `max(N, 4)`.

| Operation | Upload delta | Remote storage delta |
| --- | ---: | ---: |
| Content push | `S + P*G + O(1)` | `S + P*G + O(1)` |
| Add/revoke/rotate | `P*G + O(policy size)` | `P*G + O(policy size)` |

Large-content storage is `sum(pack ciphertext sizes)`, independent of `N`.
Envelope metadata is linear in the padded reader count per generation and
accumulates as approximately `O(generations * P * G)`. A membership transition
also carries the signed policy history inside its encrypted body. Fresh clone
work is linear in manifest generations until checkpoint compaction exists.

## 13. Security limits

- An authorized reader can export plaintext or the current snapshot key.
- Disclosure of `K_t` exposes all repository history through `t`, not only one
  pack. It exposes no later generation.
- Compromise of an active device private key is stronger: the attacker can
  unwrap later generation keys while the device remains active.
- Old immutable headers retain anonymous envelopes. Later device-key compromise
  can retroactively expose every generation addressed to that device. v5 has no
  forward secrecy for stored history.
- Full-history onboarding is mandatory; future-only access requires a new
  format or an explicit compartment.
- Storage observes padded reader count, object sizes, upload timing, generation
  count, total growth, and opaque repository root. It does not directly observe
  device public keys or IDs, roles, signer identity, or membership changes,
  although size patterns may reveal a membership transition.
- Storage can delete, freeze, or deny service.
- Writers can author destructive Git history; force remains explicit.
- Global rollback/equivocation detection requires an external anchor.

## 14. Migration and future work

v5 is intentionally wire-incompatible with v2, v3, and v4. Migration must occur
on a trusted client able to decrypt the older repository and republish under a
new v5 repository boundary. Automatic migration is not implemented. The local key
file remains format 3 because its stable repository/device identity material did
not change; manifest, policy, signature, KDF, HPKE, and AEAD domains changed and
therefore fail closed across wire versions.

Planned extensions:

1. checkpoint/compaction and garbage collection with explicit authority;
2. M-of-N administrator authorization and recovery;
3. automatic stale-push retry with explicit merge behavior;
4. S3 backend with conditional-write compatibility tests;
5. optional gossip or transparency-log anchoring.
