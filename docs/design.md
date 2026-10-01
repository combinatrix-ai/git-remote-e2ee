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
  object graph before the continuity floor or remote-tracking refs move.
- Authentication alone never advances the continuity floor. The floor advances
  after a successful import and connectivity check, after the client's own
  publication wins compare-and-swap, or during listing when every advertised
  ref already resolves to a complete local object graph. The last case matters
  because Git skips the helper's fetch command when nothing needs to be
  transferred, as after a membership change, a deletion, or a tag pointing at
  an existing object; without it, such a state would never be pinned and a
  later replay of the previous state would be accepted.
- Per-repository/remote client-state updates hold an advisory file lock across
  validation and read-modify-write. The state replacement remains durable and
  atomic, and its manifest and policy generations never move backward.
- The helper advertises `refs/heads/*` and `refs/tags/*`; every other ref
  namespace is rejected before publication.
- Branch updates require fast-forward ancestry unless force is explicit. Tags
  may be created freely, but an existing tag is moved only by a forced push.
  Lightweight and annotated tag objects are included in the encrypted pack.
- Branch and tag deletion publish a signed generation with the complete ref set
  minus the deleted ref and no pack delta. `refs/heads/main` cannot be deleted
  while it is advertised as the remote `HEAD`.

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
root substitution. A signed manifest seen by list is not yet a pin: helper
state advances after all required packs are imported and every advertised ref
passes the complete-object-graph check, or after the client's own publication
successfully wins compare-and-swap. A missing or unusable pack therefore cannot
raise the continuity floor.

Each local repository/remote pair has one stable lock file beside its client
state. Helpers hold the exclusive lock while checking the current floor and
performing an import or publication update. State writes merge monotonically
and use the existing flushed temporary-file, rename, and parent-directory
sync path. Administrator pins use the same serialized, monotonic state update
rules after initialization or a successful policy transition.

State files written by earlier builds are not lowered automatically. Their
head pin may have come from listing, but it is indistinguishable from a valid
pin made after the client's own publication; lowering it could weaken rollback
detection.

Storage alone still cannot prevent:

- a fresh client receiving an old valid chain without an invitation checkpoint;
- different valid forks shown to isolated clients;
- freeze, deletion, or denial of service;
- destructive history authored by an authorized writer;
- plaintext or snapshot-key export by an authorized reader.

Old manifest headers retain device envelopes. Later compromise of a device
private key can retroactively expose every generation addressed to that device.
There is no forward secrecy for stored history.

## Recovering from an unverifiable HEAD

Anyone with storage write access can point `HEAD` at something conforming
clients reject: bytes that fail to parse, a manifest signed by a reader-only
device, or a manifest that fails any other check. Clients already refuse such
a state and stop. Recovery lets an honest writer continue afterwards without
trusting anything the rejected state claims. It is an explicit operation,
`git-e2ee recover`; nothing recovers automatically.

### Principle

Recovery never derives a base, refs, policy, keys, or pack inventory from the
rejected state. The default base is the client's continuity floor: the newest
state it accepted after a complete connectivity check or its own successful
publication. A fully validated descendant of the floor may be chosen
explicitly. Anything else storage offers, including a rejected manifest's
`previous` pointer, is only a discovery hint and is validated independently.

The danger is an update this client never saw. If a legitimate state `L`
followed the floor and storage later replaced it, continuing from the floor
would drop `L`, and if `L` revoked a device, would deliver new keys to that
device again. The client cannot rule this out from the floor alone, so
recovery shows the user what it found and never chooses silently.

### Classifying the head

| Class | Meaning | Recovery allowed |
|---|---|---|
| valid | authenticated, authorized, continuous with the floor | not needed |
| invalid | demonstrably bad: unparseable, bad signature, signer not authorized under the authenticated policy, broken audit, commitment, or predecessor link | yes |
| unverifiable | this device cannot open any envelope | never: a valid revocation looks exactly like this to the revoked device |
| unsupported | unknown format version or transition type, even if the parser reports it as a parse error | never: an old client must not erase a newer client's state |
| unavailable | objects missing or a storage error, including failure to read a historical object | never |
| discontinuous | authenticated but older than, or diverging from, the floor | never: this is detected rollback or equivocation and is reported as such |

These restrictions bind `recover` as well; it cannot override them. A signer ID
read from a sealed header is reported as the claimed signer until its signature
verifies against a device record in the authenticated policy.

### `git-e2ee recover`

1. **Discover, read-only.** Classify the head. On the carrier backend, walk the
   outer commit history back to the floor's manifest within a fixed budget and
   list every authenticated manifest that descends from the floor, with its
   generation, outer commit, verified signer, and whether candidates conflict.
   A replay of an older manifest found in outer history is reported, never
   treated as newer. Exhausting the budget is an error, not a choice.
2. **Refuse ambiguity.** If authenticated descendants conflict, report a fork
   and stop.
3. **Select explicitly.** The default offer is the newest validated descendant
   of the floor, or the floor itself if none exists. Choosing an older base
   than one found is a deliberate history-discarding choice and requires a
   separate confirmation. On the directory backend, which has no `HEAD`
   history, only the floor can be offered, with the confirmation: "Updates
   after this floor may be omitted. This may also omit revocations and
   disclose subsequently published content to devices excluded by a newer
   policy."
4. **Publish.** The device must be an active writer under the base's policy.
   Build `R` with `R.previous = base`, `R.generation = base.generation + 1`,
   the predecessor link to the base key, refs and policy from the base, and
   compare-and-swap from the observed storage token, which is the current outer
   tip on the carrier. The verified base and the CAS token are separate values.
   On the carrier the new outer commit is a child of the current tip, so the
   push is still a fast-forward. Rebuild the `e2ee/` tree from the ciphertext
   objects the base chain requires, restored byte for byte from the carrier's
   history or the local cache and checked against their content IDs; if any is
   missing, fail as unavailable. A lost CAS fails; the operator must start a
   new `recover` invocation and review its fresh discovery report.

Git does not pass a push of unchanged refs to the helper, so a plain `git push`
cannot perform recovery; `recover` is the only entry point. It must never
publish during `list for-push`.

Fresh clones have no floor. Unless they hold an authenticated invitation
checkpoint, `recover` states that freshness and fork identity are unverified.

### Possible automatic recovery later

Automatic recovery is safe only if the client can prove nothing legitimate
came between its floor and the junk. Comparing the parent's inner `HEAD` value
with the floor is not enough: storage writers can append a legitimate `L`, then
a replay of the floor, then junk, and the junk's parent would still match. A
future automatic mode would have to anchor to the exact outer commit at which
this client established its floor, never move that anchor on a replay, and
require the current tip to be a single-parent child of it.

### Implementation requirements

- Validate every accepted ancestor under the policy in force at that point of
  the chain; never import policy authority from a rejected manifest.
- Bound discovery by outer commits, candidates, bytes read, and cryptographic
  operations, deduplicating repeated IDs.
- Record rejected heads as bounded diagnostic evidence next to the client
  state, separate from the floor. Do not blacklist unverifiable or unavailable
  states.
- Never lower the floor. A successful recovery advances it to `R`.

### Current implementation

`git-e2ee recover` accepts `--remote <carrier-url>` or `--storage <directory>`,
plus `--key`, `--repo`, and `--remote-name`. The repository defaults to `.`
and the remote name defaults to `origin`; the continuity floor is read from
`.git/git-remote-e2ee/<remote-name>/state.json`. Without `--publish`, the command
only reports. Publishing an older offer requires `--discard-newer`. Directory
publication requires `--accept-stale-floor` and prints the warning above.

Discovery scans the complete available first-parent carrier history, within
budgets of 2,048 outer commits, 256 distinct heads, 64 MiB of manifest bytes,
and 1,000,000 estimated cryptographic operations. It scans past replays of the
floor so a legitimate descendant hidden behind a replay can still be offered.
An exhausted budget fails closed. A CAS loss is returned to the operator;
there is no automatic retry with an old selection. This implements the
restart-at-discovery requirement as a fresh command invocation, matching the
requirement that a losing recovery fail without retrying blindly.

Before publication, required manifests and packs are restored into the
disposable carrier checkout, unneeded ciphertext objects are removed from that
checkout's `e2ee/` tree, and all base-chain packs are imported into a temporary
bare Git repository to verify complete ref connectivity. The temporary
repository is deleted when the command exits; the persistent carrier cache
continues to contain ciphertext Git objects only.

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
