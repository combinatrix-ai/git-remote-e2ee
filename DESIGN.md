# Design

This document summarizes the implemented v4 architecture. [`SPEC.md`](SPEC.md)
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
manifests/<object hash>        signed header + encrypted generation delta
policies/<object hash>         signed device registry and roles
HEAD                           opaque newest-manifest pointer
```

Only `HEAD` is mutable. Updating it requires compare-and-swap against the exact
value observed by the publisher.

The manifest body contains complete current refs, only packs introduced by its
generation, and the predecessor-key link. Historical pack descriptors are not
copied into every new manifest. The signed manifest chain is the append-only
pack delta log.

## Cryptography

- Ed25519 exact-byte signatures
- X25519/HKDF-SHA-256/ChaCha20-Poly1305 HPKE generation-key envelopes
- HKDF-SHA-256 domain-separated object subkeys
- XChaCha20-Poly1305 authenticated encryption, using the STREAM construction
  for Git packs
- SHA-256 content IDs and generation-key commitments

The signature covers exact header bytes and the encrypted body digest. The
header includes the complete reader-envelope list and generation-key
commitment. Every verifier checks that envelope device IDs exactly equal the
selected policy's active-reader set. Each recipient checks its unwrapped key
against the signed commitment before body decryption.

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

The repository root is derived from the genesis owner's two public keys.
Genesis contains exactly that active owner with reader, writer, and
administrator roles and is self-signed. Child policies are authorized by an
administrator in the parent policy.

The format retains an administrator threshold and signature array, but v4
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
the pointer moves, within the limits in [`DURABILITY.md`](DURABILITY.md).
Abandoned `.stage-*` files are unreachable; automatic cleanup is deferred to
future GC.
Manifest and policy objects still use bounded buffered parsing with a 16 MiB
hard limit; large pack objects always use the streaming path.

An S3 backend can use create-if-absent immutable writes and a conditional HEAD
write, but requires a provider capability test; the label "S3 compatible" does
not guarantee correct compare-and-swap behavior.

## Carrier Git mapping

The carrier backend maps protocol objects to normal blobs under `e2ee/`, split
into a dense canonical sequence of 32 MiB chunks, on the dedicated branch
`refs/heads/git-remote-e2ee`. Each protocol publication creates an outer commit.
A normal fast-forward push is the CAS: two candidates from the same parent
cannot both win.

The host sees outer commit timing, chunk sizes/counts, update frequency, public
policy/header metadata, and total growth. Inner Git metadata remains encrypted.

The current carrier implementation clones a temporary checkout for each helper
process. Uploads are incremental, but a persistent partial-clone cache is
needed before multi-gigabyte repositories are practical.

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

## Cost model

For new encrypted pack bytes `S`, active readers `N`, and a small envelope `G`:

```text
content push delta       S + N*G + O(1)
membership change       N*G + O(1)
large content storage   sum(pack ciphertext sizes), independent of N
```

Envelope metadata remains linear in readers per generation. Fresh clone time is
linear in generations until checkpoint compaction exists. The v4 wire format
reserves a checkpoint transition, but current clients reject it as unimplemented.
