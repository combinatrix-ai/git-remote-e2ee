# Design

## Goal

Provide Git synchronization where an untrusted storage service cannot read
repository contents, refs, commit IDs, author metadata, or file names. The
storage service is a byte store and concurrency primitive; Git semantics remain
on trusted clients.

## Current protocol

Each push creates two immutable ciphertext objects:

1. An incremental Git pack encrypted with XChaCha20-Poly1305.
2. A manifest containing refs, the cumulative pack inventory, generation, and
   previous-manifest ID. The manifest is signed with Ed25519, then encrypted.

Both are named by SHA-256 of the randomized ciphertext. The only mutable value
is `HEAD`, an opaque manifest ID. Updating `HEAD` requires compare-and-swap
against the value the writer fetched.

```text
objects/<ciphertext hash>      encrypted Git pack, immutable
manifests/<ciphertext hash>    encrypted signed manifest, immutable
HEAD                           opaque newest-manifest pointer
```

The filesystem implementation serializes `HEAD` CAS with an advisory lock and
publishes it with atomic rename. Uploading packs before CAS means a crashed or
losing writer can leave an unreachable object, but cannot make `HEAD` reference
a missing object.

## Storage contract

The `Storage` trait intentionally exposes four operations:

```text
put_object_if_absent(kind, id, bytes)
get_object(kind, id)
read_head()
compare_and_swap_head(expected, next)
```

An S3 backend can map immutable writes to `If-None-Match: *` and the head CAS to
an `If-Match` conditional write on providers that implement it correctly. A
provider capability test is required; "S3 compatible" alone is not a sufficient
concurrency guarantee.

### Carrier Git mapping

The carrier backend maps immutable objects to ordinary Git blobs under `e2ee/`
and divides ciphertext into 32 MiB chunks. Each storage transaction creates an
outer commit on `refs/heads/git-remote-e2ee`. A normal fast-forward push is the CAS:
if another writer advanced the outer branch, the push is rejected and the
inner update does not become visible.

The carrier is not metadata-oblivious. Its host sees outer commit timestamps,
chunk sizes/counts, update frequency, and total growth. It does not receive the
inner refs, Git object IDs, paths, author identities, messages, or plaintext.
The current implementation clones a temporary carrier checkout for each helper
process; persistent partial-clone caching is required before using this backend
with multi-gigabyte repositories.

The carrier CAS is tested against a local bare Git repository. Two independent
carrier clones race normal pushes from the same outer commit; Git's
`receive-pack` accepts exactly one ref update, and only the winner's encrypted
manifest becomes visible. This test does not need a daemon or Docker because a
local-path push invokes the same ref transaction and fast-forward machinery.
HTTP authentication, request-size limits, and provider-specific branch policy
remain separate compatibility concerns.

## Git semantics

- Clients decrypt the current manifest and enforce fast-forward updates with
  `git merge-base --is-ancestor`.
- New objects are produced by `git pack-objects --stdout --revs`. Only previous
  remote tips that exist in the pushing client's object database are used as
  exclusions, so a writer can add an independent branch without first fetching
  every other branch.
- Packs are imported with `git index-pack` before remote-tracking refs move.
- Push destinations are currently restricted to `refs/heads/*`; tags are not
  advertised as supported.
- A stale writer loses the manifest CAS and must fetch/rebase/retry. This
  prototype surfaces the conflict rather than retrying automatically.

## Threat model and current limits

The current single-writer key file contains an encryption key and Ed25519
signing key. It protects confidentiality and detects ciphertext or manifest
tampering, but it is not yet a multi-device authorization system.

Each Git repository pins its last observed manifest ID and generation under
`.git/git-remote-e2ee/<remote>/state.json`. The native remote helper validates and
updates this pin before advertising refs for fetch or push, and checks it again
immediately before publishing. Returning clients reject a lower generation or
a chain that does not descend from that pin. The signed hash chain therefore
provides continuity for returning clients. It does not independently prevent:

- a fresh client receiving an old but valid chain;
- storage presenting different valid forks to different clients;
- storage freezing a client on its last valid state;
- deletion or denial of service by storage;
- an authorized writer intentionally creating a destructive history.

The security claim is therefore confidentiality, authenticity, and local fork
continuity—not global rollback or equivocation prevention.

## Planned layers

1. Automatic stale-push fetch/retry in the existing remote helper.
2. Static multi-device writer registry rooted in an offline repository key.
3. Pack DEKs wrapped by a repository KEK, with device envelopes and revocation.
4. S3 backend with a provider compatibility suite.
5. Safe compaction and garbage collection with a separate deletion role.
6. Optional head gossip or transparency-log anchoring.
