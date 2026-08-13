# Design

## Goal

Provide Git synchronization where an untrusted storage service cannot read
repository contents, refs, commit IDs, author metadata, or file names. The
storage service is a byte store and concurrency primitive; Git semantics remain
on trusted clients.

## Current protocol

The v2 protocol has three immutable object types:

1. A Git pack encrypted under a fresh random data-encryption key (DEK).
2. A manifest with a plaintext signed header and encrypted body. The header
   binds the repository root, previous manifest, policy, epoch, writer, and an
   epoch-wrapped manifest DEK. The body contains refs and the cumulative pack
   inventory with every pack DEK wrapped under the current epoch key.
3. A plaintext-structured, signed policy entry containing per-repository device
   public keys, roles, an epoch counter, and an HPKE envelope of the epoch key
   for every active reader. Wrapped key contents remain encrypted.

Objects are named by SHA-256 of their exact stored bytes. Signatures cover a
domain tag and the SHA-256 digest of exact stored bytes; verifiers do not sign
or verify a re-serialized data structure. The only mutable value is `HEAD`, an
opaque manifest ID. Updating `HEAD` requires compare-and-swap against the value
the writer fetched.

```text
objects/<ciphertext hash>      encrypted Git pack, immutable
manifests/<object hash>        signed header + encrypted body, immutable
policies/<object hash>         signed device policy + encrypted key wraps
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

## Key and authorization model

Every key file holds a per-repository Ed25519 signing key and HPKE X25519
recipient key. A device has three independent policy roles:

- reader: receives the current epoch key through an HPKE envelope;
- writer: may sign a normal manifest update;
- administrator: may sign the next policy entry.

The repository root is derived from the genesis administrator's two public
keys. Genesis must contain exactly that one active owner and be self-signed by
it. This prevents storage from substituting a different self-signed genesis
under a repository root provisioned out of band.
The root anchors the genesis owner's identity rather than one unique randomized
genesis byte string. Someone holding that owner's private signing key could
author multiple genesis objects under the same root; storage alone cannot.

Policy entries are authorized by an administrator in the parent policy, never
by an authority newly introduced in the child. `admin_threshold` and a
signature array exist in the format, but v2 accepts exactly one signature and
threshold 1. Unknown formats and thresholds fail closed. A future M-of-N
version must count distinct parent administrators and the parent's threshold
must govern its child.

Policy data is plaintext-structured to avoid a key-discovery cycle: a client
reads the manifest header, fetches and verifies the referenced policy chain,
finds its device envelope, unwraps the epoch key, unwraps the manifest DEK, and
then decrypts refs and pack inventory. This exposes device public keys, roles,
device count, policy generations, revocation cadence, and epoch numbers to the
storage host. Keys must be unique per repository to prevent cross-repository
linkage.

### Device operations

- Add: the parent administrator adds the public device and wraps the unchanged
  epoch key to it. Existing pack ciphertext and DEK wraps are unchanged.
- Revoke: one prepared transaction removes the reader, creates a new epoch,
  wraps it only to remaining readers, and rewraps every cumulative pack DEK.
  The policy and manifest objects are uploaded first and become visible
  together through one HEAD CAS. Pack ciphertext is unchanged.
- Concurrent changes: HEAD CAS chooses exactly one winner. Administrative
  operations are not automatically rebased; the loser must inspect the winning
  state and explicitly rerun, at which point authorization is evaluated again.

Removing a reader without advancing the epoch is invalid. Advancing the epoch
without changing every historical pack-DEK wrap is also invalid.

## Threat model and current limits

Each Git repository pins its last observed manifest ID and generation under
`.git/git-remote-e2ee/<remote>/state.json`. The native remote helper validates and
updates this pin, including the repository root and policy generation, before
advertising refs for fetch or push, and checks it again immediately before
publishing. The administrative CLI uses a sibling
`<key-file>.admin-state.json` pin. Returning clients reject a lower generation
or a chain that does not descend from that pin. The signed hash chains therefore
provide continuity for returning clients. They do not independently prevent:

- a fresh client receiving an old but valid chain;
- storage presenting different valid forks to different clients;
- storage freezing a client on its last valid state;
- deletion or denial of service by storage;
- an authorized writer intentionally creating a destructive history.
- a revoked writer and colluding storage maintaining a pre-revocation fork for
  a fresh or stale client.

The security claim is therefore confidentiality, authenticity, and local fork
continuity—not global rollback or equivocation prevention.

Revocation provides forward confidentiality exclusion only: a revoked device
cannot decrypt data first encrypted under later epochs, but it permanently
retains earlier plaintext and epoch keys. Because old immutable policies retain
HPKE envelopes, later compromise of a device private key can expose every old
epoch that was wrapped to that device. There is no forward secrecy for stored
history. Garbage collection can reduce this retrospective surface but cannot
erase plaintext already obtained by a device.

## Planned layers

1. Automatic stale-push fetch/retry in the existing remote helper.
2. M-of-N administrative authorization and recovery workflows.
3. S3 backend with a provider compatibility suite.
4. Safe compaction and garbage collection with a separate deletion role.
5. Optional head gossip or transparency-log anchoring.
6. Iterative, cached policy-chain validation for long-lived repositories.
