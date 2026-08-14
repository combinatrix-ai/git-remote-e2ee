# Target protocol specification

> [!IMPORTANT]
> This document describes the **target protocol**, not the format implemented
> by the current release. [`DESIGN.md`](DESIGN.md) remains the description of
> the implemented v2 epoch-key protocol. The target format will require a new
> version and an explicit migration path.

## 1. Goals

The target protocol keeps ordinary Git semantics on trusted clients while an
untrusted storage provider stores only authenticated ciphertext and a small
amount of routing and authorization metadata.

It is designed to provide:

- confidentiality for the inner Git object graph, refs, commit IDs, paths,
  authors, messages, and file contents;
- independent per-device private keys, with no shared repository decryption
  secret that collaborators must copy between machines;
- repository-wide 1-of-N read access: every active reader can decrypt with
  only its own device private key;
- administrator-controlled membership, separate writer and administrator
  roles, and a format that can later support M-of-N administration;
- incremental encrypted Git packs and compare-and-swap publication;
- integrity, authenticity, and rollback/fork continuity for returning clients;
- compatibility with a filesystem byte store and with an ordinary Git remote
  used as a ciphertext carrier.

The central key-hierarchy change from v2 is:

```text
implemented v2: device key -> shared epoch key -> payload DEK -> ciphertext
target format:  device key ---------------------> payload DEK -> ciphertext
```

There is no repository-wide epoch key in the target format. Every encrypted
payload has an independent random data-encryption key (DEK), and that DEK is
wrapped directly to each active reader's public key.

## 2. Non-goals and unavoidable limits

- An authorized reader can always copy plaintext or disclose a DEK after
  decryption. A normal local Git checkout cannot cryptographically prevent
  this.
- Revocation cannot erase plaintext or keys previously obtained by a device.
  It only excludes that device from future payloads.
- Read authorization is repository-wide. Branch-level read confidentiality is
  not supported; data requiring a different reader set belongs in another
  repository or a future explicit compartment.
- The storage host is not metadata-oblivious. It can observe ciphertext sizes,
  object counts, update timing, and total growth. The authorization format may
  also reveal device public keys, roles, reader count, membership changes, and
  the number of recipient envelopes.
- Native hosting features cannot inspect the inner repository. GitHub or
  GitLab can carry the ciphertext, but their web diffs, code search, and
  plaintext pull-request review do not apply to it.
- Storage alone cannot prove global freshness. A fresh client needs an
  authenticated checkpoint, and prevention of freeze or equivocation across
  all clients requires gossip, a transparency service, or another external
  anchor.

## 3. Terminology

- **Inner repository**: the decrypted Git repository used locally.
- **Carrier**: an ordinary Git repository used only to transport protocol
  objects.
- **Payload**: an encrypted Git pack or encrypted manifest body.
- **Payload DEK**: a fresh random symmetric key used for exactly one payload.
- **Access set**: the signed collection of per-recipient HPKE envelopes for one
  payload DEK.
- **Policy**: the signed device registry and role assignment.
- **Manifest**: the signed state transition that selects the current policy,
  refs, pack inventory, and access sets.
- **Repository root**: the stable repository identity derived from the genesis
  administrator public keys.
- **Device ID**: a domain-separated SHA-256 digest of one device's Ed25519 and
  HPKE public keys. Device keys and IDs are unique to one repository.
- **Payload kind**: a closed, domain-separated identifier. The initial target
  version defines exactly `pack` and `manifest-body`.

## 4. Cryptographic building blocks

The initial target version should retain the currently used primitives:

- Ed25519 for signatures;
- X25519/HKDF-SHA-256/ChaCha20-Poly1305 HPKE for recipient envelopes;
- XChaCha20-Poly1305 for payload encryption;
- SHA-256 for content-addressed object identifiers.

Every signature and encryption operation must use a protocol-versioned domain
separator. Signatures cover the digest of the exact stored bytes, not a
re-serialized interpretation of a data structure.

Every pack and every manifest body receives an independently random DEK. DEKs
must not be derived from previous DEKs, device keys, commit IDs, branch names,
or another repository secret.

XChaCha20-Poly1305 payload encryption uses a fresh random 24-byte nonce stored
with the ciphertext. Its associated data binds at least the protocol version,
repository root, and payload kind. Nonce generation failure must abort the
operation before publication.

## 5. Stored object model

All objects except `HEAD` are immutable and content-addressed:

```text
objects/<hash>       encrypted incremental Git packs
states/<hash>        encrypted manifest bodies
access/<hash>        signed access sets containing per-reader DEK envelopes
manifests/<hash>     signed headers referencing encrypted state bodies
policies/<hash>      signed device registry and roles
HEAD                 opaque ID of the newest manifest
```

An implementation may shard or batch access metadata without changing the
logical model. The first implementation should prefer one access set per
payload because it is simple to validate. A later format may use recipient
indexes or append-only grant batches to reduce onboarding cost.

Private device keys exist only on trusted clients. Public device keys, roles,
signatures, and encrypted DEK envelopes are stored remotely.

Policies and access sets are plaintext-structured. A client must be able to
locate its recipient envelope by device ID without first decrypting any
repository payload. This avoids a key-discovery cycle and intentionally leaks
the authorization metadata described in section 2.

### 5.1 Pack object

A pack object contains one Git pack encrypted under a fresh payload DEK. Its
object ID is the hash of the exact ciphertext bytes.

The protocol's encryption unit is a generated Git pack, not an individual
inner Git commit. One push can therefore encrypt several commits under one
pack DEK.

### 5.2 Access set

An access set binds:

- repository root and protocol version;
- payload kind and ciphertext object ID;
- policy ID and policy generation;
- a domain-separated commitment `SHA-256(tag || payload_DEK)`;
- one HPKE envelope of the same payload DEK for every active reader;
- signer identity and signature.

Every access set referenced by a manifest, both for the manifest body and for
every pack inventory entry, must bind exactly that manifest's selected policy
ID and generation. Its recipient set must equal the active readers of that
policy: no other device may have an envelope and no active reader may be
omitted. A client must reject a manifest that violates this rule regardless of
whether every individual signature is otherwise valid.

A normal writer may sign the access set for a newly created pack or manifest
body under an unchanged policy. Replacing the access set of an existing
payload, including adding or removing a recipient envelope, is an
administrative operation. In a policy transition, its signer is evaluated
against the parent policy's administrator set even when that signer is absent
from the child policy to which the new access set is bound.

The envelope must bind the repository root, payload object ID, policy ID,
recipient device ID, and payload kind as HPKE associated information. An
envelope copied to another repository, payload, device, or policy must fail.
After HPKE open, each recipient must verify the unwrapped DEK against the
signed commitment before attempting payload decryption. This makes a wrong
envelope attributable to the access-set signer, although a third party still
cannot verify that another recipient's envelope contains the correct DEK.

### 5.3 Policy

A policy records repository-unique device public keys and independent roles:

- **reader**: may receive payload DEK envelopes and decrypt the repository;
- **writer**: may sign ordinary manifest updates and new-payload access sets;
- **administrator**: may authorize the next policy and replacement access sets.

The genesis policy contains one owner, and that owner is a reader, writer, and
administrator. Every later policy is authorized by administrators in the
parent policy, never solely by authority introduced in the child.

In the initial target version, every administrator must also be an active
reader. A policy violating this invariant is invalid. Administrative
membership operations must unwrap all current payload DEKs, so allowing a
non-reader administrator would create an unusable or easily bricked policy.

The first target implementation remains single-administrator authorization
(threshold 1). The format should retain a threshold and signature array but
must fail closed on unsupported values. A future M-of-N version must count
distinct parent administrators and use the parent policy's threshold to
authorize its child.

A writer who is not an administrator cannot add or revoke devices, change
roles, change the administrator set, replace access metadata for an existing
payload, or select a different policy.

### 5.4 Manifest

The manifest is a plaintext signed header that references a separate encrypted
body in `states/`. The header
binds at least:

- repository root and protocol version;
- manifest generation: 0 for genesis, otherwise the parent generation plus one;
- previous manifest ID, using the defined null constant only for genesis;
- current policy ID and generation;
- transition signer identity and signature;
- encrypted body object ID;
- access-set ID for the manifest body's independent DEK.

The encrypted body contains the inner refs and cumulative pack inventory. Each
inventory entry selects both a pack ciphertext ID and the access-set ID that
currently grants access to its DEK.

The header must not reveal inner ref names, inner Git object IDs, authors, or
commit messages.

Every successor is exactly one of two transition types:

1. **Ordinary update.** The selected policy is unchanged. The manifest is
   signed by an active writer in that policy. Its inventory contains every
   parent entry unchanged, including both pack ciphertext ID and access-set ID,
   and may only append new packs whose access sets are signed by that writer.
2. **Administrative transition.** The manifest selects the direct authorized
   child of the parent's policy and is signed by an administrator in the
   parent policy, regardless of the signer's writer role. Inner refs and the
   ordered list of pack ciphertext IDs are unchanged. Every existing pack gets
   a replacement access set bound to the child policy, and the new manifest
   body gets its own child-policy access set. Those replacement sets are
   authorized by the same parent administrator rule.

A client that can decrypt both adjacent bodies must compare them and enforce
these transition rules. Along the manifest chain, the selected policy is
either unchanged or advances to a direct authorized child; it can never move
backward or sideways. Policy generation is therefore non-decreasing.

## 6. Repository and device lifecycle

### 6.1 Initialization

The repository root is derived with domain separation from the genesis owner's
Ed25519 and HPKE public keys. The genesis policy is self-signed by exactly that
owner. The first manifest is the genesis base case rather than a successor: its
generation is 0, its previous-manifest field is a defined domain-separated null
constant, it selects the genesis policy and an empty repository state, and it
is signed by the genesis owner. The successor transition rules in section 5.4
apply from the second manifest onward.

### 6.2 Normal push

1. Read and fully validate the current `HEAD`, manifest chain, policy chain,
   signatures, local continuity pin, and referenced ciphertext.
2. Apply normal Git checks locally, including fast-forward enforcement unless
   force was explicitly requested.
3. Generate an incremental Git pack and a fresh pack DEK.
4. Encrypt the pack once and wrap its DEK independently to every active reader.
5. Build the next encrypted manifest body under another fresh DEK and wrap that
   DEK independently to every active reader.
6. Upload all new immutable objects.
7. Compare-and-swap `HEAD` from the value read in step 1 to the new manifest ID.

Publishing an access set or ciphertext without winning the final CAS can leave
unreachable immutable objects. That is safe and can be handled by later
garbage collection.

### 6.3 Add a reader

The default onboarding mode grants full history:

1. The new device generates its own repository-specific signing and HPKE keys
   and sends only its public device record to an administrator.
2. An already authorized administrator validates and decrypts the current
   repository state.
3. For every existing pack, the administrator unwraps its DEK locally and
   verifies it against the signed DEK commitment.
4. The administrator creates the next policy and an administrative-transition
   manifest. It encrypts that manifest's body under a new DEK and creates
   child-policy access sets for the body and every cumulative pack.
5. One `HEAD` CAS makes the membership and full-history access visible
   together.

Pack ciphertext is not re-encrypted. Onboarding work grows with the number of
encrypted packs and readers, but only small key envelopes and indexes change.
Future-only or snapshot-based invitations may be added later, but are not part
of the initial target behavior.

### 6.4 Revoke a reader

Revocation publishes a new policy without the device and replacement access
sets for every entry in the cumulative pack inventory plus the new manifest
body. Each new access set exactly matches the new active-reader set and
therefore omits the revoked device. Future payloads never contain an envelope
for it. Existing pack ciphertext remains unchanged.

Old immutable manifests and access sets may still contain envelopes for that
device, and the device may already have cached DEKs or plaintext. Replacing the
current access sets expresses current authorization and avoids accidental new
use; it does not revoke past knowledge.

### 6.5 Rotate or replace one device key

Key rotation is modeled as adding a new device identity and revoking the old
one in one administrative transition. Other devices keep their private keys.
Existing pack ciphertext remains unchanged; access metadata is regenerated for
the new active-reader set.

## 7. Git semantics and branch behavior

After decryption, the client works with an ordinary local Git repository.
Branches, commits, merges, rebases, diffs, and local hooks behave normally.

Creating or switching a local branch does not change who can decrypt the
remote. Every active reader can read every inner branch and the full encrypted
history selected by the manifest. Branch-level write policy may be added
later, but it is separate from read-key distribution.

The carrier backend uses one fixed outer branch,
`refs/heads/git-remote-e2ee`. It maps protocol objects to ordinary carrier Git
blobs. Other outer branches are unrelated and ignored by the remote helper.
The inner branch names and commit graph exist only inside encrypted manifest
and pack payloads.

The initial target version supports push destinations under `refs/heads/*`.
Tags and branch deletion remain unsupported and must be rejected before a new
manifest is published.

## 8. Concurrency and conflict handling

Race detection does not inspect encrypted inner commit parents on the server.
Two devices read the same opaque `HEAD`, prepare immutable objects, and attempt
the same compare-and-swap. Exactly one update wins; the loser receives a stale
state conflict.

- The filesystem backend implements CAS with locking and atomic rename.
- The carrier-Git backend maps `HEAD` publication to a fast-forward update of
  the fixed outer branch. Git's receive-pack ref transaction is the CAS.

After losing CAS, the client fetches and decrypts the winning state and then
uses the inner Git DAG to decide whether it can retry, merge, or must ask the
user to rebase. The initial implementation may surface the conflict rather
than retry automatically.

An administrative operation that loses CAS is never automatically rebased.
The client must validate the winning state, re-evaluate the operator's current
authorization, and explicitly reconstruct the policy and every affected access
set before retrying. This is required when, for example, an add races a revoke.

## 9. Integrity, rollback, and invitations

Clients validate content hashes, AEAD tags, DEK commitments, exact-byte
signatures, policy authorization, access-set membership and policy equality,
manifest ancestry, policy monotonicity, transition type, and every referenced
object before moving local refs or publishing a successor.

Returning clients pin at least:

- repository root;
- newest accepted manifest ID and generation;
- newest accepted policy ID and generation.

They reject rollback, a non-descendant manifest, policy rollback, or a
repository-root change.

A fresh device must be provisioned with an invitation checkpoint through an
authenticated channel. The repository root received through that channel is
the bootstrap trust anchor; the invitation signature adds administrator
authorization and accountability. Its signed body contains at least:

```text
repository_root
minimum_manifest_id
minimum_manifest_generation
minimum_policy_id
minimum_policy_generation
recipient_device_id
signing_administrator_device_id
```

The serialized invitation also carries the administrator signature, which
covers the exact signed-body bytes under a versioned invitation domain tag.

After fetching the plaintext policy chain anchored in `repository_root`, the
new device verifies the exact-byte signature and checks that its signer was
authorized for the checkpoint manifest: an administrator in the selected
policy for a genesis or ordinary manifest, or an administrator in the parent
policy for an administrative-transition manifest. This permits a departing
sole administrator to authorize an invitation for its replacement while the
checkpoint still names the decryptable child manifest.

The new device rejects any remote state older than, or not descended from, the
checkpoint or selecting a policy older than the named minimum policy. The
policy selected at `minimum_manifest_id` must exactly equal `minimum_policy_id`
and generation.

Because the new reader has no envelopes for historical manifest bodies before
its admission, it cannot independently compare those bodies or enforce their
encrypted inventory-continuity rules. It trusts the authenticated invitation
checkpoint for that prefix and fully validates transitions from the checkpoint
forward. This mirrors the unavoidable bootstrap boundary: the invitation
solves fresh-client rollback only up to its checkpoint. It does not detect a
later freeze or different valid forks shown to isolated clients.

## 10. Hosting and CI behavior

- Local `git clone`, `fetch`, `pull`, and `push` remain the intended interface.
- GitHub or GitLab can store and synchronize the carrier repository.
- A hosting-site pull request can move the outer carrier branch, but its diff
  is ciphertext and is not a meaningful review of the inner repository.
- CI can operate on plaintext only after running the remote helper with an
  authorized device key. A trusted or self-hosted runner best preserves the
  storage host confidentiality boundary.
- Server-side branch protection, code search, secret scanning, blame, and web
  browsing do not understand the encrypted inner repository.

The fixed carrier branch is protocol-owned and should not be merged through a
hosting UI. A helper may preserve unrelated paths or no-op outer commits, but
must reject any foreign mutation of the protocol namespace that does not
validate as the expected manifest transition. Carrier Git history is a CAS
transport, not an additional source of protocol authorization.

## 11. Security consequences of direct per-payload wrapping

This design removes the repository-wide transferable epoch secret. Leaking one
pack DEK exposes that pack, not every past and future pack. Compromise of a
device private key can expose every payload whose access set contains that
device, so protecting and rotating device keys still matters.

Direct recipient wrapping costs roughly O(readers × payloads) envelope
metadata and makes full-history onboarding O(payloads). This is the deliberate
initial trade-off for a simple, auditable trust model.

Broadcast encryption could reduce recipient-header size for a large reader
set, but would add protocol and implementation complexity and would not stop an
authorized reader from sharing the resulting content key. Zero-knowledge
proofs can prove possession or authorization; they do not deliver the payload
key to multiple readers or prevent its disclosure. Neither is required for the
initial target format.

## 12. Migration and future work

The target protocol is intentionally not wire-compatible with v2. Migration
must run on a trusted client that can decrypt the v2 repository and republish
its packs and state under a new repository/version boundary. Until that path is
implemented and tested, v2 repositories remain on the implemented format.

Planned extensions after the target 1-of-N format:

1. M-of-N administrator authorization and recovery workflows.
2. Indexed or batched access catalogs for large histories and reader sets.
3. Automatic stale-push fetch/retry with explicit merge behavior.
4. S3 backend and a provider-specific conditional-write compatibility suite.
5. Safe compaction and garbage collection with explicit deletion authority.
6. Optional gossip or transparency-log anchoring for equivocation detection.
7. Optional explicit read compartments, if their Git UX and leakage model can
   be made understandable; ordinary branches will not silently become security
   boundaries.
