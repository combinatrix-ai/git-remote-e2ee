# Security model

## Trust boundary

The model rests on one premise: **remote is untrusted, local is trusted.**

- **Remote** is the storage the repository is pushed to: a Git host used as
  carrier, or the bytes inside a directory used as storage. It may read,
  withhold, replay, reorder, or alter anything it holds. Everything the client
  reads from it is verified before use.
- **Local** is the machine running the client and what its user controls: the
  device key, the continuity floor and other client state, the carrier cache,
  Git checkouts and configuration, and the filesystem paths the user points
  the client at, including where directory storage lives and any links on
  that path. The client does not defend against its own machine. If local is
  compromised or misconfigured, the guarantees below do not hold.

Every entry under [Considered attacks](#considered-attacks) is judged against
this premise.

## Guarantees

The storage provider is treated as malicious. `git-remote-e2ee` aims to
guarantee:

- confidentiality of inner contents and Git metadata: files, paths, refs,
  object IDs, authors, and messages;
- authenticity and integrity of every fetched state: only devices with write
  authority under the authenticated policy history can author a state that
  conforming clients accept;
- continuity for a machine with a floor for this repository root: it rejects
  any state older than, or diverging from, the newest authenticated continuous
  head it observed, even if a later pack check or fetch failed;
- that a revoked device gets no keys for generations that conforming writers
  build on top of its revocation.

Write authority is about what clients accept, not about who can put bytes on
the storage. Anyone who can write to the storage, including a read-only member
or someone with only push access to the carrier repository, can still replay
old valid states, hide updates, or corrupt `HEAD`. Clients reject what they
cannot verify, so this can deny service but cannot make unauthorized history
accepted. Restrict storage write access as a separate layer, for example with
read-only repository permissions and branch protection on GitHub.

It does **not** prevent:

- the host or anyone with storage write access deleting data, corrupting
  `HEAD`, or refusing service;
- a machine without a continuity floor being shown an old or forked history,
  or different machines being shown different histories
  (that needs an external anchor, which is on the roadmap);
- a revoked writer or administrator creating a valid-looking fork from before
  its revocation, which clients that never saw the revocation cannot tell apart;
- an authorized writer making destructive changes;
- a revoked device reading what it could read before revocation;
- traffic analysis: update times, object sizes, total growth, and the padded
  reader count are visible;
- future quantum attacks: key exchange uses X25519.

Concurrent pushes cannot silently overwrite each other as long as the storage
honors compare-and-swap, as a Git host's fast-forward check or the directory
backend's lock does.

Keys work as a backward chain. The current key can decrypt all earlier
history, which lets a new device read the whole repository, but an old key
cannot decrypt anything newer. This is key regression, not forward secrecy for
history already published. See [design.md](design.md) and [spec.md](spec.md)
for the full threat model, and [SECURITY.md](../SECURITY.md) to report an issue.


## Considered attacks

Each entry records an attack that was raised, what it can achieve, and the
decision taken. "Audit #N" refers to findings of the November 2026 audit.

### Corrupted `HEAD` and recovery publication (audit #28)

A storage writer can point `HEAD` at an invalid manifest, which stops fetches
and pushes. It cannot forge a state clients accept. Earlier versions offered
`recover --publish` to continue from the last verified state. If storage had
hidden a later legitimate state that revoked a device, publishing from the
older base would hand new keys to that device again, and the directory backend
has no history in which to look for such a state. Recovery publication was
removed: `recover` only reports, and service resumes by pushing a healthy
clone to new storage under the membership the operator chooses then.

### Rollback and forks

A machine with a continuity floor rejects any state older than, or diverging
from, the newest authenticated head it accepted. A machine without a floor
cannot tell an old or forked history from the real one; that needs an
external anchor, which is not implemented yet.

### Long manifest chains

Normal operations stop after a fixed cumulative budget of manifest bytes and
cryptographic operations. Signatures are checked after the chain to the anchor
is collected, so lifting the budget lets storage make a client spend time and
memory proportional to the chain it presents. Returning devices start from
their floor's cached manifest and stay within the budget. A fresh device whose
legitimate history exceeds it lifts the budget only through an explicit
`bootstrap --force-full-check`. Pack imports and `verify` extend an authenticated
chain backwards through content-addressed `previous` links and key
commitments, which storage cannot lengthen, so they need no cumulative budget.
Recovery discovery stays bounded and cannot examine a longer history.

### Repeated pack IDs

A signed writer could name an older pack ID again in a new manifest. A
returning device reads only the segment above its floor and cannot see the
earlier use, but the repeated descriptor is useless: the pack's key and
authenticated data bind the generation and ordinal it was sealed under, so the
old ciphertext fails authentication on import. Walks that reach further back
reject the repetition. A writer can equally publish an undecryptable pack, so
this adds nothing to what an authorized writer can already break.

### Links in directory storage (audit #23)

Directory storage treats the stored ciphertext as untrusted, but its location
on the local filesystem is the operator's to manage. The client follows
symbolic links on that path like any other program, so storage reached through
a link works normally. If the storage directory or one of its subdirectories
is replaced by a link to somewhere else, by mistake or by anyone allowed to
write there, the client writes there instead; for example, a push replaces a
file named `HEAD` in the directory the link points to. Keeping that path free
of such links is the operator's responsibility, and the client does not defend
against it.

### Corrupted ciphertext carried forward (audit #13)

A push builds the next carrier commit on top of existing ciphertext without
re-reading it. If storage altered that ciphertext, the alteration is carried
forward. Readers check every object against its content ID and authenticated
encryption, so altered data is detected, never accepted; `verify` checks all of
it on demand. Re-reading all inherited ciphertext on every push would make
pushes scale with repository size, so it is not done. The effect is denial of
service, recovered from the same way as a corrupted `HEAD`.

### Disk exhaustion before authentication (audit #1)

The carrier backend fetches the outer Git branch before it can authenticate
anything, so a hostile host can send large data and fill the local disk. Plain
`git fetch` behaves the same way, and Git offers no client-side limit on what
a fetch receives. This is accepted. Put the cache
(`GIT_REMOTE_E2EE_CACHE_DIR`) on a volume with a quota if this matters.
