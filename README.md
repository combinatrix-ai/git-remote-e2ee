# git-remote-e2ee

[![CI](https://github.com/combinatrix-ai/git-remote-e2ee/actions/workflows/ci.yml/badge.svg)](https://github.com/combinatrix-ai/git-remote-e2ee/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

End-to-end encrypted Git remotes on storage you do not have to trust with your
repository contents or Git metadata.

`git-remote-e2ee` is a Git remote helper. You keep using ordinary `git clone`,
`git fetch`, `git pull`, and `git push`; the helper turns Git packs and refs into
authenticated ciphertext before they leave the client. The storage provider
sees opaque objects and an opaque latest-manifest pointer, not the inner branch
names, commit IDs, paths, authors, or messages.

> [!WARNING]
> This is an early prototype, not yet a safe backup system. The repository
> format is unstable and there are no compatibility guarantees between
> versions. Keep an independent copy of every repository and key.

The [current implemented v2 design](DESIGN.md) uses a shared epoch key between
per-device envelopes and per-payload keys. The [target protocol](SPEC.md) is a
separate proposal that removes that shared secret and wraps every payload key
directly to each active reader. It is not implemented yet.

## Why this exists

Git hosting normally requires the server to understand the repository. That is
useful for web diffs, pull requests, search, and CI, but it also exposes the
entire object graph and most repository metadata to the host.

`git-remote-e2ee` deliberately gives up server-side Git features. Git semantics
stay on trusted clients, while the server is reduced to two jobs:

1. store immutable ciphertext objects;
2. atomically replace one opaque head value if it has not changed.

This differs from [`git-crypt`](https://github.com/AGWA/git-crypt), which is
designed to encrypt selected files inside an otherwise normal repository. It is
closer to
[`git-remote-gcrypt`](https://github.com/spwhitton/git-remote-gcrypt), but uses
modern authenticated encryption, a signed policy and manifest chain,
per-device keys, incremental Git packs, and a backend-neutral compare-and-swap
storage contract. In
particular, the carrier-Git backend does not require uploading the entire inner
repository on every update.

## Comparison with existing tools

These projects solve two different problems. File-filter tools keep an ordinary
Git repository useful to its host while hiding selected blob contents. Encrypted
remote helpers hide the repository as a whole, which also removes server-side
diffs, pull requests, search, and CI over the plaintext.

| | [`git-crypt`](https://github.com/AGWA/git-crypt) | [`transcrypt`](https://github.com/elasticdog/transcrypt) | [`git-remote-gcrypt`](https://github.com/spwhitton/git-remote-gcrypt) | `git-remote-e2ee` |
|---|---|---|---|---|
| Primary use | Encrypt selected files | Encrypt selected files | Encrypt a complete Git remote | Encrypt a complete Git remote |
| Integration | Git clean/smudge filters | Git clean/smudge filters | Git remote helper | Git remote helper |
| Hidden from host | Selected blob contents | Selected blob contents | Inner objects, refs, and encrypted manifest contents | Inner objects, refs, paths, authors, messages, and manifest contents |
| Host retains normal Git features | Yes, for visible repository data | Yes, for visible repository data | No | No |
| Update granularity | Per encrypted file; a changed encrypted file is stored again | Per encrypted file | Backend-dependent; Git and SFTP backends may retransmit full history | Incremental Git packs on filesystem and carrier-Git backends |
| Integrity model | Git repository integrity plus deterministic encrypted blobs | Git repository integrity plus encrypted blobs | Encrypted and signed manifest; ciphertext-addressed packs | AEAD packs/manifests, signed policy and manifest chains, and per-client history pinning |
| Key and collaborator model | Symmetric key or GPG users | Shared passphrase | GPG participants and symmetric mode | Per-repository device keys; any authorized device can decrypt independently; writers and administrators are separate roles |
| Maturity | Established | Established | Established | Experimental prototype |

The closest comparison is `git-remote-gcrypt`. It already supports participant
management and several transports, making it the more mature choice today.
`git-remote-e2ee` is exploring a different storage protocol: immutable
incremental packs plus an explicit compare-and-swap head, modern AEAD, and a
signed history chain that returning clients pin locally. According to
`git-remote-gcrypt`'s
[`PERFORMANCE` documentation](https://manpages.debian.org/trixie/git-remote-gcrypt/git-remote-gcrypt.1.en.html#PERFORMANCE),
its arbitrary Git and SFTP transports upload the complete repository history on
each push; its rsync backend behaves differently. The comparison is therefore
backend-specific, not a claim that every `git-remote-gcrypt` update is a full
upload.

If you need to protect a few secrets while retaining GitHub or GitLab features,
use a file-filter tool. If the storage provider must not learn the repository
structure or metadata, use a whole-remote encryption design—and, for now, treat
this project as research-grade software.

## Current features

- Normal Git remote-helper workflow for clone, fetch, pull, and push
- Per-device HPKE (X25519/HKDF-SHA-256/ChaCha20-Poly1305) epoch-key envelopes
- Random per-pack and per-manifest keys with XChaCha20-Poly1305 encryption
- Ed25519-signed, append-only policy and manifest chains
- 1-of-N recipient access: each authorized device unlocks with only its own key
- Separate reader, writer, and administrator authorization
- Atomic device revocation, epoch rotation, and pack-key rewrapping without
  re-encrypting pack ciphertext
- Incremental Git packs rather than full repository snapshots
- Client-side fast-forward enforcement and explicit force push
- Atomic stale-writer rejection through compare-and-swap
- Per-client rollback and manifest-fork detection after first observation
- Complete current pack-ciphertext verification plus signed manifest-header and
  policy-chain verification (newly added devices use their add checkpoint for
  encrypted history they were not previously wrapped into)
- Filesystem storage backend
- Carrier-Git backend for GitHub, GitLab, a bare repository, or another ordinary
  Git remote

Push destinations are currently limited to branches under `refs/heads/*`. Tags
and branch deletion are rejected without publishing a new manifest.

## Install

The project currently builds two binaries:

- `git-e2ee`: repository initialization, key generation, and diagnostic CLI
- `git-remote-e2ee`: helper invoked automatically by Git for `e2ee::` URLs

```console
cargo install --path .
git-e2ee --help
```

Both binaries must be on `PATH` for native Git integration.

## Quick start: filesystem backend

Create a repository key and encrypted storage directory:

```console
git-e2ee keygen --output /safe/place/repository.key.json
git-e2ee init \
  --storage /srv/encrypted/example \
  --key /safe/place/repository.key.json
```

Add it to an existing local Git repository:

```console
git remote add private 'e2ee::/srv/encrypted/example'
git config remote.private.e2ee-key /safe/place/repository.key.json
git push -u private main
git fetch private
```

The key path is local Git configuration. The key file is never written to the
encrypted remote and must never be committed.

## Add and revoke devices

Each device has a different private key. Only the small public device file is
given to an administrator. If machine A created the repository, set up machine
B like this (substitute the repository root printed by A's `keygen`):

```console
# Machine B
git-e2ee keygen \
  --repository-root <repository-root> \
  --output /safe/place/machine-b.key.json
git-e2ee device-export \
  --key /safe/place/machine-b.key.json \
  --output machine-b.public.json

# Machine A, after receiving only machine-b.public.json
git-e2ee device-add \
  --storage /srv/encrypted/example \
  --key /safe/place/repository.key.json \
  --device machine-b.public.json
```

The default added device can read and write but cannot change policy. Pass
`--admin` to grant administration too. `git-e2ee device-list` prints opaque
device IDs; revoke one with:

```console
git-e2ee device-revoke \
  --storage /srv/encrypted/example \
  --key /safe/place/repository.key.json \
  --device-id <device-id>
```

For a carrier-Git backend, use `--remote <carrier-url>` instead of `--storage`
with `device-add`, `device-list`, and `device-revoke`.

Adding a device wraps the current epoch key to it and does not rewrite packs.
Revoking a reader creates a new epoch key and rewraps every small pack key in
one compare-and-swap publication; the large encrypted packs stay unchanged.
The CLI keeps an administrative continuity pin next to the administrator key as
`<key-file>.admin-state.json`. Preserve that file together with the key.

This is deliberately **not multisig**. The current implementation accepts one
authorized administrator signature for a policy change. The wire format has an
administrator threshold and signature array so a future version can add M-of-N,
but this version fails closed on any threshold other than 1.

## Carrier-Git backend

An ordinary Git repository can act as the ciphertext carrier. It may be empty
or contain unrelated branches; `git-remote-e2ee` uses its own
`git-remote-e2ee` branch.

```console
git-e2ee keygen --output /safe/place/carrier.key.json
git-e2ee carrier-init \
  --remote https://git.example/user/encrypted-carrier.git \
  --key /safe/place/carrier.key.json

git remote add private \
  'e2ee::git+https://git.example/user/encrypted-carrier.git'
git config remote.private.e2ee-key /safe/place/carrier.key.json
git push -u private main
```

Clone by supplying the key path once:

```console
git -c e2ee.key=/safe/place/carrier.key.json clone \
  'e2ee::git+https://git.example/user/encrypted-carrier.git'
```

The helper persists the path as local `remote.origin.e2ee-key` configuration in
the new clone. Later `git fetch`, `git pull`, and `git push` need no wrapper.

The carrier stores only the outer structure below:

```text
refs/heads/git-remote-e2ee
└── e2ee/
    ├── HEAD
    ├── objects/aa/<opaque-id>/00000000
    ├── manifests/bb/<opaque-id>/00000000
    └── policies/cc/<opaque-id>/00000000
```

Ciphertext is divided into 32 MiB chunks so it can be carried as ordinary Git
blobs. The host can still observe outer commit times, chunk counts and sizes,
update frequency, and total growth.

## Security model

The storage provider is treated as malicious for confidentiality and integrity.
Authenticated encryption, ciphertext-addressed objects, signatures, and the
manifest hash chain detect modification. A returning client pins the newest
manifest it has observed and rejects a lower generation or a history that no
longer descends from that pin.

The current security claim is:

- confidentiality of inner repository contents and Git metadata;
- authenticity and integrity of fetched repository state;
- continuity from the state previously observed by the same local clone.
- forward confidentiality exclusion after an atomic device revocation and
  epoch rotation.

It does **not** independently prevent:

- rollback presented to a fresh client;
- equivocation between clients shown different valid histories;
- freezing a client at its last valid state;
- deletion or denial of service by storage;
- destructive changes made by an authorized writer;
- disclosure of data a revoked device could access before its revocation;
- retroactive disclosure of every epoch ever wrapped to a later-compromised
  device key (the protocol has no forward secrecy for stored history);
- a revoked writer and colluding storage presenting a pre-revocation fork to a
  fresh or stale client;
- policy rollback, freezing, or equivocation presented to a fresh client.

Global rollback and equivocation resistance require gossip or an external
transparency anchor. A returning clone pins both manifest and policy generation.
The administrative CLI also pins its last published state and does not
automatically retry a lost CAS race; inspect the winner and rerun the operation.

Policy objects must remain plaintext-structured so a newly added device can
find its encrypted epoch-key envelope without already knowing that epoch key.
Consequently the storage host can see device count, per-repository public keys,
roles, revocation events, policy generation, and epoch number. Device keys
should never be reused between repositories. Inner refs, object IDs, paths,
authors, messages, pack keys, and contents remain encrypted.

## Storage protocol

The backend-neutral interface has four operations:

```text
put_object_if_absent(kind, id, bytes)
get_object(kind, id)
read_head()
compare_and_swap_head(expected, next)
```

The filesystem backend implements head CAS with an advisory lock and atomic
rename. The carrier-Git backend implements it as a normal fast-forward push to
the outer branch. A future S3 backend can use conditional writes, but each
provider must be capability-tested; “S3 compatible” does not by itself promise
correct compare-and-swap behavior.

See [DESIGN.md](DESIGN.md) for the protocol and threat-model details.

## Tests

```console
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

The test suite includes:

- incremental push and reconstruction into a fresh repository;
- native clone, fetch, pull, push, dry-run, refspec, and force-push behavior;
- rollback, same-generation fork, and ciphertext-tampering rejection;
- independent device add/read/write, non-admin rejection, genesis-substitution
  rejection, administrative rollback pinning, and multi-pack revoke/rewrap;
- two independent carrier writers racing real `git push` processes, with
  exactly one winner;
- plaintext-absence checks across carrier history;
- applicable black-box scenarios independently reimplemented from Git
  upstream's
  [`t/t5801-remote-helpers.sh`](https://github.com/git/git/blob/master/t/t5801-remote-helpers.sh).

A local bare Git repository is sufficient for deterministic carrier concurrency
tests: local-path pushes still execute Git's real `receive-pack`, ref locking,
and fast-forward checks. Hosted smoke tests remain useful for authentication,
request limits, and provider-specific policy.

## Roadmap

- M-of-N administrative authorization (future format version; threshold 1 only today)
- Recovery and device-key replacement workflows
- Automatic stale-push fetch/retry workflow
- Persistent partial-clone cache for large carrier repositories
- S3 conditional-write backend and provider compatibility suite
- Safe compaction and garbage collection
- Optional gossip or transparency-log anchoring
- Shallow and partial clone support

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE), or
- [MIT License](LICENSE-MIT)

at your option.
