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
modern authenticated encryption, an explicit signed manifest chain, incremental
Git packs, and a backend-neutral compare-and-swap storage contract. In
particular, the carrier-Git backend does not require uploading the entire inner
repository on every update.

## Current features

- Normal Git remote-helper workflow for clone, fetch, pull, and push
- XChaCha20-Poly1305 authenticated encryption for Git packs and manifests
- Ed25519-signed, append-only manifest chain
- Incremental Git packs rather than full repository snapshots
- Client-side fast-forward enforcement and explicit force push
- Atomic stale-writer rejection through compare-and-swap
- Per-client rollback and manifest-fork detection after first observation
- Complete manifest-chain and ciphertext verification
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
    └── manifests/bb/<opaque-id>/00000000
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

It does **not** independently prevent:

- rollback presented to a fresh client;
- equivocation between clients shown different valid histories;
- freezing a client at its last valid state;
- deletion or denial of service by storage;
- destructive changes made by an authorized writer;
- disclosure after the repository key is compromised.

Global rollback and equivocation resistance require gossip or an external
transparency anchor. The current key file is also a single-writer prototype; a
device registry, recovery policy, and key revocation hierarchy are not yet
implemented.

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

- Multi-device writer registry and recovery authorization
- KEK/DEK hierarchy, device envelopes, rotation, and revocation
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
