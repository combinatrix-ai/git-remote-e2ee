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

The implemented v4 protocol gives every published generation a fresh random
root key. Each active reader receives one small public-key envelope for that
generation; pack ciphertext is stored only once, independent of reader count,
and is authenticated in bounded-memory 1 MiB segments.
See the [design overview](DESIGN.md) and [normative specification](SPEC.md).

## The problem this project solves

Ordinary Git hosting must understand a repository to provide web diffs, pull
request review, search, and hosted CI. Even a private repository therefore
reveals its files, paths, branches, commit graph, authors, and messages to the
host.

`git-remote-e2ee` is for the different case where the storage provider should
learn none of that, while trusted clients still need ordinary Git semantics. It
keeps encryption, history validation, fast-forward checks, and conflict
handling on clients. The server is reduced to two jobs:

1. store immutable ciphertext objects;
2. atomically replace one opaque head value if it has not changed.

The project also addresses collaboration without a repository-wide private key
or passphrase. Every device has its own key, administrators can add or revoke a
device without rewriting historical packs, readers and writers can have
different permissions, and concurrent writers cannot silently overwrite each
other.

This tradeoff is intentional: a host that cannot read the repository also
cannot provide meaningful plaintext diffs, search, or review by itself.

## Comparison with existing tools

File-filter tools and encrypted remote helpers solve different problems.
[`git-crypt`](https://github.com/AGWA/git-crypt) and
[`transcrypt`](https://github.com/elasticdog/transcrypt) hide selected files in
an otherwise normal repository. [`git-remote-gcrypt`](https://github.com/spwhitton/git-remote-gcrypt)
and `git-remote-e2ee` hide the complete inner repository.

Legend: **○** supported, **△** supported with caveats or extra setup, **×** not
supported.

| What you can do | `git-crypt` | `transcrypt` | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|:---:|:---:|:---:|:---:|
| Hide the complete repository from the host | × | × | ○ | ○ |
| Encrypt only selected files | ○ | ○ | × | × |
| Use GitHub or GitLab as storage | ○ | ○ | △¹ | ○ |
| Keep using normal `clone`, `pull`, and `push` | ○ | ○ | ○ | ○ |
| Keep a hosted pull-request workflow | ○² | ○² | △² | △² |
| See encrypted-content diffs on the host | × | × | × | × |
| Run CI after explicitly providing a key | △ | △ | △ | △ |
| Avoid distributing one shared passphrase or private key | ○³ | × | ○ | ○ |
| Add a collaborator using only their public key | ○³ | × | ○ | ○ |
| Revoke one collaborator independently | △⁴ | × | ○ | ○ |
| Add a collaborator without rewriting bulk history | ○ | ○ | ○ | ○ |
| Separate reader, writer, and administrator roles | × | × | × | ○ |
| Reject concurrent-writer races without silent overwrite | ○ | ○ | ×⁵ | ○ |
| Transfer only incremental data for small updates | △⁶ | △⁶ | △¹ | ○ |
| Detect a storage rollback or fork after a prior sync | × | × | × | ○⁷ |
| Branches | ○ | ○ | ○ | ○ |
| Tags and remote branch deletion | ○ | ○ | ○ | ×⁸ |
| Established, production-mature project | ○ | ○ | ○ | △ |

1. gcrypt is incremental with its local and rsync backends. Its
   [performance documentation](https://manpages.debian.org/trixie/git-remote-gcrypt/git-remote-gcrypt.1.en.html#PERFORMANCE)
   warns that arbitrary Git and SFTP backends may upload the complete history
   on every push.
2. File-filter repositories retain normal hosted review for visible data, but
   the host cannot show plaintext diffs for encrypted files. A whole-remote
   workflow needs an authorized client or CI job to decrypt and produce an
   inner diff; the carrier repository's own diff is not meaningful.
3. This refers to git-crypt's GPG-user mode. It still uses an internal
   repository key, encrypted separately to each GPG recipient.
4. Revoking a git-crypt user requires rotating the repository key and
   re-encrypting the protected files.
5. gcrypt has a longstanding behavior where pushes are effectively force
   pushes; its explicit-force option prevents accidental use but does not add
   compare-and-swap writer coordination.
6. A changed encrypted file becomes a new complete ciphertext blob, so Git
   cannot efficiently delta-compress it against the previous plaintext.
7. A returning E2EE client pins observed history and rejects rollback or a
   different successor chain. A fresh client still needs an authenticated
   invitation checkpoint or an external anchor.
8. The current E2EE implementation accepts destinations under
   `refs/heads/*`; tag pushes and branch deletion fail without publication.

### Performance snapshot

Whole-remote tools were measured once against the same 867 MiB reachable Godot
history using local-filesystem backends. These are exploratory measurements,
not stable release claims or network-hosting benchmarks:

| Operation | Plain Git | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|---:|---:|---:|
| Initial push | 30.51 s | 12.26 s | 13.78 s |
| Fresh fetch | 30.26 s | 30.78 s | 31.75 s |
| Tiny push | 0.17 s | 0.54 s | 0.08 s |
| Add incompressible 10 MiB | 0.60 s | 0.66 s | 0.40 s |
| Add 1,000 small files | 0.56 s | 0.69 s | 0.34 s |
| Fetch tiny update | 0.12 s | 0.50 s | 0.09 s |
| Fetch 10 MiB update | 0.58 s | 0.64 s | 0.23 s |
| Fetch 1,000-file update | 0.08 s | 0.47 s | 0.10 s |

Selected-file tools use a different workload and should not be ranked directly
against whole-remote encryption:

| Operation | `git-crypt` | `transcrypt` |
|---|---:|---:|
| Encrypt and push 10 MiB | 1.14 s | 1.76 s |
| Encrypt and push 1,000 small files | 20.03 s | 143.94 s |
| Fresh clone and unlock | 29.64 s | 380.18 s |

See [BENCHMARKS.md](BENCHMARKS.md#comparison-with-the-tools-in-the-feature-table)
for method, memory, disk growth, tool revisions, and limitations.

## When another tool is a better fit

- Use **git-crypt** when only a few files are secret and retaining normal
  GitHub or GitLab diffs, reviews, search, and integrations for the rest of the
  repository matters more than hiding the repository as a whole.
- Use **transcrypt** when selected-file encryption with a shared passphrase is
  acceptable and its simple shell-based setup is preferable.
- Use **git-remote-gcrypt** when you need an established whole-remote tool,
  already use GPG, and can use its efficient local or rsync backend while
  accepting its force-push and periodic-repack behavior.
- Use an ordinary **private Git repository** when you trust the host with the
  plaintext and need first-class hosted pull requests, code search, previews,
  or CI without managing decryption keys.
- Do **not** use git-remote-e2ee as the only backup yet. Choose a mature tool if
  you require stable repository formats, recovery tooling, tags, branch
  deletion, shallow clones, or a production support commitment today.

Choose `git-remote-e2ee` when the complete repository and its metadata must be
opaque to storage, collaborators should use independent device keys, membership
changes must not rewrite bulk history, and incremental synchronization plus
client-side rollback and writer-race protection are worth giving up server-side
plaintext features.

## Current features

- Normal Git remote-helper workflow for clone, fetch, pull, and push
- Per-device HPKE (X25519/HKDF-SHA-256/ChaCha20-Poly1305) generation-key envelopes
- A fresh random generation root for every successful HEAD publication
- Domain-separated HKDF subkeys and XChaCha20-Poly1305 payload encryption
- Streaming authenticated pack encryption and decryption with bounded Rust-side
  memory rather than whole-pack buffers
- Incremental Git connectivity verification from a locally pinned, previously
  verified ref frontier
- Ed25519-signed, append-only policy and manifest chains
- 1-of-N recipient access: each authorized device unlocks with only its own key
- Separate reader, writer, and administrator authorization
- Atomic device addition and revocation without rewriting historical packs
- An authenticated backward key chain: the current key unlocks earlier
  generations, while an earlier key cannot unlock later generations
- Delta manifests and incremental Git packs rather than full repository snapshots
- Client-side fast-forward enforcement and explicit force push
- Atomic stale-writer rejection through compare-and-swap
- Per-client rollback and manifest-fork detection after first observation
- Complete signed history, ciphertext, and reconstructed Git object-graph
  verification before refs or continuity pins move
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

Adding or revoking a device publishes a fresh generation key in one
compare-and-swap operation. Its header contains one small envelope for each
active reader, while all historical manifests and packs stay unchanged. A newly
added reader can use the current key's authenticated backward links to decrypt
the complete history. A revoked reader retains the snapshot it could already
decrypt but receives no key for the new generation or later ones.
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
- future-generation exclusion after an atomic device revocation.

It does **not** independently prevent:

- rollback presented to a fresh client;
- equivocation between clients shown different valid histories;
- freezing a client at its last valid state;
- deletion or denial of service by storage;
- destructive changes made by an authorized writer;
- disclosure of data a revoked device could access before its revocation;
- disclosure of the complete historical snapshot at or before any leaked
  generation key;
- a revoked writer and colluding storage presenting a pre-revocation fork to a
  fresh or stale client;
- policy rollback, freezing, or equivocation presented to a fresh client.

Global rollback and equivocation resistance require gossip or an external
transparency anchor. A returning clone pins both manifest and policy generation.
The administrative CLI also pins its last published state and does not
automatically retry a lost CAS race; inspect the winner and rerun the operation.

Generation headers and policy objects must remain plaintext-structured so a
device can find its envelope without already knowing the generation key.
Consequently the storage host can see device count, per-repository public keys,
roles, policy changes, and generation numbers. Device keys should never be
reused between repositories. Inner refs, object IDs, paths, authors, messages,
generation keys, derived subkeys, and contents remain encrypted.

A generation key is intentionally a transferable snapshot capability: leaking
`K_t` exposes generations `0..=t` through the backward links. It does not expose
generation `t+1` or later. Continued future disclosure therefore requires a
reader's private device key, repeated release of each later generation key or
plaintext, or continued access to an authorized device. This is key regression,
not forward secrecy for already published history.

If two authorized writers race, each may locally create a valid generation key
and ciphertext, but compare-and-swap permits only one HEAD update. The loser
must discard its unpublished generation and retry from the winning HEAD. Anyone
who received the loser's key can decrypt that losing unpublished snapshot; CAS
prevents it from becoming repository history but cannot retract already shared
plaintext or keys.

## Storage protocol

The backend-neutral interface has four logical operations. Immutable object
writes are staged so the final ciphertext ID can be learned while streaming:

```text
begin_object(kind) -> writable stage; stage.finish(id)
open_object(kind, id) -> reader
read_head()
compare_and_swap_head(expected, next)
```

The filesystem backend implements head CAS with an advisory lock and atomic
rename. Stages are created inside the backend's own filesystem or checkout, so
publication does not depend on cross-filesystem rename. The carrier-Git backend
implements head CAS as a normal fast-forward push to the outer branch. A future
S3 backend can use multipart upload plus conditional writes, but each provider
must be capability-tested; “S3 compatible” does not by itself promise correct
compare-and-swap behavior.

A killed filesystem writer can leave an unreachable file under `.staging/`.
No published object or `HEAD` points to it, and stale `.stage-*` entries may be
deleted when no writer is running. Automatic age-based cleanup belongs to
future garbage collection.

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
- streaming-AEAD chunk boundaries, wrong keys/AAD, reordering, duplication,
  truncation, trailing bytes, forged sizes, and legacy-format rejection;
- independent device add/read/write, non-admin rejection, genesis-substitution
  rejection, administrative rollback pinning, device revocation without pack
  rewrites, and multi-generation offline catch-up;
- malformed predecessor-link, generation-key commitment, recipient-set, and
  signed-but-incomplete Git object-graph rejection;
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
- Signed checkpoint transitions for compaction without ambiguous key-chain semantics
- Optional gossip or transparency-log anchoring
- Shallow and partial clone support

## Performance benchmarks

An opt-in local harness measures initial encryption, fresh reconstruction,
verification, and incremental updates without contacting the source
repository's configured remote. See [BENCHMARKS.md](BENCHMARKS.md). Benchmark
outputs, repository keys, and reconstructed data must not be committed.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE), or
- [MIT License](LICENSE-MIT)

at your option.
