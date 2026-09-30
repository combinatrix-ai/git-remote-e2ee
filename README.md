<h1 align="center">git-remote-e2ee</h1>

<p align="center">
  <strong>Git your host can't read.</strong><br />
  End-to-end encrypted Git remotes. Keep using <code>clone</code>, <code>pull</code>, and <code>push</code>;
  GitHub, a NAS, or any other storage only ever holds ciphertext.
</p>

<p align="center">
  <a href="https://github.com/combinatrix-ai/git-remote-e2ee/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/combinatrix-ai/git-remote-e2ee/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="#license"><img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" /></a>
  <img alt="Status: prototype" src="https://img.shields.io/badge/status-prototype-orange.svg" />
</p>

<p align="center">
  <a href="#quick-start">Quick start</a>
  · <a href="#how-it-compares">How it compares</a>
  · <a href="docs/design.md">Design</a>
  · <a href="docs/spec.md">Specification</a>
  · <a href="README.ja.md">日本語</a>
</p>

<p align="center">
  <img src="docs/art/overview.svg" alt="On your devices the repository is ordinary Git; the storage host only holds opaque encrypted objects" width="720" />
</p>

> [!WARNING]
> This is an early prototype. The repository format is unstable and may change
> without a migration path. Do not use it as your only copy of anything: keep an
> independent copy of every repository and every key.

## Why end-to-end encryption?

**"Private" on a Git host means private from other people, not from the host.**
A private GitHub or GitLab repository is stored in a form the provider can read:
every file, every commit message, every branch name, and who wrote what. That is
what lets the host show you diffs and run CI, but it also means your code and
notes are readable by anyone who gets access to the host's side: a breach, a
leaked access token or third-party app, an insider, a legal demand, or a policy
change you did not choose.

**End-to-end encryption (E2EE) moves the keys to your devices.** Your repository
is encrypted on your computer before it is uploaded, and only devices you have
authorized can decrypt it. The host stores data it cannot read. If the host is
breached or compelled to hand over your repository, there is nothing readable
to hand over. If someone tampers with the stored data, your clients notice and
refuse it.

With `git-remote-e2ee` this happens underneath Git. You add a remote with an
`e2ee::` URL and keep working exactly as before.

**Good fits:** personal notes and journals, research before publication, client
or NDA work that must live on third-party storage, private configuration, and
backups on storage you do not control.

**What you give up:** because the host cannot read the repository, it cannot
show it to you either. There are no web diffs, pull-request reviews, code
search, or hosted CI on the plaintext. You are also responsible for your keys:
if every authorized key is lost, the data cannot be recovered by anyone.

## Why git-remote-e2ee

Encrypting a whole Git repository is not new;
[`git-remote-gcrypt`](https://github.com/spwhitton/git-remote-gcrypt) has done
it for years. `git-remote-e2ee` keeps that goal and fixes three things that
make encrypted remotes painful to live with:

- **Fast: pushes upload only what changed.** A push uploads the new Git pack
  plus a little metadata (3–4 KiB in total for a tiny commit with one
  device), on every backend. gcrypt re-uploads the entire history on every push
  to a Git or SFTP backend, and can repack without warning. One caveat today:
  with a Git host as storage, each operation first clones the whole encrypted
  carrier repository, so downloads are not yet incremental there.
- **Safe: no silent force pushes.** Fast-forward checks run on the client, and
  the storage moves `HEAD` only by compare-and-swap. When two people push at
  once, one wins and the other gets an ordinary rejection. With gcrypt every
  push is effectively a force push, so the second push can erase the first.
- **No master key: every device has its own key.** There is no long-lived
  repository password or shared private key to hand around. Each published
  generation gets a fresh random key, delivered separately to each authorized
  device. An administrator adds a device by its public key and revokes it on
  its own, without rewriting history. transcrypt shares one password, and
  git-crypt shares one repository key and does not support revoking access.

Under the hood, Git runs on your machine as usual. The helper encrypts the
packs and refs Git hands it, uploads them as opaque immutable objects, and then
atomically moves one opaque `HEAD` pointer. Storage backends today: a **local
or mounted directory**, and **any ordinary Git remote** (GitHub, GitLab, a bare
repository) used as a ciphertext carrier. The full comparison, including where
other tools are the better choice, is in [How it compares](#how-it-compares).

## Quick start

Install from source (a Rust toolchain is required). This installs both
`git-e2ee`, the setup CLI, and `git-remote-e2ee`, the helper Git calls for
`e2ee::` URLs. Both must be on `PATH`.

```console
cargo install --git https://github.com/combinatrix-ai/git-remote-e2ee
```

Use an empty GitHub repository as encrypted storage and push an existing
project to it:

```console
git-e2ee keygen --output ~/.config/git-e2ee/notes.key.json
git-e2ee carrier-init \
  --remote https://github.com/you/notes-encrypted.git \
  --key ~/.config/git-e2ee/notes.key.json

cd my-notes
git remote add private 'e2ee::git+https://github.com/you/notes-encrypted.git'
git config remote.private.e2ee-key ~/.config/git-e2ee/notes.key.json
git push -u private main
```

From then on, `git pull` and `git push` work as usual. The key file stays on
your machine; never commit it, and keep a backup somewhere safe.

To use a second machine, give it its own key and authorize its public half.
The [user guide](docs/guide.md#add-a-second-device) walks through it, as well as
the directory backend, cloning, and revoking devices.

## How it compares

There are two families of encrypted-Git tools, and they answer different
questions:

- **File filters** ([`git-crypt`](https://github.com/AGWA/git-crypt),
  [`transcrypt`](https://github.com/elasticdog/transcrypt)) encrypt the contents
  of selected files inside an otherwise normal repository. The host still sees
  the repository's structure and history, and keeps working normally for
  everything left unencrypted.
- **Encrypted remotes**
  ([`git-remote-gcrypt`](https://github.com/spwhitton/git-remote-gcrypt),
  `git-remote-e2ee`) encrypt the whole repository, history included. The host
  sees opaque blobs and nothing else of the inner repository.

### What the storage host can learn

| | Private repo | `git-crypt` | `transcrypt` | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|:---:|:---:|:---:|:---:|:---:|
| Contents of files you chose to protect | visible | hidden | hidden | hidden | hidden |
| Contents of all other files | visible | visible | visible | hidden | hidden |
| File names and directory layout | visible | visible | visible | hidden | hidden |
| Commit messages, authors, and dates | visible | visible | visible | hidden | hidden |
| Branch names and the commit graph | visible | visible | visible | hidden | hidden |
| Which files changed, their sizes, identical files | visible | visible¹ | visible | hidden | hidden |
| When you push, and roughly how much | visible | visible | visible | visible | visible |
| Collaborator keys | account list | key fingerprints² | — (shared password) | count only³ | count, public keys, roles⁴ |

### What each tool can do

| | `git-crypt` | `transcrypt` | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|:---:|:---:|:---:|:---:|
| Normal `clone`, `pull`, and `push` | ○ | ○ | ○ | ○ |
| GitHub or GitLab as storage | ○ | ○ | △⁵ | ○ |
| Hosted diffs, review, and search for unencrypted parts | ○ | ○ | × | × |
| Encrypt only selected files | ○ | ○ | × | × |
| Tampering detected | △⁶ | ×⁷ | ○ | ○ |
| No shared secret; add people by public key | ○² | × | ○ | ○ |
| Revoke one collaborator | ×⁸ | × | △⁹ | ○¹⁰ |
| Separate reader, writer, and administrator roles | × | × | × | △¹¹ |
| Concurrent pushes can't silently overwrite each other | ○ | ○ | ×¹² | ○ |
| Small updates upload small amounts of data | △¹³ | △¹³ | △⁵ | ○¹⁶ |
| Detects a rolled-back or forked remote | × | × | × | △¹⁴ |
| Tags and remote branch deletion | ○ | ○ | ○ | ×¹⁵ |
| Mature, stable format | ○ | ○ | ○ | × |
| Cryptography | AES-256-CTR, HMAC-SHA1 SIV | AES-256-CBC via OpenSSL | OpenPGP (GnuPG) | XChaCha20-Poly1305, HPKE (X25519), Ed25519 |

○ supported · △ with caveats · × not supported

1. git-crypt's README states that it does not hide when a file changes, its
   length, or whether two files are identical.
2. In git-crypt's GPG mode, the repository key is encrypted to each user and
   committed under `.git-crypt/`, named by key fingerprint.
3. gcrypt hides recipient key IDs by default (`gpg -R`); the number of
   encrypted-key packets is still observable.
4. Each device must find its own envelope before it can decrypt anything, so
   the policy is plaintext-structured: the host sees the number of devices,
   their per-repository public keys, their roles, and policy changes. Do not
   reuse device keys between repositories.
5. gcrypt is incremental with its local and rsync backends, but its
   [documentation](https://manpages.debian.org/trixie/git-remote-gcrypt/git-remote-gcrypt.1.en.html)
   says a Git or SFTP backend uploads the entire history on every push, and it
   may repack the remote without warning.
6. git-crypt authenticates encrypted file contents; file names, history, and
   which files are encrypted are ordinary Git data.
7. transcrypt uses unauthenticated CBC; its README lists ciphertext
   malleability as a known limitation.
8. git-crypt's README states that it does not support revoking access.
   Rotating the key means re-encrypting the protected files by hand.
9. Participants can be removed from `gcrypt.participants`, but gcrypt does not
   document a revocation workflow.
10. Revocation publishes a fresh key without rewriting history. Like every tool
    here, it cannot take back data the device already had.
11. The protocol separates the three roles, but the CLI currently grants either
    read and write, or read, write, and administration.
12. Every gcrypt push is effectively a force push. Its explicit-force option
    prevents accidents but does not coordinate concurrent writers.
13. A changed encrypted file becomes a new, unrelated ciphertext blob, so Git
    cannot delta-compress it against the previous version.
14. A clone that has synced before rejects rollback or a diverging history. A
    brand-new clone cannot tell without an external anchor; see
    [Security model](#security-model).
15. Pushes are limited to `refs/heads/*` for now. Tag pushes and branch
    deletion fail without publishing anything.
16. Uploads are incremental on every backend. With a Git host as storage, the
    current implementation clones the whole carrier repository for each
    operation, so every fetch and push also downloads the full encrypted
    history until a persistent cache lands.

### Other approaches

- **Keybase encrypted Git** is end-to-end encrypted, but it only works with
  Keybase's own service.
- **An encrypted filesystem under a bare repository** (rclone crypt,
  Cryptomator, gocryptfs) hides contents, but not the repository's file
  structure, sizes, or update pattern. Two machines pushing at once through a
  sync service can also corrupt the repository.
- **git-annex encrypted special remotes** protect large annexed files, not the
  Git history itself.

### When another tool is a better fit

- **git-crypt**: only a few files are secret, and you want GitHub or GitLab to
  keep working normally for the rest.
- **transcrypt**: the same, and a shared password with a simple shell setup is
  acceptable.
- **git-remote-gcrypt**: you want an established whole-repository tool, already
  use GPG, and can use its local or rsync backend.
- **An ordinary private repository**: you trust the host and want pull
  requests, search, previews, and CI.
- **Anything mature**: you need a stable format, recovery tooling, tags, or
  shallow clones today.

Choose `git-remote-e2ee` when the whole repository and its history must be
opaque to storage, each collaborator should hold their own key, and you want
Git's normal conflict behavior on storage you do not trust.

## Security model

The storage provider is treated as malicious. `git-remote-e2ee` aims to
guarantee:

- confidentiality of inner contents and Git metadata: files, paths, refs,
  object IDs, authors, and messages;
- authenticity and integrity of every fetched state;
- continuity for a clone that has synced before, so rollback and forks are
  rejected;
- that revoked devices get no keys for anything published after revocation.

It does **not** prevent:

- the host deleting data or refusing service;
- a brand-new clone being shown an old or forked history, or different clients
  being shown different histories (that needs an external anchor, which is on
  the roadmap);
- an authorized writer making destructive changes;
- a revoked device reading what it could read before revocation;
- traffic analysis: update times, object sizes, and total growth are visible;
- future quantum attacks: key exchange uses X25519.

Keys work as a backward chain. The current key can decrypt all earlier
history, which lets a new device read the whole repository, but an old key
cannot decrypt anything newer. This is key regression, not forward secrecy for
history already published. See [docs/design.md](docs/design.md) and [docs/spec.md](docs/spec.md)
for the full threat model, and [SECURITY.md](SECURITY.md) to report an issue.

## Performance

Full transfers take about as long as plain Git, and small updates stay fast.
On a local-filesystem backend with the 867 MiB Godot history, measured in a
single run:

| Operation | Plain Git | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|---:|---:|---:|
| Initial push | 30.51 s | 12.26 s | 13.78 s |
| Fresh fetch | 30.26 s | 30.78 s | 31.75 s |
| Tiny push | 0.17 s | 0.54 s | 0.08 s |
| Fetch tiny update | 0.12 s | 0.50 s | 0.09 s |

Plain Git is not directly comparable. A Git server indexes objects and builds
packs per fetch, while encrypted remotes store and replay opaque packs. That is
cheap on dumb storage, but it rules out server-side features such as partial
clone. Each update stores only its new pack plus metadata: 3–4 KiB in total with one
device, growing to roughly 30 KiB per update at 100 readers. Adding a reader
rewrote zero existing pack bytes. These numbers are for the directory backend;
the Git-carrier backend currently re-clones the carrier on each operation. See [docs/benchmarks.md](docs/benchmarks.md) for
the method, the remaining cases, and the limitations.

## FAQ

**What does the GitHub repository look like?**
One branch, `git-remote-e2ee`, holding ciphertext under `e2ee/`. It can live
next to unrelated branches. Do not edit it by hand.

**What if I lose my key?**
If no remaining device has access, the data is gone. There is no recovery
service by design. Keep an offline backup of at least one administrator key and
its `.admin-state.json` file.

**Does revoking a device hide old history from it?**
No. It keeps whatever it could already decrypt. It cannot read anything
published after the revocation.

**Can I review pull requests?**
Not on the host. Review happens on a machine that has a key: fetch the branch
and diff locally, or give a CI runner its own device key.

**Can the host roll my repository back?**
It can serve old data. A clone that has synced before detects this and refuses
it. A fresh clone cannot tell yet.

**Is this post-quantum?**
No. An attacker who records ciphertext today and later breaks X25519 could read
it.

## Status and roadmap

Working today: clone, fetch, pull, and push; the directory and carrier-Git
backends; per-device keys; adding and revoking devices; incremental transfer;
and rollback and race detection.

Planned: M-of-N administrator approval, key recovery and replacement, automatic
retry after losing a push race, an S3 conditional-write backend, garbage
collection and compaction, tags and branch deletion, shallow and partial clone,
and optional transparency-log anchoring.

## Documentation

- [User guide](docs/guide.md): backends, cloning, device management, and the
  storage layout
- [docs/design.md](docs/design.md): design overview and threat model
- [docs/spec.md](docs/spec.md): normative protocol specification
- [docs/benchmarks.md](docs/benchmarks.md): benchmark method and results
- [docs/durability.md](docs/durability.md): crash and power-loss guarantees of the filesystem backend
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing, and what the test
  suite covers

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or
the [MIT License](LICENSE-MIT), at your option.
