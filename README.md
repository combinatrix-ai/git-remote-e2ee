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
  <a href="#how-it-compares">How it compares</a>
  · <a href="#quick-start">Quick start</a>
  · <a href="docs/design.md">Design</a>
  · <a href="docs/spec.md">Specification</a>
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

Encrypting Git is not new. File-level tools such as
[`git-crypt`](https://github.com/AGWA/git-crypt) encrypt selected files, and
[`git-remote-gcrypt`](https://github.com/spwhitton/git-remote-gcrypt) has
encrypted whole repositories with GnuPG for years. `git-remote-e2ee` hides the
whole repository like gcrypt, and fixes what makes that painful to live with:

- **Fast: pushes upload only what changed.** A push uploads the new Git pack
  plus a few KB of metadata on every backend: about 9 KB for a one-line
  change in the [benchmark](#performance). With a Git or SFTP backend such as
  GitHub, gcrypt re-uploads the entire encrypted history on every push: 921 MB
  for the same change.
- **Safe: no silent force pushes.** Fast-forward checks run on the client, and
  the storage moves `HEAD` only by compare-and-swap. When two people push at
  once, one wins and the other gets an ordinary rejection. With gcrypt every
  push is effectively a force push, so a push made without pulling first can
  erase someone else's work.
- **No master key: nothing long-lived is shared.** git-crypt protects a
  repository with one symmetric key that every collaborator ends up holding,
  and it cannot revoke anyone. `git-remote-e2ee` creates a fresh random key for
  every push and wraps it separately for each authorized device's own key. An
  administrator can revoke one device without rewriting history, and it
  receives nothing built on top of that revocation.

It also does the rest of what an encrypted remote should:

- **Hides who has access.** Device keys, roles, and membership changes are
  encrypted. Storage sees only a padded device count, rounded up to a power of
  two.
- **Read, write, and admin roles.** Give a CI runner or a reviewer a read-only
  key. Only administrators can add or revoke devices.
- **Detects tampering, rollback, and forks.** A clone that has synced before
  refuses an older or diverging state, and `git-e2ee recover` lets a writer
  continue explicitly after someone corrupts `HEAD`.
- **Behaves like Git.** Branches, tags, remote branch deletion, and explicit
  force pushes all work, and the remote grows only by what you add: 878 MiB
  after five pushes, against 5.2 GiB for gcrypt.
- **Stays light.** A small push needs about 9 MiB of memory and takes about a
  second.
- **Needs nothing else.** Two Rust binaries with all cryptography built in, no
  GnuPG or OpenSSL. Storage can be any Git host (GitHub, GitLab, a bare
  repository) or a local or mounted directory.

Under the hood, Git runs on your machine as usual. The helper encrypts the
packs and refs Git hands it, uploads them as opaque immutable objects, and then
atomically moves one opaque `HEAD` pointer.

## How it compares

There are two kinds of encrypted-Git tools. **File-level tools**, represented
here by [`git-crypt`](https://github.com/AGWA/git-crypt), encrypt the contents
of selected files inside an otherwise normal repository. **Encrypted remotes**,
[`git-remote-gcrypt`](https://github.com/spwhitton/git-remote-gcrypt) and
`git-remote-e2ee`, encrypt the whole repository, history included.

### What the storage host can learn

| | Private repo | `git-crypt` | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|:---:|:---:|:---:|:---:|
| Contents of files you chose to protect | visible | hidden | hidden | hidden |
| Contents of all other files | visible | visible | hidden | hidden |
| File names and directory layout | visible | visible | hidden | hidden |
| Commit messages, authors, and dates | visible | visible | hidden | hidden |
| Branch names and the commit graph | visible | visible | hidden | hidden |
| Which files changed, their sizes, identical files | visible | visible¹ | hidden | hidden |
| When you push, and roughly how much | visible | visible | visible | visible |
| Collaborators | account list | key fingerprints² | count only³ | count only⁴ |

### What each tool can do

| | `git-crypt` | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|:---:|:---:|:---:|
| Normal `clone`, `pull`, and `push` | ○ | ○ | ○ |
| GitHub or GitLab as storage | ○ | ○ | ○ |
| Hosted diffs, review, and search for unencrypted parts | ○ | × | × |
| Encrypt only selected files | ○ | × | × |
| Push uploads only new data | △⁵ | △⁶ | ○ |
| Concurrent pushes can't silently overwrite each other | ○ | ×⁷ | ○ |
| Tampering detected | △⁸ | ○ | ○ |
| No master key | ×⁹ | ○ | ○ |
| Revoke one collaborator | ×¹⁰ | ×¹¹ | ○¹² |
| Roles (read / write / admin) | × | ×¹³ | ○ |
| Detects a rolled-back or forked remote | × | × | △¹⁴ |
| No external dependencies | △¹⁵ | ×¹⁶ | ○ |
| Tags and remote branch deletion | ○ | ○ | ○ |
| Mature, stable format | ○ | ○ | × |
| Cryptography | AES-256-CTR, HMAC-SHA1 SIV | OpenPGP (GnuPG) | XChaCha20-Poly1305, HPKE (X25519), Ed25519 |

○ supported · △ with caveats · × not supported

<details>
<summary>Notes</summary>

1. git-crypt's README states that it does not hide when a file changes, its
   length, or whether two files are identical.
2. In git-crypt's GPG mode, the repository key is encrypted to each user and
   committed under `.git-crypt/`, named by key fingerprint.
3. gcrypt hides recipient key IDs by default (`gpg -R`); the number of
   encrypted-key packets is still observable.
4. The envelope count is padded to the next power of two, with a minimum of
   four, so storage sees only an upper bound on the number of devices. Public
   keys, roles, and membership changes are encrypted, though size patterns may
   suggest a membership change. Do not reuse device keys between repositories.
5. A changed encrypted file becomes a new, unrelated ciphertext blob, so Git
   cannot delta-compress it against the previous version.
6. gcrypt is incremental with its local and rsync backends, but its
   [documentation](https://manpages.debian.org/trixie/git-remote-gcrypt/git-remote-gcrypt.1.en.html)
   says a Git or SFTP backend uploads the entire history on every push, and it
   may repack the remote without warning.
7. Every gcrypt push is effectively a force push. Its explicit-force option
   prevents accidents but does not coordinate concurrent writers.
8. git-crypt authenticates encrypted file contents; file names, history, and
   which files are encrypted are ordinary Git data.
9. A master key here means one long-lived key that every collaborator ends up
   holding. git-crypt uses one symmetric repository key for the life of the
   repository: GPG mode wraps that same key to each user's GPG key, and
   without GPG everyone shares the same exported key file. gcrypt and
   git-remote-e2ee encrypt each push under fresh keys delivered to each
   recipient's own key.
10. git-crypt's README states that it does not support revoking access.
11. A participant can be dropped from `gcrypt.participants`, but gcrypt does
    not document a revocation workflow.
12. Revocation publishes a fresh key without rewriting history. It cannot take
    back data the device already had.
13. gcrypt's recipient list is the local `gcrypt.participants` setting of
    whoever pushes, so any participant who can push decides who can read the
    next state.
14. A clone that has synced before rejects rollback or a diverging history. A
    brand-new clone cannot tell without an external anchor; see
    [Security model](#security-model).
15. git-crypt is a C++ program linked against OpenSSL; GPG mode also needs
    GnuPG.
16. gcrypt is a shell script that requires GnuPG.

</details>

### When another tool is a better fit

- **git-remote-gcrypt**: you want an established tool with a stable format,
  already use GPG, and work alone or can coordinate pushes.
- **A file-level tool such as git-crypt**: only a few files are secret, and you
  want GitHub or GitLab to keep working normally for the rest.
- **An ordinary private repository**: you trust the host and want pull
  requests, search, previews, and CI.

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

## Security model

The storage provider is treated as malicious. `git-remote-e2ee` aims to
guarantee:

- confidentiality of inner contents and Git metadata: files, paths, refs,
  object IDs, authors, and messages;
- authenticity and integrity of every fetched state: only devices with write
  authority under the authenticated policy history can author a state that
  conforming clients accept;
- continuity for a clone that has synced before: it rejects any state older
  than, or diverging from, its continuity floor, the newest state it accepted
  after a complete connectivity check or its own successful push;
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
- a brand-new clone, or a clone that has not synced since, being shown an old
  or forked history, or different clients being shown different histories
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
history already published. See [docs/design.md](docs/design.md) and [docs/spec.md](docs/spec.md)
for the full threat model, and [SECURITY.md](SECURITY.md) to report an issue.

## Performance

Committing is ordinary Git: encryption happens only when you push or fetch.
Small pushes and fetches upload or download only the change, even when GitHub
or another Git host is the storage.

Measured on the Godot repository (867 MiB of history), with a local bare
repository standing in for the Git host, on an Apple M1 Pro with 32 GiB RAM.
Median of three runs; tiny rows are a one-line change, repeated five times.

| | Plain Git | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|---:|---:|---:|
| Initial encryption (to a local directory) | 28.6 s | 11.0 s | 8.1 s |
| Initial push | 28.4 s | 36.6 s | 22.9 s |
| Fresh fetch | 27.7 s | 55.0 s | 40.0 s |
| Tiny commit | 0.09 s | 0.09 s | 0.09 s |
| Tiny push | 0.08 s | 6.5 s | 0.97 s |
| Tiny update (fetch) | 0.07 s | 22.6 s | 0.77 s |
| Data sent per tiny push | 4.5 KB | 921 MB | 8.9 KB |
| Peak memory, initial push | 1.27 GiB | 0.98 GiB | 1.27 GiB |
| Peak memory, tiny push | 37 MiB | 887 MiB | 9 MiB |
| Remote size after five tiny pushes | 891 MiB | 5,272 MiB | 878 MiB |
| Client disk after fresh fetch (`.git` plus cache) | 891 MiB | 1,780 MiB | 1,779 MiB |

With a Git backend, gcrypt sends the whole encrypted history again on every
push, so the remote grows by about the repository size each time.
`git-remote-e2ee` sends the new pack plus a few KB of metadata. On the client,
`git-remote-e2ee` keeps a local cache of the encrypted carrier next to your
repository, which roughly doubles disk use, the same as gcrypt's local copy.
Peak memory for full transfers is dominated by Git's own pack generation. Plain Git
stays faster on small operations because a Git server understands the
repository; an encrypted remote has to verify and decrypt on the client. These
are local measurements without network latency.

To reproduce these numbers, run `scripts/reproduce-benchmark.sh` from a clone
of this repository on macOS or Linux. It fetches the pinned inputs (about
1 GB), runs three rounds, and writes this table plus raw data and environment
details to `bench-results/`. Expect a few hours and about 12 GB of free disk.
[docs/benchmarks.md](docs/benchmarks.md) has the method, a Linux aarch64
cross-check, per-push series, phase breakdown, and caveats.

## FAQ

**What does the GitHub repository look like?**
One branch, `git-remote-e2ee`, holding ciphertext under `e2ee/`. It can live
next to unrelated branches. Do not edit it by hand.

**What if I lose my key?**
If no remaining device has access, the data is gone. There is no recovery
service by design. Keep an offline backup of at least one administrator key and
its `.admin-state.json` file.

**Does revoking a device hide old history from it?**
No. It keeps whatever it could already decrypt. It gets no keys for anything
published on top of the revocation. A writer who never saw the revocation, or
was shown a stale state, could still publish to the old reader set; see
[Security model](#security-model).

**Can I review pull requests?**
Not on the host. Review happens on a machine that has a key: fetch the branch
and diff locally, or give a CI runner its own read-only device key.

**What if someone corrupts `HEAD`?**
Clients refuse it and stop. A writer can then run `git-e2ee recover`, which
shows what it found and continues from the last verified state, or from a newer
legitimate state it discovers in the carrier history. See the
[user guide](docs/guide.md#recover-from-a-broken-head).

**Can the host roll my repository back?**
It can serve old data. A clone that has synced before refuses anything older
than, or diverging from, what it already accepted. A fresh clone, or a clone
that has not synced since a newer state was published, cannot tell yet.

## Status and roadmap

Working today: clone, fetch, pull, and push, including tags and remote branch
deletion; the directory and Git-host backends; incremental pushes and fetches
(the Git-host backend keeps a local cache of the carrier); per-device keys with
read, write, and admin roles; adding and revoking devices; rollback and race
detection; and explicit recovery from a corrupted `HEAD`.

Planned: M-of-N administrator approval, key recovery and replacement, automatic
retry after losing a push race, an S3 conditional-write backend, garbage
collection and compaction, shallow and partial clone, optional
transparency-log anchoring, and an optional file-level mode that encrypts only
selected files while keeping per-device keys and revocation.

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
