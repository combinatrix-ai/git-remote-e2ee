# Comparison with other encrypted-Git tools

The [README](../README.md#how-it-compares) has the short version. This page
keeps every row and the reasoning behind each mark. Competitor behavior was
checked against each project's own README and manual on 2026-09-30.

There are two kinds of encrypted-Git tools. **File-level tools**, represented
here by [`git-crypt`](https://github.com/AGWA/git-crypt), encrypt the contents
of selected files inside an otherwise normal repository. **Encrypted remotes**,
[`git-remote-gcrypt`](https://github.com/spwhitton/git-remote-gcrypt) and
`git-remote-e2ee`, encrypt the whole repository, history included.

## What the storage host can learn

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

## What each tool can do

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

## Notes

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
    [Security model](security-model.md).
15. git-crypt is a C++ program linked against OpenSSL; GPG mode also needs
    GnuPG.
16. gcrypt is a shell script that requires GnuPG.

## When another tool is a better fit

- **git-remote-gcrypt**: you want an established tool with a stable format,
  already use GPG, and work alone or can coordinate pushes.
- **A file-level tool such as git-crypt**: only a few files are secret, and you
  want GitHub or GitLab to keep working normally for the rest.
- **An ordinary private repository**: you trust the host and want pull
  requests, search, previews, and CI.

