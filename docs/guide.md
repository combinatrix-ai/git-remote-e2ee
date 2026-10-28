# User guide

This guide covers everyday use. For why the tool exists and how it compares to
alternatives, see the [README](../README.md). For the protocol, see
the [design overview](design.md) and the [specification](spec.md).

## Install

The project builds two binaries:

- `git-e2ee`: key generation, repository setup, device management, and
  diagnostics
- `git-remote-e2ee`: the remote helper Git runs automatically for `e2ee::` URLs

```console
cargo install --git https://github.com/combinatrix-ai/git-remote-e2ee
git-e2ee --help
```

On AArch64 (Apple Silicon or 64-bit Arm Linux), the ChaCha20 dependency selects
its NEON backend automatically, including for `cargo install --git` builds.
Other architectures use the backend selected for their target.

From a checkout, use `cargo install --path .` instead. Both binaries must be on
`PATH` for Git to find the helper.

## Storage URLs

An `e2ee::` URL is followed by the storage address:

| URL | Storage |
|---|---|
| `e2ee::https://host/you/repo.git`, `e2ee::git@host:you/repo.git`, `e2ee::ssh://…`, `e2ee::file://…`, `e2ee::/srv/repo.git` | A Git repository used as carrier. Anything `git push` accepts. |
| `e2ee::dir:/srv/encrypted/example` | A directory (filesystem backend). |

A relative path is resolved against the directory the command runs in, and the
helper saves the absolute form in the remote's configuration.

## Keys

`git-e2ee keygen` writes a private device key file, by default to
`$XDG_CONFIG_HOME/git-e2ee/keys/<repository-root>.json`. The first key created for a
repository is its administrator. The key path is stored only in local Git
configuration. The key file is never written to the encrypted remote and must
never be committed.

The CLI keeps an administrative continuity pin per repository root at
`$XDG_STATE_HOME/git-e2ee/<repository-root>/admin-state.json` (by default under
`~/.local/state`). Moving or renaming the key file keeps the pin. Back up that
file together with the key.

Inside a Git repository, the continuity pin is likewise kept per repository
root at `.git/git-remote-e2ee/<repository-root>/state.json`, not per Git remote
name. Renaming a remote or adding a second remote for the same encrypted
repository keeps rollback protection. Every remote for one repository root
shares one floor, so a mirror that lags behind the newest state you have seen
is reported as rolled back.

## Git host as storage (carrier-Git backend)

Any ordinary Git repository can carry the ciphertext: GitHub, GitLab, or a bare
repository. `git-remote-e2ee` stores everything on one branch, `main` by
default. Append `#<branch>` to the URL to use another branch, for example
`e2ee::https://git.example/user/notes.git#vault`. Initialization refuses a
branch that already exists, such as the `main` a hosting provider creates
with an initial README; use an empty repository or pick another branch. Other
branches of the repository are never touched.

Run `init` inside the repository you want to protect:

```console
git-e2ee init https://git.example/user/encrypted-carrier.git
git push -u origin main
```

`init` creates an administrator key at
`$XDG_CONFIG_HOME/git-e2ee/keys/<repository-root>.json` (default `~/.config`),
initializes the storage, adds it as the Git remote `origin`, and records the key
as `remote.origin.e2ee-key`. If `origin` already exists, `init` stops before
creating anything; pick another name with `--name private`. Pass
`--key <path>` to use an existing key or to create the new key elsewhere. Run
outside a Git repository, `init` only creates the key and the storage.

The carrier holds only this outer structure:

```text
refs/heads/main
├── README.md        plaintext notice: encrypted repository, do not edit
├── FORMAT           "git-remote-e2ee storage 6"
├── .gitattributes   "* -delta"
├── HEAD
├── packs/aa/<opaque-id>/00000000
└── manifests/bb/<opaque-id>/00000000
```

The directory backend uses the same root layout without `.gitattributes`.
`FORMAT` names the storage layout version so an incompatible client stops with
a clear message instead of an authentication failure. It is not
authenticated; integrity still comes from the signed manifests.

Ciphertext is split into 32 MiB chunks so it can be stored as ordinary Git
blobs. The host can still observe outer commit times, chunk counts and sizes,
update frequency, and total growth.

Each helper process fetches the carrier branch into a persistent local bare
object cache, then uses a disposable checkout that borrows those cached Git
objects. The cache is shared by helper and `git-e2ee` processes for the same
normalized remote URL and carrier branch. It is stored at
`$XDG_CACHE_HOME/git-remote-e2ee/carrier/<sha256-of-remote-and-branch>` or, when
`XDG_CACHE_HOME` is unset, `~/.cache/git-remote-e2ee/carrier/<sha256-of-remote-and-branch>`.
Set `GIT_REMOTE_E2EE_CACHE_DIR` to override the parent directory that contains
the per-remote cache directories; tests and isolated runs should set it to a
temporary directory. Fetches are serialized across processes, and each refresh
downloads only missing carrier objects. The cache stores carrier Git objects
and metadata only: no keys, plaintext, or decrypted data.

## Directory as storage (filesystem backend)

A local or mounted directory can hold the encrypted repository:

```console
git-e2ee init e2ee::dir:/srv/encrypted/example
git push -u origin main
```

Do not point two machines at the same directory through a file-sync service.
Concurrent writers rely on the backend's atomic compare-and-swap, which a sync
service does not provide across machines. Use the carrier-Git backend instead.

## Clone

Supply the key path once:

```console
git -c e2ee.key=/safe/place/notes.key.json clone \
  'e2ee::https://git.example/user/encrypted-carrier.git'
```

The helper saves the path as `remote.origin.e2ee-key` in the new clone. Later
`git fetch`, `git pull`, and `git push` need nothing extra.

## Add a second device

Each device has its own private key, and only the small public device file ever
leaves it. If machine A created the repository, set up machine B like this.
Substitute the repository root printed by A's `keygen`.

```console
# Machine B
git-e2ee keygen --repository-root <repository-root>
git-e2ee device-export \
  --key ~/.config/git-e2ee/keys/<repository-root>.json \
  --output machine-b.public.json

# Machine A, inside its clone, after receiving only machine-b.public.json
git-e2ee device-add origin machine-b.public.json
```

Commands that act on existing storage (`verify`, `device-add`, `device-list`,
`device-revoke`, `recover`) take a target. Inside a clone it can be a Git remote
name such as `origin`, and the URL and key come from that remote's
configuration. Anywhere, it can be a storage URL with `--key`:

```console
git-e2ee device-list e2ee::https://git.example/user/encrypted-carrier.git \
  --key /safe/place/notes.key.json
```

Machine B can then clone with its own key, as shown above.

`device-add --role` grants one of three roles: `read` can clone, fetch, and
pull; `write` adds push access; and `admin` also allows device membership
changes. The default is `write`. For example, add a read-only device with
`--role read`. `device-list` prints the same role names.

## Revoke a device

`git-e2ee device-list` prints opaque device IDs. Revoke one with:

```console
git-e2ee device-revoke origin <device-id>
```

Adding or revoking a device publishes a fresh generation key in a single
compare-and-swap. The new generation carries one small envelope per active
reader, and all historical manifests and packs stay unchanged. A newly added
device can use the current key's authenticated backward links to decrypt the
complete history. A revoked device keeps what it could already decrypt, but it
receives no key for the new generation or any later one.

Membership changes need one administrator signature. This is deliberately
**not multisig** yet: the wire format has an administrator threshold and a
signature array so a future version can add M-of-N approval, but this version
refuses any threshold other than 1.

The administrative CLI does not retry automatically when it loses a
compare-and-swap race. Inspect the winning state and run the command again.

## Recover from a broken HEAD

If a storage writer replaces `HEAD` with an invalid manifest, normal fetches
and pushes stop. Run recovery from a Git repository that has already pinned a
known good state for that remote. The default command prints a report and does
not publish or advance the continuity floor:

```console
cd /work/my-clone
git-e2ee recover origin
```

The local floor is read from
`<repo>/.git/git-remote-e2ee/<repository-root>/state.json`; use a repository
that previously fetched or pushed. The remote name does not matter. A fresh clone has no floor,
so recovery reports that freshness and fork identity are unverified and will
not publish.

Review the offered manifest IDs, generations, verified signers, replays, and
any fork report. Recovery is allowed only when the current head is demonstrably
invalid. It refuses valid, unverifiable, unsupported, unavailable, and
discontinuous heads. A signer extracted from an invalid head is labelled only
as a claim until its signature is verified. Read-only devices can inspect the
report but cannot publish recovery.

To publish from the default base, add `--publish`:

```console
git-e2ee recover origin --publish
```

The default base is the newest authenticated descendant found after the local
floor, or the floor if there is no descendant. Recovery refuses conflicting
authenticated descendants. Selecting an older offered base requires both
`--base <manifest-id>` and `--discard-newer`; this can omit legitimate changes
or a revocation. A lost compare-and-swap fails. Start a new command and review
the fresh report before trying again.

The directory backend has no carrier commit history, so it can offer only the
local floor. Publishing requires `--accept-stale-floor` and prints this warning:

> Updates after this floor may be omitted. This may also omit revocations and
> disclose subsequently published content to devices excluded by a newer
> policy.

Carrier recovery restores required ciphertext from prior outer commits when
available, checks each content ID, verifies the selected refs' complete Git
object graph in temporary local storage, then publishes a normal fast-forward
carrier commit. If required ciphertext is no longer available, recovery stops.
After successful recovery, run the usual `git fetch` or `git pull` to update
your local remote-tracking refs.

## Limits today

- Pushes support branches under `refs/heads/*` and tags under `refs/tags/*`;
  other namespaces are rejected. Branches keep fast-forward checks, while an
  existing tag needs `--force` to move. Branch and tag deletion publish a new
  encrypted generation without a pack. The helper advertises `main` as the
  default branch while it exists, so it refuses to delete `refs/heads/main`.
- After deleting a remote ref, use `git fetch --prune --prune-tags` on a
  returning clone to remove its stale local remote-tracking branch or tag.
- A push that loses a race with another writer fails. Fetch, integrate, and
  push again.
- A new or deleted local carrier cache downloads the complete carrier branch.
  Later operations reuse its objects and fetch only new carrier objects.
  `GIT_REMOTE_E2EE_CACHE_DIR` overrides the cache parent directory.
- Recovery discovery has fixed limits of 2,048 carrier commits, 256 distinct
  heads, 64 MiB of manifest data, and 1,000,000 estimated cryptographic
  operations. It fails closed if any limit is exhausted.
- Shallow and partial clones are not supported. Pushing from a shallow
  repository is refused before anything is published; run
  `git fetch --unshallow` first. A fresh clone downloads and verifies the
  complete history.

## Storage contract

Backends implement four logical operations. Immutable object writes are staged
so the final ciphertext ID can be learned while streaming:

```text
begin_object(kind) -> writable stage; stage.finish(id)
open_object(kind, id) -> reader
read_head()
compare_and_swap_head(expected, next)
```

The filesystem backend implements head compare-and-swap with an advisory lock
and a rename in the storage root. Object publication hard-links a staged file
from `.staging` into `packs/<prefix>/` on the same filesystem and never
replaces an existing ID. File contents are flushed before a name is published,
new directories are flushed through the preexisting ancestor, and the parent
directory is flushed again afterwards; a flush error fails the call. Crash and
power-loss limits are in [durability.md](durability.md). The carrier-Git
backend implements compare-and-swap as a normal fast-forward push to the outer
branch. A future S3 backend can use multipart upload plus conditional writes,
but each provider must be capability-tested: "S3 compatible" does not by itself
promise correct compare-and-swap behavior.

A killed filesystem writer can leave an unreachable file under `.staging/`.
Nothing published points to it, and stale `.stage-*` entries may be deleted
when no writer is running. Automatic cleanup belongs to future garbage
collection.
