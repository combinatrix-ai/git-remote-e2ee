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

From a checkout, use `cargo install --path .` instead. Both binaries must be on
`PATH` for Git to find the helper.

## Keys

`git-e2ee keygen` writes a private device key file. The first key created for a
repository is its administrator. The key path is stored only in local Git
configuration. The key file is never written to the encrypted remote and must
never be committed.

The CLI keeps an administrative continuity pin next to an administrator key,
named `<key-file>.admin-state.json`. Back up that file together with the key.

## Git host as storage (carrier-Git backend)

Any ordinary Git repository can carry the ciphertext: GitHub, GitLab, or a bare
repository. It may be empty or contain unrelated branches. `git-remote-e2ee`
uses its own `git-remote-e2ee` branch.

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

The carrier holds only this outer structure:

```text
refs/heads/git-remote-e2ee
└── e2ee/
    ├── HEAD
    ├── objects/aa/<opaque-id>/00000000
    ├── manifests/bb/<opaque-id>/00000000
```

Ciphertext is split into 32 MiB chunks so it can be stored as ordinary Git
blobs. The host can still observe outer commit times, chunk counts and sizes,
update frequency, and total growth.

Each helper process fetches the carrier branch into a persistent local bare
object cache, then uses a disposable checkout that borrows those cached Git
objects. The cache is shared by helper and `git-e2ee` processes for the same
normalized remote URL. It is stored at
`$XDG_CACHE_HOME/git-remote-e2ee/carrier/<sha256-of-normalized-remote>` or, when
`XDG_CACHE_HOME` is unset, `~/.cache/git-remote-e2ee/carrier/<sha256-of-normalized-remote>`.
Set `GIT_REMOTE_E2EE_CACHE_DIR` to override the parent directory that contains
the per-remote cache directories; tests and isolated runs should set it to a
temporary directory. Fetches are serialized across processes, and each refresh
downloads only missing carrier objects. The cache stores carrier Git objects
and metadata only: no keys, plaintext, or decrypted data.

## Directory as storage (filesystem backend)

A local or mounted directory can hold the encrypted repository:

```console
git-e2ee keygen --output /safe/place/repository.key.json
git-e2ee init \
  --storage /srv/encrypted/example \
  --key /safe/place/repository.key.json

git remote add private 'e2ee::/srv/encrypted/example'
git config remote.private.e2ee-key /safe/place/repository.key.json
git push -u private main
```

Do not point two machines at the same directory through a file-sync service.
Concurrent writers rely on the backend's atomic compare-and-swap, which a sync
service does not provide across machines. Use the carrier-Git backend instead.

## Clone

Supply the key path once:

```console
git -c e2ee.key=/safe/place/carrier.key.json clone \
  'e2ee::git+https://git.example/user/encrypted-carrier.git'
```

The helper saves the path as `remote.origin.e2ee-key` in the new clone. Later
`git fetch`, `git pull`, and `git push` need nothing extra.

## Add a second device

Each device has its own private key, and only the small public device file ever
leaves it. If machine A created the repository, set up machine B like this.
Substitute the repository root printed by A's `keygen`.

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
  --remote https://git.example/user/encrypted-carrier.git \
  --key /safe/place/carrier.key.json \
  --device machine-b.public.json
```

Machine B can then clone with its own key, as shown above.

`device-add --role` grants one of three roles: `read` can clone, fetch, and
pull; `write` adds push access; and `admin` also allows device membership
changes. The default is `write`. For example, add a read-only device with
`--role read`. `device-list` prints the same role names. For the directory
backend, use `--storage <directory>` instead of `--remote <carrier-url>` with
`device-add`, `device-list`, and `device-revoke`.

## Revoke a device

`git-e2ee device-list` prints opaque device IDs. Revoke one with:

```console
git-e2ee device-revoke \
  --remote https://git.example/user/encrypted-carrier.git \
  --key /safe/place/carrier.key.json \
  --device-id <device-id>
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
git-e2ee recover \
  --remote https://git.example/user/encrypted-carrier.git \
  --key /safe/place/carrier.key.json \
  --repo /work/my-clone \
  --remote-name private
```

For a directory backend, use `--storage <directory>` instead of `--remote`.
The local floor is read from
`<repo>/.git/git-remote-e2ee/<remote-name>/state.json`; use the same repository
and remote name that previously fetched or pushed. A fresh clone has no floor,
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
git-e2ee recover \
  --remote https://git.example/user/encrypted-carrier.git \
  --key /safe/place/carrier.key.json \
  --repo /work/my-clone \
  --remote-name private \
  --publish
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
- Shallow and partial clones are not supported. A fresh clone downloads and
  verifies the complete history.

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
from `.staging` into `objects/<prefix>/` on the same filesystem and never
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
