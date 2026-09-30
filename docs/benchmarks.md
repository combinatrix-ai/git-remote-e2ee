# Local performance benchmarks

The benchmark is opt-in and never runs in CI. It measures the release binaries
against a real Git repository using an isolated filesystem backend:

```console
scripts/benchmark-local.sh /path/to/source/repository
```

To compare the filesystem backend with a local bare Git remote, run:

```console
scripts/benchmark-comparison.sh /path/to/source/repository
```

The repository also includes two opt-in competitor harnesses. They require
separate local checkouts/builds of the named projects and do not install or
modify those tools globally:

```console
scripts/benchmark-gcrypt.sh /path/to/source/repository /path/to/git-remote-gcrypt
scripts/benchmark-file-filters.sh /path/to/git-crypt /path/to/transcrypt
```

The comparison benchmark sends the exact same commit sequence to both remotes:
an initial push, a tiny change, an incompressible 10 MiB file, a one-byte
modification of that file, and 1,000 unique small files. After the initial
transfer it adds a second E2EE reader, proves
that every existing pack is byte-for-byte unchanged, and fetches the complete
history with only the new reader's private key. Later updates are also fetched
by that new reader. Each push is followed by a fetch into a returning client.
The script records wall time, peak RSS, and both logical and allocated
remote/client disk growth. Git automatic maintenance is disabled so
asynchronous commit-graph or repack work cannot move the disk measurements
after a phase completes.

The script creates a transport clone through `file://` with `--no-local`,
removes its `origin`, and keeps every key, encrypted remote, and reconstructed
repository in a temporary directory. It never checks out the source's files and
never contacts the source repository's configured remotes.

Measured phases are initial push, fresh fetch, full verification, a one-commit
incremental push containing one small synthetic blob, and returning-client
fetch. Results contain only aggregate
sizes, counts, wall time, and peak resident memory. Raw command output and keys
remain in the temporary directory and are deleted by default. Set
`BENCH_KEEP_WORK=1` only when local debugging is necessary; never publish that
directory.

On macOS the script uses `/usr/bin/time -l`; on Linux it uses GNU
`/usr/bin/time -v`. Peak RSS includes the Git subprocesses used for pack creation
and import. Results are single-run measurements and should not be treated as
stable CI thresholds. For comparisons, run at least three times with fresh
temporary directories and report the median.

The v4 format streams each pack through 1 MiB authenticated segments between
Git and backend-owned staged storage. The Rust process therefore uses bounded
pack memory. Peak RSS for push and fetch still includes Git's `pack-objects` and
`index-pack` children, whose own memory scales with the repository and Git
configuration; verification has no Git child and shows the crypto/storage
streaming floor directly.

## Reference run: large private notes repository

On 2026-08-14 the v4 release-profile binary was measured three times on an
Apple Silicon Mac with 32 GiB RAM and Rust 1.95.0. The isolated source contained
2,620 commits and 59,648 Git objects; its reachable packed data occupied about
1.238 GiB. The initial encrypted filesystem remote occupied about 1.178 GiB.
It is smaller because `pack-objects` created a fresh single pack with different
delta-compression opportunities than the source's existing four-pack layout;
the difference is not compression performed by encryption. Values below are
medians from three fresh temporary work directories:

| Phase | Wall time | Peak RSS | Approx. ciphertext throughput |
|---|---:|---:|---:|
| Initial push and encryption | 13.52 s | 1.25 GiB | 89.2 MiB/s |
| Fresh fetch, decryption, and import | 17.00 s | 607.0 MiB | 71.0 MiB/s |
| Full verification | 6.61 s | 4.67 MiB | 182.5 MiB/s |
| Incremental push (one small blob) | 0.09 s | 8.45 MiB | — |
| Returning-client fetch | 0.24 s | 79.5 MiB | — |

The incremental encrypted pack was about 986 bytes. All runs reconstructed the
expected ref and passed `git fsck --full`. Compared with the immediately prior
v3 measurements on the same machine and nearly identical source, median peak
RSS fell from 3.54 GiB to 1.25 GiB for initial push (about 65%), from 2.37 GiB
to 607 MiB for fresh fetch (about 75%), and from 2.36 GiB to 4.67 MiB for full
verification (more than 99%). The remaining large push/fetch peaks come from
Git's pack creation and import rather than whole-pack buffers in the Rust
implementation.

These numbers are a workload-specific reference, not a performance guarantee.
Returning-client fetch still performs a full Git connectivity walk, so its cost
grows with reachable history even when the encrypted delta is tiny.

`phases.tsv` records phase name, wall seconds, peak RSS bytes, allocated storage
bytes, and logical storage bytes. `summary.json` records aggregate environment,
source, pack-count, and storage-size metadata.

## Single-run comparison with large public repositories

On 2026-08-16 the comparison benchmark was run once per repository on the same
Apple Silicon Mac, using Rust 1.95.0, the release profile, and crate commit
`f7ef09c`. Only each default branch was cloned, without tags. These are
deliberately single-run exploratory results, not stable thresholds or medians:

| Repository | Source HEAD | Commits | HEAD files | Reachable data |
|---|---|---:|---:|---:|
| `godotengine/godot` | `00932449c9f3` | 85,678 | 14,162 | 867 MiB |
| `rust-lang/rust` | `67854e511de2` | 336,609 | 62,013 | 926 MiB |
| `kubernetes/kubernetes` | `a231bf3f3776` | 140,375 | 31,300 | 1.16 GiB |

Initial transfers show that streaming encryption does not add another
whole-pack memory copy. Initial push RSS is effectively the same as Git's and
is dominated by `pack-objects`; E2EE fresh-fetch RSS is lower in all three
runs. The E2EE push does less receiver-side Git processing because the
untrusted backend stores opaque objects rather than indexing plaintext Git
objects, so its local-filesystem time is not a network-server throughput claim.

| Repository | Initial push Git / E2EE | Push RSS Git / E2EE | Remote write Git / E2EE | Fresh fetch Git / E2EE | Fetch RSS Git / E2EE |
|---|---:|---:|---:|---:|---:|
| Godot | 30.51 / 13.78 s | 1,301 / 1,331 MiB | 890 / 877 MiB | 30.26 / 31.75 s | 1,321 / 601 MiB |
| Rust | 75.77 / 34.28 s | 2,058 / 2,050 MiB | 1,031 / 970 MiB | 73.70 / 63.19 s | 2,064 / 1,429 MiB |
| Kubernetes | 45.46 / 22.38 s | 1,770 / 1,771 MiB | 1,234 / 1,203 MiB | 46.76 / 50.21 s | 1,771 / 1,053 MiB |

The initial reconstructed client's allocated disk was effectively equal for
Godot (904 MiB each), 1,034 MiB for Git versus 1,082 MiB for E2EE on Rust, and
1,235 MiB versus 1,266 MiB on Kubernetes. Those 0--4.6% differences come from
pack/index layout rather than an additional plaintext checkout; both clients
are non-bare Git repositories with empty working trees.

Adding a second reader was independent of repository history size in these
runs. The policy transition generated a new key and two recipient envelopes,
but did not create or rewrite a content pack:

| Repository | `device-add` time | Peak RSS | Remote logical growth | New-reader full fetch | Fetch peak RSS | New client disk |
|---|---:|---:|---:|---:|---:|---:|
| Godot | 0.03 s | 2.73 MiB | 3,379 bytes | 31.73 s | 577 MiB | 904 MiB |
| Rust | 0.03 s | 2.73 MiB | 3,379 bytes | 62.75 s | 1,439 MiB | 1,082 MiB |
| Kubernetes | 0.03 s | 2.75 MiB | 3,379 bytes | 47.01 s | 1,052 MiB | 1,267 MiB |

Before and after `device-add`, the benchmark compares a sorted list containing
every pack path and SHA-256 digest. All three repositories matched exactly, so
roughly 0.9--1.2 GiB of prior ciphertext remained byte-for-byte unchanged. The
new reader nevertheless reconstructed the complete history using only its own
private key. Its full-fetch cost is therefore similar to any other fresh fetch
and scales with content/history, while the administrative operation itself does
not.

With two active readers, later manifests were about 304--305 bytes larger than
the corresponding single-reader run. This is the expected per-generation
recipient-envelope cost: metadata grows linearly with active readers, while
pack storage remains independent of reader count.

### Scaling to 100 active readers

The Godot workload was repeated with one administrator and 99 collaborators,
added through 99 sequential policy transitions. `BENCH_TOTAL_READERS=100`
enables this mode. Every pre-existing pack path and SHA-256 digest still matched
after all additions, and the 100th reader fetched the complete history and all
later updates using only its own private key.

The result is bounded and practical at 100 readers, but it is not literally
constant. The immutable content is independent of reader count; policy and
recipient-envelope work is not:

| Operation | 2 active readers | 100 active readers |
|---|---:|---:|
| Last `device-add` | 0.03 s, 3,379 bytes | 0.12 s, 82,827 bytes |
| New reader full fetch | 31.73 s, 577 MiB RSS | 37.45 s, 575 MiB RSS |
| Returning tiny fetch | 3.24 s, 526 MiB RSS | 3.50 s, 528 MiB RSS |
| New client allocated disk | 904 MiB | 904 MiB |
| Existing pack rewrite | 0 bytes | 0 bytes |

Adding readers 2 through 100 took 6.42 seconds in total and retained 4.07 MiB
of logical policy/manifest metadata (4.45 MiB allocated). The 100th individual
transition was still small, but the history of adding readers one at a time is
quadratic in aggregate metadata: each immutable policy generation repeats a
larger device list and each manifest repeats a larger envelope list. This does
not multiply content packs.

Push timing also depends on the client path. The direct diagnostic
`git-e2ee push` has no clone-local continuity pin, so it deliberately validates
the complete 100-generation chain on every push. It took 3.12--3.54 seconds in
this run. Normal Git usage goes through `git-remote-e2ee`; set
`BENCH_E2EE_PUSH_MODE=native` to benchmark that path. Its first push after 99
unobserved membership changes spent 3.25 seconds catching its continuity pin
up once. Later steady-state pushes were:

| Update | 2 readers, direct CLI | 100 readers, native Git |
|---|---:|---:|
| Add incompressible 10 MiB | 0.40 s | 0.65 s |
| Add 1,000 small files | 0.34 s | 0.60 s |

At 100 readers each later manifest added about 32.5 KiB, roughly 29 KiB more
than the two-reader run. Peak push RSS stayed small (about 17--29 MiB after the
one-time catch-up), and remote growth remained the new Git pack plus that small
manifest. Thus reader count does not affect bulk encryption, pack storage, or
client repository size, while HPKE envelope creation adds about 0.25 seconds
and tens of KiB per generation at 100 readers on this machine.

Incremental push time stayed below one second for every case. Logical remote
growth was approximately 1.4--1.6 KiB for Git versus 3.1--3.3 KiB for E2EE for
the tiny commit, 10,244.5--10,244.7 KiB versus 10,246.4--10,246.5 KiB for the
10 MiB file, and about 110.2 KiB versus 79.3 KiB for the 1,000-file commit.
Pack compression and framing differ, so the smaller side is workload-dependent;
the useful result is that growth remains proportional to new objects rather
than repository size.

| Repository | Tiny push Git / E2EE | 10 MiB push Git / E2EE | 1,000-file push Git / E2EE |
|---|---:|---:|---:|
| Godot | 0.17 / 0.08 s | 0.60 / 0.40 s | 0.56 / 0.34 s |
| Rust | 0.37 / 0.08 s | 0.62 / 0.40 s | 0.59 / 0.36 s |
| Kubernetes | 0.25 / 0.08 s | 0.58 / 0.39 s | 0.50 / 0.34 s |

Before verified-frontier connectivity was implemented, the clear bottleneck
was returning-client fetch. E2EE performed a full connectivity walk after
importing even a tiny encrypted delta, so the difference grew with history
size:

| Repository | Tiny returning fetch Git / E2EE | E2EE peak RSS |
|---|---:|---:|
| Godot | 0.08 / 3.24 s | 526 MiB |
| Rust | 0.35 / 19.65 s | 1,436 MiB |
| Kubernetes | 0.26 / 6.62 s | 1,053 MiB |

Adding 10 MiB or 1,000 files barely changed those old E2EE returning-fetch
times. This identified history traversal, rather than AEAD throughput or delta
size, as the dominant incremental-read cost.

The implementation now persists the exact ref tips that passed connectivity
verification. A returning fetch requires those frontier tips to remain local
and asks `rev-list` to inspect only objects newly reachable beyond them. A
missing or legacy frontier still triggers a full walk, and the signed-ref
without-pack attack test now exercises and passes through the incremental path.

Godot was rerun once with the optimization and the additional one-byte-change
scenario. Initial/fresh operations remained unchanged within single-run noise:
initial E2EE push was 14.32 seconds, fresh fetch was 31.86 seconds, and a new
reader's full fetch was 31.70 seconds. Returning fetch changed substantially:

| Godot returning update | Plain Git | E2EE before | E2EE verified frontier |
|---|---:|---:|---:|
| Tiny commit | 0.12 s | 3.24 s | 0.09 s |
| Add incompressible 10 MiB | 0.58 s | about 3.2 s | 0.23 s |
| Change one byte in 10 MiB | 0.37 s | not measured | 0.23 s |
| Add 1,000 small files | 0.08 s | about 3.2 s | 0.10 s |

Peak E2EE RSS for those returning fetches was 39--40 MiB, down from 526 MiB
for the old Godot tiny-fetch path. The reconstructed clients still resolved to
the expected final ref and passed `git fsck --full`; the encrypted remote also
passed full authenticated-object verification. Rust and Kubernetes have not
yet been rerun with this optimization, so their old values above remain useful
as the before baseline rather than a claim about current performance.

All six reconstructed clients (Git and E2EE for each repository) resolved to
the expected synthetic final commit and passed `git fsck --full`; every E2EE
remote also passed full authenticated-object verification. Rust's upstream
history produced two pre-existing `badFilemode` warnings in both reconstructed
clients, without verification failure.

Remote logical growth is a useful approximation for local-backend write volume,
not a direct network-byte measurement. Filesystem allocation is also recorded
in the raw TSV. Results can be affected by OS page cache and local filesystem
behavior; repeat at least three times and report medians before making release
claims.

An earlier pass exposed raw Git's detached post-receive automatic maintenance:
remote metadata could grow between two otherwise read-only measurement phases.
The results above are the clean rerun after disabling `receive.autogc` and
automatic client maintenance. The tables report operation time and immediate
per-push logical delta so phase boundaries remain explicit.

## Comparison with the tools in the feature table

The tools in the README do not all encrypt at the same layer, so one combined
ranking would be misleading. The following are two separate, single-run local
workloads on the same Apple Silicon Mac on 2026-08-16. They are exploratory
measurements, not release thresholds. OS page cache and process startup affect
the results; repeat the harnesses and report medians for stronger claims.

Tool revisions were `git-remote-gcrypt` `a5ff704d071f`, `git-crypt`
`8c7a90ff38fc`, `transcrypt` `1b59c8e505c0`, and `git-remote-e2ee`
`f7ef09c` plus the uncommitted benchmark harnesses described here.

### Whole encrypted remote: Godot

This is the direct comparison. Each whole-remote tool received the same Godot
default-branch history (85,678 commits, 14,162 HEAD files, 867 MiB reachable
data), followed by the same synthetic commits. `git-remote-gcrypt` used its
local-filesystem backend, which its own documentation identifies as an
efficient backend. This does **not** represent its arbitrary Git or SFTP
transport, for which its documentation warns that complete history may be
uploaded on each push.

| Metric | Plain Git | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|---:|---:|---:|
| Initial push | 30.51 s | 12.26 s | 13.78 s |
| Initial push peak RSS | 1,301 MiB | 1,006 MiB | 1,331 MiB |
| Initial remote write | 890 MiB | 877 MiB | 877 MiB |
| Fresh fetch | 30.26 s | 30.78 s | 31.75 s |
| Fresh fetch peak RSS | 1,321 MiB | 581 MiB | 601 MiB |
| Tiny push | 0.17 s | 0.54 s | 0.08 s |
| Incompressible 10 MiB push | 0.60 s | 0.66 s | 0.40 s |
| 1,000-small-file push | 0.56 s | 0.69 s | 0.34 s |

The result is narrower than a feature-only comparison might suggest:
gcrypt's local backend is essentially tied with E2EE for initial transfer.
E2EE is faster for these incremental pushes. Before verified-frontier
connectivity, gcrypt's returning fetches were also much faster. After the
optimization, the same update classes took 0.50/0.64/0.47 seconds in gcrypt
versus 0.09/0.23/0.10 seconds in E2EE for tiny/10 MiB/1,000-file fetches.
These are separate single runs and not stable percentage claims, but the old
full-history connectivity bottleneck is no longer present on this workload.

The gcrypt remote grew by about 1.7 KiB, 10.01 MiB, and 67.2 KiB for the three
updates. E2EE grew by about 3.2 KiB, 10.01 MiB, and 79.3 KiB. Both local
backends therefore stored incremental data rather than rewriting the 877 MiB
history. Backend choice matters: these gcrypt numbers must not be generalized
to its Git-hosted transport.

### Selected encrypted files: filter microbenchmark

`git-crypt` and `transcrypt` leave the repository itself visible and encrypt
only matching blobs during `git add`. Running them on every object in the
Godot history would measure a different product contract, so the harness uses
a fresh ordinary Git repository with one selected 10 MiB random file and
1,000 selected 1 KiB random files. It measures filter staging plus a push to a
local bare Git remote. A fresh clone is then unlocked and byte-compared with
the plaintext inputs. The committed blobs are also checked to differ from the
plaintext blob ID, and both clones pass `git fsck --full`.

| Operation | `git-crypt` | `transcrypt` |
|---|---:|---:|
| Add 10 MiB: stage + push | 1.14 s | 1.76 s |
| Add 10 MiB: remote logical growth | 10.00 MiB | 10.52 MiB |
| Change one byte in that file: stage + push | 1.27 s | 2.00 s |
| One-byte change: remote logical growth | 10.00 MiB | 10.52 MiB |
| Add 1,000 small files: stage + push | 20.03 s | 143.94 s |
| 1,000 files: remote logical growth | 1.06 MiB | 1.12 MiB |
| Fresh clone + unlock | 29.64 s | 380.18 s |
| Peak RSS across measured filter phases | 74.8 MiB | 92.0 MiB |

For large individual files the filter cost is modest. File count is the more
important result: clean/smudge process startup dominates 1,000 small files,
especially for transcrypt. Filter tools also destroy plaintext similarity
before Git stores the selected blob: in this un-repacked local remote, a
one-byte plaintext change added another complete ciphertext-sized object.
That behavior is inherent to per-file ciphertext, although later Git
maintenance and filesystem compression can change allocated-disk results.

These numbers should not be read as saying that a whole-remote helper is
universally faster. The filter tools preserve host-side diffs and normal Git
features for everything not selected, use little memory, and avoid encrypting
unselected history. Conversely, their shared-secret and metadata-hiding models
are not substitutes for E2EE's per-device whole-repository design.
