# Benchmarks

## Primary Git-backend benchmark: Godot (2026-10-02)

This benchmark compares ordinary Git transport to local bare repositories.
Plain Git uses `file://` with `--no-local`; `git-remote-gcrypt` uses its Git
backend (`gcrypt::file://...`); E2EE uses its carrier-Git backend
(`e2ee::git+file://...`). The initial-encryption row is a separate local
baseline: plain Git pushes to a local bare repository, while gcrypt and E2EE
write through their local-directory backends.

The source was `godotengine/godot` at `00932449c9f372b30301d8b5fdc1be70ec12b5c0`
(default branch only, no tags): 85,678 commits, 14,162 files at HEAD, and
910,290,704 reachable object bytes. The gcrypt helper was checked out at
`a5ff704d071f14b95b6b1fa0caa8cdbf0c6cdadb`; E2EE was built in release mode
from `321f5934613b9b5bb65bf2f9df5a60854423a355`. Each of three rounds used
fresh bare remotes, clients, cache directories, and a temporary GPG home. The
Git clients used `--no-local`, no tags, and no checkout; Git auto-GC,
maintenance, and receive auto-GC were disabled. Each bare receiver used
`receive.unpackLimit=0` so incoming packs remain measurable as packs. The local
carrier receiver also used `attr.tree=refs/heads/git-remote-e2ee`, allowing its
`upload-pack` to read the committed `e2ee/** -delta` attribute. Every tiny
commit replaced one line in the tracked Godot README and was pushed and fetched
before the next. The E2EE pushing clone used one isolated carrier cache, and
its returning clone used a separate initially empty cache which became warm
on the initial clone. `scripts/benchmark-git-backend.sh` contains the complete
harness and prints per-round measurements and medians.
One unrelated periodic helper invocation briefly overlapped a benchmark
round; it was left untouched, so any effect on wall time is unquantified.

Machine: Apple M1 Max (`sysctl machdep.cpu.brand_string`), 10 CPU cores,
64 GiB RAM (`sysctl hw.memsize` = 68,719,476,736 bytes), macOS 27.0 build
26A428. Versions: Git 2.55.0, GnuPG 2.5.24, Rust 1.97.1.

The table shows medians across the three fresh rounds. Bytes are logical
stored/object-database bytes, not packet captures. Initial-encryption bytes
are total bytes stored in each local backend; push bytes are the increase in
the bare remote's `objects/` files; fresh-fetch bytes are the matching remote
object-store size; tiny-update bytes are the remote object bytes introduced by
the preceding push. Tiny-update client growth is listed separately below.
Git object compression and outer/encrypted object layouts differ, so these
logical sizes are useful for this controlled comparison but are not exact wire
traffic. The carrier server-side `attr.tree` setting is available on this
local bare receiver; hosted Git services control their own receive-side Git
configuration, so their absolute timings may differ.

| Phase | Plain Git | `git-remote-gcrypt` Git backend | `git-remote-e2ee` carrier-Git backend |
|---|---:|---:|---:|
| Initial encryption: wall time; stored bytes | 30.190 s; 934,460,946 B | 11.790 s; 921,021,599 B | 14.200 s; 920,636,512 B |
| Initial push: wall time; remote bytes added | 30.150 s; 934,460,946 B | 38.000 s; 921,304,151 B | 29.460 s; 920,777,562 B |
| Fresh fetch: wall time; matching remote object bytes | 28.850 s; 934,460,946 B | 55.650 s; 921,304,151 B | 40.430 s; 920,764,176 B |
| Tiny commit: wall time; remote bytes added | 0.160 s; 0 B | 0.160 s; 0 B | 0.160 s; 0 B |
| Tiny push: median wall time; median remote bytes added per push | 0.080 s; 4,761 B | 6.750 s; 921,315,037 B | 1.230 s; 9,460 B |
| Tiny update: median fetch time; matching remote object bytes per update | 0.060 s; 4,761 B | 24.050 s; 921,315,037 B | 0.890 s; 9,460 B |

Fresh-fetch client object-store growth was 934,460,946 B for plain Git,
1,866,126,567 B for gcrypt, and 944,824,608 B of inner Git objects for E2EE.
Gcrypt's client stores both its outer encrypted objects and the imported inner
Git objects, so this value is not a wire-byte estimate. E2EE's carrier cache
also grew by 920,764,176 B during that fresh fetch. On tiny updates, inner
client object-store growth was 3,357 B / 9,474 B / 4,498 B for plain Git /
gcrypt / E2EE respectively; E2EE's carrier cache received the new encrypted
pack and manifest.

The per-push series shows the first and steady updates separately. Each cell
is median wall time and logical remote object-store growth over the three
rounds:

| Tiny push | Plain Git | gcrypt Git backend | E2EE carrier-Git backend |
|---|---:|---:|---:|
| 1 (first) | 0.180 s / 4,775 B | 7.420 s / 921,307,775 B | 4.380 s / 9,344 B |
| 2 | 0.080 s / 4,762 B | 6.640 s / 921,311,411 B | 1.090 s / 9,407 B |
| 3 | 0.080 s / 4,760 B | 6.780 s / 921,315,037 B | 1.150 s / 9,460 B |
| 4 | 0.080 s / 4,761 B | 6.630 s / 921,318,661 B | 1.220 s / 9,520 B |
| 5 | 0.080 s / 4,759 B | 6.750 s / 921,322,287 B | 1.250 s / 9,578 B |

Returning-clone fetch times and matching remote deltas by update were:

| Tiny update | Plain Git | gcrypt Git backend | E2EE carrier-Git backend |
|---|---:|---:|---:|
| 1 (first) | 0.170 s / 4,775 B | 24.380 s / 921,307,775 B | 0.730 s / 9,344 B |
| 2 | 0.060 s / 4,762 B | 24.000 s / 921,311,411 B | 0.790 s / 9,407 B |
| 3 | 0.070 s / 4,760 B | 24.130 s / 921,315,037 B | 0.910 s / 9,460 B |
| 4 | 0.060 s / 4,761 B | 24.050 s / 921,318,661 B | 0.890 s / 9,520 B |
| 5 | 0.060 s / 4,759 B | 24.050 s / 921,322,287 B | 1.050 s / 9,578 B |

Each gcrypt update added about 921 MiB to the bare remote, consistent with a
full-history encrypted payload per update in this workload. E2EE's first tiny
push took 4.38 s, then warm pushes were 1.09--1.25 s; each added about 9.3--9.6
KiB. E2EE's median update fetch was 0.89 s and downloaded only the matching
new carrier objects. These fetch-byte values are object-store growth, not
packet-level counters. The results are local `file://` measurements, not
GitHub service throughput or network-latency measurements.

The initial-encryption row is the one measured row where E2EE remains slower
than gcrypt: 14.20 s versus 11.79 s. It uses the local-directory backends, not
the carrier Git path. The trace attributes almost all of E2EE's time to the
inner `git pack-objects` operation (about 14.7 s); the carrier-side optimizations
below do not change that local history-packing work.

### Carrier receiver attribute sensitivity probe (2026-10-02)

I repeated the E2EE phases once with `BENCH_ROUNDS=1 BENCH_E2EE_ONLY=1
BENCH_CARRIER_ATTR_TREE=0 BENCH_TRACE=1 BENCH_TINY_COMMITS=5`. This leaves the
local bare carrier receiver's `attr.tree` unset while keeping
`receive.unpackLimit=0`; plain Git and gcrypt were skipped. The probe used the
same Godot and gcrypt revisions above and helper revision
`338d94ef59b8141309355007678e0e0d94a1cbf8`. Its single-run readings are
compared below with the three-round medians above, so small differences include
normal run-to-run noise.

| E2EE phase | `attr.tree` set: 3-round median | `attr.tree` unset: one run |
|---|---:|---:|
| Initial encryption: wall time; stored bytes | 14.200 s; 920,636,512 B | 15.160 s; 920,636,512 B |
| Initial carrier push: wall time; remote bytes added | 29.460 s; 920,777,562 B | 31.080 s; 920,777,562 B |
| Fresh fetch: wall time; matching remote object bytes | 40.430 s; 920,764,176 B | 41.540 s; 920,764,396 B |
| Tiny commit: median wall time across five commits | 0.160 s | 0.150 s |
| Tiny push: median wall time; median remote bytes per push | 1.230 s; 9,460 B | 1.290 s; 9,460 B |
| Tiny update: median fetch; matching remote bytes per update | 0.890 s; 9,460 B | 0.840 s; 9,460 B |

The receiver without `attr.tree` did not make fresh fetch materially slower:
41.54 s versus 40.43 s, a 1.11 s difference in these differently sized
samples. The traced carrier-cache fetch from the remote took 6.72 s; object
reads took 0.40 s for 920.6 MB, decryption took 15.75 s, `index-pack` took
28.34 s, and inner-ref connectivity took 3.15 s. The decryption and
`index-pack` timers overlap. Warm update fetches took 0.80--0.94 s, with remote
cache refresh around 0.08 s and incremental decrypt/import around 0.01--0.02 s.

| Tiny operation | `attr.tree` set: earlier median | `attr.tree` unset: one run |
|---|---:|---:|
| Push 1 | 4.380 s / 9,344 B | 4.160 s / 9,346 B |
| Push 2 | 1.090 s / 9,407 B | 1.170 s / 9,405 B |
| Push 3 | 1.150 s / 9,460 B | 1.290 s / 9,460 B |
| Push 4 | 1.220 s / 9,520 B | 1.260 s / 9,518 B |
| Push 5 | 1.250 s / 9,578 B | 1.370 s / 9,577 B |
| Update fetches 1--5 | 0.730 / 0.790 / 0.910 / 0.890 / 1.050 s | 0.800 / 0.840 / 0.830 / 0.920 / 0.940 s |

No client-side change was warranted by this result. The test client created
the uploaded carrier pack with delta search disabled, and the receiver kept
incoming packs intact with `receive.unpackLimit=0`. The 6.72 s remote fetch
shows no sign of the expensive server-side repack seen in the pre-optimization
profile; pack reuse is the likely explanation, though this run did not
instrument the server's `upload-pack` internals. A Git client cannot set a
hosted server's `upload-pack` configuration; hosted services may choose
different pack reuse and generation behavior. To reproduce the probe, the
harness accepts `BENCH_E2EE_ONLY=1 BENCH_CARRIER_ATTR_TREE=0`.

### Phase profile before and after carrier optimizations

The before figures are a traced single run of the previous implementation;
the after figures are a traced smoke run after the changes. The three-round
medians above are the final benchmark results. Pack decryption and
`index-pack` timers overlap because Git consumes the decrypted stream while it
is being produced; their durations must not be summed.

| Operation | Before: wall and main phases | After: wall and main phases |
|---|---|---|
| Initial carrier push | 181.7 s total; cache remote fetch was small; inner pack 14.5 s; `git add e2ee` 22.7 s; carrier `git push` 143.6 s | 32.1 s total; cache fetch 0.05 s, checkout setup 0.15 s; inner pack/encryption 14.7 s; `git add` 10.3 s; commit 0.17 s; carrier push 5.9 s |
| Fresh E2EE fetch | 178.3 s total; carrier cache fetch 143.1 s; object reads 0.08 s / 920.6 MB; decrypt 15.5 s; `index-pack` 28.2 s; connectivity 3.1 s | 44.0 s total; carrier cache fetch 9.3 s; checkout setup 0.18 s; object reads 0.41 s / 920.6 MB; decrypt 15.8 s; `index-pack` 28.3 s; connectivity 3.1 s |
| First tiny push | 141.0 s total; cache remote fetch 133.9 s; checkout 1.14 s; connectivity 3.55 s; `git add` 1.79 s | 4.84 s total; cache refresh and checkout 0.28 s; connectivity 3.78 s; incremental pack 0.02 s; staging 0.01 s |
| Warm tiny push | 3.03 s total; checkout 1.16 s; refresh 0.12 s; connectivity 0.05 s; `git add` 1.08 s | 1.25 s total; checkout 0.17 s; refresh 0.11 s; connectivity 0.11 s; staging 0.01 s |
| Tiny update fetch | 1.50 s total; cache refresh about 0.14 s; checkout about 1.08 s | 0.89 s median; cache fetch 0.09 s; checkout 0.18 s; chain verification 0.13 s; connectivity 0.06 s; decrypt/import about 0.02 s |

The most effective changes were compression-free carrier Git settings and a
committed `-delta` attribute honored by the local receiver, direct writes of
published objects into the locked cache, and a temporary checkout with an
index but no materialized historical files. Carrier push fell from 143.6 s in
the profile to 5.9 s, cache fetch from 143.1 s to 9.3 s, and the first tiny
push from 141.0 s to 4.84 s. The code keeps a disposable Git directory and
index per helper process rather than sharing a mutable index in the cache.
This avoids cross-process index races while removing the history checkout and
full-tree `git add` scan. Trace can be enabled with
`GIT_REMOTE_E2EE_TRACE=1`; the benchmark passes it and prints per-phase lines
when run with `BENCH_TRACE=1`.

## Earlier local performance benchmarks

These earlier measurements use the local filesystem backend or other
backend-specific scenarios. They are retained as historical comparisons and
are not a substitute for the Git-backend results above.

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

## Earlier comparison with the tools in the feature table

The tools in the README do not all encrypt at the same layer, so one combined
ranking would be misleading. The following are two separate, single-run local
workloads on the same Apple Silicon Mac on 2026-08-16. They are exploratory
measurements, not release thresholds. OS page cache and process startup affect
the results; repeat the harnesses and report medians for stronger claims.

Tool revisions were `git-remote-gcrypt` `a5ff704d071f`, `git-crypt`
`8c7a90ff38fc`, `transcrypt` `1b59c8e505c0`, and `git-remote-e2ee`
`f7ef09c` plus the uncommitted benchmark harnesses described here.

### Earlier whole encrypted remote: Godot (gcrypt local-filesystem backend)

This is the direct comparison. Each whole-remote tool received the same Godot
default-branch history (85,678 commits, 14,162 HEAD files, 867 MiB reachable
data), followed by the same synthetic commits. `git-remote-gcrypt` used its
local-filesystem backend, which its own documentation identifies as an
efficient backend. It does **not** represent the Git backend measured above;
these older numbers cannot establish what gcrypt sends to a Git-hosted remote.

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
