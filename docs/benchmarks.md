# Benchmarks

## Reproduce

From a fresh clone on macOS or Linux, run:

```sh
./scripts/reproduce-benchmark.sh
```

The first run downloads about 1 GB for Godot's full default-branch history and
the pinned gcrypt source. Keep free temporary disk space of about 12 times the
Godot `.git` size. The default three-round run takes hours. Results go to
`./bench-results/<UTC timestamp>-<host>/` and include raw and median TSV files,
`environment.json`, and a README-format `summary.md`.

On Linux, the work directory defaults to `/var/tmp` because `/tmp` may be
tmpfs. The runner detects the selected filesystem and refuses tmpfs or ramfs.
Set `TMPDIR` to a disk-backed temporary directory, or set
`BENCH_WORK_PARENT` to a disk-backed path under `/var/tmp` or `TMPDIR`.

The fresh-fetch client-disk row totals the client .git directory and any
auxiliary cache or state.

## Latest reproduce run (2026-10-08)

The README table comes from this run of `scripts/reproduce-benchmark.sh` with
its defaults (three rounds, five tiny commits), at e2ee `971894a` with no
uncommitted changes, on an Apple M1 Max with 64 GiB RAM, macOS 27.0, and
Git 2.56.0. The runner's `summary.md`:

| | Plain Git | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|---:|---:|---:|
| Initial encryption (to a local directory) | 30.3 s | 12.0 s | 8.9 s |
| Initial push | 30.3 s | 37.6 s | 23.9 s |
| Fresh fetch | 28.0 s | 53.5 s | 38.0 s |
| Tiny commit | 0.16 s | 0.16 s | 0.16 s |
| Tiny push | 0.09 s | 6.8 s | 1.2 s |
| Tiny update (fetch) | 0.07 s | 24.3 s | 0.84 s |
| Data sent per tiny push | 4.8 KB | 921 MB | 9.5 KB |
| Peak memory, initial push | 1.27 GiB | 0.96 GiB | 1.27 GiB |
| Peak memory, tiny push | 37 MiB | 887 MiB | 9 MiB |
| Remote size after 5 tiny pushes | 891 MiB | 5,272 MiB | 878 MiB |
| Total client disk after fresh fetch (.git + auxiliary cache/state) | 891 MiB | 1,780 MiB | 1,779 MiB |

The machine was shared with other work during the run (load average about
7-16 on 10 cores), so individual timings carry some noise. The sections below
record earlier runs and the investigation that led here.

## Primary Git-backend benchmark: Godot (2026-10-03)

This compares plain Git over `file://` with `--no-local`, `git-remote-gcrypt`
using its Git backend (`gcrypt::file://...`), and E2EE using its carrier-Git
backend (`e2ee::git+file://...`). Initial encryption is a separate local
backend baseline: plain Git pushes to a local bare repository, while gcrypt
and E2EE use their local-directory backends.

The source was `godotengine/godot` at `00932449c9f372b30301d8b5fdc1be70ec12b5c0`
(default branch only, no tags): 85,678 commits, 14,162 files at HEAD, and
910,290,704 reachable object bytes. The gcrypt helper was at
`a5ff704d071f14b95b6b1fa0caa8cdbf0c6cdadb`; the E2EE release binary was built
from `7036a37dda4eea16195e19429e5a5807ebd37858`. Each of three rounds used
fresh bare remotes, clients, cache directories, and a temporary GPG home. Git
auto-GC, maintenance, and receive auto-GC were disabled. The bare receivers
used `receive.unpackLimit=0`; the carrier receiver also used
`attr.tree=refs/heads/git-remote-e2ee`, so it could read the committed
`e2ee/** -delta` attribute. The E2EE push and returning-client caches were
isolated per round under the temporary benchmark directory. Each tiny commit
replaced one line in Godot's tracked README and was pushed and fetched before
the next. See `scripts/benchmark-git-backend.sh` for the complete harness.

Machine: Apple M1 Max (10 CPU cores), 64 GiB RAM (`sysctl hw.memsize` =
68,719,476,736 bytes), macOS 27.0 build 26A428. Versions: Git 2.55.0, GnuPG
2.5.24, Rust 1.97.1.

The harness wraps every measured command in macOS `/usr/bin/time -l` (or GNU
`/usr/bin/time -v` on Linux). Peak RSS is the platform-reported maximum for
that command and its waited-for children, where supported; it is not the sum
of concurrent process RSS. Logical directory size sums regular-file lengths.
Allocated size uses `du -sk` in 1 KiB blocks. `Remote / stored L/A` is logical
and allocated MiB for the local storage directory or bare remote after the
phase. `Client .git L/A` is the whole client Git directory after the phase.
`Auxiliary state / cache L/A` is gcrypt's `.git/remote-gcrypt` state or the
whole isolated E2EE cache; `—` means not applicable. The byte column is the
logical object-store increase for pushes and tiny updates, the stored amount
for initial encryption, and the remote object-store reference size for fresh
fetch. Fetch rows also include client object-store growth in the final column.
These are filesystem/object-database measurements, not packet-level wire
counts. Gcrypt's client `.git` contains both encrypted carrier objects and
imported inner Git objects. The sizes are workload-specific and the local
`file://` timings do not predict GitHub server throughput.
The harness processes used only run-specific caches under the temporary
benchmark directory. A separate short-lived Git helper against the default
user cache appeared in process listings during the run; it was left untouched,
and any timing effect from that concurrent activity is unquantified.

Medians across three fresh rounds; repository sizes are MiB (`L/A` = logical /
allocated). The byte column remains exact bytes.

| Phase | Transport | Time | Peak RSS | Object/stored bytes | Remote / stored L/A | Client `.git` L/A | Auxiliary state / cache L/A | Client object growth B |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Initial encryption | Plain Git | 31.97 s | 1302.70 MiB | 934,460,946 | 891.20 / 903.80 | 892.77 / 904.83 | — | — |
| Initial encryption | gcrypt | 13.38 s | 983.23 MiB | 921,021,599 | 878.35 / 878.36 | 892.77 / 904.84 | — | — |
| Initial encryption | E2EE | 10.08 s | 1302.02 MiB | 920,636,512 | 877.99 / 880.02 | 892.77 / 904.85 | — | — |
| Initial push | Plain Git | 32.91 s | 1301.84 MiB | 934,460,946 | 891.20 / 903.42 | 892.77 / 904.86 | — | — |
| Initial push | gcrypt | 41.11 s | 983.28 MiB | 921,304,151 | 878.65 / 881.59 | 1771.39 / 1785.52 | — | — |
| Initial push | E2EE | 25.76 s | 1304.09 MiB | 920,777,562 | 878.15 / 880.31 | 1771.39 / 1785.53 | 878.18 / 892.33 | — |
| Fresh fetch | Plain Git | 30.83 s | 1306.02 MiB | 934,460,946 | 891.20 / 903.42 | 891.20 / 903.25 | — | 934,460,946 |
| Fresh fetch | gcrypt | 56.70 s | 886.61 MiB | 921,304,151 | 878.65 / 881.59 | 1779.70 / 1784.19 | 0.00 / 0.00 | 1,866,126,563 |
| Fresh fetch | E2EE | 41.09 s | 886.42 MiB | 920,764,311 | 878.15 / 880.31 | 901.08 / 903.70 | 878.14 / 878.37 | 944,824,608 |
| Tiny commit | Plain Git | 0.19 s | 13.53 MiB | 0 | 891.21 / 903.44 | 1771.41 / 1785.24 | — | — |
| Tiny commit | gcrypt | 0.19 s | 13.53 MiB | 0 | 2635.91 / 2656.59 | 1771.41 / 1785.24 | — | — |
| Tiny commit | E2EE | 0.19 s | 13.53 MiB | 0 | 878.17 / 880.34 | 1771.41 / 1785.24 | 878.20 / 892.42 | — |
| Tiny push (median) | Plain Git | 0.10 s | 37.47 MiB | 4,762 | 891.21 / 903.45 | 1771.41 / 1785.24 | — | — |
| Tiny push (median) | gcrypt | 7.29 s | 887.44 MiB | 921,315,032 | 3514.54 / 3548.37 | 1771.42 / 1785.27 | — | — |
| Tiny push (median) | E2EE | 1.47 s | 37.91 MiB | 9,462 | 878.18 / 880.36 | 1771.42 / 1785.27 | 878.21 / 892.47 | — |
| Tiny update (median) | Plain Git | 0.08 s | 37.33 MiB | 4,762 | 891.21 / 903.45 | 891.21 / 903.30 | — | 3,359 |
| Tiny update (median) | gcrypt | 25.41 s | 886.67 MiB | 921,315,032 | 3514.54 / 3548.37 | 1779.73 / 1784.28 | 0.00 / 0.00 | 9,472 |
| Tiny update (median) | E2EE | 1.04 s | 39.03 MiB | 9,462 | 878.18 / 880.36 | 901.10 / 903.74 | 878.16 / 878.51 | 4,499 |

The size pairs are rounded to 0.01 MiB. Gcrypt's auxiliary state was 78 B
logical / 4,096 B allocated after fresh fetch and 312 B / 4,096 B after tiny
update; both display as `0.00 / 0.00 MiB` above. Compared with the prior
published run, E2EE's warm tiny-push and tiny-update medians moved from 1.23 s
/ 0.89 s to 1.47 s / 1.04 s. This is an observed difference across separate
three-round runs; the independent helper activity described above overlapped
the latest run, so its cause is unmeasured.

The per-push medians below include wall time, peak RSS, and logical bytes
added to the bare remote (for fetches, remote bytes associated with that
update followed by client object-store growth). RSS is MiB.

| Tiny push | Plain Git: time / RSS / remote bytes | gcrypt Git: time / RSS / remote bytes | E2EE carrier Git: time / RSS / remote bytes |
|---|---:|---:|---:|
| 1 (first) | 0.20 s / 37.3 MiB / 4,776 | 8.06 s / 887.1 MiB / 921,307,778 | 5.20 s / 522.3 MiB / 9,345 |
| 2 | 0.10 s / 37.9 MiB / 4,760 | 7.38 s / 887.1 MiB / 921,311,401 | 1.32 s / 38.0 MiB / 9,405 |
| 3 | 0.10 s / 37.9 MiB / 4,762 | 7.21 s / 887.1 MiB / 921,315,032 | 1.35 s / 37.9 MiB / 9,462 |
| 4 | 0.10 s / 37.9 MiB / 4,763 | 7.47 s / 887.2 MiB / 921,318,660 | 1.47 s / 37.9 MiB / 9,522 |
| 5 | 0.10 s / 38.0 MiB / 4,759 | 7.27 s / 887.2 MiB / 921,322,283 | 1.53 s / 37.9 MiB / 9,577 |

| Tiny update fetch | Plain Git: time / RSS / remote bytes / client growth | gcrypt Git: time / RSS / remote bytes / client growth | E2EE carrier Git: time / RSS / remote bytes / client growth |
|---|---:|---:|---:|
| 1 (first) | 0.18 s / 37.4 MiB / 4,776 / 3,358 B | 25.95 s / 887.0 MiB / 921,307,778 / 9,010 B | 0.89 s / 39.0 MiB / 9,345 / 4,498 B |
| 2 | 0.08 s / 37.3 MiB / 4,760 / 3,359 B | 25.20 s / 887.0 MiB / 921,311,401 / 9,241 B | 0.92 s / 39.0 MiB / 9,405 / 4,500 B |
| 3 | 0.08 s / 37.3 MiB / 4,762 / 3,359 B | 25.33 s / 887.1 MiB / 921,315,032 / 9,472 B | 1.04 s / 39.1 MiB / 9,462 / 4,499 B |
| 4 | 0.09 s / 37.3 MiB / 4,763 / 3,359 B | 25.50 s / 887.1 MiB / 921,318,660 / 9,706 B | 1.04 s / 39.0 MiB / 9,522 / 4,501 B |
| 5 | 0.08 s / 37.3 MiB / 4,759 / 3,356 B | 25.41 s / 887.1 MiB / 921,322,283 / 9,927 B | 1.15 s / 39.1 MiB / 9,577 / 4,498 B |

In the 2026-10-03 run, gcrypt added about 921 MiB to the remote on each tiny
push. E2EE's first tiny push took 5.20 s and used 522.3 MiB peak RSS. Later
pushes took 1.32 to 1.53 s, used about 38 MiB, and added 9.3 to 9.6 KiB.
E2EE's median tiny push and fetch were below 1.5 s and 1.1 s, respectively.

#### First-push follow-up (2026-10-08)

Commit `f4526d8` advances the verified refs after a local publication only
when the client's previous refs already match its verified set and the local
repository is neither shallow nor promisor-enabled. This removes the full
history connectivity walk from the first tiny push after an initial push.

Both samples used the pinned Godot history, one round, and three tiny commits.
The before sample ran E2EE only. The after sample ran all three backends.

| Tiny push | Before fix time | Before fix peak RSS | After fix time | After fix peak RSS |
|---|---:|---:|---:|---:|
| 1 | 4.33 s | 528.0 MiB | 1.10 s | 8.97 MiB |
| 2 | 1.08 s | 37.7 MiB | 1.17 s | 8.84 MiB |
| 3 | 1.14 s | 37.7 MiB | 1.32 s | 8.81 MiB |

A separate pre-fix trace spent 3,335 ms in `git_ref_connectivity_walk` on
push 1. A post-fix trace checked zero objects in that walk and spent 71 ms
there. The Mac's one-minute load average was 11.87 on 10 cores before the
after run. These are single-round follow-up samples, not replacements for the
three-round table above.

#### Initial-encryption profiling and changes

The before and after profiles are traced single runs; the final result above
is the median of three untraced rounds. Phase timers overlap and must not be
summed. Before enabling accelerated crypto, the traced directory encryption
took 17.47 s: `git_pack_objects_stream_lifetime` 16.928 s, pack-pipe reads
8.276 s, ciphertext stage writes 3.254 s, SHA-256 2.919 s, ChaCha20-Poly1305
2.451 s, and durable stage finish 0.033 s. With `sha2` hardware assembly and
the AArch64 ChaCha20 NEON backend, a traced run took 9.80 s: stream lifetime
9.399 s, pipe reads 6.411 s, stage writes 0.877 s, SHA-256 0.453 s, ChaCha
1.657 s, and stage finish 0.033 s. The final untraced median was 10.08 s.
Compared with the prior 14.20 s median, this is 4.12 s (29%) faster; in the
same final run, it beat gcrypt's 13.38 s by 3.30 s (25%).
E2EE used 1302.02 MiB peak RSS for this phase, 318.79 MiB more than gcrypt's
983.23 MiB; Git's inner `pack-objects` process dominates that peak.

The source repository had no bitmap and no pack-related compression overrides.
The carrier's compression-free settings do not apply to the user's inner Git
repository. A cold standalone `pack-objects --stdout --revs` took 8.96 s.
For gcrypt's shape, `rev-list --objects` took 3.16 s and the following
`pack-objects --stdout` took 4.17 s; the intermediate object list was 46.5 MB
for 756,518 objects. On warm probes, the direct pipeline took 6.33 s versus
6.72 s for `pack-objects --stdout --revs`. Individual options also showed no
stable gain: `--delta-base-offset` took 6.40 s, `--threads=0` 6.37 s, and
`--path-walk` 6.56 s. There was no bitmap index for `--use-bitmap-index` to
use. Existing packed-object reuse remains enabled. A bounded writer-thread
experiment was reverted: its queue wait was only about 40 ms and the traced
end-to-end samples did not improve.
The retained change accelerates the existing SHA-256 and ChaCha20 operations;
the wire format, AAD, segment counters, durability steps, and Git pack
generation command are unchanged.

#### End-user `cargo install` verification (2026-10-03)

I built the pushed `64ae6e4` revision using `cargo install --git
https://github.com/combinatrix-ai/git-remote-e2ee --branch readme-rewrite`
from outside the checkout, with an isolated temporary `CARGO_HOME` and no
`RUSTFLAGS`. The exact invocation also used `--root <temporary-root> --force
git-remote-e2ee` to isolate the installation. Cargo resolved
`chacha20poly1305 0.11.0`, `chacha20 0.10.2`, and `aead-stream 0.6.0`. A
one-round E2EE-only run of the benchmark harness measured these
initial-encryption values; the other phases from that round are omitted here.

| Build | Phase | Time | Peak RSS | Stored logical bytes | Stored allocated size |
|---|---|---:|---:|---:|---:|
| `cargo install --git`, no build flags | Initial encryption | 10.080 s | 1304.61 MiB | 920,636,512 B (877.99 MiB) | 880.02 MiB |

The row is a single run, not a median. Peak RSS is 1,367,982,080 bytes. Stored
allocated size is 922,767,360 bytes. The no-flags AArch64 build selected the
NEON backend; a stream test with tracing reported
`chacha20_backend=aarch64-neon`.

### Linux aarch64 cross-check (2026-10-06)

The same `scripts/reproduce-benchmark.sh` was run from a fresh clone, with an
empty input cache, in a Debian 13 LXC container on an Oracle Cloud
`VM.Standard.A1.Flex` host (Ampere Altra, AArch64), limited to 2 CPUs and
6 GiB RAM, on Btrfs. Git 2.47.3, GnuPG 2.4.7, Rust 1.99.0, e2ee `81e43c1`
(the runner revision; protocol and crypto code identical to the macOS run).
Three rounds, five tiny commits each. `TMPDIR=/var/tmp` was set by hand
because that runner revision still defaulted to the container's tmpfs `/tmp`;
later revisions default to `/var/tmp` on Linux.

| | Plain Git | `git-remote-gcrypt` | `git-remote-e2ee` |
|---|---:|---:|---:|
| Initial encryption (to a local directory) | 82.7 s | 22.8 s | 24.2 s |
| Initial push | 81.1 s | 82.8 s | 64.1 s |
| Fresh fetch | 92.4 s | 145.7 s | 118.9 s |
| Tiny commit | 0.07 s | 0.07 s | 0.07 s |
| Tiny push | 0.04 s | 23.9 s | 0.22 s |
| Tiny update (fetch) | 0.03 s | 43.4 s | 0.20 s |
| Data sent per tiny push | 4.5 KB | 921 MB | 8.9 KB |
| Peak memory, initial push | 1.11 GiB | 0.96 GiB | 1.11 GiB |
| Peak memory, tiny push | 44 MiB | 884 MiB | 48 MiB |
| Remote size after 5 tiny pushes | 891 MiB | 5,272 MiB | 878 MiB |
| Total client disk after fresh fetch (.git + auxiliary cache/state) | 891 MiB | 1,780 MiB | 1,779 MiB |

The ordering matches the macOS run except initial encryption, where gcrypt is
about 6% faster on this two-core machine. The client disk total was computed
from the run's `medians.tsv` (client `.git` plus carrier cache), because that
runner revision's summary omitted the cache.

In that run the first tiny push after the initial push took 9-32 s and about
450 MiB, because the client re-walked the full history before the push; later
pushes took about 0.2 s. After the fix in `f4526d8`, a one-round e2ee-only
rerun on the same container measured 0.15-0.16 s and 6-7 MiB for all three
tiny pushes, including the first.

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

### Historical phase profile before and after carrier optimizations

These traced single-run figures predate the initial-encryption crypto
acceleration above. The three-round medians earlier in this section are the
current benchmark results. Pack decryption and `index-pack` timers overlap
because Git consumes the decrypted stream while it is being produced; their
durations must not be summed.

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
