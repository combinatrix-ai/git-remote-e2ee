# Local performance benchmarks

The benchmark is opt-in and never runs in CI. It measures the release binaries
against a real Git repository using an isolated filesystem backend:

```console
scripts/benchmark-local.sh /path/to/source/repository
```

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
