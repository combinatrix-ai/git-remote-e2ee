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

The current format buffers each complete pack and its ciphertext in memory.
Large repositories can therefore require several times the pack size in peak
RAM. Streaming authenticated encryption would address this but requires a
future wire-format change.

## Reference run: large private notes repository

On 2026-08-14 the v3 release binary was measured three times on an Apple
Silicon Mac with 32 GiB RAM and Rust 1.95.0. The isolated source contained
2,618 commits and 59,640 Git objects; its reachable packed data occupied about
1.238 GiB. The initial encrypted filesystem remote occupied about 1.178 GiB.
It is smaller because `pack-objects` created a fresh single pack with different
delta-compression opportunities than the source's existing four-pack layout;
the difference is not compression performed by encryption. Values below are
medians from three fresh temporary work directories:

| Phase | Wall time | Peak RSS | Approx. ciphertext throughput |
|---|---:|---:|---:|
| Initial push and encryption | 10.37 s | 3.54 GiB | 116.3 MiB/s |
| Fresh fetch, decryption, and import | 18.20 s | 2.37 GiB | 66.3 MiB/s |
| Full verification | 6.74 s | 2.36 GiB | 179.0 MiB/s |
| Incremental push (one small blob) | 0.09 s | 8.5 MiB | — |
| Returning-client fetch | 0.24 s | 79.4 MiB | — |

The incremental encrypted pack was about 990 bytes and consumed one additional
filesystem allocation block. All runs reconstructed the expected ref and
passed `git fsck --full`. These numbers are a workload-specific reference, not
a performance guarantee. The main scalability limitation is peak memory, not
CPU throughput: the initial push held roughly three times the encrypted pack
size in resident memory. Returning-client fetch still performs a full Git
connectivity walk, so its cost grows with reachable history even when the
encrypted delta is tiny.

`phases.tsv` records phase name, wall seconds, peak RSS bytes, allocated storage
bytes, and logical storage bytes. `summary.json` records aggregate environment,
source, pack-count, and storage-size metadata.
