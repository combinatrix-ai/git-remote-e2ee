#!/usr/bin/env bash
set -euo pipefail

# Benchmark a cold full-history fetch without network or production data.
if [[ $# -ne 1 ]]; then
  echo "usage: $0 BIN_DIR" >&2
  exit 2
fi
bin_dir=$(cd "$1" && pwd -P)
for binary in git-e2ee git-remote-e2ee; do
  [[ -x "$bin_dir/$binary" ]] || { echo "missing $bin_dir/$binary" >&2; exit 2; }
done
generations=${BENCH_GENERATIONS:-30}
rounds=${BENCH_ROUNDS:-5}
[[ $generations =~ ^[1-9][0-9]*$ && $rounds =~ ^[1-9][0-9]*$ ]] || {
  echo "BENCH_GENERATIONS and BENCH_ROUNDS must be positive integers" >&2
  exit 2
}
work=$(mktemp -d "${TMPDIR:-/tmp}/e2ee-cold-fetch.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset GIT_REMOTE_E2EE_CACHE_DIR
export XDG_STATE_HOME="$work/setup-state" XDG_CACHE_HOME="$work/setup-cache"
git init --bare -q "$work/carrier.git"
"$bin_dir/git-e2ee" keygen --output "$work/key.json" >/dev/null
(cd "$work" && "$bin_dir/git-e2ee" init "e2ee::file://$work/carrier.git" --key "$work/key.json" >/dev/null)
git init -q "$work/source"
git -C "$work/source" config user.name Benchmark
git -C "$work/source" config user.email benchmark@example.invalid
git -C "$work/source" remote add origin "e2ee::file://$work/carrier.git"
git -C "$work/source" config remote.origin.e2ee-key "$work/key.json"
for ((generation = 1; generation <= generations; generation++)); do
  printf '%s\n' "$generation" > "$work/source/value"
  git -C "$work/source" add value
  git -C "$work/source" commit -qm "generation $generation"
  PATH="$bin_dir:$PATH" git -C "$work/source" push -q origin HEAD:refs/heads/main
done
expected=$(git -C "$work/source" rev-parse HEAD)
printf 'run\twall_seconds\tmanifest_total_ms\tref_id\n'
for ((run = 1; run <= rounds; run++)); do
  git init -q "$work/fresh-$run"
  git -C "$work/fresh-$run" remote add origin "e2ee::file://$work/carrier.git"
  git -C "$work/fresh-$run" config remote.origin.e2ee-key "$work/key.json"
  export XDG_STATE_HOME="$work/state-$run" XDG_CACHE_HOME="$work/cache-$run"
  started=$(perl -MTime::HiRes=time -e 'print time')
  GIT_REMOTE_E2EE_TRACE=1 PATH="$bin_dir:$PATH" git -C "$work/fresh-$run" fetch -q origin >/dev/null 2>"$work/trace-$run"
  ended=$(perl -MTime::HiRes=time -e 'print time')
  actual=$(git -C "$work/fresh-$run" rev-parse refs/remotes/origin/main)
  [[ $actual == "$expected" ]] || { echo "wrong fetched ref" >&2; exit 1; }
  git -C "$work/fresh-$run" fsck --no-reflogs --unreachable >/dev/null 2>"$work/fsck-$run"
  manifest_ms=$(awk '/phase=manifest_chain_authentication elapsed_ms=/ {
    sub(/.*elapsed_ms=/, "")
    sub(/[^0-9].*/, "")
    total += $0
    found = 1
  } END { if (found) print total }' "$work/trace-$run")
  [[ -n $manifest_ms ]] || { echo "missing manifest trace" >&2; exit 1; }
  wall=$(awk -v start="$started" -v end="$ended" 'BEGIN {printf "%.3f", end-start}')
  printf '%s\t%s\t%s\t%s\n' "$run" "$wall" "$manifest_ms" "$actual"
done
