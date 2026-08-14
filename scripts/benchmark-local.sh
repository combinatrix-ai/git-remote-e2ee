#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 SOURCE_GIT_REPOSITORY [RESULTS_DIRECTORY]" >&2
  echo "Runs an isolated release benchmark against the filesystem backend." >&2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

source_repo=$1
project_root=$(cd "$(dirname "$0")/.." && pwd -P)
results_dir=${2:-$project_root/bench-results/$(date -u +%Y%m%dT%H%M%SZ)}
source_repo=$(cd "$source_repo" && pwd -P)
results_dir=$(mkdir -p "$results_dir" && cd "$results_dir" && pwd -P)

git -C "$source_repo" rev-parse --verify HEAD >/dev/null
[[ -x /usr/bin/time ]] || {
  echo "/usr/bin/time is required (install the GNU time package on Linux)" >&2
  exit 1
}
source_ref=$(git -C "$source_repo" symbolic-ref --quiet HEAD) || {
  echo "source repository must have a symbolic branch checked out" >&2
  exit 2
}
source_branch=${source_ref#refs/heads/}
source_git_dir=$(git -C "$source_repo" rev-parse --absolute-git-dir)
source_git_kib=$(du -sk "$source_git_dir" | awk '{print $1}')
available_kib=$(df -Pk "${TMPDIR:-/tmp}" | awk 'NR == 2 {print $4}')
required_kib=$((source_git_kib * 5))
if (( available_kib < required_kib )); then
  echo "insufficient temporary disk: need about $((required_kib / 1024 / 1024)) GiB" >&2
  exit 1
fi

work_parent=${TMPDIR:-/tmp}
work=$(mktemp -d "$work_parent/git-remote-e2ee-bench.XXXXXX")
cleanup() {
  if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
    echo "benchmark work directory retained at $work" >&2
    return
  fi
  case "$work" in
    "$work_parent"/git-remote-e2ee-bench.*) rm -rf -- "$work" ;;
    *) echo "refusing to remove unexpected benchmark path: $work" >&2 ;;
  esac
}
trap cleanup EXIT

if [[ ${BENCH_SKIP_BUILD:-0} != 1 ]]; then
  cargo build --release --bins --manifest-path "$project_root/Cargo.toml"
fi
git_e2ee="$project_root/target/release/git-e2ee"
[[ -x "$git_e2ee" ]] || {
  echo "release binary not found: $git_e2ee" >&2
  exit 1
}

case $(uname -s) in
  Darwin) time_style=bsd ;;
  Linux) time_style=gnu ;;
  *) echo "unsupported platform for RSS measurement: $(uname -s)" >&2; exit 2 ;;
esac

phases_tsv="$results_dir/phases.tsv"
printf 'phase\twall_seconds\tpeak_rss_bytes\tstorage_disk_bytes\tstorage_logical_bytes\n' >"$phases_tsv"

storage_bytes() {
  if [[ -d $work/storage ]]; then
    du -sk "$work/storage" | awk '{print $1 * 1024}'
  else
    echo 0
  fi
}

tree_logical_bytes() {
  path=$1
  if [[ ! -d $path ]]; then
    echo 0
  elif [[ $time_style == bsd ]]; then
    find "$path" -type f -exec stat -f '%z' {} + | awk '{sum += $1} END {print sum + 0}'
  else
    find "$path" -type f -exec stat -c '%s' {} + | awk '{sum += $1} END {print sum + 0}'
  fi
}

parse_elapsed_gnu() {
  awk -F': ' '/Elapsed \(wall clock\)/ {
    n=split($2, a, ":");
    if (n == 3) print a[1] * 3600 + a[2] * 60 + a[3];
    else print a[1] * 60 + a[2];
  }' "$1"
}

run_phase() {
  phase=$1
  shift
  timing="$work/$phase.time"
  stdout="$work/$phase.stdout"
  stderr="$work/$phase.stderr"
  if [[ $time_style == bsd ]]; then
    if ! /usr/bin/time -l -o "$timing" "$@" >"$stdout" 2>"$stderr"; then
      echo "benchmark phase failed: $phase" >&2
      sed -n '1,40p' "$stderr" >&2
      return 1
    fi
    wall=$(awk '/ real / {print $1; exit}' "$timing")
    rss=$(awk '/maximum resident set size/ {print $1; exit}' "$timing")
  else
    if ! /usr/bin/time -v -o "$timing" "$@" >"$stdout" 2>"$stderr"; then
      echo "benchmark phase failed: $phase" >&2
      sed -n '1,40p' "$stderr" >&2
      return 1
    fi
    wall=$(parse_elapsed_gnu "$timing")
    rss_kib=$(awk -F': ' '/Maximum resident set size/ {print $2; exit}' "$timing")
    rss=$((rss_kib * 1024))
  fi
  bytes=$(storage_bytes)
  logical_bytes=$(tree_logical_bytes "$work/storage")
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$phase" "$wall" "$rss" "$bytes" "$logical_bytes" >>"$phases_tsv"
}

echo "creating isolated transport clone" >&2
git clone --quiet --no-local --no-checkout --single-branch --branch "$source_branch" \
  "file://$source_repo" "$work/source"
git -C "$work/source" remote remove origin

mkdir -p "$work/storage"
"$git_e2ee" keygen --output "$work/repository.key.json" >/dev/null
"$git_e2ee" init --storage "$work/storage" --key "$work/repository.key.json" >/dev/null

run_phase initial_push "$git_e2ee" push \
  --storage "$work/storage" --key "$work/repository.key.json" \
  --repo "$work/source" --ref "$source_ref"
storage_after_initial=$(storage_bytes)
storage_logical_after_initial=$(tree_logical_bytes "$work/storage")
pack_logical_after_initial=$(tree_logical_bytes "$work/storage/objects")
initial_pack_files=$(find "$work/storage/objects" -type f | wc -l | tr -d ' ')

git init -q "$work/destination"
run_phase fresh_fetch "$git_e2ee" fetch \
  --storage "$work/storage" --key "$work/repository.key.json" \
  --repo "$work/destination" --remote-name benchmark
run_phase verify "$git_e2ee" verify \
  --storage "$work/storage" --key "$work/repository.key.json"

old_head=$(git -C "$work/source" rev-parse "$source_ref")
tree=$(git -C "$work/source" rev-parse "$old_head^{tree}")
marker_blob=$(printf 'git-remote-e2ee benchmark marker\n' | \
  git -C "$work/source" hash-object -w --stdin)
benchmark_index="$work/benchmark.index"
GIT_INDEX_FILE="$benchmark_index" git -C "$work/source" read-tree "$tree"
GIT_INDEX_FILE="$benchmark_index" git -C "$work/source" update-index \
  --add --cacheinfo "100644,$marker_blob,git-remote-e2ee-benchmark-marker.txt"
tree=$(GIT_INDEX_FILE="$benchmark_index" git -C "$work/source" write-tree)
new_head=$(printf 'git-remote-e2ee benchmark increment\n' | \
  git -C "$work/source" -c user.name=Benchmark -c user.email=benchmark@example.invalid \
    commit-tree "$tree" -p "$old_head")
git -C "$work/source" update-ref "$source_ref" "$new_head" "$old_head"

run_phase incremental_push "$git_e2ee" push \
  --storage "$work/storage" --key "$work/repository.key.json" \
  --repo "$work/source" --ref "$source_ref"
run_phase returning_fetch "$git_e2ee" fetch \
  --storage "$work/storage" --key "$work/repository.key.json" \
  --repo "$work/destination" --remote-name benchmark

destination_ref="refs/remotes/benchmark/$source_branch"
[[ $(git -C "$work/destination" rev-parse "$destination_ref") == "$new_head" ]]
git -C "$work/destination" fsck --full --no-dangling >/dev/null

source_commits=$(git -C "$source_repo" rev-list --count HEAD)
source_objects=$(git -C "$source_repo" count-objects -v | \
  awk -F': ' '/^count:|^in-pack:/ {sum += $2} END {print sum}')
source_reachable_bytes=$(git -C "$source_repo" rev-list --disk-usage --objects HEAD | \
  awk '{print $1}')
final_storage=$(storage_bytes)
final_storage_logical=$(tree_logical_bytes "$work/storage")
final_pack_logical=$(tree_logical_bytes "$work/storage/objects")
final_pack_files=$(find "$work/storage/objects" -type f | wc -l | tr -d ' ')
manifest_files=$(find "$work/storage/manifests" -type f | wc -l | tr -d ' ')
policy_files=$(find "$work/storage/policies" -type f | wc -l | tr -d ' ')
crate_sha=$(git -C "$project_root" rev-parse HEAD)
if [[ -n $(git -C "$project_root" status --porcelain=v1) ]]; then
  crate_dirty=true
else
  crate_dirty=false
fi
rustc_version=$(rustc --version | tr '"' "'")

cat >"$results_dir/summary.json" <<JSON
{
  "schema_version": 1,
  "platform": "$(uname -s)",
  "architecture": "$(uname -m)",
  "crate_commit": "$crate_sha",
  "crate_dirty": $crate_dirty,
  "rustc": "$rustc_version",
  "source_commits": $source_commits,
  "source_all_refs_objects": $source_objects,
  "source_git_bytes": $((source_git_kib * 1024)),
  "source_reachable_disk_bytes": $source_reachable_bytes,
  "storage_disk_after_initial_push_bytes": $storage_after_initial,
  "storage_logical_after_initial_push_bytes": $storage_logical_after_initial,
  "pack_logical_after_initial_push_bytes": $pack_logical_after_initial,
  "storage_disk_after_incremental_push_bytes": $final_storage,
  "storage_logical_after_incremental_push_bytes": $final_storage_logical,
  "pack_logical_after_incremental_push_bytes": $final_pack_logical,
  "pack_files_after_initial_push": $initial_pack_files,
  "pack_files_after_incremental_push": $final_pack_files,
  "manifest_files": $manifest_files,
  "policy_files": $policy_files
}
JSON

echo "benchmark complete: $results_dir" >&2
cat "$phases_tsv"
