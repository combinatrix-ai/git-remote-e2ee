#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: benchmark-comparison.sh SOURCE_GIT_REPOSITORY [RESULTS_DIRECTORY]

Compares a local bare Git remote with the git-remote-e2ee filesystem backend.
The source repository is cloned into an isolated temporary directory and is
never modified. Set BENCH_TOTAL_READERS to an integer of at least 2 to exercise
recipient scaling (default: 2). Set BENCH_KEEP_WORK=1 to retain the temporary
directory. Set BENCH_E2EE_PUSH_MODE=native to measure pushes through the Git
remote helper instead of the direct diagnostic CLI (default: direct).
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

source_repo=$1
total_readers=${BENCH_TOTAL_READERS:-2}
e2ee_push_mode=${BENCH_E2EE_PUSH_MODE:-direct}
if [[ ! $total_readers =~ ^[0-9]+$ ]] || (( total_readers < 2 )); then
  echo "BENCH_TOTAL_READERS must be an integer of at least 2" >&2
  exit 2
fi
if [[ $e2ee_push_mode != direct && $e2ee_push_mode != native ]]; then
  echo "BENCH_E2EE_PUSH_MODE must be direct or native" >&2
  exit 2
fi
project_root=$(cd "$(dirname "$0")/.." && pwd -P)
results_dir=${2:-$project_root/bench-results/comparison-$(date -u +%Y%m%dT%H%M%SZ)}
source_repo=$(cd "$source_repo" && pwd -P)
results_dir=$(mkdir -p "$results_dir" && cd "$results_dir" && pwd -P)

git -C "$source_repo" rev-parse --verify HEAD >/dev/null
source_ref=$(git -C "$source_repo" symbolic-ref --quiet HEAD) || {
  echo "source repository must have a symbolic branch checked out" >&2
  exit 2
}
source_branch=${source_ref#refs/heads/}
source_head=$(git -C "$source_repo" rev-parse HEAD)
source_git_dir=$(git -C "$source_repo" rev-parse --absolute-git-dir)
source_git_kib=$(du -sk "$source_git_dir" | awk '{print $1}')
available_kib=$(df -Pk "${TMPDIR:-/tmp}" | awk 'NR == 2 {print $4}')
required_kib=$((source_git_kib * 6))
if (( available_kib < required_kib )); then
  echo "insufficient temporary disk: need about $((required_kib / 1024 / 1024)) GiB" >&2
  exit 1
fi

case $(uname -s) in
  Darwin) time_style=bsd ;;
  Linux) time_style=gnu ;;
  *) echo "unsupported platform for RSS measurement: $(uname -s)" >&2; exit 2 ;;
esac
[[ -x /usr/bin/time ]] || {
  echo "/usr/bin/time is required" >&2
  exit 1
}

if [[ ${BENCH_SKIP_BUILD:-0} != 1 ]]; then
  cargo build --release --bins --manifest-path "$project_root/Cargo.toml"
fi
git_e2ee="$project_root/target/release/git-e2ee"
[[ -x $git_e2ee ]] || {
  echo "release binary not found: $git_e2ee" >&2
  exit 1
}

work_parent=${TMPDIR:-/tmp}
work=$(mktemp -d "$work_parent/git-remote-e2ee-compare.XXXXXX")
cleanup() {
  if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
    echo "benchmark work directory retained at $work" >&2
    return
  fi
  case "$work" in
    "$work_parent"/git-remote-e2ee-compare.*) rm -rf -- "$work" ;;
    *) echo "refusing to remove unexpected benchmark path: $work" >&2 ;;
  esac
}
trap cleanup EXIT

tree_allocated_bytes() {
  local path=$1
  if [[ ! -e $path ]]; then
    echo 0
  else
    du -sk "$path" | awk '{print $1 * 1024}'
  fi
}

tree_logical_bytes() {
  local path=$1
  if [[ ! -e $path ]]; then
    echo 0
  elif [[ $time_style == bsd ]]; then
    find "$path" -type f -exec stat -f '%z' {} + | awk '{sum += $1} END {print sum + 0}'
  else
    find "$path" -type f -exec stat -c '%s' {} + | awk '{sum += $1} END {print sum + 0}'
  fi
}

object_snapshot() {
  local root=$1
  local object digest
  find "$root/objects" -type f -print | LC_ALL=C sort | while IFS= read -r object; do
    if [[ $time_style == bsd ]]; then
      digest=$(shasum -a 256 "$object" | awk '{print $1}')
    else
      digest=$(sha256sum "$object" | awk '{print $1}')
    fi
    printf '%s\t%s\n' "${object#"$root"/}" "$digest"
  done
}

parse_elapsed_gnu() {
  awk -F': ' '/Elapsed \(wall clock\)/ {
    n=split($2, a, ":");
    if (n == 3) print a[1] * 3600 + a[2] * 60 + a[3];
    else print a[1] * 60 + a[2];
  }' "$1"
}

phases_tsv="$results_dir/phases.tsv"
printf 'scenario\ttransport\toperation\twall_seconds\tpeak_rss_bytes\tremote_allocated_bytes\tremote_allocated_delta_bytes\tremote_logical_bytes\tremote_logical_delta_bytes\tclient_allocated_bytes\tclient_allocated_delta_bytes\n' >"$phases_tsv"

run_phase() {
  local scenario=$1
  local transport=$2
  local operation=$3
  local remote_path=$4
  local client_path=$5
  shift 5

  local label="${scenario}-${transport}-${operation}"
  local timing="$work/$label.time"
  local stdout="$work/$label.stdout"
  local stderr="$work/$label.stderr"
  local remote_allocated_before remote_logical_before client_allocated_before
  local wall rss
  remote_allocated_before=$(tree_allocated_bytes "$remote_path")
  remote_logical_before=$(tree_logical_bytes "$remote_path")
  client_allocated_before=$(tree_allocated_bytes "$client_path")

  if [[ $time_style == bsd ]]; then
    if ! /usr/bin/time -l -o "$timing" "$@" >"$stdout" 2>"$stderr"; then
      echo "benchmark phase failed: $label" >&2
      sed -n '1,80p' "$stderr" >&2
      return 1
    fi
    wall=$(awk '/ real / {print $1; exit}' "$timing")
    rss=$(awk '/maximum resident set size/ {print $1; exit}' "$timing")
  else
    if ! /usr/bin/time -v -o "$timing" "$@" >"$stdout" 2>"$stderr"; then
      echo "benchmark phase failed: $label" >&2
      sed -n '1,80p' "$stderr" >&2
      return 1
    fi
    wall=$(parse_elapsed_gnu "$timing")
    rss_kib=$(awk -F': ' '/Maximum resident set size/ {print $2; exit}' "$timing")
    rss=$((rss_kib * 1024))
  fi

  local remote_allocated_after remote_logical_after client_allocated_after
  remote_allocated_after=$(tree_allocated_bytes "$remote_path")
  remote_logical_after=$(tree_logical_bytes "$remote_path")
  client_allocated_after=$(tree_allocated_bytes "$client_path")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$scenario" "$transport" "$operation" "$wall" "$rss" \
    "$remote_allocated_after" "$((remote_allocated_after - remote_allocated_before))" \
    "$remote_logical_after" "$((remote_logical_after - remote_logical_before))" \
    "$client_allocated_after" "$((client_allocated_after - client_allocated_before))" \
    >>"$phases_tsv"
}

make_commit() {
  local scenario=$1
  local old_head tree index_file new_head
  old_head=$(git -C "$work/source" rev-parse "$source_ref")
  tree=$(git -C "$work/source" rev-parse "$old_head^{tree}")
  index_file="$work/${scenario}.index"
  GIT_INDEX_FILE="$index_file" git -C "$work/source" read-tree "$tree"

  case $scenario in
    tiny_change)
      blob=$(printf 'git-remote-e2ee comparison benchmark tiny change\n' |
        git -C "$work/source" hash-object -w --stdin)
      GIT_INDEX_FILE="$index_file" git -C "$work/source" update-index \
        --add --cacheinfo "100644,$blob,.git-e2ee-benchmark/tiny-change.txt"
      ;;
    add_10mib)
      dd if=/dev/urandom of="$work/random-10mib.bin" \
        bs=1048576 count=10 2>/dev/null
      blob=$(git -C "$work/source" hash-object -w "$work/random-10mib.bin")
      GIT_INDEX_FILE="$index_file" git -C "$work/source" update-index \
        --add --cacheinfo "100644,$blob,.git-e2ee-benchmark/random-10mib.bin"
      ;;
    modify_10mib_one_byte)
      cp "$work/random-10mib.bin" "$work/random-10mib-mutated.bin"
      old_byte=$(dd if="$work/random-10mib-mutated.bin" bs=1 skip=5242880 count=1 \
        2>/dev/null | od -An -tu1 | tr -d ' ')
      new_byte=$(((old_byte + 1) % 256))
      replacement=$(printf '%03o' "$new_byte")
      printf '%b' "\\$replacement" | dd of="$work/random-10mib-mutated.bin" \
        bs=1 seek=5242880 conv=notrunc 2>/dev/null
      blob=$(git -C "$work/source" hash-object -w "$work/random-10mib-mutated.bin")
      GIT_INDEX_FILE="$index_file" git -C "$work/source" update-index \
        --add --cacheinfo "100644,$blob,.git-e2ee-benchmark/random-10mib.bin"
      ;;
    add_1000_small)
      index_info="$work/${scenario}.index-info"
      : >"$index_info"
      for n in $(seq 1 1000); do
        content=$(printf 'small benchmark file %04d\n%s\n' "$n" \
          '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
        blob=$(printf '%s' "$content" | git -C "$work/source" hash-object -w --stdin)
        printf '100644 %s\t.git-e2ee-benchmark/small/file-%04d.txt\n' "$blob" "$n" \
          >>"$index_info"
      done
      GIT_INDEX_FILE="$index_file" git -C "$work/source" update-index \
        --add --index-info <"$index_info"
      ;;
    *) echo "unknown scenario: $scenario" >&2; return 2 ;;
  esac

  tree=$(GIT_INDEX_FILE="$index_file" git -C "$work/source" write-tree)
  new_head=$(printf 'benchmark: %s\n' "$scenario" |
    git -C "$work/source" -c user.name=Benchmark \
      -c user.email=benchmark@example.invalid commit-tree "$tree" -p "$old_head")
  git -C "$work/source" update-ref "$source_ref" "$new_head" "$old_head"
}

echo "creating isolated source clone" >&2
git clone --quiet --no-local --no-checkout --single-branch --branch "$source_branch" \
  "file://$source_repo" "$work/source"
git -C "$work/source" remote remove origin
git -C "$work/source" config gc.auto 0
git -C "$work/source" config maintenance.auto false

git init -q --bare "$work/raw.git"
git init -q "$work/raw-client"
git -C "$work/raw.git" config receive.autogc false
git -C "$work/raw.git" config maintenance.auto false
git -C "$work/raw-client" config gc.auto 0
git -C "$work/raw-client" config maintenance.auto false
mkdir -p "$work/e2ee-storage"
git init -q "$work/e2ee-client"
git init -q "$work/e2ee-new-client"
git -C "$work/e2ee-client" config gc.auto 0
git -C "$work/e2ee-client" config maintenance.auto false
git -C "$work/e2ee-new-client" config gc.auto 0
git -C "$work/e2ee-new-client" config maintenance.auto false
"$git_e2ee" keygen --output "$work/repository.key.json" >/dev/null
"$git_e2ee" init --storage "$work/e2ee-storage" \
  --key "$work/repository.key.json" >/dev/null
if [[ $e2ee_push_mode == native ]]; then
  git -C "$work/source" remote add private "e2ee::$work/e2ee-storage"
  git -C "$work/source" config remote.private.e2ee-key "$work/repository.key.json"
  e2ee_push_command=(
    env "PATH=$project_root/target/release:$PATH"
    git -C "$work/source" push --quiet private "$source_ref:$source_ref"
  )
else
  e2ee_push_command=(
    "$git_e2ee" push --storage "$work/e2ee-storage"
    --key "$work/repository.key.json" --repo "$work/source" --ref "$source_ref"
  )
fi

run_phase initial git push "$work/raw.git" "$work/source" \
  git -C "$work/source" push --quiet "$work/raw.git" "$source_ref:$source_ref"
run_phase initial e2ee push "$work/e2ee-storage" "$work/source" \
  "${e2ee_push_command[@]}"
run_phase initial git fetch "$work/raw.git" "$work/raw-client" \
  git -C "$work/raw-client" fetch --quiet "$work/raw.git" \
    "$source_ref:refs/remotes/benchmark/$source_branch"
run_phase initial e2ee fetch "$work/e2ee-storage" "$work/e2ee-client" \
  "$git_e2ee" fetch --storage "$work/e2ee-storage" \
    --key "$work/repository.key.json" --repo "$work/e2ee-client" \
    --remote-name benchmark

repository_root=$(sed -n 's/^[[:space:]]*"repository_root": "\([^"]*\)",$/\1/p' \
  "$work/repository.key.json")
[[ -n $repository_root ]]
"$git_e2ee" keygen --repository-root "$repository_root" \
  --output "$work/new-user.key.json" >/dev/null
"$git_e2ee" device-export --key "$work/new-user.key.json" \
  --output "$work/new-user.public.json" >/dev/null
object_snapshot "$work/e2ee-storage" >"$work/objects-before-device-add.sha256"
run_phase add_user e2ee device-add "$work/e2ee-storage" "$work/e2ee-new-client" \
  "$git_e2ee" device-add --storage "$work/e2ee-storage" \
    --key "$work/repository.key.json" --device "$work/new-user.public.json"
active_reader_key="$work/new-user.key.json"
if (( total_readers > 2 )); then
  for reader_number in $(seq 3 "$total_readers"); do
    reader_label=$(printf '%03d' "$reader_number")
    reader_key="$work/reader-$reader_label.key.json"
    reader_public="$work/reader-$reader_label.public.json"
    "$git_e2ee" keygen --repository-root "$repository_root" \
      --output "$reader_key" >/dev/null
    "$git_e2ee" device-export --key "$reader_key" \
      --output "$reader_public" >/dev/null
    run_phase "add_reader_$reader_label" e2ee device-add \
      "$work/e2ee-storage" "$work/e2ee-new-client" \
      "$git_e2ee" device-add --storage "$work/e2ee-storage" \
        --key "$work/repository.key.json" --device "$reader_public"
    active_reader_key=$reader_key
  done
fi
object_snapshot "$work/e2ee-storage" >"$work/objects-after-device-add.sha256"
cmp "$work/objects-before-device-add.sha256" "$work/objects-after-device-add.sha256"
run_phase add_user e2ee fetch-new-user "$work/e2ee-storage" \
  "$work/e2ee-new-client" \
  "$git_e2ee" fetch --storage "$work/e2ee-storage" \
    --key "$active_reader_key" --repo "$work/e2ee-new-client" \
    --remote-name benchmark
initial_head=$(git -C "$work/source" rev-parse "$source_ref")
new_user_head=$(git -C "$work/e2ee-new-client" \
  rev-parse "refs/remotes/benchmark/$source_branch")
[[ $new_user_head == "$initial_head" ]]

for scenario in tiny_change add_10mib modify_10mib_one_byte add_1000_small; do
  make_commit "$scenario"
  run_phase "$scenario" git push "$work/raw.git" "$work/source" \
    git -C "$work/source" push --quiet "$work/raw.git" "$source_ref:$source_ref"
  run_phase "$scenario" e2ee push "$work/e2ee-storage" "$work/source" \
    "${e2ee_push_command[@]}"
  run_phase "$scenario" git fetch "$work/raw.git" "$work/raw-client" \
    git -C "$work/raw-client" fetch --quiet "$work/raw.git" \
      "$source_ref:refs/remotes/benchmark/$source_branch"
  run_phase "$scenario" e2ee fetch "$work/e2ee-storage" "$work/e2ee-new-client" \
    "$git_e2ee" fetch --storage "$work/e2ee-storage" \
      --key "$active_reader_key" --repo "$work/e2ee-new-client" \
      --remote-name benchmark
done

expected=$(git -C "$work/source" rev-parse "$source_ref")
raw_received=$(git -C "$work/raw-client" rev-parse "refs/remotes/benchmark/$source_branch")
e2ee_received=$(git -C "$work/e2ee-new-client" \
  rev-parse "refs/remotes/benchmark/$source_branch")
[[ $raw_received == "$expected" ]]
[[ $e2ee_received == "$expected" ]]
git -C "$work/raw-client" fsck --full --no-dangling >/dev/null
git -C "$work/e2ee-new-client" fsck --full --no-dangling >/dev/null
"$git_e2ee" verify --storage "$work/e2ee-storage" \
  --key "$work/repository.key.json" >/dev/null

source_commits=$(git -C "$source_repo" rev-list --count HEAD)
source_files=$(git -C "$source_repo" ls-tree -r --name-only HEAD | wc -l | tr -d ' ')
source_reachable_bytes=$(git -C "$source_repo" rev-list --disk-usage --objects HEAD |
  awk '{print $1}')
crate_sha=$(git -C "$project_root" rev-parse HEAD)
if [[ -n $(git -C "$project_root" status --porcelain=v1) ]]; then
  crate_dirty=true
else
  crate_dirty=false
fi

cat >"$results_dir/summary.json" <<JSON
{
  "schema_version": 1,
  "platform": "$(uname -s)",
  "architecture": "$(uname -m)",
  "crate_commit": "$crate_sha",
  "crate_dirty": $crate_dirty,
  "e2ee_push_mode": "$e2ee_push_mode",
  "source_head": "$source_head",
  "source_commits": $source_commits,
  "source_files": $source_files,
  "source_git_bytes": $((source_git_kib * 1024)),
  "source_reachable_disk_bytes": $source_reachable_bytes,
  "total_readers": $total_readers,
  "added_readers": $((total_readers - 1)),
  "device_add_pack_snapshot_unchanged": true,
  "final_head": "$expected"
}
JSON

echo "benchmark complete: $results_dir" >&2
cat "$phases_tsv"
