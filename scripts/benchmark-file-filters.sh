#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 GIT_CRYPT_CHECKOUT TRANSCRYPT_CHECKOUT [RESULTS_DIRECTORY]" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
  exit 2
fi

git_crypt_checkout=$(cd "$1" && pwd -P)
transcrypt_checkout=$(cd "$2" && pwd -P)
git_crypt="$git_crypt_checkout/git-crypt"
transcrypt="$transcrypt_checkout/transcrypt"
[[ -x $git_crypt && -x $transcrypt ]]

results_dir=${3:-$(pwd -P)/bench-results/file-filters-$(date -u +%Y%m%dT%H%M%SZ)}
results_dir=$(mkdir -p "$results_dir" && cd "$results_dir" && pwd -P)

case $(uname -s) in
  Darwin) time_style=bsd ;;
  Linux) time_style=gnu ;;
  *) echo "unsupported platform: $(uname -s)" >&2; exit 2 ;;
esac

work_parent=${BENCH_WORK_PARENT:-/tmp}
work=$(mktemp -d "$work_parent/git-remote-e2ee-filter-bench.XXXXXX")
cleanup() {
  if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
    echo "benchmark work directory retained at $work" >&2
    return
  fi
  case "$work" in
    "$work_parent"/git-remote-e2ee-filter-bench.*) rm -rf -- "$work" ;;
    *) echo "refusing to remove unexpected benchmark path: $work" >&2 ;;
  esac
}
trap cleanup EXIT

tree_allocated_bytes() {
  local path=$1
  if [[ -e $path ]]; then du -sk "$path" | awk '{print $1 * 1024}'; else echo 0; fi
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

parse_elapsed_gnu() {
  awk -F': ' '/Elapsed \(wall clock\)/ {
    n=split($2, a, ":");
    if (n == 3) print a[1] * 3600 + a[2] * 60 + a[3];
    else print a[1] * 60 + a[2];
  }' "$1"
}

phases_tsv="$results_dir/phases.tsv"
printf 'tool\tscenario\toperation\twall_seconds\tpeak_rss_bytes\tremote_allocated_bytes\tremote_allocated_delta_bytes\tremote_logical_bytes\tremote_logical_delta_bytes\tclient_allocated_bytes\tclient_allocated_delta_bytes\n' >"$phases_tsv"

run_phase() {
  local tool=$1 scenario=$2 operation=$3 remote_path=$4 client_path=$5
  shift 5
  local label="${tool}-${scenario}-${operation}"
  local timing="$work/$label.time" stdout="$work/$label.stdout" stderr="$work/$label.stderr"
  local ra_before rl_before ca_before wall rss
  ra_before=$(tree_allocated_bytes "$remote_path")
  rl_before=$(tree_logical_bytes "$remote_path")
  ca_before=$(tree_allocated_bytes "$client_path")
  if [[ $time_style == bsd ]]; then
    if ! /usr/bin/time -l -o "$timing" "$@" >"$stdout" 2>"$stderr"; then
      echo "benchmark phase failed: $label" >&2
      sed -n '1,100p' "$stderr" >&2
      return 1
    fi
    wall=$(awk '/ real / {print $1; exit}' "$timing")
    rss=$(awk '/maximum resident set size/ {print $1; exit}' "$timing")
  else
    if ! /usr/bin/time -v -o "$timing" "$@" >"$stdout" 2>"$stderr"; then
      echo "benchmark phase failed: $label" >&2
      sed -n '1,100p' "$stderr" >&2
      return 1
    fi
    wall=$(parse_elapsed_gnu "$timing")
    rss_kib=$(awk -F': ' '/Maximum resident set size/ {print $2; exit}' "$timing")
    rss=$((rss_kib * 1024))
  fi
  local ra_after rl_after ca_after
  ra_after=$(tree_allocated_bytes "$remote_path")
  rl_after=$(tree_logical_bytes "$remote_path")
  ca_after=$(tree_allocated_bytes "$client_path")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$tool" "$scenario" "$operation" "$wall" "$rss" "$ra_after" \
    "$((ra_after - ra_before))" "$rl_after" "$((rl_after - rl_before))" \
    "$ca_after" "$((ca_after - ca_before))" >>"$phases_tsv"
}

make_payloads() {
  mkdir -p "$work/payloads/small"
  dd if=/dev/urandom of="$work/payloads/random-10mib.bin" \
    bs=1048576 count=10 2>/dev/null
  cp "$work/payloads/random-10mib.bin" "$work/payloads/random-10mib-mutated.bin"
  printf '\001' | dd of="$work/payloads/random-10mib-mutated.bin" \
    bs=1 seek=5242880 conv=notrunc 2>/dev/null
  for n in $(seq 1 1000); do
    dd if=/dev/urandom of="$work/payloads/small/file-$(printf '%04d' "$n").bin" \
      bs=1024 count=1 2>/dev/null
  done
}

commit_repo() {
  local repo=$1 message=$2
  git -C "$repo" -c user.name=Benchmark -c user.email=benchmark@example.invalid \
    commit -q -m "$message"
}

benchmark_tool() {
  local tool=$1 repo="$work/$1-source" remote="$work/$1-remote.git"
  local client="$work/$1-client" secret_pattern='secret/**'
  local password='benchmark-only-not-a-user-secret'

  git init -q -b main "$repo"
  git init -q --bare "$remote"
  git -C "$remote" symbolic-ref HEAD refs/heads/main
  git -C "$repo" config gc.auto 0
  git -C "$repo" config maintenance.auto false
  git -C "$repo" remote add origin "$remote"
  mkdir -p "$repo/secret"

  if [[ $tool == git-crypt ]]; then
    (cd "$repo" && "$git_crypt" init)
    printf '%s filter=git-crypt diff=git-crypt\n' "$secret_pattern" >"$repo/.gitattributes"
    (cd "$repo" && "$git_crypt" export-key "$work/git-crypt.key")
  else
    git -C "$repo" -c advice.detachedHead=false status --short >/dev/null
    (cd "$repo" && "$transcrypt" -c aes-256-cbc -p "$password" -y >/dev/null)
    (cd "$repo" && "$transcrypt" --add="$secret_pattern" >/dev/null)
  fi
  git -C "$repo" add .gitattributes
  commit_repo "$repo" 'configure encrypted file filter'
  git -C "$repo" push -q -u origin main

  cp "$work/payloads/random-10mib.bin" "$repo/secret/random-10mib.bin"
  run_phase "$tool" add_10mib stage "$remote" "$repo" \
    git -C "$repo" add secret/random-10mib.bin
  commit_repo "$repo" 'add encrypted 10 MiB file'
  run_phase "$tool" add_10mib push "$remote" "$repo" \
    git -C "$repo" push -q origin main

  cp "$work/payloads/random-10mib-mutated.bin" "$repo/secret/random-10mib.bin"
  run_phase "$tool" modify_10mib_one_byte stage "$remote" "$repo" \
    git -C "$repo" add secret/random-10mib.bin
  commit_repo "$repo" 'modify one byte in encrypted 10 MiB file'
  run_phase "$tool" modify_10mib_one_byte push "$remote" "$repo" \
    git -C "$repo" push -q origin main

  mkdir -p "$repo/secret/small"
  cp -R "$work/payloads/small/." "$repo/secret/small/"
  run_phase "$tool" add_1000_small stage "$remote" "$repo" \
    git -C "$repo" add secret/small
  commit_repo "$repo" 'add 1000 encrypted small files'
  run_phase "$tool" add_1000_small push "$remote" "$repo" \
    git -C "$repo" push -q origin main

  plaintext_hash=$(git -C "$repo" hash-object --no-filters secret/random-10mib.bin)
  ciphertext_hash=$(git -C "$repo" rev-parse HEAD:secret/random-10mib.bin)
  [[ $plaintext_hash != "$ciphertext_hash" ]]

  run_phase "$tool" fresh_reader clone "$remote" "$client" \
    git clone -q "$remote" "$client"
  git -C "$client" config gc.auto 0
  git -C "$client" config maintenance.auto false
  if [[ $tool == git-crypt ]]; then
    run_phase "$tool" fresh_reader unlock "$remote" "$client" \
      bash -c 'cd "$1" && "$2" unlock "$3"' \
      _ "$client" "$git_crypt" "$work/git-crypt.key"
  else
    run_phase "$tool" fresh_reader unlock "$remote" "$client" \
      bash -c 'cd "$1" && "$2" -c aes-256-cbc -p "$3" -y >/dev/null' \
      _ "$client" "$transcrypt" "$password"
  fi
  cmp "$work/payloads/random-10mib-mutated.bin" "$client/secret/random-10mib.bin"
  git -C "$client" fsck --full --no-dangling >/dev/null
}

make_payloads
benchmark_tool git-crypt
benchmark_tool transcrypt

cat >"$results_dir/summary.json" <<JSON
{
  "schema_version": 1,
  "workload": "selected-file-filter",
  "platform": "$(uname -s)",
  "architecture": "$(uname -m)",
  "git_crypt_commit": "$(git -C "$git_crypt_checkout" rev-parse HEAD)",
  "transcrypt_commit": "$(git -C "$transcrypt_checkout" rev-parse HEAD)"
}
JSON

echo "benchmark complete: $results_dir" >&2
cat "$phases_tsv"
