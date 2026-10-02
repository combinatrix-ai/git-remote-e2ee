#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 SOURCE_GIT_REPOSITORY GCRYPT_CHECKOUT [RESULTS_DIRECTORY]" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
  exit 2
fi

source_repo=$(cd "$1" && pwd -P)
gcrypt_checkout=$(cd "$2" && pwd -P)
results_dir=${3:-$(pwd -P)/bench-results/gcrypt-$(date -u +%Y%m%dT%H%M%SZ)}
results_dir=$(mkdir -p "$results_dir" && cd "$results_dir" && pwd -P)
gcrypt_helper="$gcrypt_checkout/git-remote-gcrypt"
[[ -x $gcrypt_helper ]]

source_ref=$(git -C "$source_repo" symbolic-ref --quiet HEAD) || {
  echo "source repository must have a symbolic branch checked out" >&2
  exit 2
}
source_branch=${source_ref#refs/heads/}
source_head=$(git -C "$source_repo" rev-parse HEAD)

case $(uname -s) in
  Darwin) time_style=bsd ;;
  Linux) time_style=gnu ;;
  *) echo "unsupported platform: $(uname -s)" >&2; exit 2 ;;
esac

work_parent=${BENCH_WORK_PARENT:-/tmp}
work=$(mktemp -d "$work_parent/git-remote-e2ee-gcrypt-bench.XXXXXX")
cleanup() {
  if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
    echo "benchmark work directory retained at $work" >&2
    return
  fi
  case "$work" in
    "$work_parent"/git-remote-e2ee-gcrypt-bench.*) rm -rf -- "$work" ;;
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
printf 'scenario\toperation\twall_seconds\tpeak_rss_bytes\tremote_allocated_bytes\tremote_allocated_delta_bytes\tremote_logical_bytes\tremote_logical_delta_bytes\tclient_allocated_bytes\tclient_allocated_delta_bytes\n' >"$phases_tsv"

run_phase() {
  local scenario=$1 operation=$2 remote_path=$3 client_path=$4
  shift 4
  local label="${scenario}-${operation}"
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
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$scenario" "$operation" "$wall" "$rss" "$ra_after" \
    "$((ra_after - ra_before))" "$rl_after" "$((rl_after - rl_before))" \
    "$ca_after" "$((ca_after - ca_before))" >>"$phases_tsv"
}

make_commit() {
  local scenario=$1 old_head tree index_file new_head blob
  old_head=$(git -C "$work/source" rev-parse "$source_ref")
  tree=$(git -C "$work/source" rev-parse "$old_head^{tree}")
  index_file="$work/${scenario}.index"
  GIT_INDEX_FILE="$index_file" git -C "$work/source" read-tree "$tree"
  case $scenario in
    tiny_change)
      blob=$(printf 'git-remote-gcrypt comparison tiny change\n' |
        git -C "$work/source" hash-object -w --stdin)
      GIT_INDEX_FILE="$index_file" git -C "$work/source" update-index \
        --add --cacheinfo "100644,$blob,.gcrypt-benchmark/tiny-change.txt"
      ;;
    add_10mib)
      dd if=/dev/urandom of="$work/random-10mib.bin" \
        bs=1048576 count=10 2>/dev/null
      blob=$(git -C "$work/source" hash-object -w "$work/random-10mib.bin")
      GIT_INDEX_FILE="$index_file" git -C "$work/source" update-index \
        --add --cacheinfo "100644,$blob,.gcrypt-benchmark/random-10mib.bin"
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
        --add --cacheinfo "100644,$blob,.gcrypt-benchmark/random-10mib.bin"
      ;;
    add_1000_small)
      index_info="$work/${scenario}.index-info"
      : >"$index_info"
      for n in $(seq 1 1000); do
        blob=$(printf 'small gcrypt benchmark file %04d\n' "$n" |
          git -C "$work/source" hash-object -w --stdin)
        printf '100644 %s\t.gcrypt-benchmark/small/file-%04d.txt\n' "$blob" "$n" \
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

mkdir -m 700 "$work/gnupg"
export GNUPGHOME="$work/gnupg"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
  'Benchmark <benchmark@example.invalid>' ed25519 sign 0 >/dev/null
fingerprint=$(gpg --batch --with-colons --list-secret-keys |
  awk -F: '$1 == "fpr" {print $10; exit}')
gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-add-key "$fingerprint" cv25519 encr 0 \
  >/dev/null

echo "creating isolated source clone" >&2
git clone --quiet --no-local --no-checkout --single-branch --branch "$source_branch" \
  "file://$source_repo" "$work/source"
git -C "$work/source" remote remove origin
git -C "$work/source" config gc.auto 0
git -C "$work/source" config maintenance.auto false
git -C "$work/source" remote add crypt "gcrypt::$work/remote"
git -C "$work/source" config remote.crypt.gcrypt-participants "$fingerprint"
git -C "$work/source" config remote.crypt.gcrypt-signingkey "$fingerprint"
git -C "$work/source" config remote.crypt.gcrypt-require-explicit-force-push true

git init -q "$work/client"
git -C "$work/client" config gc.auto 0
git -C "$work/client" config maintenance.auto false
git -C "$work/client" remote add crypt "gcrypt::$work/remote"
git -C "$work/client" config remote.crypt.gcrypt-participants "$fingerprint"
git -C "$work/client" config remote.crypt.gcrypt-signingkey "$fingerprint"

export PATH="$gcrypt_checkout:$PATH"
run_phase initial push "$work/remote" "$work/source" \
  git -C "$work/source" push --quiet --force crypt "$source_ref:$source_ref"
run_phase initial fetch "$work/remote" "$work/client" \
  git -C "$work/client" fetch --quiet crypt \
    "$source_ref:refs/remotes/crypt/$source_branch"

for scenario in tiny_change add_10mib modify_10mib_one_byte add_1000_small; do
  make_commit "$scenario"
  run_phase "$scenario" push "$work/remote" "$work/source" \
    git -C "$work/source" push --quiet --force crypt "$source_ref:$source_ref"
  run_phase "$scenario" fetch "$work/remote" "$work/client" \
    git -C "$work/client" fetch --quiet crypt \
      "$source_ref:refs/remotes/crypt/$source_branch"
done

expected=$(git -C "$work/source" rev-parse "$source_ref")
received=$(git -C "$work/client" rev-parse "refs/remotes/crypt/$source_branch")
[[ $received == "$expected" ]]
git -C "$work/client" fsck --full --no-dangling >/dev/null

cat >"$results_dir/summary.json" <<JSON
{
  "schema_version": 1,
  "tool": "git-remote-gcrypt",
  "tool_commit": "$(git -C "$gcrypt_checkout" rev-parse HEAD)",
  "backend": "local-filesystem",
  "platform": "$(uname -s)",
  "architecture": "$(uname -m)",
  "source_head": "$source_head",
  "final_head": "$expected"
}
JSON

echo "benchmark complete: $results_dir" >&2
cat "$phases_tsv"
