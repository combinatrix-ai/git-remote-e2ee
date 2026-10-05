#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: benchmark-git-backend.sh GODOT_CHECKOUT GCRYPT_CHECKOUT GODOT_REVISION GCRYPT_REVISION RESULTS_DIR

Internal measurement engine for reproduce-benchmark.sh. It requires the
explicit, revision-verified input checkouts and a results directory.
BENCH_TINY_COMMITS defaults to 5. BENCH_GCRYPT_TINY_COMMITS defaults to the
same value and may be lower for a prohibitively slow full-history run.
BENCH_ROUNDS defaults to 3. BENCH_SKIP_BUILD=1 uses existing release binaries.
BENCH_KEEP_WORK=1 retains temporary repositories and command logs under the
work directory and throwaway GPG homes under /tmp. Results contain measurement
TSV files only; no keys or command logs are written there. BENCH_TRACE=1 prints
E2EE trace lines to stderr.
BENCH_E2EE_ONLY=1 skips plain and gcrypt measurements. Set
BENCH_CARRIER_ATTR_TREE=0 to leave attr.tree unset on the local carrier
receiver, simulating servers that ignore the committed carrier attributes.
EOF
}

if [[ $# -gt 0 && ( $1 == -h || $1 == --help ) ]]; then
  usage
  exit 0
fi
if [[ $# -ne 5 ]]; then
  usage
  exit 2
fi

project_root=$(cd "$(dirname "$0")/.." && pwd -P)
source_repo=$1
gcrypt_checkout=$2
source_revision=$3
gcrypt_revision=$4
results_dir=$5
source_repo=$(cd "$source_repo" && pwd -P)
gcrypt_checkout=$(cd "$gcrypt_checkout" && pwd -P)
results_dir=$(cd "$results_dir" && pwd -P)
[[ -d $results_dir ]] || {
  echo "results directory does not exist: $results_dir" >&2
  exit 2
}
for result_file in raw.tsv medians.tsv; do
  [[ ! -e $results_dir/$result_file ]] || {
    echo "results file already exists: $results_dir/$result_file" >&2
    exit 2
  }
done
e2ee_revision=$(git -C "$project_root" rev-parse HEAD)
tiny_commits=${BENCH_TINY_COMMITS:-5}
gcrypt_tiny_commits=${BENCH_GCRYPT_TINY_COMMITS:-$tiny_commits}
rounds=${BENCH_ROUNDS:-3}
e2ee_only=${BENCH_E2EE_ONLY:-0}
carrier_attr_tree=${BENCH_CARRIER_ATTR_TREE:-1}

if [[ $e2ee_only != 0 && $e2ee_only != 1 ]]; then
  echo "BENCH_E2EE_ONLY must be 0 or 1" >&2
  exit 2
fi
if [[ $carrier_attr_tree != 0 && $carrier_attr_tree != 1 ]]; then
  echo "BENCH_CARRIER_ATTR_TREE must be 0 or 1" >&2
  exit 2
fi
transports=(plain gcrypt e2ee)
if [[ $e2ee_only == 1 ]]; then
  transports=(e2ee)
fi

if [[ ! $tiny_commits =~ ^[1-5]$ ]]; then
  echo "BENCH_TINY_COMMITS must be from 1 to 5" >&2
  exit 2
fi
if [[ ! $gcrypt_tiny_commits =~ ^[1-5]$ ]] || (( gcrypt_tiny_commits > tiny_commits )); then
  echo "BENCH_GCRYPT_TINY_COMMITS must be from 1 to BENCH_TINY_COMMITS" >&2
  exit 2
fi
if [[ ! $rounds =~ ^[1-3]$ ]]; then
  echo "BENCH_ROUNDS must be from 1 to 3" >&2
  exit 2
fi
[[ $(git -C "$source_repo" rev-parse HEAD) == "$source_revision" ]] || {
  echo "Godot checkout must be at $source_revision" >&2
  exit 2
}
[[ $(git -C "$source_repo" rev-parse --is-shallow-repository) == false ]] || {
  echo "Godot checkout must contain full history, not a shallow clone" >&2
  exit 2
}
[[ $(git -C "$gcrypt_checkout" rev-parse HEAD) == "$gcrypt_revision" ]] || {
  echo "git-remote-gcrypt checkout must be at $gcrypt_revision" >&2
  exit 2
}
[[ -x $gcrypt_checkout/git-remote-gcrypt ]] || {
  echo "git-remote-gcrypt script is missing or not executable" >&2
  exit 1
}
git -C "$source_repo" cat-file -e HEAD:README.md || {
  echo "benchmark source must contain README.md" >&2
  exit 2
}

gpg_bin=$(command -v gpg || true)
[[ -n $gpg_bin && -x $gpg_bin ]] || {
  echo "GnuPG executable 'gpg' was not found on PATH" >&2
  exit 1
}
os=$(uname -s)
case $os in
  Darwin) time_style=bsd ;;
  Linux) time_style=gnu ;;
  *) echo "unsupported platform: $os" >&2; exit 2 ;;
esac
[[ -x /usr/bin/time ]] || {
  echo "/usr/bin/time is required" >&2
  exit 1
}
if [[ $os == Linux ]]; then
  default_tmp=${TMPDIR:-/var/tmp}
else
  default_tmp=${TMPDIR:-/tmp}
fi
work_parent=${BENCH_WORK_PARENT:-$default_tmp}
[[ -d $work_parent ]] || {
  echo "BENCH_WORK_PARENT must already exist: $work_parent" >&2
  exit 2
}
work_parent=$(cd "$work_parent" && pwd -P)
allowed_work_parent=false
case $os in
  Darwin)
    allowed_roots=(/private/tmp "$default_tmp")
    allowed_work_description="/private/tmp or TMPDIR"
    ;;
  Linux)
    allowed_roots=(/var/tmp /tmp "$default_tmp")
    allowed_work_description="/var/tmp, /tmp, or TMPDIR"
    ;;
esac
for allowed_root in "${allowed_roots[@]}"; do
  [[ -n $allowed_root ]] || continue
  [[ -d $allowed_root ]] || continue
  allowed_root=$(cd "$allowed_root" && pwd -P)
  if [[ $work_parent == "$allowed_root" || $work_parent == "$allowed_root"/* ]]; then
    allowed_work_parent=true
    break
  fi
done
if [[ $allowed_work_parent != true ]]; then
  echo "benchmark work parent must resolve under $allowed_work_description: $work_parent" >&2
  exit 2
fi
case $os in
  Darwin)
    work_filesystem_device=$(df -P "$work_parent" | awk 'NR == 2 { print $1 }')
    work_filesystem=$(mount | awk -v device="$work_filesystem_device" '$1 == device {
      if (match($0, /\([^,]+/)) {
        print substr($0, RSTART + 1, RLENGTH - 1)
        exit
      }
    }')
    ;;
  Linux)
    work_filesystem=$(stat -f -c '%T' "$work_parent")
    ;;
esac
case $work_filesystem in
  tmpfs|ramfs)
    echo "benchmark work directory is on $work_filesystem: $work_parent" >&2
    echo "Choose disk-backed storage by setting TMPDIR, or set BENCH_WORK_PARENT under /var/tmp or TMPDIR." >&2
    exit 2
    ;;
esac
source_git_kib=$(du -sk "$source_repo/.git" | awk '{print $1}')
available_kib=$(df -Pk "$work_parent" |
  awk 'NR == 2 {print $4}')
if (( available_kib < source_git_kib * 12 )); then
  echo "need at least 12x the Godot .git size free under the benchmark temporary directory" >&2
  exit 1
fi
gpg_home_root=$(cd /tmp && pwd -P)
gpg_agent_socket_path="$gpg_home_root/git-remote-e2ee-gnupg.XXXXXX/S.gpg-agent"
if (( ${#gpg_agent_socket_path} >= 90 )); then
  echo "the canonical /tmp path is too long for a GnuPG agent socket: $gpg_home_root" >&2
  exit 2
fi

if [[ ${BENCH_SKIP_BUILD:-0} != 1 ]]; then
  cargo build --release --bins --manifest-path "$project_root/Cargo.toml"
fi
git_e2ee="$project_root/target/release/git-e2ee"
[[ -x $git_e2ee && -x $project_root/target/release/git-remote-e2ee ]] || {
  echo "release helper binaries are missing under target/release" >&2
  exit 1
}

export PATH="$gcrypt_checkout:$project_root/target/release:$PATH"
if [[ ${BENCH_TRACE:-0} == 1 ]]; then
  export GIT_REMOTE_E2EE_TRACE=1
fi
work=$(mktemp -d "$work_parent/git-remote-e2ee-bench.XXXXXX")
work=$(cd "$work" && pwd -P)
chmod 700 "$work"
gpgconf_bin=$(command -v gpgconf || true)
active_gpg_home=
cleanup_gpg_home() {
  local path=$1
  case "$path" in
    "$gpg_home_root"/git-remote-e2ee-gnupg.*)
      if [[ $(cd "$(dirname "$path")" && pwd -P) == "$gpg_home_root" && -d $path && ! -L $path ]]; then
        rm -rf "$path"
      else
        echo "refusing to remove unexpected GPG home: $path" >&2
      fi
      ;;
    *) echo "refusing to remove unexpected GPG home: $path" >&2 ;;
  esac
}
cleanup() {
  if [[ -n $active_gpg_home && -n $gpgconf_bin ]]; then
    "$gpgconf_bin" --homedir "$active_gpg_home" --kill all >/dev/null 2>&1 || true
  fi
  if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
    echo "benchmark work directory retained at $work" >&2
    if [[ -n $active_gpg_home ]]; then
      echo "throwaway GPG home retained at $active_gpg_home" >&2
    fi
    return
  fi
  if [[ -n $active_gpg_home ]]; then
    cleanup_gpg_home "$active_gpg_home"
    active_gpg_home=
  fi
  case "$work" in
    "$work_parent"/git-remote-e2ee-bench.*)
      if [[ $(cd "$(dirname "$work")" && pwd -P) == "$work_parent" && ! -L $work ]]; then
        rm -rf "$work"
      else
        echo "refusing to remove unexpected benchmark path: $work" >&2
      fi
      ;;
    *) echo "refusing to remove unexpected benchmark path: $work" >&2 ;;
  esac
}
trap cleanup EXIT

raw_tsv="$work/measurements.tsv"
printf 'round\ttransport\tphase\titeration\twall_seconds\tmax_rss_bytes\tremote_or_stored_delta_bytes\tremote_or_stored_total_logical_bytes\tremote_or_stored_total_allocated_bytes\tclient_git_logical_bytes\tclient_git_allocated_bytes\tlocal_state_logical_bytes\tlocal_state_allocated_bytes\tclient_object_store_growth\n' >"$raw_tsv"

tree_logical_bytes() {
  local path=$1
  if [[ ! -e $path ]]; then
    echo 0
  elif [[ $time_style == bsd ]]; then
    find "$path" -type f -exec stat -f '%z' {} + | awk '{sum += $1} END {printf "%.0f\n", sum + 0}'
  else
    find "$path" -type f -exec stat -c '%s' {} + | awk '{sum += $1} END {printf "%.0f\n", sum + 0}'
  fi
}

tree_allocated_bytes() {
  local path=$1
  if [[ ! -e $path ]]; then
    echo 0
  else
    du -sk "$path" | awk '{printf "%.0f\n", $1 * 1024}'
  fi
}

git_object_db_bytes() {
  local repo=$1 git_dir
  if [[ ! -d $repo ]]; then
    echo 0
    return
  fi
  git_dir=$(git -C "$repo" rev-parse --absolute-git-dir)
  tree_logical_bytes "$git_dir/objects"
}

git_bare_object_db_bytes() {
  local repo=$1
  tree_logical_bytes "$repo/objects"
}

carrier_cache_object_db_bytes() {
  local root=$1 config repo value total=0
  [[ -d $root ]] || { echo 0; return; }
  while IFS= read -r config; do
    repo=${config%/config}
    if [[ $(git -C "$repo" rev-parse --is-bare-repository 2>/dev/null || true) == true ]]; then
      value=$(git_object_db_bytes "$repo")
      total=$((total + value))
    fi
  done < <(find "$root" -type f -name config -print)
  echo "$total"
}

measure() {
  local label=$1 timing="$work/$1.time" output="$work/$1.stdout" error="$work/$1.stderr"
  shift
  if [[ $time_style == bsd ]]; then
    if ! /usr/bin/time -l -o "$timing" "$@" >"$output" 2>"$error"; then
      echo "benchmark phase failed: $label" >&2
      sed -n '1,100p' "$error" >&2
      sed -n '1,100p' "$output" >&2
      return 1
    fi
    MEASURED_WALL=$(awk '/ real / {print $1; exit}' "$timing")
    MEASURED_RSS_BYTES=$(awk '/maximum resident set size/ {print $1; exit}' "$timing")
  else
    if ! /usr/bin/time -v -o "$timing" "$@" >"$output" 2>"$error"; then
      echo "benchmark phase failed: $label" >&2
      sed -n '1,100p' "$error" >&2
      sed -n '1,100p' "$output" >&2
      return 1
    fi
    MEASURED_WALL=$(awk -F': ' '/Elapsed \(wall clock\)/ {
      n = split($2, a, ":")
      if (n == 3) printf "%.3f\n", a[1] * 3600 + a[2] * 60 + a[3]
      else printf "%.3f\n", a[1] * 60 + a[2]
    }' "$timing")
    MEASURED_RSS_BYTES=$(awk -F': ' '/Maximum resident set size \(kbytes\)/ {
      printf "%.0f\n", $2 * 1024
      exit
    }' "$timing")
  fi
  if [[ -z $MEASURED_RSS_BYTES ]]; then
    echo "could not read max RSS from $timing" >&2
    return 1
  fi
  if [[ ${BENCH_TRACE:-0} == 1 && $label == *e2ee* ]]; then
    awk -v phase="$label" '/^git-remote-e2ee trace / {
      printf "benchmark_trace phase=%s %s\n", phase, $0
    }' "$error" >&2
  fi
}

record() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >>"$raw_tsv"
}

record_sizes() {
  local round=$1 transport=$2 phase=$3 iteration=$4 wall=$5 max_rss=$6
  local remote_delta=$7 remote_path=$8 client_path=$9 state_path=${10} growth=${11}
  local remote_logical remote_allocated client_logical=0 client_allocated=0
  local state_logical=0 state_allocated=0
  remote_logical=$(tree_logical_bytes "$remote_path")
  remote_allocated=$(tree_allocated_bytes "$remote_path")
  if [[ -n $client_path ]]; then
    client_logical=$(tree_logical_bytes "$client_path")
    client_allocated=$(tree_allocated_bytes "$client_path")
  fi
  if [[ -n $state_path ]]; then
    state_logical=$(tree_logical_bytes "$state_path")
    state_allocated=$(tree_allocated_bytes "$state_path")
  fi
  record "$round" "$transport" "$phase" "$iteration" "$wall" "$max_rss" \
    "$remote_delta" "$remote_logical" "$remote_allocated" \
    "$client_logical" "$client_allocated" "$state_logical" \
    "$state_allocated" "$growth"
}

run_round() {
  local round=$1 round_dir="$work/$1"
  local branch=main bare_local plain_git gcrypt_dir gcrypt_git carrier_git
  local gcrypt_url e2ee_url key_directory key_carrier fingerprint gpg_home bare_repo
  local source_work plain_fresh gcrypt_fresh e2ee_fresh
  local cache_push cache_returning wall rss before after secondary i transport
  local remote_path state_path

  mkdir -m 700 "$round_dir"
  source_work="$round_dir/source"
  bare_local="$round_dir/plain-local.git"
  plain_git="$round_dir/plain-git.git"
  gcrypt_dir="$round_dir/gcrypt-directory"
  gcrypt_git="$round_dir/gcrypt-git.git"
  carrier_git="$round_dir/e2ee-carrier.git"
  plain_fresh="$round_dir/plain-returning"
  gcrypt_fresh="$round_dir/gcrypt-returning"
  e2ee_fresh="$round_dir/e2ee-returning"
  cache_push="$round_dir/cache/push"
  cache_returning="$round_dir/cache/returning"
  gpg_home=$(mktemp -d "$gpg_home_root/git-remote-e2ee-gnupg.XXXXXX")
  active_gpg_home=$gpg_home

  export GNUPGHOME="$gpg_home"
  if ! "$gpg_bin" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key 'Benchmark <benchmark@example.invalid>' ed25519 sign 0 \
    >"$gpg_home/keygen.stdout" 2>"$gpg_home/keygen.stderr"; then
    echo "throwaway GPG key generation failed" >&2
    sed -n '1,100p' "$gpg_home/keygen.stderr" >&2
    sed -n '1,100p' "$gpg_home/keygen.stdout" >&2
    return 1
  fi
  fingerprint=$("$gpg_bin" --batch --with-colons --list-secret-keys |
    awk -F: '$1 == "fpr" {print $10; exit}')
  [[ -n $fingerprint ]]
  if ! "$gpg_bin" --batch --pinentry-mode loopback --passphrase '' \
    --quick-add-key "$fingerprint" cv25519 encr 0 \
    >"$gpg_home/subkey.stdout" 2>"$gpg_home/subkey.stderr"; then
    echo "throwaway GPG encryption subkey generation failed" >&2
    sed -n '1,100p' "$gpg_home/subkey.stderr" >&2
    sed -n '1,100p' "$gpg_home/subkey.stdout" >&2
    return 1
  fi

  git clone --quiet --no-local --no-checkout --single-branch --no-tags \
    "file://$source_repo" "$source_work"
  git -C "$source_work" checkout --quiet -B "$branch" "$source_revision"
  git -C "$source_work" checkout --quiet -- README.md
  git -C "$source_work" config gc.auto 0
  git -C "$source_work" config maintenance.auto false
  git -C "$source_work" config gpg.program "$gpg_bin"
  git -C "$source_work" config user.name Benchmark
  git -C "$source_work" config user.email benchmark@example.invalid

  for bare_repo in "$bare_local" "$plain_git" "$gcrypt_git" "$carrier_git"; do
    git init --bare --quiet --initial-branch=main "$bare_repo"
    git --git-dir="$bare_repo" config gc.auto 0
    git --git-dir="$bare_repo" config maintenance.auto false
    git --git-dir="$bare_repo" config receive.autogc false
    git --git-dir="$bare_repo" config receive.unpackLimit 0
  done
  git --git-dir="$gcrypt_git" symbolic-ref HEAD refs/heads/gcrypt-carrier
  if [[ $carrier_attr_tree == 1 ]]; then
    git --git-dir="$carrier_git" config attr.tree refs/heads/git-remote-e2ee
  else
    git --git-dir="$carrier_git" config --unset-all attr.tree 2>/dev/null || true
  fi

  key_directory="$round_dir/directory.key.json"
  key_carrier="$round_dir/carrier.key.json"
  "$git_e2ee" keygen --output "$key_directory" >/dev/null 2>&1
  "$git_e2ee" keygen --output "$key_carrier" >/dev/null 2>&1
  gcrypt_url="gcrypt::file://$gcrypt_git#gcrypt-carrier"
  e2ee_url="e2ee::git+file://$carrier_git"

  git -C "$source_work" remote add plain-local "file://$bare_local"
  git -C "$source_work" remote add gcrypt-directory "gcrypt::$gcrypt_dir"
  git -C "$source_work" remote add plain-git "file://$plain_git"
  git -C "$source_work" remote add gcrypt-git "$gcrypt_url"
  git -C "$source_work" remote add e2ee-directory "e2ee::$round_dir/e2ee-directory"
  git -C "$source_work" remote add e2ee-carrier "$e2ee_url"

  for remote_name in gcrypt-directory gcrypt-git; do
    git -C "$source_work" config "remote.$remote_name.gcrypt-participants" "$fingerprint"
    git -C "$source_work" config "remote.$remote_name.gcrypt-signingkey" "$fingerprint"
    git -C "$source_work" config "remote.$remote_name.gcrypt-require-explicit-force-push" true
  done
  git -C "$source_work" config remote.e2ee-directory.e2ee-key "$key_directory"
  git -C "$source_work" config remote.e2ee-carrier.e2ee-key "$key_carrier"
  "$git_e2ee" init --storage "$round_dir/e2ee-directory" --key "$key_directory" >/dev/null
  env "GIT_REMOTE_E2EE_CACHE_DIR=$cache_push" \
    "$git_e2ee" carrier-init --remote "$carrier_git" --key "$key_carrier" >/dev/null

  echo "round $round: initial local encryption and initial Git-backend pushes" >&2
  if [[ $e2ee_only != 1 ]]; then
    measure "$round-initial-local-plain" \
      git -C "$source_work" push --quiet plain-local "$branch:$branch"
    wall=$MEASURED_WALL
    rss=$MEASURED_RSS_BYTES
    after=$(git_bare_object_db_bytes "$bare_local")
    record_sizes "$round" plain initial_encryption 0 "$wall" "$rss" \
      "$after" "$bare_local" "$source_work/.git" "" 0

    measure "$round-initial-local-gcrypt" \
      git -C "$source_work" push --quiet --force gcrypt-directory "$branch:master"
    wall=$MEASURED_WALL
    rss=$MEASURED_RSS_BYTES
    after=$(tree_logical_bytes "$gcrypt_dir")
    record_sizes "$round" gcrypt initial_encryption 0 "$wall" "$rss" \
      "$after" "$gcrypt_dir" "$source_work/.git" "$source_work/.git/remote-gcrypt" 0
  fi

  measure "$round-initial-local-e2ee" \
    git -C "$source_work" push --quiet e2ee-directory "$branch:$branch"
  wall=$MEASURED_WALL
  rss=$MEASURED_RSS_BYTES
  after=$(tree_logical_bytes "$round_dir/e2ee-directory")
  record_sizes "$round" e2ee initial_encryption 0 "$wall" "$rss" \
    "$after" "$round_dir/e2ee-directory" "$source_work/.git" "" 0

  if [[ $e2ee_only != 1 ]]; then
    before=$(git_bare_object_db_bytes "$plain_git")
    measure "$round-initial-plain-push" \
      git -C "$source_work" push --quiet plain-git "$branch:$branch"
    wall=$MEASURED_WALL
    rss=$MEASURED_RSS_BYTES
    after=$(git_bare_object_db_bytes "$plain_git")
    record_sizes "$round" plain initial_push 0 "$wall" "$rss" \
      "$((after - before))" "$plain_git" "$source_work/.git" "" 0

    before=$(git_bare_object_db_bytes "$gcrypt_git")
    measure "$round-initial-gcrypt-git-push" \
      git -C "$source_work" push --quiet --force gcrypt-git "$branch:master"
    wall=$MEASURED_WALL
    rss=$MEASURED_RSS_BYTES
    after=$(git_bare_object_db_bytes "$gcrypt_git")
    record_sizes "$round" gcrypt initial_push 0 "$wall" "$rss" \
      "$((after - before))" "$gcrypt_git" "$source_work/.git" \
      "$source_work/.git/remote-gcrypt" 0
  fi

  before=$(git_bare_object_db_bytes "$carrier_git")
  measure "$round-initial-e2ee-carrier-push" \
    env "GIT_REMOTE_E2EE_CACHE_DIR=$cache_push" \
    git -C "$source_work" push --quiet e2ee-carrier "$branch:$branch"
  wall=$MEASURED_WALL
  rss=$MEASURED_RSS_BYTES
  after=$(git_bare_object_db_bytes "$carrier_git")
  record_sizes "$round" e2ee initial_push 0 "$wall" "$rss" \
    "$((after - before))" "$carrier_git" "$source_work/.git" "$cache_push" 0

  echo "round $round: fresh no-checkout clones from Git backends" >&2
  if [[ $e2ee_only != 1 ]]; then
    measure "$round-fresh-plain-clone" git \
      -c gc.auto=0 -c maintenance.auto=false \
      clone --quiet --no-local --no-tags --no-checkout --branch "$branch" \
      "file://$plain_git" "$plain_fresh"
    wall=$MEASURED_WALL
    rss=$MEASURED_RSS_BYTES
    after=$(git_object_db_bytes "$plain_fresh")
    record_sizes "$round" plain fresh_fetch 0 "$wall" "$rss" \
      "$(git_bare_object_db_bytes "$plain_git")" "$plain_git" \
      "$plain_fresh/.git" "" "$after"

    measure "$round-fresh-gcrypt-clone" git \
      -c gc.auto=0 -c maintenance.auto=false -c "gpg.program=$gpg_bin" \
      -c "remote.origin.gcrypt-participants=$fingerprint" \
      -c "remote.origin.gcrypt-signingkey=$fingerprint" \
      clone --quiet --no-local --no-tags --no-checkout --branch master \
      "$gcrypt_url" "$gcrypt_fresh"
    wall=$MEASURED_WALL
    rss=$MEASURED_RSS_BYTES
    git -C "$gcrypt_fresh" config gc.auto 0
    git -C "$gcrypt_fresh" config maintenance.auto false
    after=$(git_object_db_bytes "$gcrypt_fresh")
    record_sizes "$round" gcrypt fresh_fetch 0 "$wall" "$rss" \
      "$(git_bare_object_db_bytes "$gcrypt_git")" "$gcrypt_git" \
      "$gcrypt_fresh/.git" "$gcrypt_fresh/.git/remote-gcrypt" "$after"
  fi

  before=$(carrier_cache_object_db_bytes "$cache_returning")
  measure "$round-fresh-e2ee-clone" env \
    "GIT_REMOTE_E2EE_CACHE_DIR=$cache_returning" \
    git -c gc.auto=0 -c maintenance.auto=false -c "e2ee.key=$key_carrier" \
    clone --quiet --no-local --no-tags --no-checkout --branch "$branch" \
    "$e2ee_url" "$e2ee_fresh"
  wall=$MEASURED_WALL
  rss=$MEASURED_RSS_BYTES
  if [[ $e2ee_only != 1 ]]; then
    git -C "$plain_fresh" config gc.auto 0
    git -C "$plain_fresh" config maintenance.auto false
  fi
  git -C "$e2ee_fresh" config gc.auto 0
  git -C "$e2ee_fresh" config maintenance.auto false
  after=$(carrier_cache_object_db_bytes "$cache_returning")
  secondary=$(git_object_db_bytes "$e2ee_fresh")
  record_sizes "$round" e2ee fresh_fetch 0 "$wall" "$rss" \
    "$((after - before))" "$carrier_git" "$e2ee_fresh/.git" \
    "$cache_returning" "$secondary"

  for ((i = 1; i <= tiny_commits; i++)); do
    local plain_added=0 gcrypt_added=0 e2ee_added=0
    measure "$round-tiny-commit-$i" bash -c '
      set -euo pipefail
      repo=$1
      iteration=$2
      readme="$repo/README.md"
      temporary="$repo/README.md.benchmark"
      { printf "Godot Git backend benchmark update %s\\n" "$iteration"; tail -n +2 "$readme"; } >"$temporary"
      mv "$temporary" "$readme"
      git -C "$repo" add -- README.md
      git -C "$repo" commit --quiet -m "benchmark: tiny update $iteration"
    ' _ "$source_work" "$i"
    for transport in "${transports[@]}"; do
      wall=$MEASURED_WALL
      rss=$MEASURED_RSS_BYTES
      case $transport in
        plain) remote_path=$plain_git; state_path= ;;
        gcrypt) remote_path=$gcrypt_git; state_path="$source_work/.git/remote-gcrypt" ;;
        e2ee) remote_path=$carrier_git; state_path=$cache_push ;;
      esac
      record_sizes "$round" "$transport" tiny_commit "$i" "$wall" "$rss" \
        0 "$remote_path" "$source_work/.git" "$state_path" 0
    done

    if [[ $e2ee_only != 1 ]]; then
      before=$(git_bare_object_db_bytes "$plain_git")
      measure "$round-tiny-plain-push-$i" \
        git -C "$source_work" push --quiet plain-git "$branch:$branch"
      wall=$MEASURED_WALL
      rss=$MEASURED_RSS_BYTES
      after=$(git_bare_object_db_bytes "$plain_git")
      plain_added=$((after - before))
      record_sizes "$round" plain tiny_push "$i" "$wall" "$rss" \
        "$plain_added" "$plain_git" "$source_work/.git" "" 0
    fi

    if [[ $e2ee_only != 1 ]] && (( i <= gcrypt_tiny_commits )); then
      before=$(git_bare_object_db_bytes "$gcrypt_git")
      measure "$round-tiny-gcrypt-push-$i" \
        git -C "$source_work" push --quiet --force gcrypt-git "$branch:master"
      wall=$MEASURED_WALL
      rss=$MEASURED_RSS_BYTES
      after=$(git_bare_object_db_bytes "$gcrypt_git")
      gcrypt_added=$((after - before))
      record_sizes "$round" gcrypt tiny_push "$i" "$wall" "$rss" \
        "$gcrypt_added" "$gcrypt_git" "$source_work/.git" \
        "$source_work/.git/remote-gcrypt" 0
    fi

    before=$(git_bare_object_db_bytes "$carrier_git")
    measure "$round-tiny-e2ee-push-$i" \
      env "GIT_REMOTE_E2EE_CACHE_DIR=$cache_push" \
      git -C "$source_work" push --quiet e2ee-carrier "$branch:$branch"
    wall=$MEASURED_WALL
    rss=$MEASURED_RSS_BYTES
    after=$(git_bare_object_db_bytes "$carrier_git")
    e2ee_added=$((after - before))
    record_sizes "$round" e2ee tiny_push "$i" "$wall" "$rss" \
      "$e2ee_added" "$carrier_git" "$source_work/.git" "$cache_push" 0

    if [[ $e2ee_only != 1 ]]; then
      before=$(git_object_db_bytes "$plain_fresh")
      measure "$round-tiny-plain-fetch-$i" \
        git -C "$plain_fresh" fetch --quiet origin
      wall=$MEASURED_WALL
      rss=$MEASURED_RSS_BYTES
      after=$(git_object_db_bytes "$plain_fresh")
      record_sizes "$round" plain tiny_update "$i" "$wall" "$rss" \
        "$plain_added" "$plain_git" "$plain_fresh/.git" "" \
        "$((after - before))"
    fi

    if [[ $e2ee_only != 1 ]] && (( i <= gcrypt_tiny_commits )); then
      before=$(git_object_db_bytes "$gcrypt_fresh")
      measure "$round-tiny-gcrypt-fetch-$i" \
        git -C "$gcrypt_fresh" fetch --quiet origin
      wall=$MEASURED_WALL
      rss=$MEASURED_RSS_BYTES
      after=$(git_object_db_bytes "$gcrypt_fresh")
      record_sizes "$round" gcrypt tiny_update "$i" "$wall" "$rss" \
        "$gcrypt_added" "$gcrypt_git" "$gcrypt_fresh/.git" \
        "$gcrypt_fresh/.git/remote-gcrypt" "$((after - before))"
    fi

    before=$(carrier_cache_object_db_bytes "$cache_returning")
    secondary_before=$(git_object_db_bytes "$e2ee_fresh")
    measure "$round-tiny-e2ee-fetch-$i" \
      env "GIT_REMOTE_E2EE_CACHE_DIR=$cache_returning" \
      git -C "$e2ee_fresh" fetch --quiet origin
    wall=$MEASURED_WALL
    rss=$MEASURED_RSS_BYTES
    after=$(carrier_cache_object_db_bytes "$cache_returning")
    secondary=$(git_object_db_bytes "$e2ee_fresh")
    record_sizes "$round" e2ee tiny_update "$i" "$wall" "$rss" \
      "$e2ee_added" "$carrier_git" "$e2ee_fresh/.git" \
      "$cache_returning" "$((secondary - secondary_before))"
  done

  if [[ $e2ee_only != 1 ]]; then
    [[ $(git -C "$plain_fresh" rev-parse "refs/remotes/origin/$branch") == \
      $(git -C "$source_work" rev-parse "$branch") ]]
    [[ $(git -C "$gcrypt_fresh" rev-parse refs/remotes/origin/master) == \
      $(git -C "$source_work" rev-parse "$branch~$((tiny_commits - gcrypt_tiny_commits))") ]]
  fi
  [[ $(git -C "$e2ee_fresh" rev-parse "refs/remotes/origin/$branch") == \
    $(git -C "$source_work" rev-parse "$branch") ]]

  if [[ -n $gpgconf_bin ]]; then
    "$gpgconf_bin" --homedir "$gpg_home" --kill all >/dev/null 2>&1 || true
  fi
  unset GNUPGHOME
  if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
    echo "throwaway GPG home retained at $gpg_home" >&2
  else
    cleanup_gpg_home "$gpg_home"
  fi
  active_gpg_home=
  if [[ ${BENCH_KEEP_WORK:-0} != 1 ]]; then
    case "$round_dir" in
      "$work"/[1-3])
        if [[ -d $round_dir && ! -L $round_dir ]]; then
          rm -rf "$round_dir"
        fi
        ;;
      *) echo "refusing to remove unexpected round path: $round_dir" >&2 ;;
    esac
  fi
}

median_value() {
  local transport=$1 phase=$2 field=$3 iteration=${4:-}
  awk -F '\t' -v t="$transport" -v p="$phase" -v i="$iteration" -v f="$field" '
    NR > 1 && $2 == t && $3 == p && (i == "" || $4 == i) { print $f }
  ' "$raw_tsv" | sort -n | awk '
    { values[NR] = $1 }
    END {
      if (NR == 0) { print "-"; exit }
      if (NR % 2 == 1) printf "%.3f", values[(NR + 1) / 2]
      else printf "%.3f", (values[NR / 2] + values[NR / 2 + 1]) / 2
    }
  '
}

for ((round = 1; round <= rounds; round++)); do
  run_round "$round"
done

medians_tsv="$work/medians.tsv"
printf 'transport\tphase\titeration\tmedian_wall_seconds\tmedian_max_rss_bytes\tmedian_remote_delta_bytes\tmedian_remote_total_logical_bytes\tmedian_remote_total_allocated_bytes\tmedian_client_git_logical_bytes\tmedian_client_git_allocated_bytes\tmedian_local_state_logical_bytes\tmedian_local_state_allocated_bytes\tmedian_client_object_store_growth\n' >"$medians_tsv"
for phase in initial_encryption initial_push fresh_fetch tiny_commit tiny_push tiny_update; do
  for transport in "${transports[@]}"; do
    printf '%s\t%s\tall' "$transport" "$phase" >>"$medians_tsv"
    for field in 5 6 7 8 9 10 11 12 13 14; do
      printf '\t%s' "$(median_value "$transport" "$phase" "$field")" >>"$medians_tsv"
    done
    printf '\n' >>"$medians_tsv"
  done
done

for phase in tiny_push tiny_update; do
  for ((i = 1; i <= tiny_commits; i++)); do
    for transport in "${transports[@]}"; do
      printf '%s\t%s\t%s' "$transport" "$phase" "$i" >>"$medians_tsv"
      for field in 5 6 7 8 9 10 11 12 13 14; do
        printf '\t%s' "$(median_value "$transport" "$phase" "$field" "$i")" >>"$medians_tsv"
      done
      printf '\n' >>"$medians_tsv"
    done
  done
done

cp "$raw_tsv" "$results_dir/raw.tsv"
cp "$medians_tsv" "$results_dir/medians.tsv"
printf 'Wrote %s and %s\n' "$results_dir/raw.tsv" "$results_dir/medians.tsv"
if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
  echo "raw command logs, repositories, and GPG homes retained under $work" >&2
else
  echo "raw command logs, repositories, and GPG homes were removed from $work" >&2
fi
