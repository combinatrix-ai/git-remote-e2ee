#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: benchmark-git-backend.sh [GODOT_CHECKOUT [GCRYPT_CHECKOUT]]

Runs three fresh rounds comparing plain Git, git-remote-gcrypt's Git backend,
and git-remote-e2ee's carrier-Git backend. Inputs default to the checkouts at
/Volumes/Shared/local/references/godot and
/Volumes/Shared/local/references/git-remote-gcrypt. The Godot checkout must
have benchmark-00932449 at 00932449c9f372b30301d8b5fdc1be70ec12b5c0; the
gcrypt checkout must be at a5ff704d071f14b95b6b1fa0caa8cdbf0c6cdadb.

Set BENCH_WORK_PARENT to override the default /private/tmp location; the
resolved path must remain under /private/tmp or $TMPDIR. Set
BENCH_KEEP_WORK=1 to retain temporary repositories, raw logs, and the
throwaway GPG home for local debugging. Results are printed as TSV; keys and
raw logs are never written into the project. BENCH_TINY_COMMITS defaults to 5
and BENCH_GCRYPT_TINY_COMMITS defaults to 5 (3 is allowed for a prohibitively
slow full-history gcrypt run). BENCH_ROUNDS defaults to 3 and may be reduced
for a smoke run. BENCH_SKIP_BUILD=1 uses existing release binaries instead of
building them. Byte values are logical object-store file sizes, not packet
captures. For fetches they use the matching newly published remote objects;
client object-store growth is reported separately where measurable.
Set BENCH_TRACE=1 to enable E2EE phase timing and print trace lines for each
measured E2EE operation to stderr.
Set BENCH_E2EE_ONLY=1 to skip plain and gcrypt measurements. Set
BENCH_CARRIER_ATTR_TREE=0 to leave attr.tree unset on the local carrier
receiver, simulating servers that ignore the committed carrier attributes.
EOF
}

if [[ $# -gt 2 ]]; then
  usage
  exit 2
fi
if [[ $# -gt 0 && ( $1 == -h || $1 == --help ) ]]; then
  usage
  exit 0
fi

project_root=$(cd "$(dirname "$0")/.." && pwd -P)
source_repo=${1:-/Volumes/Shared/local/references/godot}
gcrypt_checkout=${2:-/Volumes/Shared/local/references/git-remote-gcrypt}
source_repo=$(cd "$source_repo" && pwd -P)
gcrypt_checkout=$(cd "$gcrypt_checkout" && pwd -P)
source_revision=00932449c9f372b30301d8b5fdc1be70ec12b5c0
gcrypt_revision=a5ff704d071f14b95b6b1fa0caa8cdbf0c6cdadb
e2ee_revision=$(git -C "$project_root" rev-parse HEAD)
tiny_commits=${BENCH_TINY_COMMITS:-5}
gcrypt_tiny_commits=${BENCH_GCRYPT_TINY_COMMITS:-5}
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
[[ $(git -C "$source_repo" symbolic-ref --quiet --short HEAD) == benchmark-00932449 ]] || {
  echo "Godot revision must be checked out on local branch benchmark-00932449" >&2
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

gpg_bin=${BENCH_GPG:-/opt/homebrew/bin/gpg}
[[ -x $gpg_bin ]] || {
  echo "GnuPG executable not found: $gpg_bin" >&2
  exit 1
}
case $(uname -s) in
  Darwin) time_style=bsd ;;
  Linux) time_style=gnu ;;
  *) echo "unsupported platform: $(uname -s)" >&2; exit 2 ;;
esac
[[ -x /usr/bin/time ]] || {
  echo "/usr/bin/time is required" >&2
  exit 1
}
work_parent=${BENCH_WORK_PARENT:-/private/tmp}
mkdir -p "$work_parent"
work_parent=$(cd "$work_parent" && pwd -P)
allowed_work_parent=false
for allowed_root in /private/tmp "${TMPDIR:-}"; do
  [[ -n $allowed_root ]] || continue
  [[ -d $allowed_root ]] || continue
  allowed_root=$(cd "$allowed_root" && pwd -P)
  if [[ $work_parent == "$allowed_root" || $work_parent == "$allowed_root"/* ]]; then
    allowed_work_parent=true
    break
  fi
done
if [[ $allowed_work_parent != true ]]; then
  echo "benchmark work parent must resolve under /private/tmp or TMPDIR: $work_parent" >&2
  exit 2
fi
source_git_kib=$(du -sk "$source_repo/.git" | awk '{print $1}')
available_kib=$(df -Pk "$work_parent" |
  awk 'NR == 2 {print $4}')
if (( available_kib < source_git_kib * 12 )); then
  echo "need at least 12x the Godot .git size free under the benchmark temp directory" >&2
  exit 1
fi

if [[ ${BENCH_SKIP_BUILD:-0} != 1 ]]; then
  cargo build --release --bins --manifest-path "$project_root/Cargo.toml"
fi
git_e2ee="$project_root/target/release/git-e2ee"
[[ -x $git_e2ee && -x $project_root/target/release/git-remote-e2ee ]] || {
  echo "release helper binaries are missing under target/release" >&2
  exit 1
}

export PATH="$gcrypt_checkout:$project_root/target/release:$(dirname "$gpg_bin"):$PATH"
if [[ ${BENCH_TRACE:-0} == 1 ]]; then
  export GIT_REMOTE_E2EE_TRACE=1
fi
work=$(mktemp -d "$work_parent/git-remote-e2ee-git-backend.XXXXXX")
chmod 700 "$work"
cleanup() {
  if [[ -n ${GNUPGHOME:-} ]]; then
    cleanup_gpgconf="$(dirname "$gpg_bin")/gpgconf"
    if [[ -x $cleanup_gpgconf ]]; then
      "$cleanup_gpgconf" --homedir "$GNUPGHOME" --kill all >/dev/null 2>&1 || true
    fi
  fi
  if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
    echo "benchmark work directory retained at $work" >&2
    return
  fi
  case "$work" in
    "$work_parent"/git-remote-e2ee-git-backend.*)
      python3 -c 'import pathlib, shutil, sys; root = pathlib.Path(sys.argv[1]).resolve(); target = pathlib.Path(sys.argv[2]).resolve(); assert target.parent == root and target.name.startswith("git-remote-e2ee-git-backend."); shutil.rmtree(target)' "$work_parent" "$work"
      ;;
    *) echo "refusing to remove unexpected benchmark path: $work" >&2 ;;
  esac
}
trap cleanup EXIT

raw_tsv="$work/measurements.tsv"
printf 'round\ttransport\tphase\titeration\twall_seconds\tremote_or_stored_bytes\tclient_object_store_growth\n' >"$raw_tsv"

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
    awk '/ real / {print $1; exit}' "$timing"
  else
    if ! /usr/bin/time -v -o "$timing" "$@" >"$output" 2>"$error"; then
      echo "benchmark phase failed: $label" >&2
      sed -n '1,100p' "$error" >&2
      sed -n '1,100p' "$output" >&2
      return 1
    fi
    awk -F': ' '/Elapsed \(wall clock\)/ {
      n = split($2, a, ":")
      if (n == 3) printf "%.3f\n", a[1] * 3600 + a[2] * 60 + a[3]
      else printf "%.3f\n", a[1] * 60 + a[2]
    }' "$timing"
  fi
  if [[ ${BENCH_TRACE:-0} == 1 && $label == *e2ee* ]]; then
    awk -v phase="$label" '/^git-remote-e2ee trace / {
      printf "benchmark_trace phase=%s %s\n", phase, $0
    }' "$error" >&2
  fi
}

record() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >>"$raw_tsv"
}

run_round() {
  local round=$1 round_dir="$work/$1"
  local branch=main bare_local plain_git gcrypt_dir gcrypt_git carrier_git
  local gcrypt_url e2ee_url key_directory key_carrier fingerprint gpg_home bare_repo
  local source_work plain_fresh gcrypt_fresh e2ee_fresh
  local cache_push cache_returning wall before after secondary i transport

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
  gpg_home="$round_dir/gnupg"

  mkdir -m 700 "$gpg_home"
  export GNUPGHOME="$gpg_home"
  if ! "$gpg_bin" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key 'Benchmark <benchmark@example.invalid>' ed25519 sign 0 \
    >"$gpg_home/keygen.stdout" 2>"$gpg_home/keygen.stderr"; then
    echo "throwaway GPG key generation failed (temporary diagnostics: $gpg_home)" >&2
    return 1
  fi
  fingerprint=$("$gpg_bin" --batch --with-colons --list-secret-keys |
    awk -F: '$1 == "fpr" {print $10; exit}')
  [[ -n $fingerprint ]]
  if ! "$gpg_bin" --batch --pinentry-mode loopback --passphrase '' \
    --quick-add-key "$fingerprint" cv25519 encr 0 \
    >"$gpg_home/subkey.stdout" 2>"$gpg_home/subkey.stderr"; then
    echo "throwaway GPG encryption subkey generation failed (temporary diagnostics: $gpg_home)" >&2
    return 1
  fi

  git clone --quiet --no-local --no-checkout --single-branch --no-tags \
    --branch benchmark-00932449 "file://$source_repo" "$source_work"
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
    wall=$(measure "$round-initial-local-plain" \
      git -C "$source_work" push --quiet plain-local "$branch:$branch")
    after=$(git_bare_object_db_bytes "$bare_local")
    record "$round" plain initial_encryption 0 "$wall" "$after" 0

    wall=$(measure "$round-initial-local-gcrypt" \
      git -C "$source_work" push --quiet --force gcrypt-directory "$branch:master")
    after=$(tree_logical_bytes "$gcrypt_dir")
    record "$round" gcrypt initial_encryption 0 "$wall" "$after" 0
  fi

  wall=$(measure "$round-initial-local-e2ee" \
    git -C "$source_work" push --quiet e2ee-directory "$branch:$branch")
  after=$(tree_logical_bytes "$round_dir/e2ee-directory")
  record "$round" e2ee initial_encryption 0 "$wall" "$after" 0

  if [[ $e2ee_only != 1 ]]; then
    before=$(git_bare_object_db_bytes "$plain_git")
    wall=$(measure "$round-initial-plain-push" \
      git -C "$source_work" push --quiet plain-git "$branch:$branch")
    after=$(git_bare_object_db_bytes "$plain_git")
    record "$round" plain initial_push 0 "$wall" "$((after - before))" 0

    before=$(git_bare_object_db_bytes "$gcrypt_git")
    wall=$(measure "$round-initial-gcrypt-git-push" \
      git -C "$source_work" push --quiet --force gcrypt-git "$branch:master")
    after=$(git_bare_object_db_bytes "$gcrypt_git")
    record "$round" gcrypt initial_push 0 "$wall" "$((after - before))" 0
  fi

  before=$(git_bare_object_db_bytes "$carrier_git")
  wall=$(measure "$round-initial-e2ee-carrier-push" \
    env "GIT_REMOTE_E2EE_CACHE_DIR=$cache_push" \
    git -C "$source_work" push --quiet e2ee-carrier "$branch:$branch")
  after=$(git_bare_object_db_bytes "$carrier_git")
  record "$round" e2ee initial_push 0 "$wall" "$((after - before))" 0

  echo "round $round: fresh no-checkout clones from Git backends" >&2
  if [[ $e2ee_only != 1 ]]; then
    wall=$(measure "$round-fresh-plain-clone" git \
      -c gc.auto=0 -c maintenance.auto=false \
      clone --quiet --no-local --no-tags --no-checkout --branch "$branch" \
      "file://$plain_git" "$plain_fresh")
    after=$(git_object_db_bytes "$plain_fresh")
    record "$round" plain fresh_fetch 0 "$wall" \
      "$(git_bare_object_db_bytes "$plain_git")" "$after"

    wall=$(measure "$round-fresh-gcrypt-clone" git \
      -c gc.auto=0 -c maintenance.auto=false -c "gpg.program=$gpg_bin" \
      -c "remote.origin.gcrypt-participants=$fingerprint" \
      -c "remote.origin.gcrypt-signingkey=$fingerprint" \
      clone --quiet --no-local --no-tags --no-checkout --branch master \
      "$gcrypt_url" "$gcrypt_fresh")
    git -C "$gcrypt_fresh" config gc.auto 0
    git -C "$gcrypt_fresh" config maintenance.auto false
    after=$(git_object_db_bytes "$gcrypt_fresh")
    record "$round" gcrypt fresh_fetch 0 "$wall" \
      "$(git_bare_object_db_bytes "$gcrypt_git")" "$after"
  fi

  before=$(carrier_cache_object_db_bytes "$cache_returning")
  wall=$(measure "$round-fresh-e2ee-clone" env \
    "GIT_REMOTE_E2EE_CACHE_DIR=$cache_returning" \
    git -c gc.auto=0 -c maintenance.auto=false -c "e2ee.key=$key_carrier" \
    clone --quiet --no-local --no-tags --no-checkout --branch "$branch" \
    "$e2ee_url" "$e2ee_fresh")
  if [[ $e2ee_only != 1 ]]; then
    git -C "$plain_fresh" config gc.auto 0
    git -C "$plain_fresh" config maintenance.auto false
  fi
  git -C "$e2ee_fresh" config gc.auto 0
  git -C "$e2ee_fresh" config maintenance.auto false
  after=$(carrier_cache_object_db_bytes "$cache_returning")
  secondary=$(git_object_db_bytes "$e2ee_fresh")
  record "$round" e2ee fresh_fetch 0 "$wall" "$((after - before))" "$secondary"

  for ((i = 1; i <= tiny_commits; i++)); do
    local plain_added=0 gcrypt_added=0 e2ee_added=0
    wall=$(measure "$round-tiny-commit-$i" bash -c '
      set -euo pipefail
      repo=$1
      iteration=$2
      readme="$repo/README.md"
      temporary="$repo/README.md.benchmark"
      { printf "Godot Git backend benchmark update %s\\n" "$iteration"; tail -n +2 "$readme"; } >"$temporary"
      mv "$temporary" "$readme"
      git -C "$repo" add -- README.md
      git -C "$repo" commit --quiet -m "benchmark: tiny update $iteration"
    ' _ "$source_work" "$i")
    for transport in "${transports[@]}"; do
      record "$round" "$transport" tiny_commit "$i" "$wall" 0 0
    done

    if [[ $e2ee_only != 1 ]]; then
      before=$(git_bare_object_db_bytes "$plain_git")
      wall=$(measure "$round-tiny-plain-push-$i" \
        git -C "$source_work" push --quiet plain-git "$branch:$branch")
      after=$(git_bare_object_db_bytes "$plain_git")
      plain_added=$((after - before))
      record "$round" plain tiny_push "$i" "$wall" "$plain_added" 0
    fi

    if [[ $e2ee_only != 1 ]] && (( i <= gcrypt_tiny_commits )); then
      before=$(git_bare_object_db_bytes "$gcrypt_git")
      wall=$(measure "$round-tiny-gcrypt-push-$i" \
        git -C "$source_work" push --quiet --force gcrypt-git "$branch:master")
      after=$(git_bare_object_db_bytes "$gcrypt_git")
      gcrypt_added=$((after - before))
      record "$round" gcrypt tiny_push "$i" "$wall" "$gcrypt_added" 0
    fi

    before=$(git_bare_object_db_bytes "$carrier_git")
    wall=$(measure "$round-tiny-e2ee-push-$i" \
      env "GIT_REMOTE_E2EE_CACHE_DIR=$cache_push" \
      git -C "$source_work" push --quiet e2ee-carrier "$branch:$branch")
    after=$(git_bare_object_db_bytes "$carrier_git")
    e2ee_added=$((after - before))
    record "$round" e2ee tiny_push "$i" "$wall" "$e2ee_added" 0

    if [[ $e2ee_only != 1 ]]; then
      before=$(git_object_db_bytes "$plain_fresh")
      wall=$(measure "$round-tiny-plain-fetch-$i" \
        git -C "$plain_fresh" fetch --quiet origin)
      after=$(git_object_db_bytes "$plain_fresh")
      record "$round" plain tiny_update "$i" "$wall" \
        "$plain_added" "$((after - before))"
    fi

    if [[ $e2ee_only != 1 ]] && (( i <= gcrypt_tiny_commits )); then
      before=$(git_object_db_bytes "$gcrypt_fresh")
      wall=$(measure "$round-tiny-gcrypt-fetch-$i" \
        git -C "$gcrypt_fresh" fetch --quiet origin)
      after=$(git_object_db_bytes "$gcrypt_fresh")
      record "$round" gcrypt tiny_update "$i" "$wall" \
        "$gcrypt_added" "$((after - before))"
    fi

    before=$(carrier_cache_object_db_bytes "$cache_returning")
    secondary_before=$(git_object_db_bytes "$e2ee_fresh")
    wall=$(measure "$round-tiny-e2ee-fetch-$i" \
      env "GIT_REMOTE_E2EE_CACHE_DIR=$cache_returning" \
      git -C "$e2ee_fresh" fetch --quiet origin)
    after=$(carrier_cache_object_db_bytes "$cache_returning")
    secondary=$(git_object_db_bytes "$e2ee_fresh")
    record "$round" e2ee tiny_update "$i" "$wall" \
      "$e2ee_added" "$((secondary - secondary_before))"
  done

  if [[ $e2ee_only != 1 ]]; then
    [[ $(git -C "$plain_fresh" rev-parse "refs/remotes/origin/$branch") == \
      $(git -C "$source_work" rev-parse "$branch") ]]
    [[ $(git -C "$gcrypt_fresh" rev-parse refs/remotes/origin/master) == \
      $(git -C "$source_work" rev-parse "$branch~$((tiny_commits - gcrypt_tiny_commits))") ]]
  fi
  [[ $(git -C "$e2ee_fresh" rev-parse "refs/remotes/origin/$branch") == \
    $(git -C "$source_work" rev-parse "$branch") ]]

  gpgconf_bin="$(dirname "$gpg_bin")/gpgconf"
  if [[ -x $gpgconf_bin ]]; then
    "$gpgconf_bin" --homedir "$gpg_home" --kill all >/dev/null 2>&1 || true
  fi
  unset GNUPGHOME
  if [[ ${BENCH_KEEP_WORK:-0} != 1 ]]; then
    python3 -c 'import errno, pathlib, shutil, sys, time; root = pathlib.Path(sys.argv[1]).resolve(); target = pathlib.Path(sys.argv[2]).resolve(); assert target.parent == root and target.name in {"1", "2", "3"};
for attempt in range(20):
  try:
    shutil.rmtree(target)
    break
  except OSError as error:
    if error.errno not in (errno.ENOTEMPTY, errno.EBUSY) or attempt == 19:
      raise
    time.sleep(0.5)' "$work" "$round_dir"
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

printf 'source_revision\t%s\n' "$source_revision"
printf 'godot_commits\t%s\n' "$(git -C "$source_repo" rev-list --count HEAD)"
printf 'godot_head_files\t%s\n' "$(git -C "$source_repo" ls-tree -r --name-only HEAD | wc -l | tr -d ' ')"
printf 'godot_reachable_bytes\t%s\n' "$(git -C "$source_repo" rev-list --disk-usage --objects HEAD | awk '{print $1}')"
printf 'gcrypt_revision\t%s\n' "$gcrypt_revision"
printf 'git_remote_e2ee_revision\t%s\n' "$e2ee_revision"
printf 'git_version\t%s\n' "$(git --version)"
printf 'gpg_version\t%s\n' "$("$gpg_bin" --version | sed -n '1p')"
printf '\nmedians across %s fresh round(s)\n' "$rounds"
printf 'transport\tphase\titeration\tmedian_wall_seconds\tmedian_remote_or_stored_bytes\tmedian_client_object_store_growth\n'
for phase in initial_encryption initial_push fresh_fetch tiny_commit tiny_push tiny_update; do
  for transport in "${transports[@]}"; do
    wall=$(median_value "$transport" "$phase" 5)
    bytes=$(median_value "$transport" "$phase" 6)
    client_bytes=$(median_value "$transport" "$phase" 7)
    printf '%s\t%s\tall\t%s\t%s\t%s\n' \
      "$transport" "$phase" "$wall" "$bytes" "$client_bytes"
  done
done

printf '\nper-push series: tiny push\n'
printf 'transport\titeration\tmedian_wall_seconds\tmedian_remote_bytes_added\n'
for ((i = 1; i <= tiny_commits; i++)); do
  for transport in "${transports[@]}"; do
    if [[ $transport == gcrypt ]] && (( i > gcrypt_tiny_commits )); then
      continue
    fi
    printf '%s\t%s\t%s\t%s\n' "$transport" "$i" \
      "$(median_value "$transport" tiny_push 5 "$i")" \
      "$(median_value "$transport" tiny_push 6 "$i")"
  done
done

printf '\nper-push series: tiny update fetch\n'
printf 'transport\titeration\tmedian_wall_seconds\tmedian_new_remote_object_bytes\n'
for ((i = 1; i <= tiny_commits; i++)); do
  for transport in "${transports[@]}"; do
    if [[ $transport == gcrypt ]] && (( i > gcrypt_tiny_commits )); then
      continue
    fi
    printf '%s\t%s\t%s\t%s\n' "$transport" "$i" \
      "$(median_value "$transport" tiny_update 5 "$i")" \
      "$(median_value "$transport" tiny_update 6 "$i")"
  done
done

printf '\nraw per-round metrics (not command logs)\n'
cat "$raw_tsv"
if [[ ${BENCH_KEEP_WORK:-0} == 1 ]]; then
  echo "raw command logs, repositories, and GPG homes retained under $work" >&2
else
  echo "raw command logs, repositories, and GPG homes were removed from $work" >&2
fi
