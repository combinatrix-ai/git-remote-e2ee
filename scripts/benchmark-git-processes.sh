#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: benchmark-git-processes.sh SETUP_BIN_DIR MEASURE_BIN_DIR...

Counts the git processes and wall time of the remote helper for a fetch
(list + fetch) into a fresh clone and for a push of one ref, in a repository
with BENCH_BRANCHES branches (default 50) and BENCH_TAGS annotated tags
(default 1000). Each directory holds git-e2ee and git-remote-e2ee. The
repository is built once with SETUP_BIN_DIR; each measured build then runs
against its own copy of the storage, source repository, and client state.
Processes are counted from GIT_TRACE "built-in" and "exec" lines, which
every git process writes once.
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi
setup_bin=$(cd "$1" && pwd -P)
shift
branches=${BENCH_BRANCHES:-50}
tags=${BENCH_TAGS:-1000}

work=$(mktemp -d "${TMPDIR:-/tmp}/git-remote-e2ee-processes.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
export XDG_STATE_HOME="$work/xdg-state" XDG_CONFIG_HOME="$work/xdg-config"
export GIT_CONFIG_NOSYSTEM=1 HOME="$work/home"
mkdir -p "$HOME"
git config --global user.name bench
git config --global user.email bench@example.invalid
git config --global init.defaultBranch main
git config --global gc.auto 0
git config --global maintenance.auto false

PATH="$setup_bin:$PATH" git-e2ee keygen --output "$work/key.json" >/dev/null
mkdir "$work/storage"
(cd "$work" && PATH="$setup_bin:$PATH" git-e2ee init "e2ee::dir:$work/storage" \
  --key "$work/key.json" >/dev/null)

git init -q "$work/source"
for ((i = 0; i < branches; i++)); do
  git -C "$work/source" commit -q --allow-empty -m "commit $i"
  [[ $i -eq 0 ]] || git -C "$work/source" branch "branch-$i"
done
{
  for ((i = 0; i < tags; i++)); do
    printf 'create refs/tags/v%d %s\n' "$i" \
      "$(git -C "$work/source" mktag <<EOF
object $(git -C "$work/source" rev-parse "HEAD~$((i % branches))")
type commit
tag v$i
tagger bench <bench@example.invalid> 0 +0000

tag $i
EOF
)"
  done
} | git -C "$work/source" update-ref --stdin
git -C "$work/source" remote add origin "e2ee::dir:$work/storage"
git -C "$work/source" config remote.origin.e2ee-key "$work/key.json"
setup_started=$(date +%s)
PATH="$setup_bin:$PATH" git -C "$work/source" push -q origin --all
PATH="$setup_bin:$PATH" git -C "$work/source" push -q origin --tags
echo "setup: $((branches + tags)) refs pushed in $(($(date +%s) - setup_started)) s" >&2

measure() {
  local label=$1
  shift
  local trace="$run/trace-$label"
  local started ended
  started=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
  PATH="$measure_bin:$PATH" GIT_TRACE="$trace" "$@"
  ended=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
  printf '%-12s %-9s processes=%-6d wall=%.3fs\n' "$(basename "$measure_bin")" "$label" \
    "$(grep -cE 'trace: (built-in|exec): ' "$trace")" \
    "$(echo "$ended - $started" | bc)"
  sed -nE 's/.*trace: (built-in|exec): git ([^ ]+).*/\2/p' "$trace" | sort | uniq -c |
    sort -rn | head -5 | awk '{printf "    %6d git %s\n", $1, $2}'
}

git -C "$work/source" commit -q --allow-empty -m "measured push"
for bin in "$@"; do
  measure_bin=$(cd "$bin" && pwd -P)
  run="$work/run-$(basename "$measure_bin")"
  mkdir "$run"
  cp -R "$work/storage" "$run/storage"
  cp -R "$work/source" "$run/source"
  cp -R "$XDG_STATE_HOME" "$run/xdg-state"
  (
    export XDG_STATE_HOME="$run/xdg-state"
    git -C "$run/source" remote set-url origin "e2ee::dir:$run/storage"
    git init -q "$run/clone"
    git -C "$run/clone" remote add origin "e2ee::dir:$run/storage"
    git -C "$run/clone" config remote.origin.e2ee-key "$work/key.json"
    measure fetch git -C "$run/clone" fetch -q origin
    measure push-one git -C "$run/source" push -q origin main
  )
done
