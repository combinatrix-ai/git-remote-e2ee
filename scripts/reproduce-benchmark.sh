#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

usage() {
  cat <<'EOF'
usage: scripts/reproduce-benchmark.sh

Fetches the pinned Godot and git-remote-gcrypt histories, runs the full
three-round benchmark, and writes raw.tsv, medians.tsv, environment.json, and
summary.md under ./bench-results/<UTC timestamp>-<host>/.

Set BENCH_CACHE_DIR to override the input cache. Set BENCH_RESULTS_DIR to
choose an exact results directory. Set BENCH_WORK_PARENT to choose a temporary
work directory under an allowed temporary root. Linux defaults to /var/tmp;
TMPDIR overrides the default when set. tmpfs and ramfs work directories are
rejected. BENCH_ROUNDS defaults to 3, BENCH_TINY_COMMITS defaults to 5, and
BENCH_GCRYPT_TINY_COMMITS defaults to BENCH_TINY_COMMITS.
EOF
}

if [[ $# -gt 0 ]]; then
  if [[ $# == 1 && ( $1 == -h || $1 == --help ) ]]; then
    usage
    exit 0
  fi
  usage >&2
  exit 2
fi

project_root=$(cd "$(dirname "$0")/.." && pwd -P)
godot_url=https://github.com/godotengine/godot.git
gcrypt_url=https://github.com/spwhitton/git-remote-gcrypt.git
godot_revision=00932449c9f372b30301d8b5fdc1be70ec12b5c0
gcrypt_revision=a5ff704d071f14b95b6b1fa0caa8cdbf0c6cdadb

rounds=${BENCH_ROUNDS:-3}
tiny_commits=${BENCH_TINY_COMMITS:-5}
gcrypt_tiny_commits=${BENCH_GCRYPT_TINY_COMMITS:-$tiny_commits}
e2ee_only=${BENCH_E2EE_ONLY:-0}
carrier_attr_tree=${BENCH_CARRIER_ATTR_TREE:-1}
trace=${BENCH_TRACE:-0}
skip_build=${BENCH_SKIP_BUILD:-0}
keep_work=${BENCH_KEEP_WORK:-0}

if [[ ! $rounds =~ ^[1-3]$ ]]; then
  echo "BENCH_ROUNDS must be from 1 to 3" >&2
  exit 2
fi
if [[ ! $tiny_commits =~ ^[1-5]$ ]]; then
  echo "BENCH_TINY_COMMITS must be from 1 to 5" >&2
  exit 2
fi
if [[ ! $gcrypt_tiny_commits =~ ^[1-5]$ ]] || (( gcrypt_tiny_commits > tiny_commits )); then
  echo "BENCH_GCRYPT_TINY_COMMITS must be from 1 to BENCH_TINY_COMMITS" >&2
  exit 2
fi
validate_switch() {
  local name=$1 value=$2
  if [[ $value != 0 && $value != 1 ]]; then
    echo "$name must be 0 or 1" >&2
    exit 2
  fi
}
validate_switch BENCH_E2EE_ONLY "$e2ee_only"
validate_switch BENCH_CARRIER_ATTR_TREE "$carrier_attr_tree"
validate_switch BENCH_TRACE "$trace"
validate_switch BENCH_SKIP_BUILD "$skip_build"
validate_switch BENCH_KEEP_WORK "$keep_work"

os=$(uname -s)
case $os in
  Darwin) time_style=bsd ;;
  Linux) time_style=gnu ;;
  *) echo "unsupported operating system: $os (supported: macOS and Linux)" >&2; exit 2 ;;
esac

missing=()
for tool in git gpg cargo rustc du df awk find sort stat mktemp hostname date sed tr tail wc chmod cp mv mkdir rmdir rm cat dirname; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf "missing required command on PATH: %s\n" "$tool" >&2
    missing+=("$tool")
  fi
done
if [[ $os == Darwin ]] && ! command -v mount >/dev/null 2>&1; then
  echo "missing required command on PATH: mount" >&2
  missing+=(mount)
fi
if [[ ! -x /usr/bin/time ]]; then
  echo "missing required command: /usr/bin/time" >&2
  missing+=(time)
fi
if (( ${#missing[@]} > 0 )); then
  echo "Install the missing tools, then rerun the benchmark." >&2
  echo "Debian/Ubuntu: sudo apt-get install git gnupg cargo rustc time coreutils findutils gawk sed" >&2
  echo "Homebrew: brew install git gnupg rust gawk" >&2
  exit 1
fi

case $time_style in
  bsd)
    if ! /usr/bin/time -l -o /dev/null true >/dev/null 2>&1; then
      echo "/usr/bin/time must support BSD -l output on macOS" >&2
      echo "Debian/Ubuntu: sudo apt-get install time" >&2
      echo "Homebrew: macOS normally supplies BSD /usr/bin/time; restore the system tool." >&2
      exit 1
    fi
    ;;
  gnu)
    if ! /usr/bin/time -v -o /dev/null true >/dev/null 2>&1; then
      echo "/usr/bin/time must support GNU -v output on Linux" >&2
      echo "Debian/Ubuntu: sudo apt-get install time" >&2
      echo "Homebrew: brew install gnu-time" >&2
      exit 1
    fi
    ;;
esac

gpg_bin=$(command -v gpg)
git_version=$(git --version)
gpg_version=$(gpg --version | sed -n '1p')
rustc_version=$(rustc --version)
cargo_version=$(cargo --version)
e2ee_revision=$(git -C "$project_root" rev-parse HEAD)
if [[ -n $(git -C "$project_root" status --porcelain --untracked-files=normal) ]]; then
  e2ee_dirty=true
else
  e2ee_dirty=false
fi

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
  [[ -d $allowed_root ]] || continue
  allowed_root=$(cd "$allowed_root" && pwd -P)
  if [[ $work_parent == "$allowed_root" || $work_parent == "$allowed_root"/* ]]; then
    allowed_work_parent=true
    break
  fi
done
if [[ $allowed_work_parent != true ]]; then
  echo "BENCH_WORK_PARENT must resolve under $allowed_work_description: $work_parent" >&2
  exit 2
fi

case $os in
  Darwin)
    work_filesystem_device=$(df -P "$work_parent" | awk 'NR == 2 { print $1 }')
    filesystem=$(mount | awk -v device="$work_filesystem_device" '$1 == device {
      if (match($0, /\([^,]+/)) {
        print substr($0, RSTART + 1, RLENGTH - 1)
        exit
      }
    }')
    ;;
  Linux)
    filesystem=$(stat -f -c '%T' "$work_parent")
    ;;
esac
if [[ -z $filesystem ]]; then
  echo "could not identify the filesystem for $work_parent" >&2
  exit 1
fi
case $filesystem in
  tmpfs|ramfs)
    echo "benchmark work directory is on $filesystem: $work_parent" >&2
    echo "Choose disk-backed storage by setting TMPDIR, or set BENCH_WORK_PARENT under /var/tmp or TMPDIR." >&2
    exit 2
    ;;
esac

cache_default=${XDG_CACHE_HOME:-${HOME:?HOME must be set}/.cache}/git-remote-e2ee-bench
cache_dir=${BENCH_CACHE_DIR:-$cache_default}
mkdir -p "$cache_dir"
cache_dir=$(cd "$cache_dir" && pwd -P)
godot_cache="$cache_dir/godot-$godot_revision"
gcrypt_cache="$cache_dir/git-remote-gcrypt-$gcrypt_revision"
stage_dir=
cache_lock=
cache_lock_owned=false
results_dir=
results_created=false
run_complete=false

cleanup() {
  if [[ -n $stage_dir ]]; then
    case $stage_dir in
      "$cache_dir"/.godot-fetch.*|"$cache_dir"/.gcrypt-fetch.*)
        [[ ! -L $stage_dir ]] && rm -rf "$stage_dir"
        ;;
      *) echo "refusing to remove unexpected cache staging path: $stage_dir" >&2 ;;
    esac
  fi
  if [[ $cache_lock_owned == true && -n $cache_lock && -d $cache_lock && ! -L $cache_lock ]]; then
    rmdir "$cache_lock" 2>/dev/null || true
  fi
  if [[ $results_created == true && $run_complete != true && -d $results_dir ]]; then
    rmdir "$results_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT

validate_single_branch_cache() {
  local path=$1 revision=$2 name=$3 default_ref branch_count
  [[ -d $path && ! -L $path ]] || {
    echo "$name cache is not a directory: $path" >&2
    return 1
  }
  [[ $(git -C "$path" rev-parse HEAD) == "$revision" ]] || {
    echo "$name cache has the wrong revision at $path; refusing to modify it" >&2
    return 1
  }
  [[ $(git -C "$path" rev-parse --is-shallow-repository) == false ]] || {
    echo "$name cache is shallow at $path; choose a new BENCH_CACHE_DIR" >&2
    return 1
  }
  default_ref=$(git -C "$path" symbolic-ref --quiet refs/remotes/origin/HEAD || true)
  [[ $default_ref == refs/remotes/origin/* ]] || {
    echo "$name cache does not identify its default branch: $path" >&2
    return 1
  }
  branch_count=$(git -C "$path" for-each-ref --format='%(refname)' refs/remotes/origin |
    awk '$0 != "refs/remotes/origin/HEAD" { count++ } END { print count + 0 }')
  [[ $branch_count == 1 ]] || {
    echo "$name cache must contain only its default branch; choose a new BENCH_CACHE_DIR" >&2
    return 1
  }
  [[ -z $(git -C "$path" tag --list) ]] || {
    echo "$name cache contains tags; choose a new BENCH_CACHE_DIR" >&2
    return 1
  }
  git -C "$path" merge-base --is-ancestor "$revision" "$default_ref" || {
    echo "$name pinned revision is not reachable from the cached default branch" >&2
    return 1
  }
}

publish_cache() {
  local stage=$1 destination=$2 name=$3
  cache_lock="$destination.publish-lock"
  if ! mkdir "$cache_lock" 2>/dev/null; then
    echo "$name cache publication is already in progress or has a stale lock: $cache_lock" >&2
    echo "If no benchmark is running, remove that lock directory and rerun." >&2
    return 1
  fi
  cache_lock_owned=true
  if [[ -e $destination || -L $destination ]]; then
    validate_single_branch_cache "$destination" "$4" "$name"
    rm -rf "$stage"
    stage_dir=
  else
    mv "$stage/repo" "$destination"
    rmdir "$stage"
    stage_dir=
  fi
  rmdir "$cache_lock"
  cache_lock=
  cache_lock_owned=false
}

if [[ -e $godot_cache || -L $godot_cache ]]; then
  validate_single_branch_cache "$godot_cache" "$godot_revision" Godot
  echo "Reusing Godot cache at $godot_cache" >&2
else
  echo "Fetching the full Godot default-branch history without tags" >&2
  stage_dir=$(mktemp -d "$cache_dir/.godot-fetch.XXXXXX")
  git clone --quiet --no-tags --single-branch "$godot_url" "$stage_dir/repo"
  git -C "$stage_dir/repo" checkout --quiet --detach "$godot_revision"
  validate_single_branch_cache "$stage_dir/repo" "$godot_revision" Godot
  publish_cache "$stage_dir" "$godot_cache" Godot "$godot_revision"
  echo "Cached Godot at $godot_cache" >&2
fi

if [[ -e $gcrypt_cache || -L $gcrypt_cache ]]; then
  validate_single_branch_cache "$gcrypt_cache" "$gcrypt_revision" git-remote-gcrypt
  [[ -x $gcrypt_cache/git-remote-gcrypt ]] || {
    echo "git-remote-gcrypt executable is missing in $gcrypt_cache" >&2
    exit 1
  }
  echo "Reusing git-remote-gcrypt cache at $gcrypt_cache" >&2
else
  echo "Fetching the pinned git-remote-gcrypt history" >&2
  stage_dir=$(mktemp -d "$cache_dir/.gcrypt-fetch.XXXXXX")
  git clone --quiet --no-tags --single-branch "$gcrypt_url" "$stage_dir/repo"
  git -C "$stage_dir/repo" checkout --quiet --detach "$gcrypt_revision"
  validate_single_branch_cache "$stage_dir/repo" "$gcrypt_revision" git-remote-gcrypt
  [[ -x $stage_dir/repo/git-remote-gcrypt ]] || {
    echo "git-remote-gcrypt executable is missing at the pinned revision" >&2
    exit 1
  }
  publish_cache "$stage_dir" "$gcrypt_cache" git-remote-gcrypt "$gcrypt_revision"
  echo "Cached git-remote-gcrypt at $gcrypt_cache" >&2
fi

[[ $(git -C "$godot_cache" rev-parse HEAD) == "$godot_revision" ]]
[[ $(git -C "$gcrypt_cache" rev-parse HEAD) == "$gcrypt_revision" ]]
[[ -x $gcrypt_cache/git-remote-gcrypt ]]

if [[ -n ${BENCH_RESULTS_DIR:-} ]]; then
  results_dir=$BENCH_RESULTS_DIR
  [[ $results_dir == /* ]] || results_dir="$PWD/$results_dir"
  mkdir -p "$(dirname "$results_dir")"
  mkdir "$results_dir"
else
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  host_short=$(hostname | awk -F. '{print $1}')
  host_short=$(printf '%s' "$host_short" | tr -c '[:alnum:]_.-' '_')
  results_dir="$project_root/bench-results/$timestamp-$host_short"
  mkdir -p "$(dirname "$results_dir")"
  mkdir "$results_dir"
fi
results_dir=$(cd "$results_dir" && pwd -P)
results_created=true

echo "Running $rounds round(s) with $tiny_commits tiny commit(s)" >&2
BENCH_GCRYPT_TINY_COMMITS=$gcrypt_tiny_commits \
  "$project_root/scripts/benchmark-git-backend.sh" \
  "$godot_cache" \
  "$gcrypt_cache" \
  "$godot_revision" \
  "$gcrypt_revision" \
  "$results_dir" >/dev/null

os_name=
os_version=
os_build=
case $os in
  Darwin)
    os_name=$(sw_vers -productName)
    os_version=$(sw_vers -productVersion)
    os_build=$(sw_vers -buildVersion)
    cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)
    if [[ -z $cpu_model ]]; then
      cpu_model=$(sysctl -n hw.model 2>/dev/null || uname -m)
    fi
    core_count=$(sysctl -n hw.ncpu)
    ram_bytes=$(sysctl -n hw.memsize)
    ;;
  Linux)
    os_name=$(awk -F= '$1 == "NAME" { gsub(/^"|"$/, "", $2); print $2; exit }' /etc/os-release 2>/dev/null || true)
    os_version=$(awk -F= '$1 == "VERSION_ID" { gsub(/^"|"$/, "", $2); print $2; exit }' /etc/os-release 2>/dev/null || true)
    [[ -n $os_name ]] || os_name=Linux
    [[ -n $os_version ]] || os_version=$(uname -r)
    cpu_model=
    if command -v lscpu >/dev/null 2>&1; then
      cpu_model=$(lscpu 2>/dev/null | awk -F: '
        {
          label = tolower($1)
          value = $2
          sub(/^[[:space:]]+/, "", label)
          sub(/[[:space:]]+$/, "", label)
          sub(/^[[:space:]]+/, "", value)
          sub(/[[:space:]]+$/, "", value)
          if (label == "model name" && model == "") model = value
          if (label == "vendor id" && vendor == "") vendor = value
        }
        END {
          if (model != "") print model
          else if (vendor != "") print vendor
        }
      ' || true)
    fi
    if [[ -z $cpu_model ]]; then
      cpu_model=$(awk -F: '
        {
          label = tolower($1)
          value = $2
          sub(/^[[:space:]]+/, "", label)
          sub(/[[:space:]]+$/, "", label)
          sub(/^[[:space:]]+/, "", value)
          sub(/[[:space:]]+$/, "", value)
          if (label == "model name" && model_name == "") model_name = value
          if (label == "hardware" && hardware == "") hardware = value
          if (label == "processor" && processor == "") processor = value
          if (label == "cpu implementer" && implementer == "") implementer = value
          if (label == "cpu part" && part == "") part = value
        }
        END {
          if (model_name != "") {
            print model_name
          } else if (hardware != "") {
            print hardware
          } else if (implementer != "" && part != "") {
            printf "CPU implementer %s, CPU part %s\n", implementer, part
          } else if (processor != "") {
            print processor
          } else if (implementer != "") {
            printf "CPU implementer %s\n", implementer
          } else if (part != "") {
            printf "CPU part %s\n", part
          }
        }
      ' /proc/cpuinfo 2>/dev/null || true)
    fi
    [[ -n $cpu_model ]] || cpu_model=$(uname -m)
    core_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    if [[ -z $core_count ]]; then
      core_count=$(awk '/^processor[[:space:]]*:/ { count++ } END { print count + 0 }' /proc/cpuinfo)
    fi
    ram_bytes=$(awk '/^MemTotal:/ { printf "%.0f", $2 * 1024; exit }' /proc/meminfo)
    ;;
esac
kernel=$(uname -r)

json_quote() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '"%s"' "$value"
}

{
  printf '{\n'
  printf '  "os_name": %s,\n' "$(json_quote "$os_name")"
  printf '  "os_version": %s,\n' "$(json_quote "$os_version")"
  printf '  "os_build": %s,\n' "$(json_quote "$os_build")"
  printf '  "kernel": %s,\n' "$(json_quote "$kernel")"
  printf '  "cpu_model": %s,\n' "$(json_quote "$cpu_model")"
  printf '  "core_count": %s,\n' "$core_count"
  printf '  "ram_bytes": %s,\n' "$ram_bytes"
  printf '  "work_filesystem": %s,\n' "$(json_quote "$filesystem")"
  printf '  "git_version": %s,\n' "$(json_quote "$git_version")"
  printf '  "gpg_version": %s,\n' "$(json_quote "$gpg_version")"
  printf '  "rustc_version": %s,\n' "$(json_quote "$rustc_version")"
  printf '  "cargo_version": %s,\n' "$(json_quote "$cargo_version")"
  printf '  "godot_revision": %s,\n' "$(json_quote "$godot_revision")"
  printf '  "gcrypt_revision": %s,\n' "$(json_quote "$gcrypt_revision")"
  printf '  "e2ee_revision": %s,\n' "$(json_quote "$e2ee_revision")"
  printf '  "e2ee_uncommitted_changes": %s,\n' "$e2ee_dirty"
  printf '  "benchmark_parameters": {\n'
  printf '    "rounds": %s,\n' "$rounds"
  printf '    "tiny_commits": %s,\n' "$tiny_commits"
  printf '    "gcrypt_tiny_commits": %s,\n' "$gcrypt_tiny_commits"
  printf '    "e2ee_only": %s,\n' "$([[ $e2ee_only == 1 ]] && echo true || echo false)"
  printf '    "carrier_attr_tree": %s,\n' "$([[ $carrier_attr_tree == 1 ]] && echo true || echo false)"
  printf '    "trace": %s,\n' "$([[ $trace == 1 ]] && echo true || echo false)"
  printf '    "skip_build": %s,\n' "$([[ $skip_build == 1 ]] && echo true || echo false)"
  printf '    "keep_work": %s\n' "$([[ $keep_work == 1 ]] && echo true || echo false)"
  printf '  }\n'
  printf '}\n'
} >"$results_dir/environment.json"

medians_tsv="$results_dir/medians.tsv"
metric() {
  local transport=$1 phase=$2 iteration=$3 column=$4
  awk -F '\t' -v t="$transport" -v p="$phase" -v i="$iteration" -v c="$column" \
    '$1 == t && $2 == p && $3 == i { print $c; exit }' "$medians_tsv"
}
total_client_disk_bytes() {
  local transport=$1 git_bytes auxiliary_bytes
  git_bytes=$(metric "$transport" fresh_fetch all 9)
  auxiliary_bytes=$(metric "$transport" fresh_fetch all 11)
  if [[ -z $git_bytes || $git_bytes == - ]]; then
    printf '-'
    return
  fi
  [[ -n $auxiliary_bytes && $auxiliary_bytes != - ]] || auxiliary_bytes=0
  awk -v git="$git_bytes" -v auxiliary="$auxiliary_bytes" 'BEGIN { printf "%.0f", git + auxiliary }'
}
format_initial_time() {
  if [[ -z $1 || $1 == - ]]; then printf '—'; else awk -v n="$1" 'BEGIN { printf "%.1f s", n + 0 }'; fi
}
format_operation_time() {
  if [[ -z $1 || $1 == - ]]; then printf '—'; else awk -v n="$1" 'BEGIN { if (n < 1) printf "%.2f s", n + 0; else printf "%.1f s", n + 0 }'; fi
}
format_seconds_two() {
  if [[ -z $1 || $1 == - ]]; then printf '—'; else awk -v n="$1" 'BEGIN { printf "%.2f s", n + 0 }'; fi
}
format_gib() {
  if [[ -z $1 || $1 == - ]]; then printf '—'; else awk -v n="$1" 'BEGIN { printf "%.2f GiB", (n + 0) / 1073741824 }'; fi
}
format_mib() {
  if [[ -z $1 || $1 == - ]]; then printf '—'; else awk -v n="$1" '
    function grouped(value, digits, result) {
      digits = sprintf("%.0f", value)
      while (length(digits) > 3) {
        result = "," substr(digits, length(digits) - 2) result
        digits = substr(digits, 1, length(digits) - 3)
      }
      return digits result
    }
    BEGIN { printf "%s MiB", grouped((n + 0) / 1048576) }
  '; fi
}
format_sent_bytes() {
  if [[ -z $1 || $1 == - ]]; then printf '—'; else awk -v n="$1" 'BEGIN { if (n >= 1000000) printf "%.0f MB", n / 1000000; else printf "%.1f KB", n / 1000 }'; fi
}

if [[ $e2ee_only == 1 ]]; then
  common_pushes=$tiny_commits
else
  common_pushes=$gcrypt_tiny_commits
fi
summary_file="$results_dir/summary.md"
{
  printf '# Benchmark summary\n\n'
  printf 'Medians across %s fresh round(s). Tiny commit and update rows cover %s commit(s) per round.\n\n' "$rounds" "$tiny_commits"
  printf '| | Plain Git | `git-remote-gcrypt` | `git-remote-e2ee` |\n'
  printf '|---|---:|---:|---:|\n'
  printf '| Initial encryption (to a local directory) | %s | %s | %s |\n' \
    "$(format_initial_time "$(metric plain initial_encryption all 4)")" \
    "$(format_initial_time "$(metric gcrypt initial_encryption all 4)")" \
    "$(format_initial_time "$(metric e2ee initial_encryption all 4)")"
  printf '| Initial push | %s | %s | %s |\n' \
    "$(format_initial_time "$(metric plain initial_push all 4)")" \
    "$(format_initial_time "$(metric gcrypt initial_push all 4)")" \
    "$(format_initial_time "$(metric e2ee initial_push all 4)")"
  printf '| Fresh fetch | %s | %s | %s |\n' \
    "$(format_initial_time "$(metric plain fresh_fetch all 4)")" \
    "$(format_initial_time "$(metric gcrypt fresh_fetch all 4)")" \
    "$(format_initial_time "$(metric e2ee fresh_fetch all 4)")"
  printf '| Tiny commit | %s | %s | %s |\n' \
    "$(format_seconds_two "$(metric plain tiny_commit all 4)")" \
    "$(format_seconds_two "$(metric gcrypt tiny_commit all 4)")" \
    "$(format_seconds_two "$(metric e2ee tiny_commit all 4)")"
  printf '| Tiny push | %s | %s | %s |\n' \
    "$(format_operation_time "$(metric plain tiny_push all 4)")" \
    "$(format_operation_time "$(metric gcrypt tiny_push all 4)")" \
    "$(format_operation_time "$(metric e2ee tiny_push all 4)")"
  printf '| Tiny update (fetch) | %s | %s | %s |\n' \
    "$(format_operation_time "$(metric plain tiny_update all 4)")" \
    "$(format_operation_time "$(metric gcrypt tiny_update all 4)")" \
    "$(format_operation_time "$(metric e2ee tiny_update all 4)")"
  printf '| Data sent per tiny push | %s | %s | %s |\n' \
    "$(format_sent_bytes "$(metric plain tiny_push all 6)")" \
    "$(format_sent_bytes "$(metric gcrypt tiny_push all 6)")" \
    "$(format_sent_bytes "$(metric e2ee tiny_push all 6)")"
  printf '| Peak memory, initial push | %s | %s | %s |\n' \
    "$(format_gib "$(metric plain initial_push all 5)")" \
    "$(format_gib "$(metric gcrypt initial_push all 5)")" \
    "$(format_gib "$(metric e2ee initial_push all 5)")"
  printf '| Peak memory, tiny push | %s | %s | %s |\n' \
    "$(format_mib "$(metric plain tiny_push all 5)")" \
    "$(format_mib "$(metric gcrypt tiny_push all 5)")" \
    "$(format_mib "$(metric e2ee tiny_push all 5)")"
  tiny_push_label="tiny pushes"
  if (( common_pushes == 1 )); then
    tiny_push_label="tiny push"
  fi
  printf '| Remote size after %s %s | %s | %s | %s |\n' "$common_pushes" "$tiny_push_label" \
    "$(format_mib "$(metric plain tiny_push "$common_pushes" 7)")" \
    "$(format_mib "$(metric gcrypt tiny_push "$common_pushes" 7)")" \
    "$(format_mib "$(metric e2ee tiny_push "$common_pushes" 7)")"
  printf '| Total client disk after fresh fetch (.git + auxiliary cache/state) | %s | %s | %s |\n' \
    "$(format_mib "$(total_client_disk_bytes plain)")" \
    "$(format_mib "$(total_client_disk_bytes gcrypt)")" \
    "$(format_mib "$(total_client_disk_bytes e2ee)")"
  if (( common_pushes != tiny_commits )); then
    printf '\nThe remote-size row uses %s pushes because gcrypt ran %s tiny pushes.\n' "$common_pushes" "$gcrypt_tiny_commits"
  fi
} >"$summary_file"

run_complete=true
printf 'Results: %s\n\n' "$results_dir"
cat "$summary_file"
