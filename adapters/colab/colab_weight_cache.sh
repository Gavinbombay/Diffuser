#!/usr/bin/env bash
# Google Drive model weight cache for Imagination Studio (FastH3) on
# ephemeral Colab G4 VMs launched by Diffuser (colab.g4.exec/v1).
#
# Source this file from the Colab setup cell. It never embeds secrets.
# Weights already on disk are moved or parked, never deleted.
#
#   source colab_weight_cache.sh
#   run_setup_with_retry

set -euo pipefail

: "${DIFFUSER_DRIVE_ROOT:=/content/drive/MyDrive}"
: "${MIN_FREE_GB:=45}"
: "${CACHE_ROOT:=${DIFFUSER_DRIVE_ROOT}/ImaginationStudio/weight-cache}"
: "${COMFY_MODELS_DIR:=/content/ImaginationStudio/ComfyUI/models}"
: "${CACHE_RETRY_ATTEMPTS:=4}"
: "${CACHE_RETRY_BACKOFF_SEC:=60}"

CACHE_FALLBACK_MSG='[cache] Drive unavailable or <45GB free; falling back to ephemeral local storage with HF_HUB_DISABLE_XET=1'

# KiB free on the filesystem that holds $1, parsed from `df -Pk`.
# Capacity (NN%) anchors the available column so filesystem names and
# mount points that contain spaces still parse.
df_available_kb() {
  local target="$1"
  local out
  out=$(df -Pk "$target" 2>/dev/null) || return 1
  printf '%s\n' "$out" | awk '
    NR == 1 { next }
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+%$/) {
          print $(i - 1)
          exit
        }
      }
    }
  '
}

min_free_kb() {
  awk -v gb="$MIN_FREE_GB" 'BEGIN { printf "%.0f\n", gb * 1024 * 1024 }'
}

drive_cache_ready() {
  [[ -d "$DIFFUSER_DRIVE_ROOT" && -r "$DIFFUSER_DRIVE_ROOT" ]] || return 1
  command -v df >/dev/null 2>&1 || return 1
  local avail min_kb
  avail=$(df_available_kb "$DIFFUSER_DRIVE_ROOT") || return 1
  [[ "$avail" =~ ^[0-9]+$ ]] || return 1
  min_kb=$(min_free_kb)
  [[ "$min_kb" =~ ^[0-9]+$ ]] || return 1
  awk -v avail="$avail" -v min="$min_kb" 'BEGIN { exit !(avail + 0 >= min + 0) }'
}

# Next unused path that preserves a local file when the cache already
# has the same name. The cached bytes stay where they are.
park_path() {
  local dest="$1"
  local base="$2"
  local candidate="${dest}/${base}.local"
  local n=1
  if [[ ! -e "$candidate" && ! -L "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  while [[ -e "${dest}/${base}.local.${n}" || -L "${dest}/${base}.local.${n}" ]]; do
    n=$((n + 1))
  done
  printf '%s\n' "${dest}/${base}.local.${n}"
}

# Move everything under $1 into $2. Name clashes keep the cache copy and
# park the local copy beside it. Caller enables nullglob and dotglob.
migrate_tree() {
  local src="$1"
  local dest="$2"
  local entry base target
  mkdir -p "$dest"
  for entry in "$src"/*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    base="${entry##*/}"
    target="${dest}/${base}"
    if [[ -d "$entry" && ! -L "$entry" && -d "$target" && ! -L "$target" ]]; then
      migrate_tree "$entry" "$target"
    elif [[ -e "$target" || -L "$target" ]]; then
      mv "$entry" "$(park_path "$dest" "$base")"
    else
      mv "$entry" "$target"
    fi
  done
}

paths_overlap() {
  local left="$1"
  local right="$2"
  case "$left" in
    "$right"|"$right"/*) return 0 ;;
  esac
  case "$right" in
    "$left"|"$left"/*) return 0 ;;
  esac
  return 1
}

link_model_dir() {
  local name="$1"
  local local_dir="${COMFY_MODELS_DIR}/${name}"
  local cache_dir="${CACHE_ROOT}/comfy-models/${name}"
  local current had_dotglob=0 had_nullglob=0

  mkdir -p "$cache_dir"

  if [[ -L "$local_dir" ]]; then
    current=$(readlink "$local_dir")
    if [[ "$current" == "$cache_dir" ]]; then
      return 0
    fi
    rm "$local_dir"
    ln -s "$cache_dir" "$local_dir"
    return 0
  fi

  if [[ -d "$local_dir" ]]; then
    shopt -q dotglob && had_dotglob=1
    shopt -q nullglob && had_nullglob=1
    shopt -s dotglob nullglob
    migrate_tree "$local_dir" "$cache_dir"
    if [[ "$had_dotglob" -eq 0 ]]; then
      shopt -u dotglob
    fi
    if [[ "$had_nullglob" -eq 0 ]]; then
      shopt -u nullglob
    fi
    # rmdir refuses non-empty directories, so leftover user files stay put.
    find "$local_dir" -depth -type d -exec rmdir {} \; 2>/dev/null || true
    if [[ -d "$local_dir" ]]; then
      printf '[cache] warning: kept %s; could not move every file into cache\n' "$local_dir" >&2
      return 0
    fi
    ln -s "$cache_dir" "$local_dir"
    return 0
  fi

  if [[ -e "$local_dir" ]]; then
    printf '[cache] warning: %s is not a directory; left in place\n' "$local_dir" >&2
    return 0
  fi

  ln -s "$cache_dir" "$local_dir"
}

enable_drive_cache() {
  local name
  if paths_overlap "$COMFY_MODELS_DIR" "$CACHE_ROOT"; then
    printf '[cache] warning: COMFY_MODELS_DIR and CACHE_ROOT overlap; leaving models in place\n' >&2
    return 0
  fi
  mkdir -p "${CACHE_ROOT}/comfy-models" "${CACHE_ROOT}/hf-cache"
  export HF_HOME="${CACHE_ROOT}/hf-cache"
  mkdir -p "$COMFY_MODELS_DIR"
  for name in diffusion_models text_encoders vae loras; do
    link_model_dir "$name"
  done
  printf '[cache] Drive cache ready at %s\n' "$CACHE_ROOT"
}

setup_weight_cache() {
  export HF_HUB_DISABLE_XET=1
  if drive_cache_ready; then
    enable_drive_cache
    return 0
  fi
  printf '%s\n' "$CACHE_FALLBACK_MSG"
  return 0
}

# Resume oneshot-setup-spark.sh after transient Hugging Face failures.
# Runs `bash oneshot-setup-spark.sh --no-render` up to CACHE_RETRY_ATTEMPTS
# times (default 4) and sleeps CACHE_RETRY_BACKOFF_SEC (default 60) between
# tries. Non-transient failures return immediately. Call this from the
# directory that contains oneshot-setup-spark.sh.
run_setup_with_retry() {
  local attempt=1
  local max_attempts="${CACHE_RETRY_ATTEMPTS:-4}"
  local backoff="${CACHE_RETRY_BACKOFF_SEC:-60}"
  local log rc

  if ! [[ "$max_attempts" =~ ^[0-9]+$ ]] || [[ "$max_attempts" -lt 1 ]]; then
    max_attempts=4
  fi
  if ! [[ "$backoff" =~ ^[0-9]+$ ]]; then
    backoff=60
  fi

  while [[ "$attempt" -le "$max_attempts" ]]; do
    log=$(mktemp)
    rc=0
    bash oneshot-setup-spark.sh --no-render >"$log" 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
      cat "$log"
      rm -f "$log"
      return 0
    fi
    cat "$log" >&2
    if [[ "$attempt" -lt "$max_attempts" ]] && grep -Eiq 'transient|huggingface|hugging face|hf_hub|hf hub|service unavailable|timed out|timeout|connection reset|connection aborted|429|502|503|504' "$log"; then
      printf '[cache] transient Hugging Face error (attempt %s/%s); retrying in %ss\n' \
        "$attempt" "$max_attempts" "$backoff" >&2
      sleep "$backoff"
      rm -f "$log"
      attempt=$((attempt + 1))
      continue
    fi
    rm -f "$log"
    return "$rc"
  done
  return 1
}

setup_weight_cache
