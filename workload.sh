#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${1:-/tmp/ebpf-files-lab}"
HOT_DIR="$WORKDIR/hot"
LOG_DIR="$HOT_DIR/logs"
CACHE_DIR="$HOT_DIR/cache"
TREE_DIR="$HOT_DIR/tree"
ARCHIVE_DIR="$WORKDIR/archive"
ARCHIVE_SLOTS=8

rm -rf "$WORKDIR"
mkdir -p "$LOG_DIR" "$CACHE_DIR" "$TREE_DIR" "$ARCHIVE_DIR"

if [[ ! -f "$CACHE_DIR/blob.bin" ]]; then
  dd if=/dev/urandom of="$CACHE_DIR/blob.bin" bs=1M count=4 status=none
fi

echo "Gerando atividade em $WORKDIR. Pressione Ctrl+C para parar."

i=0
while true; do
  printf '%s request=%s\n' "$(date +%s.%N)" "$i" > "$LOG_DIR/app.log"
  cat "$CACHE_DIR/blob.bin" > /dev/null

  mkdir -p "$TREE_DIR/dir-$((i % 8))/sub-$((i % 4))"
  printf 'item=%s\n' "$i" > "$TREE_DIR/dir-$((i % 8))/sub-$((i % 4))/file-$((i % 16)).txt"

  cp "$CACHE_DIR/blob.bin" "$ARCHIVE_DIR/blob-$((i % ARCHIVE_SLOTS)).bin" >/dev/null 2>&1 || true
  find "$HOT_DIR" -maxdepth 3 -type f | wc -l > /dev/null

  i=$((i + 1))
  sleep 0.1
done
