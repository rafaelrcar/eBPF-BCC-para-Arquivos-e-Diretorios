#!/usr/bin/env bash
# Sobe 4 workers com perfis distintos de I/O:
#   http-serve  -> le arquivo e envia pela rede      (correlacao forte)
#   curl-loop   -> recebe da rede e grava em arquivo (correlacao forte, inversa)
#   file-only   -> so arquivo, sem rede
#   net-only    -> so rede (iperf3 loopback), sem arquivo
#
# Salva PIDs em $WORKDIR/.pids/<nome> para o validate.sh localizar.
set -euo pipefail

WORKDIR="${1:-/tmp/ebpf-netfile-lab}"
PORT="${PORT:-18080}"
IPERF_PORT=$((PORT + 1))
BLOB_MB="${BLOB_MB:-8}"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/serve" "$WORKDIR/client-dl" "$WORKDIR/file-only" "$WORKDIR/.pids"

echo "gerando blob de ${BLOB_MB}M em $WORKDIR/serve/blob.bin..."
dd if=/dev/urandom of="$WORKDIR/serve/blob.bin" bs=1M count="$BLOB_MB" status=none

echo
echo "sandbox:       $WORKDIR"
echo "http port:     $PORT"
echo "iperf port:    $IPERF_PORT"
echo

pids=()

cleanup() {
  echo
  echo "parando workers..."
  for p in "${pids[@]}"; do pkill -P "$p" 2>/dev/null || true; kill "$p" 2>/dev/null || true; done
  sleep 0.5
  for p in "${pids[@]}"; do pkill -P "$p" -9 2>/dev/null || true; kill -9 "$p" 2>/dev/null || true; done
  pkill -f "http.server $PORT" 2>/dev/null || true
  pkill -f "iperf3 -s -p $IPERF_PORT" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -f "$WORKDIR/.pids"/*
}
trap cleanup EXIT INT TERM

spawn() {
  local name="$1"; shift
  "$@" &
  local pid=$!
  echo "$pid" > "$WORKDIR/.pids/$name"
  pids+=("$pid")
  printf "  %-14s pid=%s\n" "$name" "$pid"
}

# 1) http-serve: exec substitui bash por python3 no mesmo PID
spawn http-serve bash -c "cd '$WORKDIR/serve' && exec python3 -m http.server $PORT >/dev/null 2>&1"
sleep 1

# 2) curl-loop: downloader Python de vida longa (PID estavel). Usamos Python e
#    nao bash+curl porque cada curl seria um subprocesso novo (PID efemero),
#    impossivel de rastrear deterministicamente.
spawn curl-loop python3 -u -c "
import urllib.request, time
URL = 'http://127.0.0.1:$PORT/blob.bin'
DST = '$WORKDIR/client-dl/blob.bin'
while True:
    try:
        with urllib.request.urlopen(URL) as r, open(DST, 'wb') as f:
            while True:
                b = r.read(65536)
                if not b:
                    break
                f.write(b)
    except Exception:
        time.sleep(0.1)
"

# 3) file-only: Python de longa duracao, le+escreve em loop, zero rede
spawn file-only python3 -u -c "
import time
src = '$WORKDIR/serve/blob.bin'
dst = '$WORKDIR/file-only/copy.bin'
while True:
    with open(src, 'rb') as f, open(dst, 'wb') as g:
        while True:
            buf = f.read(1048576)
            if not buf:
                break
            g.write(buf)
    time.sleep(0.01)
"

# 4) net-only: iperf3 server + client em loopback (sem I/O de arquivo).
#    Cliente tem -t longo para manter o mesmo PID durante todo o experimento.
spawn net-only-srv iperf3 -s -p "$IPERF_PORT"
sleep 0.5
spawn net-only iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -t 86400 -l 1M

echo
echo "workers rodando. Ctrl+C para parar."
wait
