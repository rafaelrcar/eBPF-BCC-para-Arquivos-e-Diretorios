#!/usr/bin/env bash
# Oraculo de validacao: com workload_netfile.sh rodando em outro terminal,
# executa netfile_top.py por DURATION segundos em modo JSON e verifica que:
#   - http-serve e curl-loop aparecem com correlacao > 0;
#   - file-only tem pouca rede;
#   - net-only tem pouco arquivo.
# Uso: sudo ./validate.sh [WORKDIR]
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "rode como root: sudo $0 $*" >&2
  exit 2
fi

WORKDIR="${1:-/tmp/ebpf-netfile-lab}"
DURATION="${DURATION:-20}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -d "$WORKDIR/.pids" ]]; then
  echo "ERRO: $WORKDIR/.pids nao existe. Rode workload_netfile.sh antes." >&2
  exit 2
fi

declare -A PID
for f in "$WORKDIR/.pids"/*; do
  [[ -e "$f" ]] || continue
  PID["$(basename "$f")"]="$(cat "$f")"
done

echo "PIDs dos workers:"
for n in "${!PID[@]}"; do printf "  %-14s %s\n" "$n" "${PID[$n]}"; done

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

echo
echo "coletando por ${DURATION}s..."
timeout "${DURATION}s" python3 "$HERE/netfile_top.py" -i 2 -n 30 -j --min-bytes 0 > "$OUT" || true

python3 - "$OUT" \
  "${PID[http-serve]:-0}" "${PID[curl-loop]:-0}" \
  "${PID[file-only]:-0}" "${PID[net-only]:-0}" <<'PY'
import json, sys, collections

out_path = sys.argv[1]
p_http, p_curl, p_file, p_net = map(int, sys.argv[2:6])

totals = collections.Counter()
file_tot = collections.Counter()
net_tot = collections.Counter()
sf_tot = collections.Counter()
comms = {}

with open(out_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        for r in ev.get("top", []):
            pid = r["pid"]
            totals[pid] += r["corr"]
            file_tot[pid] += r["file_rd"] + r["file_wr"]
            net_tot[pid] += r["tcp_tx"] + r["tcp_rx"]
            sf_tot[pid] += r["sendfile"]
            comms[pid] = r["comm"]

ranked = [p for p, _ in totals.most_common(50)]

def rank(p):
    return ranked.index(p) + 1 if p in ranked else None

def row(label, p):
    if p == 0:
        return f"  [skip] {label}: pid nao registrado"
    return (f"  {label:<12} pid={p:<7} comm={comms.get(p,'?'):<16} "
            f"rank={rank(p)} corr={totals[p]:>10} "
            f"file={file_tot[p]:>10} net={net_tot[p]:>10} sf={sf_tot[p]}")

print("\n--- agregado da janela de validacao ---")
for lbl, p in [("http-serve", p_http), ("curl-loop", p_curl),
               ("file-only", p_file), ("net-only", p_net)]:
    print(row(lbl, p))

fails = []
MB = 1024 * 1024

if p_http and totals[p_http] == 0:
    fails.append(f"http-serve (pid {p_http}) teve correlacao zero")
if p_curl and totals[p_curl] == 0:
    fails.append(f"curl-loop (pid {p_curl}) teve correlacao zero")
if p_file and net_tot[p_file] > MB:
    fails.append(f"file-only (pid {p_file}) com {net_tot[p_file]} bytes de rede (>1M)")
if p_net and file_tot[p_net] > MB:
    fails.append(f"net-only (pid {p_net}) com {file_tot[p_net]} bytes de arquivo (>1M)")

print()
if fails:
    print("VALIDACAO: FALHOU")
    for m in fails:
        print("  -", m)
    sys.exit(1)
print("VALIDACAO: OK")
PY
