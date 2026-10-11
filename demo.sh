#!/usr/bin/env bash
# QuantumTrace one-command demo.
#
#   ./demo.sh [PATH]            PATH = what to scan (default: ../JunctionX-QuantumTrace, the starter kit)
#   ./demo.sh [PATH] --docker   force the Docker image even if QuantumTrace is installed locally
#   ./demo.sh [PATH] --local    force a local install (.venv is created if needed)
#
# It (1) scans PATH and writes report/findings.json, report/report.json, report/cbom.json,
# (2) validates the CBOM against the CycloneDX 1.6 schema, (3) measures accuracy against the
# hand-labelled benchmarks, (4) opens the dashboard on the report (Ctrl+C to stop).
set -euo pipefail
cd "$(dirname "$0")"

TARGET="../JunctionX-QuantumTrace"
MODE=auto
for arg in "$@"; do
  case "$arg" in
    --docker) MODE=docker ;;
    --local) MODE=local ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) TARGET="$arg" ;;
  esac
done
[ -e "$TARGET" ] || { echo "Nothing to scan at $TARGET (pass a file or folder: ./demo.sh PATH)"; exit 1; }
TARGET="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"
OUT="$PWD/report"
mkdir -p "$OUT"

free_port() {          # first port from 8501 that nothing on this machine answers on
  local p=8501
  while (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; do p=$((p + 1)); done
  echo "$p"
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

if [ "$MODE" = auto ]; then
  if command -v quantumtrace >/dev/null 2>&1 || [ -x .venv/bin/quantumtrace ] || [ -x venv/bin/quantumtrace ]; then
    MODE=local
  elif command -v docker >/dev/null 2>&1; then
    MODE=docker
  else
    MODE=local
  fi
fi

if [ "$MODE" = docker ]; then
  # the target is mounted read-only at /data; a file is mounted inside an empty folder
  if [ -d "$TARGET" ]; then MOUNT=(-v "$TARGET:/data:ro"); DATA=/data
  else MOUNT=(-v "$TARGET:/data/$(basename "$TARGET"):ro"); DATA="/data/$(basename "$TARGET")"; fi
  RUN=(docker run --rm --user "$(id -u):$(id -g)" "${MOUNT[@]}" -v "$OUT:/out")
  step "Building the image (first time: a minute or two)"
  docker build -q -t quantumtrace . >/dev/null
  step "1. Scan $TARGET"
  "${RUN[@]}" quantumtrace scan "$DATA" --out /out
  step "2. Validate the CBOM"
  "${RUN[@]}" quantumtrace validate /out/cbom.json
  step "3. Accuracy against the labelled benchmarks"
  "${RUN[@]}" quantumtrace benchmark
  PORT="$(free_port)"
  step "4. Dashboard on http://localhost:$PORT  (Ctrl+C to stop)"
  exec "${RUN[@]}" -p "$PORT:8501" quantumtrace dashboard "$DATA" --report /out --headless --port 8501
fi

# ---- local install
if command -v quantumtrace >/dev/null 2>&1; then QT=quantumtrace
elif [ -x .venv/bin/quantumtrace ]; then QT=.venv/bin/quantumtrace
elif [ -x venv/bin/quantumtrace ]; then QT=venv/bin/quantumtrace
else
  step "Installing QuantumTrace into .venv (first time only)"
  python3 -m venv .venv
  .venv/bin/pip install -q ".[dashboard]"
  QT=.venv/bin/quantumtrace
fi
command -v tshark >/dev/null 2>&1 || echo "! tshark not found: PCAP files will be skipped (Debian/Ubuntu: sudo apt install tshark)"

step "1. Scan $TARGET"
"$QT" scan "$TARGET" --out "$OUT"
step "2. Validate the CBOM"
"$QT" validate "$OUT/cbom.json"
step "3. Accuracy against the labelled benchmarks"
QT_KIT="${QT_KIT:-$(cd .. && pwd)/JunctionX-QuantumTrace}" "$QT" benchmark --suite tests/benchmarks
step "4. Dashboard  (Ctrl+C to stop)"
exec "$QT" dashboard "$TARGET" --report "$OUT"
