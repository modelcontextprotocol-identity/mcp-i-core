#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ── Colours ──────────────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

PIDS=()
cleanup() {
  echo ""
  echo -e "${DIM}Shutting down example servers...${NC}"
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo -e "${GREEN}Done.${NC}"
}
trap cleanup EXIT INT TERM

usage() {
  echo -e "${BOLD}Usage:${NC} $0 [options] [example...]"
  echo ""
  echo "Start MCP-I example servers for testing with the MCP Inspector."
  echo ""
  echo -e "${BOLD}Examples:${NC}"
  echo "  $0                    # start all examples"
  echo "  $0 consent-basic      # start just consent-basic"
  echo "  $0 consent-basic node-server"
  echo "  $0 --no-inspector     # start servers without opening Inspector"
  echo ""
  echo -e "${BOLD}Available examples:${NC}"
  echo "  node-server        Low-level MCP-I server with proof + restricted tools"
  echo "  consent-basic      Human-in-the-loop consent flow (built-in UI)"
  echo "  consent-full       Consent flow with @kya-os/consent (production UI)"
  echo "  context7-with-mcpi Context7 MCP server + MCP-I identity"
  echo ""
  exit 0
}

# ── Parse args ───────────────────────────────────────────────────────
OPEN_INSPECTOR=true
REQUESTED=()

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage ;;
    --no-inspector) OPEN_INSPECTOR=false ;;
    *) REQUESTED+=("$arg") ;;
  esac
done

ALL_EXAMPLES=(node-server consent-basic consent-full context7-with-mcpi)

if [ ${#REQUESTED[@]} -eq 0 ]; then
  EXAMPLES=("${ALL_EXAMPLES[@]}")
else
  EXAMPLES=("${REQUESTED[@]}")
  for ex in "${EXAMPLES[@]}"; do
    if [[ ! " ${ALL_EXAMPLES[*]} " =~ " ${ex} " ]]; then
      echo -e "${RED}Unknown example: ${ex}${NC}"
      echo "Available: ${ALL_EXAMPLES[*]}"
      exit 1
    fi
  done
fi

# ── Install deps ─────────────────────────────────────────────────────
echo -e "${BOLD}Installing dependencies...${NC}"

if [ ! -d "$ROOT/node_modules" ]; then
  echo -e "${DIM}  root${NC}"
  npm install --silent 2>/dev/null
fi

for ex in "${EXAMPLES[@]}"; do
  dir="$ROOT/examples/$ex"
  if [ -f "$dir/package.json" ] && [ ! -d "$dir/node_modules" ]; then
    echo -e "${DIM}  $ex${NC}"
    if [ -f "$dir/pnpm-lock.yaml" ]; then
      (cd "$dir" && pnpm install --silent 2>/dev/null) || (cd "$dir" && npm install --silent 2>/dev/null)
    else
      (cd "$dir" && npm install --silent 2>/dev/null)
    fi
  fi
done

echo -e "${GREEN}Dependencies ready.${NC}"
echo ""

# ── Start servers ────────────────────────────────────────────────────
declare -A PORTS
declare -A URLS
declare -A TRANSPORTS

start_example() {
  local name="$1"
  case "$name" in
    node-server)
      PORT=3001 npx tsx examples/node-server/server.ts &
      PIDS+=($!)
      PORTS[$name]=3001
      URLS[$name]="http://localhost:3001/sse"
      TRANSPORTS[$name]="SSE"
      ;;
    consent-basic)
      PORT=3002 CONSENT_PORT=3012 npx tsx examples/consent-basic/src/server.ts &
      PIDS+=($!)
      PORTS[$name]=3002
      URLS[$name]="http://localhost:3002/sse"
      TRANSPORTS[$name]="SSE"
      ;;
    consent-full)
      PORT=3003 CONSENT_PORT=3013 npx tsx examples/consent-full/src/server.ts &
      PIDS+=($!)
      PORTS[$name]=3003
      URLS[$name]="http://localhost:3003/sse"
      TRANSPORTS[$name]="SSE"
      ;;
    context7-with-mcpi)
      npx tsx examples/context7-with-mcpi/src/index.ts --transport http --port 3004 &
      PIDS+=($!)
      PORTS[$name]=3004
      URLS[$name]="http://localhost:3004/mcp"
      TRANSPORTS[$name]="Streamable HTTP"
      ;;
  esac
}

for ex in "${EXAMPLES[@]}"; do
  start_example "$ex"
done

sleep 2

# ── Print summary ────────────────────────────────────────────────────
echo -e "${BOLD}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}│  MCP-I Example Servers                                        │${NC}"
echo -e "${BOLD}├──────────────────────┬───────────┬────────────────────────────┤${NC}"
printf  "${BOLD}│ %-20s │ %-9s │ %-26s │${NC}\n" "Example" "Transport" "URL"
echo -e "${BOLD}├──────────────────────┼───────────┼────────────────────────────┤${NC}"

for ex in "${EXAMPLES[@]}"; do
  printf "│ ${CYAN}%-20s${NC} │ %-9s │ ${GREEN}%-26s${NC} │\n" \
    "$ex" "${TRANSPORTS[$ex]}" "${URLS[$ex]}"
done

echo -e "${BOLD}└──────────────────────┴───────────┴────────────────────────────┘${NC}"
echo ""

# ── Inspector ────────────────────────────────────────────────────────
if [ "$OPEN_INSPECTOR" = true ]; then
  echo -e "${BOLD}Starting MCP Inspector...${NC}"
  echo -e "${DIM}Connect to any URL above using the matching transport type.${NC}"
  echo ""
  npx @modelcontextprotocol/inspector &
  PIDS+=($!)
  sleep 3
fi

echo -e "${YELLOW}Press Ctrl+C to stop all servers.${NC}"
wait
