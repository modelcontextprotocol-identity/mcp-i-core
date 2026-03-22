# Sourced by the demo shell to mock commands for VHS recording
# This aliases npm/npx so VHS types real commands but gets fast, clean output

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

npm() {
  if [[ "$1" == "install" && "$2" == "@mcp-i/core" ]]; then
    sleep 1
    echo ""
    echo "added 3 packages, and audited 47 packages in 1.8s"
    echo ""
    echo "found 0 vulnerabilities"
  else
    command npm "$@"
  fi
}

npx() {
  if [[ "$1" == "tsx" && "$2" == "server.ts" ]]; then
    sleep 0.8
    echo "[mcp-i] ✓ Identity: did:key:z6MkhaXgBZhvQKpr3aCn5gVRemSmRYPXwCFmYLcud7QejHB"
    sleep 0.3
    echo "[mcp-i] ✓ Proofs enabled for all tools"
    sleep 0.3
    echo "[mcp-i] ✓ weather-server running on stdio"
    sleep 120  # keep alive until Ctrl+C
  else
    command npx "$@"
  fi
}

export -f npm npx
cd "$DEMO_DIR"
export PS1="$ "
