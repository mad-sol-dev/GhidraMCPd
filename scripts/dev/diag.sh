#!/usr/bin/env bash
#
# Lightweight diagnostic script for the bridge ↔︎ Ghidra integration.
#
# Checks:
#   1. Plugin probe via GET /projectInfo (or /project_info fallback)
#   2. Bridge /api/health.json reachability flag
#   3. SSE guard rails (405 POST, 200 first GET, 409 second GET)
#   4. Function search payload normalisation
#   5. /api/openapi.json availability
#
# Usage:
#   GHIDRA_SERVER_URL=http://127.0.0.1:8080 \
#   MCP_SHIM=http://127.0.0.1:8000 \
#   bash scripts/dev/diag.sh

set -euo pipefail
IFS=$'\n\t'

BRIDGE_BASE=${MCP_SHIM:-http://127.0.0.1:8000}
BRIDGE_BASE=${BRIDGE_BASE%/}
PLUGIN_BASE=${GHIDRA_SERVER_URL:-http://127.0.0.1:8080}
PLUGIN_BASE=${PLUGIN_BASE%/}

PASS=0
WARN=0
FAIL=0

tmp_dir=$(mktemp -d -t bridge-diag-XXXXXX)
sse_pid=""

cleanup() {
  if [[ -n "$sse_pid" ]]; then
    if kill -0 "$sse_pid" 2>/dev/null; then
      kill "$sse_pid" 2>/dev/null || true
    fi
    wait "$sse_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

pass() { echo "PASS  $*"; PASS=$((PASS+1)); }
warn() { echo "WARN  $*"; WARN=$((WARN+1)); }
fail() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }

http_status_body() {
  local method=$1
  local url=$2
  local body_file=$3
  shift 3
  local status
  set +e
  status=$(curl -sS -X "$method" "$url" -o "$body_file" -w '%{http_code}' "$@")
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "000"
  else
    echo "$status"
  fi
}

echo "== Plugin probe =="
probe_status=$(http_status_body GET "$PLUGIN_BASE/projectInfo" "$tmp_dir/plugin.json" --max-time 3)
if [[ "$probe_status" == "404" ]]; then
  # Attempt the snake_case alias for older plugins
  probe_status=$(http_status_body GET "$PLUGIN_BASE/project_info" "$tmp_dir/plugin.json" --max-time 3)
fi
if [[ "$probe_status" == "200" ]]; then
  pass "Plugin reachable at $PLUGIN_BASE (project info)"
else
  fail "Plugin probe failed (HTTP $probe_status)"
  [[ -s "$tmp_dir/plugin.json" ]] && sed 's/^/      /' "$tmp_dir/plugin.json"
fi

echo "\n== Bridge health =="
health_body="$tmp_dir/health.json"
health_status=$(http_status_body GET "$BRIDGE_BASE/api/health.json" "$health_body" --max-time 3)
if [[ "$health_status" != "200" ]]; then
  fail "Bridge health endpoint returned HTTP $health_status"
else
  reachable=$(python - <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    payload = json.load(fh)
print(payload.get('data', {}).get('ghidra', {}).get('reachable'))
PY
"$health_body")
  if [[ "$reachable" == "True" ]]; then
    pass "Bridge reports plugin reachable"
  else
    warn "Bridge health reachable flag is $reachable"
  fi
fi

echo "\n== SSE guard rails =="
body_file="$tmp_dir/sse_post.json"
status=$(http_status_body POST "$BRIDGE_BASE/sse" "$body_file" -H 'accept: text/event-stream' --max-time 3)
if [[ "$status" == "405" ]]; then
  pass "POST /sse rejected with 405"
else
  fail "POST /sse returned HTTP $status"
fi

sse_log="$tmp_dir/sse.log"
curl -sS --no-buffer -H 'accept: text/event-stream' "$BRIDGE_BASE/sse" --max-time 5 >"$sse_log" &
sse_pid=$!
sleep 1
if [[ -s "$sse_log" ]] && grep -q '^data:' "$sse_log"; then
  pass "First GET /sse yielded data"
else
  warn "First GET /sse produced no data"
fi

body_file="$tmp_dir/sse_conflict.json"
status=$(http_status_body GET "$BRIDGE_BASE/sse" "$body_file" -H 'accept: text/event-stream' --max-time 3)
if [[ "$status" == "409" ]]; then
  pass "Second GET /sse rejected with 409"
else
  warn "Second GET /sse returned HTTP $status"
fi

if [[ -n "$sse_pid" ]]; then
  kill "$sse_pid" 2>/dev/null || true
  wait "$sse_pid" 2>/dev/null || true
  sse_pid=""
fi

print_json_field() {
  python - "$@" <<'PY'
import json, sys
path = sys.argv[1]
with open(sys.argv[2], 'r', encoding='utf-8') as fh:
    data = json.load(fh)
for key in path.split('.'):
    if isinstance(data, dict):
        data = data.get(key)
    else:
        data = None
        break
print(data)
PY
}

echo "\n== Function search =="
search_body="$tmp_dir/search.json"
status=$(http_status_body POST "$BRIDGE_BASE/api/search_functions.json" "$search_body" \
  -H 'content-type: application/json' \
  --data '{"query":"Reset","limit":5,"page":1}' --max-time 5)
if [[ "$status" != "200" ]]; then
  fail "search_functions returned HTTP $status"
else
  ok=$(print_json_field 'ok' "$search_body")
  total=$(print_json_field 'data.total' "$search_body")
  first_addr=$(print_json_field 'data.items.0.address' "$search_body")
  if [[ "$ok" == "True" && "$total" != "None" && "$total" != "0" ]]; then
    if [[ "$first_addr" =~ ^0x[0-9a-fA-F]+$ ]]; then
      pass "search_functions payload looks healthy (total=$total)"
    else
      warn "First address did not match 0x hex pattern: $first_addr"
    fi
  else
    warn "search_functions returned ok=$ok total=$total"
  fi
fi

echo "\n== OpenAPI spec =="
openapi_body="$tmp_dir/openapi.json"
status=$(http_status_body GET "$BRIDGE_BASE/api/openapi.json" "$openapi_body" --max-time 3)
if [[ "$status" == "200" ]] && grep -q '"openapi"' "$openapi_body"; then
  pass "OpenAPI document fetched"
else
  warn "Failed to fetch OpenAPI document (HTTP $status)"
fi

echo
printf 'Summary: PASS=%d WARN=%d FAIL=%d\n' "$PASS" "$WARN" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
