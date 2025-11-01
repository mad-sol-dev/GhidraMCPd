#!/usr/bin/env bash
#
# Bridge Guard smoke test.
#
# This script exercises the guard rails added around the SSE transport:
#   * POST /sse → 405 method_not_allowed
#   * First GET /sse → 200 with an endpoint event (and heartbeats)
#   * Second GET /sse (while the first is active) → 409 conflict
#   * POST to the session URI before initialization → 425 mcp_not_ready
#   * initialize + notifications/initialized → ready → ping returns 202
#
# Usage:
#   GHIDRA_SERVER_URL=http://127.0.0.1:8080/ \
#   MCP_SHIM=http://127.0.0.1:8081 \
#   bash scripts/smoke_bridge.sh
#
# Environment variables:
#   MCP_SHIM – Base URL for the Starlette shim (default http://127.0.0.1:8081)
#
set -euo pipefail
IFS=$'\n\t'

BASE=${MCP_SHIM:-http://127.0.0.1:8081}
BASE=${BASE%/}
SSE_URL="$BASE/sse"

PASS=0
FAIL=0

tmp_dir=$(mktemp -d -t bridge-smoke-XXXXXX)
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

say()  { echo -e "\n==== $* ====\n"; }
pass(){ echo "PASS  $*"; PASS=$((PASS+1)); }
fail(){ echo "FAIL  $*"; FAIL=$((FAIL+1)); }

http_status_body() {
  local method=$1
  local url=$2
  local body_file=$3
  shift 3
  curl -sS -X "$method" "$url" -o "$body_file" -w '%{http_code}' "$@"
}

say "POST /sse returns 405"
body_file="$tmp_dir/post_sse.json"
status=$(http_status_body POST "$SSE_URL" "$body_file" -H 'accept: text/event-stream') || status=000
if [[ "$status" == "405" ]] && grep -q 'method_not_allowed' "$body_file"; then
  pass "POST /sse correctly rejected (405)"
else
  fail "POST /sse returned HTTP $status"
  cat "$body_file"
fi

say "First GET /sse establishes stream"
sse_log="$tmp_dir/sse.log"
curl -sS --no-buffer -H 'accept: text/event-stream' "$SSE_URL" >"$sse_log" &
sse_pid=$!

session_uri=""
event_line=""
for _ in {1..40}; do
  if ! kill -0 "$sse_pid" 2>/dev/null; then
    break
  fi
  if [[ -s "$sse_log" ]] && grep -q '^data:' "$sse_log"; then
    session_uri=$(grep -m1 '^data:' "$sse_log" | sed 's/^data:[[:space:]]*//')
    event_line=$(grep -m1 '^event:' "$sse_log" | sed 's/[[:space:]]*$//')
    break
  fi
  sleep 0.25
done

if [[ -z "$session_uri" ]]; then
  fail "SSE stream did not yield an endpoint event"
  [[ -s "$sse_log" ]] && sed 's/^/      /' "$sse_log"
else
  echo "      event: $event_line"
  echo "      data : $session_uri"
  pass "First GET /sse returned endpoint event"
fi

if [[ -n "$session_uri" ]]; then
  say "Second GET /sse rejected"
  conflict_body="$tmp_dir/sse_conflict.json"
  status=$(http_status_body GET "$SSE_URL" "$conflict_body" -H 'accept: text/event-stream') || status=000
  if [[ "$status" == "409" ]] && grep -q 'sse_already_active' "$conflict_body"; then
    pass "Second GET /sse returned 409 conflict"
  else
    fail "Second GET /sse returned HTTP $status"
    cat "$conflict_body"
  fi
fi

if [[ -n "$session_uri" ]]; then
  say "POST /messages before initialize returns 425"
  session_url="$BASE$session_uri"
  ping_body="$tmp_dir/ping_pre.json"
  ping_payload='{"jsonrpc":"2.0","id":42,"method":"ping","params":null}'
  status=$(http_status_body POST "$session_url" "$ping_body" \
    -H 'content-type: application/json' \
    --data "$ping_payload") || status=000
  if [[ "$status" == "425" ]] && grep -q 'mcp_not_ready' "$ping_body"; then
    pass "POST before initialization blocked with 425"
  else
    fail "POST before initialization returned HTTP $status"
    cat "$ping_body"
  fi

  say "Send initialize notifications"
  init_payload='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke_bridge","version":"1.0"}}}'
  status=$(http_status_body POST "$session_url" "$tmp_dir/init.json" \
    -H 'content-type: application/json' \
    --data "$init_payload") || status=000
  if [[ "$status" == "202" ]]; then
    pass "initialize accepted (202)"
  else
    fail "initialize returned HTTP $status"
    cat "$tmp_dir/init.json"
  fi

  notif_payload='{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  status=$(http_status_body POST "$session_url" "$tmp_dir/initialized.json" \
    -H 'content-type: application/json' \
    --data "$notif_payload") || status=000
  if [[ "$status" == "202" ]]; then
    pass "notifications/initialized accepted (202)"
  else
    fail "notifications/initialized returned HTTP $status"
    cat "$tmp_dir/initialized.json"
  fi

  say "POST /messages after initialize returns 202"
  ready_ok=false
  for _ in {1..20}; do
    status=$(http_status_body POST "$session_url" "$tmp_dir/ping_post.json" \
      -H 'content-type: application/json' \
      --data "$ping_payload") || status=000
    if [[ "$status" == "202" ]]; then
      ready_ok=true
      break
    fi
    sleep 0.25
  done
  if [[ "$ready_ok" == true ]]; then
    pass "POST after initialization succeeded (202)"
  else
    fail "POST after initialization never returned 202"
    cat "$tmp_dir/ping_post.json"
  fi
fi

say "Heartbeats (first few lines)"
if [[ -s "$sse_log" ]]; then
  sed -n '1,8p' "$sse_log" | sed 's/^/      /'
fi

say "Summary"
echo "PASS: $PASS  FAIL: $FAIL"
[[ $FAIL -eq 0 ]]
