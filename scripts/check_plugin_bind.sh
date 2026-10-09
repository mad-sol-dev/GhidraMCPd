#!/usr/bin/env bash
# Acceptance check for Stage 8a: the plugin's HTTP server answers on loopback
# and nowhere else.
#
# Three checks, each against the running plugin:
#   1. every listening socket on the port is a loopback address (ss),
#   2. a request to 127.0.0.1:<port> gets an HTTP response,
#   3. a request to this machine's LAN address on the same port is refused.
#
# Check 3 is a negative finding, so it only counts once the method is shown to
# work: a throwaway listener is bound to the LAN address first, and the same
# curl must reach it.  If it cannot, the script says so instead of passing.
#
# Usage:
#   scripts/check_plugin_bind.sh            # port 8080
#   scripts/check_plugin_bind.sh 8081
#
# Exit codes: 0 pass, 1 fail, 2 could not check (and the reason is printed).
set -uo pipefail

PORT="${1:-8080}"

fail() { echo "FAIL: $*"; exit 1; }
cannot() { echo "CANNOT CHECK: $*"; exit 2; }

command -v ss >/dev/null || cannot "ss not installed"
command -v curl >/dev/null || cannot "curl not installed"
command -v python3 >/dev/null || cannot "python3 not installed (needed for the positive control)"

# --- 1. listening sockets -------------------------------------------------
mapfile -t LISTEN < <(ss -ltnH "sport = :$PORT" | awk '{print $4}')
if [ "${#LISTEN[@]}" -eq 0 ]; then
  cannot "nothing listens on port $PORT -- is Ghidra running with the plugin enabled?"
fi
for addr in "${LISTEN[@]}"; do
  host="${addr%:*}"
  case "$host" in
    127.*|"[::1]") echo "ok: listening on $addr" ;;
    *) fail "listening on $addr, which is not loopback" ;;
  esac
done

# --- 2. loopback answers --------------------------------------------------
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/")"
[ "$code" != "000" ] || fail "no HTTP response on 127.0.0.1:$PORT although a socket is listening"
echo "ok: 127.0.0.1:$PORT answered (HTTP $code)"

# --- 3. LAN address refused, with positive control -------------------------
LAN="$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
[ -n "$LAN" ] || cannot "this machine has no global IPv4 address, so there is no LAN path to test"

CONTROL_LOG="$(mktemp)"
python3 - "$LAN" >"$CONTROL_LOG" 2>&1 <<'EOF' &
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
with socketserver.TCPServer((sys.argv[1], 0), H) as s:
    print(s.server_address[1], flush=True)
    s.handle_request()
EOF
CONTROL_PID=$!
trap 'kill "$CONTROL_PID" 2>/dev/null; rm -f "$CONTROL_LOG"' EXIT
for _ in $(seq 50); do [ -s "$CONTROL_LOG" ] && break; sleep 0.1; done
CONTROL_PORT="$(head -1 "$CONTROL_LOG")"
[[ "$CONTROL_PORT" =~ ^[0-9]+$ ]] || cannot "positive control could not bind to $LAN: $(cat "$CONTROL_LOG")"

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$LAN:$CONTROL_PORT/")"
[ "$code" = "204" ] || cannot "positive control on $LAN:$CONTROL_PORT was not reachable (HTTP $code); a refusal below would mean nothing"
echo "ok: positive control reached $LAN:$CONTROL_PORT"

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$LAN:$PORT/")"
[ "$code" = "000" ] || fail "$LAN:$PORT answered (HTTP $code) -- the plugin is reachable from the LAN"
echo "ok: $LAN:$PORT refused"

echo "PASS: port $PORT is reachable on loopback only"
