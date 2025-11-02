#!/usr/bin/env bash
set -euo pipefail
mf=".plan/tasks.manifest.json"
tmp="$mf.tmp"

add() {
  local id="$1" title="$2" after_csv="$3"
  # baue after-Array aus CSV
  local after="["; IFS=, read -r -a arr <<< "$after_csv"; for i in "${arr[@]}"; do
    [ -n "$i" ] && after="$after\"$i\","
  done; after="${after%,}]"
  # jq: wenn id noch nicht vorhanden → anhängen
  jq --arg id "$id" --arg title "$title" --argjson after "$after" '
    if any(.sequence[]; .id==$id) then .
    else .sequence += [ { "id": $id, "title": $title, "after": $after } ]
    end
  ' "$mf" > "$tmp" && mv "$tmp" "$mf"
}

# --- New maintenance tasks (analysis → actionable) ---
add ADAPTER-PROBERESULT-CLEANUP "Remove dead ProbeResult exports/imports" "OPTIONAL-ADAPTERS"
add ADAPTER-PROBE-ALIAS          "Introduce Probe typing alias in adapters Protocol" "OPTIONAL-ADAPTERS"
add SMOKE-MOJIBAKE-FIX           "Fix mojibake in bin/smoke.sh" "DOCS-BOOTSTRAP"
add PLAN-CHECK-IO-POLISH         "Single-read IO + docstrings in plan_check.py" "PLAN-CHECK"

jq . "$mf" >/dev/null   # JSON quick-validate
echo "Updated: $mf"
