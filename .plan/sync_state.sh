#!/usr/bin/env bash
set -euo pipefail

# 0) Helper: latest short SHA touching any of the given paths (or empty)
sha() { git log -n1 --format='%h' -- "$@" 2>/dev/null || true; }

# 1) Collect SHAs per task (nur Files, die den Task wirklich belegen)
state_commit() {
  local id="$1"
  jq -r --arg id "$id" '
    .tasks[$id] as $task
    | if ($task | type) == "object" and ($task.commit // "") != "" then
        $task.commit
      else
        ""
      end
  ' .plan/state.json
}
OPENAPI_FREEZE_SHA=$(sha \
  README.md \
  bridge/tests/golden/data/openapi_snapshot.json \
  bridge/tests/golden/test_openapi_snapshot.py)

API_MOUNT_SHA=$(sha \
  bridge/api/routes.py \
  bridge/api/tools.py \
  bridge/tests/integration/test_api_mount.py)

JT_SCAN_SHA=$(sha \
  bridge/api/routes.py \
  bridge/api/tools.py \
  bridge/features/jt.py \
  bridge/tests/contract/test_http_contracts.py \
  bridge/tests/golden/data/jt_slot_cases.json)

JT_SCAN_CONSISTENCY_SHA=$(sha \
  bridge/tests/contract/conftest.py \
  bridge/tests/contract/test_http_contracts.py \
  bridge/tests/contract/test_jt_scan_consistency.py)

# JT-VERIFY does not map to unique files yet; keep the known commit documented here.
JT_VERIFY_SHA=844252e

RANGE_CONTRACT_SHA=$(sha \
  bridge/adapters/arm_thumb.py \
  bridge/tests/unit/test_adapters_arm_thumb.py)

CLIENT_UNIFY_SHA=$(sha \
  bridge/tests/unit/test_ghidra_whitelist.py \
  bridge/client)

CI_TESTS_SHA=$(sha \
  .github/workflows/build.yml)
if [ -z "${CI_TESTS_SHA:-}" ]; then
  CI_TESTS_SHA=$(state_commit CI-TESTS)
fi

STRINGS_ASSERTS_SHA=$(state_commit STRINGS-ASSERTS)

BRIDGE_GUARD_03_SERIALIZE_PLUGIN_SHA=$(sha \
  bridge/api/routes.py \
  bridge/app.py \
  bridge/ghidra/client.py \
  bridge/tests/unit/test_plugin_serialization.py)

SSE_HANDSHAKE_SHA=$(state_commit SSE-HANDSHAKE)

# 2) Update .plan/state.json for found SHAs
NOW=$(date -Iseconds)
update() {
  local id="$1" sha_val="$2"
  [ -z "${sha_val:-}" ] && return 0
  tmp=.plan/state.json.tmp
  jq --arg id "$id" --arg sha "$sha_val" --arg now "$NOW" \
     '.tasks[$id].status="done"
    | .tasks[$id].commit=$sha
    | .tasks[$id].updated_at=$now' \
    .plan/state.json > "$tmp" && mv "$tmp" .plan/state.json
  echo "✓ $id → $sha_val"
}

update OPENAPI-FREEZE   "$OPENAPI_FREEZE_SHA"
update API-MOUNT        "$API_MOUNT_SHA"
update JT-SCAN          "$JT_SCAN_SHA"
update JT-SCAN-CONSISTENCY "$JT_SCAN_CONSISTENCY_SHA"
update JT-VERIFY        "$JT_VERIFY_SHA"
update RANGE-CONTRACT   "$RANGE_CONTRACT_SHA"
update CLIENT-UNIFY     "$CLIENT_UNIFY_SHA"
update STRINGS-ASSERTS   "$STRINGS_ASSERTS_SHA"
update BRIDGE_GUARD_03_SERIALIZE_PLUGIN "$BRIDGE_GUARD_03_SERIALIZE_PLUGIN_SHA"
update SSE-HANDSHAKE    "$SSE_HANDSHAKE_SHA"
update CI-TESTS         "$CI_TESTS_SHA"

echo
echo "Current state:"
jq '.tasks | to_entries[] | {id: .key, status: .value.status, commit: .value.commit}' .plan/state.json
