#!/usr/bin/env bash
# Timed full chain on a fixture sized like the proven case (~400k messages). Task 9.3 evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
ROOT="${1:-/tmp/reline-scale}"
N="${2:-400000}"
rm -rf "$ROOT"; mkdir -p "$ROOT/dest"
CLI=(cargo run -q --release -p recovery-cli --)
export LINE_BACKUP_PASSWORD=fixture-password
t() { local s=$(date +%s); "$@" >/dev/null 2>&1; echo "  $(( $(date +%s) - s ))s  ${*: -1:1}" | cut -c1-120; }
echo "generate fixture ($N messages)"
t "${CLI[@]}" "$ROOT/ws0" "{\"op\":\"generate_fixture\",\"output_dir\":\"$ROOT/fx\",\"spec\":{\"line\":{\"message_count\":$N,\"chat_count\":300,\"current_only_messages\":5000}}}"
OLD=$(python3 -c "import json;print(json.load(open('$ROOT/fx/expected.json'))['old_backup_dir'])")
CUR=$(python3 -c "import json;print(json.load(open('$ROOT/fx/expected.json'))['current_backup_dir'])")
ls -la "$ROOT/fx/plain/" | awk '{print "  "$5, $9}' | grep sqlite
echo "intake old";     t "${CLI[@]}" "$ROOT/ws" "{\"op\":\"intake\",\"role\":\"old\",\"backup_dir\":\"$OLD\"}" --password-env LINE_BACKUP_PASSWORD
echo "intake current"; t "${CLI[@]}" "$ROOT/ws" "{\"op\":\"intake\",\"role\":\"current\",\"backup_dir\":\"$CUR\"}" --password-env LINE_BACKUP_PASSWORD
echo "analyze";        t "${CLI[@]}" "$ROOT/ws" '{"op":"analyze"}'
PLAN_ID=$("${CLI[@]}" "$ROOT/ws" '{"op":"analyze"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["ok"]["plan"]["plan_id"])')
echo "analyze+patch+verify"
S=$(date +%s)
RES=$("${CLI[@]}" "$ROOT/ws" "{\"op\":\"analyze_and_patch\",\"destination_dir\":\"$ROOT/dest\",\"confirm\":{\"predicted_update_count\":227,\"plan_id\":\"$PLAN_ID\",\"destination_dir\":\"$ROOT/dest\",\"rollback_source_dir\":\"$CUR\"}}" --password-env LINE_BACKUP_PASSWORD 2>/dev/null)
echo "  $(( $(date +%s) - S ))s"
echo "$RES" | python3 -c 'import json,sys; r=json.load(sys.stdin)["ok"]; print("  updates:", r["patch"]["repair"]["actual_update_count"], "| gates:", r["verification"]["all_gates_passed"], "| pages:", r["patch"]["validation"]["pages_before"]["page_count"], "->", r["patch"]["validation"]["pages_after"]["page_count"])'
echo "export";         t "${CLI[@]}" "$ROOT/ws" "{\"op\":\"export\",\"destination_dir\":\"$ROOT/dest\"}"
echo "cleanup";        t "${CLI[@]}" "$ROOT/ws" '{"op":"cleanup"}'
du -sh "$ROOT/dest" | awk '{print "  dest:", $1}'
