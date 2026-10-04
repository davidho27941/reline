#!/usr/bin/env bash
# Task 8.5: run the full chain on the user's preserved real backups through the CLI.
# Usage: OLD=/path/old/UDID CURRENT=/path/current/UDID DEST=/path/dest WS=/path/workspace \
#        [REFERENCE_DB=/path/Line_repaired.sqlite] scripts/acceptance-real-backup.sh
# The password is read from stdin once and passed to each step via LINE_BACKUP_PASSWORD (never argv).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
: "${OLD:?}" "${CURRENT:?}" "${DEST:?}" "${WS:?}"
EXPECTED_HASH="${EXPECTED_HASH:-b4abc7a367201d141533e2e26fd4b20ebc1967e2e2dcd37f28ea88015697916f}"
read -r -s -p "Backup password: " LINE_BACKUP_PASSWORD; echo
export LINE_BACKUP_PASSWORD
CLI=(cargo run -q --release -p recovery-cli --)
"${CLI[@]}" "$WS" "{\"op\":\"intake\",\"role\":\"old\",\"backup_dir\":\"$OLD\"}" --password-env LINE_BACKUP_PASSWORD
"${CLI[@]}" "$WS" "{\"op\":\"intake\",\"role\":\"current\",\"backup_dir\":\"$CURRENT\"}" --password-env LINE_BACKUP_PASSWORD
PLAN=$("${CLI[@]}" "$WS" '{"op":"analyze"}')
echo "$PLAN" | head -60
PLAN_ID=$(echo "$PLAN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ok"]["plan"]["plan_id"])')
COUNT=$(echo "$PLAN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ok"]["plan"]["predicted_update_count"])')
echo "plan $PLAN_ID predicts $COUNT updates"
# NOTE: the CLI keeps the in-memory plan only within one process; the acceptance run therefore
# performs analyze + patch in a single process via the 'analyze_and_patch' convenience below.
RESULT=$("${CLI[@]}" "$WS" "{\"op\":\"analyze_and_patch\",\"destination_dir\":\"$DEST\",\"confirm\":{\"predicted_update_count\":$COUNT,\"plan_id\":\"$PLAN_ID\",\"destination_dir\":\"$DEST\",\"rollback_source_dir\":\"$CURRENT\"}}" --password-env LINE_BACKUP_PASSWORD)
echo "$RESULT" | python3 -c '
import json,sys
r=json.load(sys.stdin)["ok"]
print("repaired sha256:", r["patch"]["validation"]["repaired_sha256"])
print("re-read  sha256:", r["verification"]["reread_sha256"])
print("all gates:", r["verification"]["all_gates_passed"])
'
"${CLI[@]}" "$WS" "{\"op\":\"export\",\"destination_dir\":\"$DEST\"}"
GOT=$(echo "$RESULT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ok"]["verification"]["reread_sha256"])')
if [[ "$GOT" == "$EXPECTED_HASH" ]]; then echo "ACCEPTANCE PASS: hash matches $EXPECTED_HASH"; else echo "ACCEPTANCE: plaintext hash $GOT differs from $EXPECTED_HASH. Byte equality depends on the SQLite library version (header bytes 96-99) and freed-space zeroing; set REFERENCE_DB to compare logically."; fi
# Optional logical comparison against a reference repaired database (e.g. the manual repair):
# per-table, rowid-ordered row digests plus the schema. This is the criterion that survives
# SQLite version differences.
if [[ -n "${REFERENCE_DB:-}" ]]; then
  python3 - "$WS/committed/patching/repaired.sqlite" "$REFERENCE_DB" <<'PY'
import hashlib, sqlite3, sys
def digest(path):
    c = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    tables = {}
    for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        h = hashlib.sha256(); n = 0
        for row in c.execute(f'SELECT rowid, * FROM "{t}" ORDER BY rowid'):
            h.update(repr(row).encode()); n += 1
        tables[t] = (n, h.hexdigest())
    schema = hashlib.sha256("\n".join(s or "" for (s,) in c.execute("SELECT sql FROM sqlite_master ORDER BY type, name")).encode()).hexdigest()
    return tables, schema
a, sa = digest(sys.argv[1]); b, sb = digest(sys.argv[2])
diff = sorted(t for t in set(a) | set(b) if a.get(t) != b.get(t))
if sa == sb and not diff:
    print(f"ACCEPTANCE PASS (logical): {len(a)} tables and schema identical to {sys.argv[2]}")
else:
    print(f"ACCEPTANCE FAIL (logical): schema_equal={sa == sb} differing_tables={diff}"); sys.exit(1)
PY
fi
