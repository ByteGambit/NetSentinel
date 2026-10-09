"""Bounded VM-only installer acceptance receipts; no firewall dispatch."""

from hashlib import sha256
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys


def run(action):
    assert os.name == "nt" and os.environ["COMPUTERNAME"] == "DESKTOP-B18OKSK"
    assert os.environ.get("NETSENTINEL_NS101_VM_AUTHORIZED") == "YES"
    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root / "src"))
    base = Path(os.environ["LOCALAPPDATA"]) / "NetSentinel"
    db = base / "netsentinel.sqlite3"
    exe = base.parent / "Programs/NetSentinel/NetSentinel.exe"
    result = {"action": action, "result": "FAIL"}
    try:
        if action == "seed19":
            from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
            from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations
            with SQLiteDatabase(db, migration_runner=MigrationRunner(builtin_migrations()[:19])).connection() as c:
                assert c.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 19
                values = ("00000000-0000-4000-8000-000000000104", "tcp", "127.0.0.1", 49190, 104,
                          "NS104-MIGRATION-MARKER", "available", "closed", 1, 2)
                columns = "id,protocol,local_address,local_port,pid,process_name,process_status,connection_state,first_seen_utc_us,last_seen_utc_us"
                prior = c.execute("SELECT " + columns + " FROM connection_history WHERE id=?", (values[0],)).fetchone()
                if prior is None:
                    c.execute("INSERT INTO connection_history(" + columns + ") VALUES(?,?,?,?,?,?,?,?,?,?)", values)
                else:
                    assert tuple(prior) == values  # Retry only the operator's exact marker.
                c.commit()
        with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)) as c:
            schema = c.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            marker = c.execute("SELECT count(*) FROM connection_history WHERE id=? AND process_name=?",
                               ("00000000-0000-4000-8000-000000000104", "NS104-MIGRATION-MARKER")).fetchone()[0]
            tables = sorted(row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'response_%'"))
            # Hash complete bounded local custody, do not export its content/witness.
            custody = {table: sorted(list(c.execute('SELECT * FROM "' + table + '"')), key=repr) for table in tables}
        def encode_blob(value):
            assert isinstance(value, bytes)
            return {"blob": value.hex()}

        result.update(schema=schema, marker_count=marker, config_sha256=sha256((base / "config.json").read_bytes()).hexdigest(),
                      custody_sha256=sha256(json.dumps(custody, sort_keys=True, default=encode_blob).encode()).hexdigest(),
                      response_counts={table: len(rows) for table, rows in custody.items()})
        if action == "upgrade-post":
            pre = json.loads((root / "installer-seed19.result.json").read_text())
            assert pre["result"] == "PASS" and pre["schema"] == 19 and schema == 20 and marker == 1
            assert result["config_sha256"] == pre["config_sha256"]
            result["migration_and_data_preserved"] = True
        elif action == "custody-post":
            pre = json.loads((root / "installer-custody-pre.result.json").read_text())
            assert schema == 20 and result["custody_sha256"] == pre["custody_sha256"]
            assert result["config_sha256"] == pre["config_sha256"] and marker == 1
            result["complete_custody_and_audit_preserved"] = True
        elif action == "denied-delete":
            before = db.read_bytes()
            report = subprocess.run([str(exe), "--uninstall-report-firewall"], timeout=30, check=False)
            assert report.returncode == 0
            text = (base / "firewall-uninstall-report.txt").read_text(encoding="utf-8-sig")
            assert "Potentially remaining recorded rules: 1" in text and "Current presence: UNKNOWN" in text
            refused = subprocess.run([str(exe), "--uninstall-delete-local-data-confirmed"], timeout=30, check=False)
            assert refused.returncode == 1 and db.read_bytes() == before and exe.is_file()
            result.update(delete_refused=True, exact_recovery_list=True, no_false_cleanup=True)
        elif action not in {"seed19", "status", "custody-pre"}:
            raise ValueError("Unknown acceptance action")
        result["result"] = "PASS"
    except Exception as exc:
        result["failure_type"] = type(exc).__name__
        raise
    finally:
        (root / ("installer-" + action + ".result.json")).write_text(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Explicit acceptance action required")
    run(sys.argv[1])
