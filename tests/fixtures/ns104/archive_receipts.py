"""Bounded non-sensitive VM acceptance receipts; never export raw inventory/custody."""

from hashlib import sha256
import json
import os
from pathlib import Path


def main():
    assert os.name == "nt" and os.environ["COMPUTERNAME"] == "DESKTOP-B18OKSK"
    root = Path(__file__).resolve().parents[3]
    files = sorted(root.glob("*.result.json"))
    for folder in ("lab-state", "install-state"):
        files.extend(sorted((root / folder).glob("*.result.json")))
    files.extend(root / name for name in (
        "clean-self-test.json", "previous-self-test-final.json", "upgrade-self-test-final.json",
        "restart-owned-self-test.json", "post-denial-monitoring-self-test.json", "restricted-thread.json",
        "final-install-state.json",
    ))
    assert len(files) <= 100
    values = {}
    for path in files:
        assert path.is_file() and not path.is_symlink() and path.stat().st_size < 32768
        payload = path.read_bytes()
        value = json.loads(payload.decode("utf-8-sig"))
        assert isinstance(value, dict)

        def check(item):
            if isinstance(item, dict):
                assert not {"witness", "description", "rules", "manifest", "payload", "command_line", "password"}.intersection(item)
                for child in item.values():
                    check(child)
            elif isinstance(item, list):
                for child in item:
                    check(child)
            else:
                assert item is None or type(item) in {str, int, bool}

        check(value)
        values[path.relative_to(root).as_posix()] = {"sha256": sha256(payload).hexdigest(), "receipt": value}
    for key in ("lab-state/observe-cleanup.result.json", "install-state/undo.result.json"):
        receipt = values[key]["receipt"]
        assert receipt["result"] == "PASS" and receipt["owned_count"] == 0 and receipt["unrelated_count"] == 476
    state = values["final-install-state.json"]["receipt"]
    assert state["OriginalCandidateRestored"] and state["OriginalDataAbsenceRestored"] and state["SinglePerUserRegistration"]
    assert state["AppRunning"] == state["Services"] == state["Tasks"] == state["MatchingFirewallCount"] == 0
    (root / "acceptance-receipts.json").write_text(json.dumps({"task": "NS-104", "receipts": values}, indent=2) + "\n")


if __name__ == "__main__":
    main()
