"""Offline safeguards for authorized individual inline guest commands."""

import pytest
import re

from tests.fixtures.ns102.inline_metadata_roundtrip import commands


PATH = r"C:\Users\deneme\AppData\Local\Temp\NS102-native-00000000000000000000000000000001.json"


def test_individual_commands_have_physical_host_guards_and_no_policy_changes():
    built = commands(PATH)
    assert set(built) == {"prepare", "create", "read", "drift", "cleanup"}
    for value in built.values():
        assert len(value) < 7500
        assert "DESKTOP-B18OKSK" in value and "VMware" in value
        assert "existing admin token required" in value
        assert "-Command" in value
        for forbidden in ("Set-ExecutionPolicy", "Unblock-File", "Invoke-Expression", ".ps1", "-EncodedCommand"):
            assert forbidden not in value
        assert re.search(r"(?<![\w-])-ExecutionPolicy\b", value) is None
    assert "$p.Rules.Add(" not in built["prepare"]
    assert r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" in built["prepare"]
    assert "$p.Rules.Add(" in built["create"]
    assert "never replay Add from an uncertain stage" in built["create"]
    assert "$p.Rules.Add(" not in built["read"]
    assert "$p.Rules.Add(" not in built["drift"]
    assert "$p.Rules.Add(" not in built["cleanup"]


def test_cleanup_compares_full_planned_states_and_independent_absence():
    cleanup = commands(PATH)["cleanup"]
    assert "$observed -cne $s.expected" in cleanup
    assert "$observed -cne $s.drift" in cleanup
    assert "cleanup refuses ambiguity" in cleanup
    assert "stale probe rule after cleanup" in cleanup
    assert "baseline consistency failed" in cleanup


@pytest.mark.parametrize("path", [
    "", r"C:\Users\berke\host.json", PATH + "'; injected", PATH.replace(".json", ".ps1"),
    PATH.replace("00000000000000000000000000000001", "operation"),
])
def test_unreviewed_or_shell_metacharacter_receipt_paths_are_rejected(path):
    with pytest.raises(ValueError, match="exact dedicated-guest JSON"):
        commands(path)
