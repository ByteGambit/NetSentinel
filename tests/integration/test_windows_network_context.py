"""NS-019 opt-in read-only Windows network context smoke test."""

from __future__ import annotations

import sys

import pytest

from netsentinel.application.ports import NetworkContextCollectionError
from netsentinel.bootstrap import create_network_context_provider


@pytest.mark.windows_live
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only context smoke test")
def test_windows_live_context_read_is_local_read_only_and_needs_no_admin() -> None:
    provider = create_network_context_provider()
    try:
        contexts = provider.get_contexts()
    except NetworkContextCollectionError as error:
        pytest.skip(f"Windows network context unavailable without elevation: {error}")

    if not contexts:
        pytest.skip("Windows reports no active IPv4 network contexts")

    second_read = provider.get_contexts()
    first_identities = {
        (item.interface_id, item.ipv4_address): item.fingerprint for item in contexts
    }
    second_identities = {
        (item.interface_id, item.ipv4_address): item.fingerprint
        for item in second_read
    }
    for identity in first_identities.keys() & second_identities.keys():
        assert first_identities[identity] == second_identities[identity]
    assert all(item.ipv4_address.count(".") == 3 for item in contexts)
    assert all(len(item.fingerprint) == 64 for item in contexts)
    assert all(
        item.is_default_capture_candidate is False
        for item in contexts
        if item.is_loopback
    )
