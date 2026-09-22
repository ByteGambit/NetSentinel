"""NS-020 opt-in passive capture smoke test for an authorized Windows lab."""

from __future__ import annotations

import os
import sys

import pytest

from netsentinel.application.ports import (
    NetworkContextCollectionError,
    PacketCaptureRequest,
)
from netsentinel.bootstrap import (
    create_network_context_provider,
    create_packet_capture,
)
from netsentinel.shared.diagnostics import CapabilityStatus


@pytest.mark.lab_live
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only capture smoke test")
def test_authorized_lab_capture_starts_and_stops_without_sending_packets() -> None:
    if os.environ.get("NETSENTINEL_LAB_CAPTURE") != "1":
        pytest.skip("set NETSENTINEL_LAB_CAPTURE=1 only on an authorized lab network")

    provider = create_network_context_provider()
    try:
        contexts = provider.get_contexts()
    except NetworkContextCollectionError as error:
        pytest.skip(f"local network context is unavailable: {error}")
    candidates = tuple(
        item for item in contexts if item.is_default_capture_candidate
    )
    if not candidates:
        pytest.skip("Windows reports no eligible active IPv4 capture interface")

    capture = create_packet_capture(
        context_provider=provider,
        queue_capacity=8,
        startup_timeout=1.0,
        shutdown_timeout=1.0,
    )
    selected = candidates[0]
    capability = capture.probe(selected)
    if capability.status is not CapabilityStatus.AVAILABLE:
        pytest.skip(f"passive capture unavailable: {capability.reason.value}")

    if not capture.start(PacketCaptureRequest(selected, "arp")):
        pytest.skip(
            f"passive capture could not start: "
            f"{capture.health_snapshot().capability.reason.value}"
        )
    assert capture.stop(timeout=1.0)
    health = capture.health_snapshot()
    assert health.worker_alive is False
    assert health.queue_depth <= health.queue_capacity
