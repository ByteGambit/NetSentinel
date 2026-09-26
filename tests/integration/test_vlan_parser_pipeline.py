"""NS-043 offline capture callback to portable bounded queue flow."""

from __future__ import annotations

from netsentinel.application.ports import PacketCaptureRequest
from netsentinel.domain.vlan import VlanTagKind
from netsentinel.shared.diagnostics import CaptureState, DiagnosticCode
from tests.fixtures.packets.vlan import stacked, tagged, untagged
from tests.unit.infrastructure.test_scapy_capture import context, worker_for


def test_vlan_parser_uses_existing_capture_queue_and_isolates_malformed_frame() -> None:
    worker, _, backend = worker_for(queue_capacity=4)
    assert worker.start(PacketCaptureRequest(context(), "vlan"))
    handle = backend.handles[0]
    malformed = tagged()
    malformed.getlayer("Dot1Q").prio = 8
    for packet in (tagged(0), malformed, untagged(), stacked()):
        handle.emit(packet)

    observations = worker.drain(4)
    assert [item.vlan.kind for item in observations] == [
        VlanTagKind.PRIORITY_TAGGED, VlanTagKind.UNTAGGED, VlanTagKind.STACKED,
    ]
    assert all(item.network_fingerprint == context().fingerprint for item in observations)
    assert all(b"secret" not in repr(item).encode() for item in observations)
    assert worker.health.counters.malformed_packets == 1
    assert worker.health.last_error.code is DiagnosticCode.CAPTURE_MALFORMED_PACKET
    assert worker.health.queue_depth == 0
    assert worker.stop()
    assert worker.health.state is CaptureState.STOPPED
    assert handle.closed
