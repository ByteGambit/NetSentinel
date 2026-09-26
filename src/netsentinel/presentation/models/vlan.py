"""Bounded Dashboard text from the selected scope's persisted VLAN summary."""

from __future__ import annotations

from dataclasses import dataclass

from netsentinel.application.services.device_inventory import DeviceInventorySnapshot
from netsentinel.domain.vlan_summary import VlanBaselineState
from netsentinel.presentation.models.history import format_local_timestamp


@dataclass(frozen=True, slots=True)
class VlanDashboardState:
    scope: str = "No network selected"
    status: str = "No VLAN observations saved for this network/interface."
    baseline: str = "—"
    observed: str = "—"
    reference: str = "—"
    counts: str = "—"
    times: str = "—"
    rows: str = "No normal VLAN IDs observed."
    visibility: str = (
        "NIC/driver VLAN offload or the capture filter can hide tags. "
        "Observed IDs are not a complete VLAN inventory; untagged does not prove VLAN absence."
    )


def vlan_dashboard_state(inventory: DeviceInventorySnapshot) -> VlanDashboardState:
    """Filter the portable summary to the worker's selected network and interface."""
    context = next((item for item in inventory.contexts
                    if item.fingerprint == inventory.selected_fingerprint), None)
    if context is None:
        return VlanDashboardState()
    scope = f"{context.interface_name} · {context.subnet} · interface #{context.interface_index}"
    if inventory.vlan_summary_unavailable:
        return VlanDashboardState(scope=scope,
                                  status="Saved VLAN observations are unavailable. Try refreshing.")
    summary = inventory.vlan_summary
    if (summary is None or summary.network_fingerprint != context.fingerprint
            or summary.interface_id != context.interface_id.casefold()
            or summary.interface_index != context.interface_index):
        return VlanDashboardState(scope=scope)
    state = {
        VlanBaselineState.LEARNING: "Learning — passive observations are still accumulating.",
        VlanBaselineState.LEARNED: "Learned — observed reference, not accepted by the user.",
        VlanBaselineState.VERIFIED: "Verified — user accepted the frozen observed reference.",
    }[summary.baseline_state]
    if summary.verified_at is not None:
        state += f" Accepted {format_local_timestamp(summary.verified_at)}."
    rows = "\n".join(
        f"VID {item.vlan_id}: {item.count} frame(s) · "
        f"{format_local_timestamp(item.first_seen)} → {format_local_timestamp(item.last_seen)}"
        for item in summary.vlan_ids
    ) or "No normal VLAN IDs observed."
    return VlanDashboardState(
        scope=scope,
        status=("Passive capture running — selected scope." if inventory.capture and inventory.capture.running
                else "Saved observations — capture is off or unavailable."),
        baseline=state,
        observed=", ".join(str(item.vlan_id) for item in summary.vlan_ids) or "None observed",
        reference=", ".join(map(str, summary.learned_vlan_ids)) or "None learned",
        counts=(f"Tagged {summary.tagged_count} · Untagged observed {summary.untagged_count} · "
                f"Priority tagged VID 0 {summary.priority_tagged_count} · "
                f"Reserved VID 4095 {summary.reserved_count} · "
                f"Stacked VLAN tag observed {summary.stacked_count} · "
                f"Overflow {summary.overflow_count}"),
        times=(f"First {format_local_timestamp(summary.first_seen)} · "
               f"Last {format_local_timestamp(summary.last_seen)}"),
        rows=rows,
    )


__all__ = ("VlanDashboardState", "vlan_dashboard_state")
