"""Bounded Dashboard text from the selected scope's persisted VLAN summary."""

from __future__ import annotations

from netsentinel.presentation.i18n.text import translate

from netsentinel.presentation.i18n.text import format_text, render_join

from dataclasses import field

from dataclasses import dataclass

from netsentinel.application.services.device_inventory import DeviceInventorySnapshot
from netsentinel.domain.vlan_summary import VlanBaselineState
from netsentinel.presentation.models.history import format_local_timestamp


@dataclass(frozen=True, slots=True)
class VlanDashboardState:
    scope: str = field(default_factory=lambda: translate('VlanModel', 'No network selected'))
    status: str = field(default_factory=lambda: translate('VlanModel', 'No VLAN observations saved for this network/interface.'))
    baseline: str = "—"
    observed: str = "—"
    reference: str = "—"
    counts: str = "—"
    times: str = "—"
    rows: str = field(default_factory=lambda: translate('VlanModel', 'No normal VLAN IDs observed.'))
    visibility: str = (
        field(default_factory=lambda: translate('VlanModel', 'NIC/driver VLAN offload or the capture filter can hide tags. Observed IDs are not a complete VLAN inventory; untagged does not prove VLAN absence.'))
    )


def vlan_dashboard_state(inventory: DeviceInventorySnapshot) -> VlanDashboardState:
    """Filter the portable summary to the worker's selected network and interface."""
    context = next((item for item in inventory.contexts
                    if item.fingerprint == inventory.selected_fingerprint), None)
    if context is None:
        return VlanDashboardState()
    scope = format_text(translate('VlanModel', '{value1} · {value2} · interface #{value3}'), value1=context.interface_name, value2=context.subnet, value3=context.interface_index)
    if inventory.vlan_summary_unavailable:
        return VlanDashboardState(scope=scope,
                                  status=translate('VlanModel', 'Saved VLAN observations are unavailable. Try refreshing.'))
    summary = inventory.vlan_summary
    if (summary is None or summary.network_fingerprint != context.fingerprint
            or summary.interface_id != context.interface_id.casefold()
            or summary.interface_index != context.interface_index):
        return VlanDashboardState(scope=scope)
    state = {
        VlanBaselineState.LEARNING: translate('VlanModel', 'Learning — passive observations are still accumulating.'),
        VlanBaselineState.LEARNED: translate('VlanModel', 'Learned — observed reference, not accepted by the user.'),
        VlanBaselineState.VERIFIED: translate('VlanModel', 'Verified — user accepted the frozen observed reference.'),
    }[summary.baseline_state]
    if summary.verified_at is not None:
        state += format_text(translate('VlanModel', ' Accepted {value1}.'), value1=format_local_timestamp(summary.verified_at))
    rows = render_join('\n', (format_text(translate('VlanModel', 'VID {value1}: %n frame(s) · {value3} → {value4}', None, item.count), value1=item.vlan_id, value3=format_local_timestamp(item.first_seen), value4=format_local_timestamp(item.last_seen)) for item in summary.vlan_ids)) or translate('VlanModel', 'No normal VLAN IDs observed.')
    return VlanDashboardState(scope=scope, status=translate('VlanModel', 'Passive capture running — selected scope.') if inventory.capture and inventory.capture.running else translate('VlanModel', 'Saved observations — capture is off or unavailable.'), baseline=state, observed=render_join(', ', (str(item.vlan_id) for item in summary.vlan_ids)) or translate('VlanModel', 'None observed'), reference=render_join(', ', map(str, summary.learned_vlan_ids)) or translate('VlanModel', 'None learned'), counts=format_text(translate('VlanModel', 'Tagged {value1} · Untagged observed {value2} · Priority tagged VID 0 {value3} · Reserved VID 4095 {value4} · Stacked VLAN tag observed {value5} · Overflow {value6}'), value1=summary.tagged_count, value2=summary.untagged_count, value3=summary.priority_tagged_count, value4=summary.reserved_count, value5=summary.stacked_count, value6=summary.overflow_count), times=format_text(translate('VlanModel', 'First {value1} · Last {value2}'), value1=format_local_timestamp(summary.first_seen), value2=format_local_timestamp(summary.last_seen)), rows=rows)


__all__ = ("VlanDashboardState", "vlan_dashboard_state")
