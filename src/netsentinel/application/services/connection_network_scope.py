"""Conservative, bounded attribution of connections to current local contexts."""

from __future__ import annotations

from dataclasses import replace
from ipaddress import ip_address

from netsentinel.application.ports import NetworkContextProvider
from netsentinel.domain.connections import (
    ConnectionNetworkScope,
    ConnectionSnapshot,
    NetworkAttributionMethod,
    NetworkScopeStatus,
)
from netsentinel.domain.devices import NetworkContext


MAX_NETWORK_CONTEXTS = 4_096


class ConnectionNetworkScopeResolver:
    """Match assigned local IPv4 addresses; never infer a Windows route."""

    def __init__(self, provider: NetworkContextProvider) -> None:
        self._provider = provider

    def attribute(self, snapshots: tuple[ConnectionSnapshot, ...]) -> tuple[ConnectionSnapshot, ...]:
        if not snapshots:
            return snapshots
        try:
            contexts = self._provider.get_contexts()
        except Exception:
            # Context is optional enrichment. Its loss cannot turn a connection
            # collection round into a failed or reduced connection observation.
            return tuple(replace(snapshot, network_scope=ConnectionNetworkScope.unknown()) for snapshot in snapshots)
        if len(contexts) > MAX_NETWORK_CONTEXTS:
            return tuple(replace(snapshot, network_scope=ConnectionNetworkScope.unknown()) for snapshot in snapshots)

        by_address: dict[str, dict[tuple[str, int, str], NetworkContext]] = {}
        for context in contexts:
            if context.is_loopback:
                continue
            identity = (context.interface_id.casefold(), context.interface_index, context.fingerprint)
            by_address.setdefault(context.ipv4_address, {})[identity] = context

        result: list[ConnectionSnapshot] = []
        for snapshot in snapshots:
            local = ip_address(snapshot.local_endpoint.address)
            scope = ConnectionNetworkScope.unknown()
            if local.version == 4 and not local.is_unspecified and not local.is_loopback:
                candidates = by_address.get(snapshot.local_endpoint.address, {})
                if len(candidates) == 1:
                    context = next(iter(candidates.values()))
                    scope = ConnectionNetworkScope(
                        status=NetworkScopeStatus.RESOLVED,
                        fingerprint=context.fingerprint,
                        interface_id=context.interface_id,
                        interface_index=context.interface_index,
                        method=NetworkAttributionMethod.LOCAL_ADDRESS_MATCH,
                    )
                elif len(candidates) > 1:
                    scope = ConnectionNetworkScope.ambiguous()
            result.append(replace(snapshot, network_scope=scope))
        return tuple(result)


__all__ = ("ConnectionNetworkScopeResolver", "MAX_NETWORK_CONTEXTS")
