"""Passive ARP sender observations into scoped, persisted device state."""

from __future__ import annotations

from ipaddress import IPv4Address

from netsentinel.application.ports import DeviceRepository
from netsentinel.domain.devices import DeviceIdentity, IdentityBinding, NetworkContext
from netsentinel.domain.observations import PacketObservation


class DeviceObservationRejected(ValueError):
    """The portable observation does not belong to the supplied context."""


class DeviceRegistryService:
    """Synchronous single-consumer registry with no capture or worker ownership.

    A non-device-worthy ARP sender is ignored. Target fields never establish
    identity, including request targets and ARP probes. The repository owns
    transaction isolation when multiple callers happen to submit concurrently.
    """

    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    def observe(
        self, context: NetworkContext, observation: PacketObservation
    ) -> tuple[DeviceIdentity, IdentityBinding] | None:
        if not isinstance(context, NetworkContext):
            raise TypeError("context must be a NetworkContext")
        if not isinstance(observation, PacketObservation):
            raise TypeError("observation must be a PacketObservation")
        arp = observation.arp
        if arp is None:
            return None
        if (
            observation.network_fingerprint != context.fingerprint
            or observation.interface_id.casefold() != context.interface_id.casefold()
            or observation.interface_index != context.interface_index
        ):
            raise DeviceObservationRejected("Observation network context does not match.")

        mac = arp.sender_mac
        ip = IPv4Address(arp.sender_ip)
        if (
            mac.is_zero
            or mac.is_broadcast
            or mac.is_multicast
            or ip.is_unspecified
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_reserved
            or ip == IPv4Address("255.255.255.255")
        ):
            return None

        at = observation.observed_at
        device = DeviceIdentity(context.fingerprint, mac, at, at)
        binding = IdentityBinding(context.fingerprint, mac, str(ip), at, at)
        return self._repository.record_binding(device, binding)

    def devices(self, context: NetworkContext) -> tuple[DeviceIdentity, ...]:
        if not isinstance(context, NetworkContext):
            raise TypeError("context must be a NetworkContext")
        return self._repository.list_devices(context.fingerprint)

    def bindings(self, device: DeviceIdentity, limit: int | None = None) -> tuple[IdentityBinding, ...]:
        if not isinstance(device, DeviceIdentity):
            raise TypeError("device must be a DeviceIdentity")
        if limit is None:
            return self._repository.list_bindings(device.device_id)
        return self._repository.list_bindings(device.device_id, limit)


__all__ = ("DeviceObservationRejected", "DeviceRegistryService")
