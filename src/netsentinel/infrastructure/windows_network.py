"""Read-only Windows adapter for normalized local IPv4 network contexts.

The production source uses the Windows IP Helper API instead of parsing
localized command output. It performs no DNS lookup, packet capture, socket
creation, active discovery, or background polling.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, ip_address, ip_network
import os
import socket

from netsentinel.application.ports import (
    NetworkContextPermissionDenied,
    NetworkContextUnavailable,
)
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind


_ERROR_ACCESS_DENIED = 5
_ERROR_BUFFER_OVERFLOW = 111
_ERROR_NO_DATA = 232
_NO_ERROR = 0

_GAA_FLAG_SKIP_ANYCAST = 0x0002
_GAA_FLAG_SKIP_MULTICAST = 0x0004
_GAA_FLAG_INCLUDE_PREFIX = 0x0010
_GAA_FLAG_INCLUDE_GATEWAYS = 0x0080

_IF_OPER_STATUS_UP = 1
_IF_TYPE_ETHERNET_CSMACD = 6
_IF_TYPE_PPP = 23
_IF_TYPE_SOFTWARE_LOOPBACK = 24
_IF_TYPE_IEEE80211 = 71
_IF_TYPE_TUNNEL = 131
_MAX_ADAPTER_ADDRESS_LENGTH = 8
_MAX_DHCPV6_DUID_LENGTH = 130

_MAX_ADAPTERS = 4_096
_MAX_LINKED_ADDRESSES = 4_096


@dataclass(frozen=True, slots=True)
class WindowsIPv4Address:
    """Infrastructure DTO for one Windows unicast IPv4 address."""

    address: str
    prefix_length: int


@dataclass(frozen=True, slots=True)
class WindowsNetworkAdapterSnapshot:
    """Raw-but-typed adapter configuration returned by the Windows source."""

    interface_id: str
    interface_index: int
    name: str
    description: str
    if_type: int
    is_up: bool
    ipv4_addresses: tuple[WindowsIPv4Address, ...]
    gateways: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()


SnapshotProvider = Callable[[], Iterable[WindowsNetworkAdapterSnapshot]]
Clock = Callable[[], datetime]


class WindowsNetworkContextProvider:
    """Normalize current Windows IP configuration at the application port."""

    def __init__(
        self,
        *,
        snapshot_provider: SnapshotProvider | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._snapshot_provider = (
            snapshot_provider
            if snapshot_provider is not None
            else _read_windows_adapter_snapshots
        )
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    def get_contexts(self) -> tuple[NetworkContext, ...]:
        """Return active IPv4 contexts in deterministic order.

        Whole-read failures become sanitized typed errors. A malformed address
        or adapter is skipped independently so one OS record cannot discard the
        rest of the snapshot. No result is cached: a later call observes network
        changes without introducing a scheduler or worker.
        """

        try:
            snapshots = tuple(self._snapshot_provider())
        except PermissionError as error:
            raise NetworkContextPermissionDenied(
                "access to local network configuration was denied"
            ) from error
        except OSError as error:
            if getattr(error, "winerror", None) == _ERROR_ACCESS_DENIED:
                raise NetworkContextPermissionDenied(
                    "access to local network configuration was denied"
                ) from error
            raise NetworkContextUnavailable(
                "local network configuration is temporarily unavailable"
            ) from error

        observed_at = _utc_time(self._clock())
        contexts: dict[tuple[object, ...], NetworkContext] = {}
        for snapshot in snapshots:
            try:
                normalized = _normalize_adapter(snapshot, observed_at)
            except (AttributeError, TypeError, ValueError):
                continue
            for context in normalized:
                key = (
                    context.interface_id.casefold(),
                    context.interface_index,
                    context.ipv4_address,
                    context.subnet,
                    context.gateway,
                )
                existing = contexts.get(key)
                if existing is None or _context_preference_key(
                    context
                ) < _context_preference_key(existing):
                    contexts[key] = context

        return tuple(sorted(contexts.values(), key=_context_sort_key))


def _normalize_adapter(
    snapshot: WindowsNetworkAdapterSnapshot,
    observed_at: datetime,
) -> tuple[NetworkContext, ...]:
    if snapshot.is_up is not True:
        return ()
    if isinstance(snapshot.if_type, bool) or not isinstance(snapshot.if_type, int):
        raise TypeError("if_type must be an integer")

    kind = _classify_interface(snapshot)
    gateways = _canonical_ipv4_values(snapshot.gateways)
    dns_servers = _canonical_ipv4_values(snapshot.dns_servers)
    gateway = gateways[0] if gateways else None

    contexts: list[NetworkContext] = []
    for raw_address in snapshot.ipv4_addresses:
        try:
            address = ip_address(raw_address.address)
            if not isinstance(address, IPv4Address):
                continue
            if isinstance(raw_address.prefix_length, bool) or not isinstance(
                raw_address.prefix_length, int
            ):
                continue
            if not 0 <= raw_address.prefix_length <= 32:
                continue
            subnet = ip_network(
                f"{address}/{raw_address.prefix_length}",
                strict=False,
            )
            address_kind = (
                NetworkInterfaceKind.LOOPBACK if address.is_loopback else kind
            )
            contexts.append(
                NetworkContext(
                    interface_id=snapshot.interface_id,
                    interface_index=snapshot.interface_index,
                    interface_name=snapshot.name,
                    interface_kind=address_kind,
                    ipv4_address=str(address),
                    subnet=str(subnet),
                    gateway=gateway,
                    dns_servers=dns_servers,
                    observed_at=observed_at,
                )
            )
        except (AttributeError, TypeError, ValueError):
            continue
    return tuple(contexts)


def _canonical_ipv4_values(values: Iterable[str]) -> tuple[str, ...]:
    normalized: set[str] = set()
    for value in values:
        try:
            parsed = ip_address(value)
        except (TypeError, ValueError):
            continue
        if isinstance(parsed, IPv4Address) and not parsed.is_unspecified:
            normalized.add(str(parsed))
    return tuple(sorted(normalized, key=lambda value: int(IPv4Address(value))))


def _classify_interface(
    snapshot: WindowsNetworkAdapterSnapshot,
) -> NetworkInterfaceKind:
    if snapshot.if_type == _IF_TYPE_SOFTWARE_LOOPBACK:
        return NetworkInterfaceKind.LOOPBACK
    if snapshot.if_type in {_IF_TYPE_PPP, _IF_TYPE_TUNNEL}:
        return NetworkInterfaceKind.VPN

    label = f"{snapshot.name} {snapshot.description}".casefold()
    if any(
        marker in label
        for marker in ("vpn", "wireguard", "openvpn", "tailscale", "zerotier")
    ):
        return NetworkInterfaceKind.VPN
    if any(
        marker in label
        for marker in (
            "hyper-v",
            "virtualbox",
            "vmware",
            "virtual ethernet",
            "vethernet",
        )
    ):
        return NetworkInterfaceKind.VIRTUAL
    if snapshot.if_type == _IF_TYPE_IEEE80211:
        return NetworkInterfaceKind.WIFI
    if snapshot.if_type == _IF_TYPE_ETHERNET_CSMACD:
        return NetworkInterfaceKind.ETHERNET
    return NetworkInterfaceKind.OTHER


def _context_sort_key(context: NetworkContext) -> tuple[object, ...]:
    return (
        not context.is_default_capture_candidate,
        context.interface_kind.value,
        context.interface_name.casefold(),
        context.interface_id.casefold(),
        context.interface_index,
        int(IPv4Address(context.subnet.split("/", 1)[0])),
        int(IPv4Address(context.ipv4_address)),
    )


def _context_preference_key(context: NetworkContext) -> tuple[object, ...]:
    """Resolve duplicate OS records without depending on provider order."""

    return (
        context.interface_kind is NetworkInterfaceKind.OTHER,
        -len(context.dns_servers),
        context.interface_kind.value,
        context.interface_name.casefold(),
        context.dns_servers,
    )


def _utc_time(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("clock must return a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC)


class _SOCKADDR(ctypes.Structure):
    _fields_ = (
        ("sa_family", ctypes.c_ushort),
        ("sa_data", ctypes.c_ubyte * 14),
    )


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = (
        ("lpSockaddr", ctypes.POINTER(_SOCKADDR)),
        ("iSockaddrLength", ctypes.c_int),
    )


class _SOCKADDR_IN(ctypes.Structure):
    _fields_ = (
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    )


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


class _IP_ADAPTER_DNS_SERVER_ADDRESS(ctypes.Structure):
    pass


class _IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
    pass


class _IP_ADAPTER_PREFIX(ctypes.Structure):
    pass


class _IP_ADAPTER_WINS_SERVER_ADDRESS(ctypes.Structure):
    pass


_IP_ADAPTER_UNICAST_ADDRESS._fields_ = (
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", wintypes.ULONG),
    ("PreferredLifetime", wintypes.ULONG),
    ("LeaseLifetime", wintypes.ULONG),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
)

_IP_ADAPTER_DNS_SERVER_ADDRESS._fields_ = (
    ("Length", wintypes.ULONG),
    ("Reserved", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_DNS_SERVER_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
)

_IP_ADAPTER_GATEWAY_ADDRESS._fields_ = (
    ("Length", wintypes.ULONG),
    ("Reserved", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
)

_IP_ADAPTER_PREFIX._fields_ = (
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_PREFIX)),
    ("Address", _SOCKET_ADDRESS),
    ("PrefixLength", wintypes.ULONG),
)

_IP_ADAPTER_WINS_SERVER_ADDRESS._fields_ = (
    ("Length", wintypes.ULONG),
    ("Reserved", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_WINS_SERVER_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
)


class _GUID(ctypes.Structure):
    _fields_ = (
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    )


class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


_IP_ADAPTER_ADDRESSES._fields_ = (
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.POINTER(_IP_ADAPTER_DNS_SERVER_ADDRESS)),
    ("DnsSuffix", wintypes.LPWSTR),
    ("Description", wintypes.LPWSTR),
    ("FriendlyName", wintypes.LPWSTR),
    ("PhysicalAddress", ctypes.c_ubyte * _MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", wintypes.DWORD),
    ("Flags", wintypes.DWORD),
    ("Mtu", wintypes.DWORD),
    ("IfType", wintypes.DWORD),
    ("OperStatus", ctypes.c_int),
    ("Ipv6IfIndex", wintypes.DWORD),
    ("ZoneIndices", wintypes.DWORD * 16),
    ("FirstPrefix", ctypes.POINTER(_IP_ADAPTER_PREFIX)),
    ("TransmitLinkSpeed", ctypes.c_ulonglong),
    ("ReceiveLinkSpeed", ctypes.c_ulonglong),
    ("FirstWinsServerAddress", ctypes.POINTER(_IP_ADAPTER_WINS_SERVER_ADDRESS)),
    ("FirstGatewayAddress", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Ipv4Metric", wintypes.ULONG),
    ("Ipv6Metric", wintypes.ULONG),
    ("Luid", ctypes.c_ulonglong),
    ("Dhcpv4Server", _SOCKET_ADDRESS),
    ("CompartmentId", wintypes.DWORD),
    ("NetworkGuid", _GUID),
    ("ConnectionType", ctypes.c_int),
    ("TunnelType", ctypes.c_int),
    ("Dhcpv6Server", _SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid", ctypes.c_ubyte * _MAX_DHCPV6_DUID_LENGTH),
    ("Dhcpv6ClientDuidLength", wintypes.ULONG),
    ("Dhcpv6Iaid", wintypes.ULONG),
)


def _read_windows_adapter_snapshots() -> tuple[WindowsNetworkAdapterSnapshot, ...]:
    if os.name != "nt":
        raise OSError("Windows network context is only available on Windows")

    ip_helper = ctypes.WinDLL("iphlpapi", use_last_error=True)
    get_adapters_addresses = ip_helper.GetAdaptersAddresses
    get_adapters_addresses.argtypes = (
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        ctypes.POINTER(_IP_ADAPTER_ADDRESSES),
        ctypes.POINTER(wintypes.ULONG),
    )
    get_adapters_addresses.restype = wintypes.ULONG

    flags = (
        _GAA_FLAG_SKIP_ANYCAST
        | _GAA_FLAG_SKIP_MULTICAST
        | _GAA_FLAG_INCLUDE_PREFIX
        | _GAA_FLAG_INCLUDE_GATEWAYS
    )
    size = wintypes.ULONG(15_000)
    buffer = ctypes.create_string_buffer(size.value)
    result = get_adapters_addresses(
        socket.AF_INET,
        flags,
        None,
        ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
        ctypes.byref(size),
    )
    if result == _ERROR_BUFFER_OVERFLOW:
        buffer = ctypes.create_string_buffer(size.value)
        result = get_adapters_addresses(
            socket.AF_INET,
            flags,
            None,
            ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
            ctypes.byref(size),
        )
    if result == _ERROR_NO_DATA:
        return ()
    if result != _NO_ERROR:
        raise ctypes.WinError(result)

    first = ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
    snapshots: list[WindowsNetworkAdapterSnapshot] = []
    for adapter in _walk_linked(first, max_items=_MAX_ADAPTERS):
        interface_id = _decode_adapter_name(adapter.AdapterName)
        interface_index = int(adapter.IfIndex)
        if not interface_id:
            interface_id = f"ifindex:{interface_index}"
        name = adapter.FriendlyName or adapter.Description or interface_id
        description = adapter.Description or ""
        ipv4_addresses = tuple(
            address
            for item in _walk_linked(
                adapter.FirstUnicastAddress,
                max_items=_MAX_LINKED_ADDRESSES,
            )
            if (
                address := _read_unicast_ipv4(item)
            )
            is not None
        )
        gateways = tuple(
            address
            for item in _walk_linked(
                adapter.FirstGatewayAddress,
                max_items=_MAX_LINKED_ADDRESSES,
            )
            if (address := _read_ipv4_socket_address(item.Address)) is not None
        )
        dns_servers = tuple(
            address
            for item in _walk_linked(
                adapter.FirstDnsServerAddress,
                max_items=_MAX_LINKED_ADDRESSES,
            )
            if (address := _read_ipv4_socket_address(item.Address)) is not None
        )
        snapshots.append(
            WindowsNetworkAdapterSnapshot(
                interface_id=interface_id,
                interface_index=interface_index,
                name=name,
                description=description,
                if_type=int(adapter.IfType),
                is_up=int(adapter.OperStatus) == _IF_OPER_STATUS_UP,
                ipv4_addresses=ipv4_addresses,
                gateways=gateways,
                dns_servers=dns_servers,
            )
        )
    return tuple(snapshots)


def _walk_linked(pointer: object, *, max_items: int) -> Iterator[object]:
    current = pointer
    count = 0
    while bool(current) and count < max_items:
        item = current.contents
        yield item
        current = item.Next
        count += 1


def _read_unicast_ipv4(item: object) -> WindowsIPv4Address | None:
    address = _read_ipv4_socket_address(item.Address)
    if address is None:
        return None
    prefix_length = int(item.OnLinkPrefixLength)
    if not 0 <= prefix_length <= 32:
        return None
    return WindowsIPv4Address(address=address, prefix_length=prefix_length)


def _read_ipv4_socket_address(value: _SOCKET_ADDRESS) -> str | None:
    if not bool(value.lpSockaddr) or value.iSockaddrLength < ctypes.sizeof(
        _SOCKADDR_IN
    ):
        return None
    if int(value.lpSockaddr.contents.sa_family) != socket.AF_INET:
        return None
    sockaddr = ctypes.cast(
        value.lpSockaddr,
        ctypes.POINTER(_SOCKADDR_IN),
    ).contents
    return socket.inet_ntop(socket.AF_INET, bytes(sockaddr.sin_addr))


def _decode_adapter_name(value: bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("ascii", errors="replace").strip()


__all__ = (
    "WindowsIPv4Address",
    "WindowsNetworkAdapterSnapshot",
    "WindowsNetworkContextProvider",
)
