"""Bounded passive packet capture behind the application capture port.

Scapy is imported lazily by :class:`ScapyCaptureBackend`; importing this module
does not enumerate interfaces, open a socket, or start a worker.  Raw packets
exist only inside the infrastructure callback and are reduced immediately to a
portable :class:`~netsentinel.domain.observations.PacketObservation`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from math import isfinite
from queue import Empty, Full, Queue
import sys
from threading import Event, RLock
from time import monotonic
from typing import Protocol

from netsentinel.application.ports import (
    NetworkContextCollectionError,
    NetworkContextPermissionDenied,
    NetworkContextProvider,
    PacketCaptureDependencyUnavailable,
    PacketCaptureError,
    PacketCaptureInterfaceUnavailable,
    PacketCaptureNetworkChanged,
    PacketCapturePermissionDenied,
    PacketCaptureRequest,
    PacketCaptureTransientError,
)
from netsentinel.domain.devices import NetworkContext
from netsentinel.domain.observations import (
    ArpObservation,
    LinkLayerProtocol,
    MAX_CAPTURED_PACKET_BYTES,
    NetworkLayerProtocol,
    PacketObservation,
)
from netsentinel.domain.dns import DnsObservation
from netsentinel.infrastructure.parsers.arp import parse_arp_packet
from netsentinel.infrastructure.parsers.dns import parse_dns_packet
from netsentinel.shared.diagnostics import (
    CapabilityStatus,
    CaptureCapabilityReason,
    CaptureCapabilitySnapshot,
    CaptureCounters,
    CaptureHealthSnapshot,
    CaptureState,
    Diagnostic,
    DiagnosticCode,
    DiagnosticComponent,
    DiagnosticSeverity,
)


Clock = Callable[[], datetime]
PacketCallback = Callable[[object], None]
ArpParser = Callable[[object, PacketObservation], ArpObservation | None]
DnsParser = Callable[[object, PacketObservation], DnsObservation | None]


class SnifferHandle(Protocol):
    """Narrow lifecycle surface used by the adapter and fake tests."""

    def start(self, timeout: float) -> None: ...

    def request_stop(self) -> None: ...

    def join(self, timeout: float) -> None: ...

    def is_alive(self) -> bool: ...

    def close(self) -> None: ...


class CaptureBackend(Protocol):
    """Infrastructure-only factory for one passive sniffer."""

    def probe(self, interface_id: str) -> None: ...

    def create(
        self,
        *,
        interface_id: str,
        capture_filter: str,
        callback: PacketCallback,
    ) -> SnifferHandle: ...


class ScapyCaptureBackend:
    """Lazy Scapy/Npcap backend with no import-time side effects."""

    def probe(self, interface_id: str) -> None:
        _, conf, resolve_iface = self._runtime()
        if sys.platform == "win32" and not bool(conf.use_pcap):
            raise PacketCaptureDependencyUnavailable(
                "The Windows packet capture driver is unavailable."
            )
        _resolve_scapy_interface(conf, resolve_iface, interface_id)

    def create(
        self,
        *,
        interface_id: str,
        capture_filter: str,
        callback: PacketCallback,
    ) -> SnifferHandle:
        AsyncSniffer, conf, resolve_iface = self._runtime()
        try:
            interface = _resolve_scapy_interface(
                conf,
                resolve_iface,
                interface_id,
            )
            # Opening the socket belongs to explicit start preparation.  It is
            # done synchronously so permission/driver/interface errors do not
            # disappear inside AsyncSniffer's background thread.
            capture_socket = conf.L2listen(
                iface=interface,
                filter=capture_filter,
                promisc=False,
            )
        except Exception as error:
            raise _classify_backend_exception(error) from error
        return _ScapySnifferHandle(
            AsyncSniffer=AsyncSniffer,
            capture_socket=capture_socket,
            callback=callback,
        )

    @staticmethod
    def _runtime() -> tuple[type[object], object, Callable[[str], object]]:
        try:
            from scapy.all import AsyncSniffer, conf
            from scapy.interfaces import resolve_iface
        except (ImportError, ModuleNotFoundError) as error:
            raise PacketCaptureDependencyUnavailable(
                "The packet capture dependency is unavailable."
            ) from error
        return AsyncSniffer, conf, resolve_iface


class _ScapySnifferHandle:
    """Resource-owning wrapper around one Scapy AsyncSniffer."""

    def __init__(
        self,
        *,
        AsyncSniffer: type[object],
        capture_socket: object,
        callback: PacketCallback,
    ) -> None:
        self._capture_socket = capture_socket
        self._started = Event()
        self._sniffer = AsyncSniffer(
            opened_socket=capture_socket,
            prn=callback,
            store=False,
            started_callback=self._started.set,
        )
        self._closed = False

    def start(self, timeout: float) -> None:
        try:
            self._sniffer.start()
            if not self._started.wait(timeout):
                self.request_stop()
                raise PacketCaptureTransientError(
                    "The packet capture worker did not start in time."
                )
        except PacketCaptureError:
            raise
        except Exception as error:
            raise _classify_backend_exception(error) from error

    def request_stop(self) -> None:
        try:
            if bool(getattr(self._sniffer, "running", False)):
                self._sniffer.stop(join=False)
        except Exception as error:
            raise _classify_backend_exception(error) from error

    def join(self, timeout: float) -> None:
        try:
            self._sniffer.join(timeout=timeout)
        except Exception as error:
            raise _classify_backend_exception(error) from error

    def is_alive(self) -> bool:
        thread = getattr(self._sniffer, "thread", None)
        return bool(thread is not None and thread.is_alive())

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = getattr(self._capture_socket, "close", None)
        if callable(close):
            close()


class ScapyCaptureWorker:
    """Safe lifecycle, capability, and backpressure boundary for Scapy.

    The worker never chooses an interface.  ``start`` requires a concrete
    NS-019 ``NetworkContext`` and re-reads the provider before opening capture.
    A changed fingerprint or disappeared interface prevents stale capture.
    """

    def __init__(
        self,
        context_provider: NetworkContextProvider,
        *,
        backend: CaptureBackend | None = None,
        queue_capacity: int = 1_024,
        startup_timeout: float = 1.0,
        shutdown_timeout: float = 2.0,
        clock: Clock | None = None,
        arp_parser: ArpParser | None = None,
        dns_parser: DnsParser | None = None,
    ) -> None:
        if not hasattr(context_provider, "get_contexts"):
            raise TypeError("context_provider must implement NetworkContextProvider")
        if isinstance(queue_capacity, bool) or not isinstance(queue_capacity, int):
            raise TypeError("queue_capacity must be an integer")
        if queue_capacity <= 0:
            raise ValueError("queue_capacity must be greater than zero")
        for field_name, value in (
            ("startup_timeout", startup_timeout),
            ("shutdown_timeout", shutdown_timeout),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not isfinite(value)
                or value < 0
            ):
                raise ValueError(f"{field_name} must be zero or greater")

        self._context_provider = context_provider
        self._backend = backend if backend is not None else ScapyCaptureBackend()
        self._queue: Queue[PacketObservation] = Queue(maxsize=queue_capacity)
        self._startup_timeout = float(startup_timeout)
        self._shutdown_timeout = float(shutdown_timeout)
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._arp_parser = arp_parser if arp_parser is not None else parse_arp_packet
        if not callable(self._arp_parser):
            raise TypeError("arp_parser must be callable")
        self._dns_parser = dns_parser if dns_parser is not None else parse_dns_packet
        if not callable(self._dns_parser):
            raise TypeError("dns_parser must be callable")

        self._lock = RLock()
        self._handle: SnifferHandle | None = None
        self._accepting = False
        self._generation = 0
        initial_capability = CaptureCapabilitySnapshot(
            status=CapabilityStatus.UNAVAILABLE,
            reason=CaptureCapabilityReason.NOT_PROBED,
            checked_at=self._utc_now(),
        )
        self._health = CaptureHealthSnapshot(
            state=CaptureState.STOPPED,
            capability=initial_capability,
            queue_depth=0,
            queue_capacity=queue_capacity,
            counters=CaptureCounters(),
        )

    @property
    def health(self) -> CaptureHealthSnapshot:
        return self.health_snapshot()

    def health_snapshot(self) -> CaptureHealthSnapshot:
        with self._lock:
            self._reconcile_dead_worker_locked()
            alive = self._handle is not None and self._handle.is_alive()
            return replace(
                self._health,
                queue_depth=self._queue.qsize(),
                worker_alive=alive,
            )

    def probe(self, context: NetworkContext) -> CaptureCapabilitySnapshot:
        if not isinstance(context, NetworkContext):
            raise TypeError("context must be a NetworkContext")
        try:
            current = self._resolve_current_context(context)
            self._backend.probe(current.interface_id)
        except Exception as error:
            capability, code = self._failure_capability(error)
            self._record_failure(capability, code, count_worker_failure=False)
            return capability

        capability = CaptureCapabilitySnapshot(
            status=CapabilityStatus.AVAILABLE,
            reason=CaptureCapabilityReason.NONE,
            checked_at=self._utc_now(),
        )
        with self._lock:
            self._health = replace(self._health, capability=capability)
        return capability

    def start(self, request: PacketCaptureRequest) -> bool:
        if not isinstance(request, PacketCaptureRequest):
            raise TypeError("request must be a PacketCaptureRequest")
        with self._lock:
            self._reconcile_dead_worker_locked()
            if self._health.state is not CaptureState.STOPPED:
                return False
            self._health = replace(self._health, state=CaptureState.STARTING)
            self._accepting = False

        try:
            current = self._resolve_current_context(request.context)
            self._backend.probe(current.interface_id)
            generation = self._next_generation_and_clear_queue()
            callback = lambda packet: self._capture_packet(
                packet,
                context=current,
                generation=generation,
            )
            handle = self._backend.create(
                interface_id=current.interface_id,
                capture_filter=request.capture_filter,
                callback=callback,
            )
            with self._lock:
                self._handle = handle
                self._accepting = True
                self._health = replace(
                    self._health,
                    selected_interface_id=current.interface_id,
                    network_fingerprint=current.fingerprint,
                )
            handle.start(self._startup_timeout)
        except Exception as error:
            with self._lock:
                handle = self._handle
                self._accepting = False
                self._handle = None
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            capability, code = self._failure_capability(error)
            self._record_failure(capability, code, count_worker_failure=True)
            with self._lock:
                self._health = replace(
                    self._health,
                    state=CaptureState.STOPPED,
                    selected_interface_id=None,
                    network_fingerprint=None,
                    worker_alive=False,
                )
            return False

        capability = CaptureCapabilitySnapshot(
            status=CapabilityStatus.AVAILABLE,
            reason=CaptureCapabilityReason.NONE,
            checked_at=self._utc_now(),
        )
        with self._lock:
            self._health = replace(
                self._health,
                state=CaptureState.RUNNING,
                capability=capability,
                worker_alive=handle.is_alive(),
            )
        return True

    def stop(self, timeout: float | None = None) -> bool:
        timeout_value = self._validate_timeout(timeout)
        with self._lock:
            handle = self._handle
            self._accepting = False
            self._generation += 1
            if handle is None:
                self._health = replace(
                    self._health,
                    state=CaptureState.STOPPED,
                    worker_alive=False,
                )
                return True
            self._health = replace(self._health, state=CaptureState.STOPPING)

        error: Exception | None = None
        started = monotonic()
        try:
            handle.request_stop()
        except Exception as caught:
            error = caught
        remaining = max(0.0, timeout_value - (monotonic() - started))
        try:
            handle.join(remaining)
        except Exception as caught:
            error = caught

        if handle.is_alive():
            self._record_diagnostic(
                DiagnosticCode.CAPTURE_SHUTDOWN_TIMEOUT,
                DiagnosticSeverity.WARNING,
            )
            with self._lock:
                self._health = replace(
                    self._health,
                    state=CaptureState.STOPPING,
                    worker_alive=True,
                )
            return False

        try:
            handle.close()
        except Exception as caught:
            error = caught
        with self._lock:
            if self._handle is handle:
                self._handle = None
            self._health = replace(
                self._health,
                state=CaptureState.STOPPED,
                worker_alive=False,
            )
        if error is not None:
            capability, code = self._failure_capability(error)
            self._record_failure(capability, code, count_worker_failure=True)
        return True

    def drain(self, limit: int) -> tuple[PacketObservation, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= self._queue.maxsize:
            raise ValueError("limit must be between 1 and queue capacity")
        observations: list[PacketObservation] = []
        for _ in range(limit):
            try:
                observations.append(self._queue.get_nowait())
            except Empty:
                break
        return tuple(observations)

    def _resolve_current_context(self, selected: NetworkContext) -> NetworkContext:
        if selected.is_loopback:
            raise PacketCaptureInterfaceUnavailable(
                "Loopback is not a LAN capture interface."
            )
        try:
            contexts = self._context_provider.get_contexts()
        except NetworkContextPermissionDenied as error:
            raise PacketCapturePermissionDenied(
                "The current network context could not be read."
            ) from error
        except NetworkContextCollectionError as error:
            raise PacketCaptureTransientError(
                "The current network context is unavailable."
            ) from error
        except Exception as error:
            raise PacketCaptureTransientError(
                "The current network context is unavailable."
            ) from error

        same_interface = tuple(
            context
            for context in contexts
            if context.interface_id.casefold() == selected.interface_id.casefold()
        )
        if not same_interface:
            raise PacketCaptureInterfaceUnavailable(
                "The selected capture interface is no longer active."
            )
        for context in same_interface:
            if context.fingerprint == selected.fingerprint:
                if context.is_loopback:
                    raise PacketCaptureInterfaceUnavailable(
                        "Loopback is not a LAN capture interface."
                    )
                return context
        raise PacketCaptureNetworkChanged(
            "The selected network context has changed."
        )

    def _next_generation_and_clear_queue(self) -> int:
        discarded = 0
        while True:
            try:
                self._queue.get_nowait()
                discarded += 1
            except Empty:
                break
        with self._lock:
            self._generation += 1
            counters = self._health.counters
            if discarded:
                counters = replace(
                    counters,
                    dropped_observations=(
                        counters.dropped_observations + discarded
                    ),
                )
            self._health = replace(self._health, counters=counters, queue_depth=0)
            return self._generation

    def _capture_packet(
        self,
        packet: object,
        *,
        context: NetworkContext,
        generation: int,
    ) -> None:
        with self._lock:
            if not self._accepting or generation != self._generation:
                return
            self._health = replace(
                self._health,
                counters=replace(
                    self._health.counters,
                    captured_packets=self._health.counters.captured_packets + 1,
                ),
            )
        try:
            observation = _packet_observation(
                packet,
                context,
                self._utc_now(),
                arp_parser=self._arp_parser,
                dns_parser=self._dns_parser,
            )
        except Exception:
            with self._lock:
                if generation != self._generation:
                    return
                self._health = replace(
                    self._health,
                    counters=replace(
                        self._health.counters,
                        malformed_packets=(
                            self._health.counters.malformed_packets + 1
                        ),
                    ),
                    last_error=self._diagnostic(
                        DiagnosticCode.CAPTURE_MALFORMED_PACKET,
                        DiagnosticSeverity.WARNING,
                    ),
                )
            return

        with self._lock:
            if not self._accepting or generation != self._generation:
                return
            try:
                self._queue.put_nowait(observation)
            except Full:
                self._health = replace(
                    self._health,
                    counters=replace(
                        self._health.counters,
                        dropped_observations=(
                            self._health.counters.dropped_observations + 1
                        ),
                    ),
                    last_error=self._diagnostic(
                        DiagnosticCode.CAPTURE_QUEUE_OVERFLOW,
                        DiagnosticSeverity.WARNING,
                    ),
                )
                return
            self._health = replace(
                self._health,
                queue_depth=self._queue.qsize(),
                counters=replace(
                    self._health.counters,
                    enqueued_observations=(
                        self._health.counters.enqueued_observations + 1
                    ),
                ),
                last_observation_at=observation.observed_at,
            )

    def _reconcile_dead_worker_locked(self) -> None:
        handle = self._handle
        if (
            handle is None
            or self._health.state is not CaptureState.RUNNING
            or handle.is_alive()
        ):
            return
        self._accepting = False
        self._generation += 1
        error: Exception | None = None
        try:
            handle.join(0.0)
        except Exception as caught:
            error = caught
        try:
            handle.close()
        except Exception as caught:
            error = caught
        self._handle = None
        capability, code = self._failure_capability(
            error
            if error is not None
            else PacketCaptureTransientError("The capture worker stopped.")
        )
        self._health = replace(
            self._health,
            state=CaptureState.STOPPED,
            capability=capability,
            counters=replace(
                self._health.counters,
                worker_failures=self._health.counters.worker_failures + 1,
            ),
            last_error=self._diagnostic(code, DiagnosticSeverity.ERROR),
            worker_alive=False,
        )

    def _record_failure(
        self,
        capability: CaptureCapabilitySnapshot,
        code: DiagnosticCode,
        *,
        count_worker_failure: bool,
    ) -> None:
        with self._lock:
            counters = self._health.counters
            if count_worker_failure:
                counters = replace(
                    counters,
                    worker_failures=counters.worker_failures + 1,
                )
            self._health = replace(
                self._health,
                capability=capability,
                counters=counters,
                last_error=self._diagnostic(code, DiagnosticSeverity.ERROR),
            )

    def _record_diagnostic(
        self,
        code: DiagnosticCode,
        severity: DiagnosticSeverity,
    ) -> None:
        with self._lock:
            self._health = replace(
                self._health,
                last_error=self._diagnostic(code, severity),
            )

    def _failure_capability(
        self,
        error: Exception,
    ) -> tuple[CaptureCapabilitySnapshot, DiagnosticCode]:
        if isinstance(error, PacketCapturePermissionDenied):
            status = CapabilityStatus.UNAVAILABLE
            reason = CaptureCapabilityReason.PERMISSION_DENIED
            code = DiagnosticCode.CAPTURE_PERMISSION_DENIED
        elif isinstance(error, PacketCaptureDependencyUnavailable):
            status = CapabilityStatus.UNAVAILABLE
            reason = CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE
            code = DiagnosticCode.CAPTURE_DEPENDENCY_UNAVAILABLE
        elif isinstance(error, PacketCaptureInterfaceUnavailable):
            status = CapabilityStatus.UNAVAILABLE
            reason = CaptureCapabilityReason.INTERFACE_UNAVAILABLE
            code = DiagnosticCode.CAPTURE_INTERFACE_UNAVAILABLE
        elif isinstance(error, PacketCaptureNetworkChanged):
            status = CapabilityStatus.UNAVAILABLE
            reason = CaptureCapabilityReason.NETWORK_CHANGED
            code = DiagnosticCode.CAPTURE_NETWORK_CHANGED
        else:
            status = CapabilityStatus.DEGRADED
            reason = CaptureCapabilityReason.TRANSIENT_FAILURE
            code = DiagnosticCode.CAPTURE_TRANSIENT_FAILURE
        return (
            CaptureCapabilitySnapshot(
                status=status,
                reason=reason,
                checked_at=self._utc_now(),
            ),
            code,
        )

    def _validate_timeout(self, timeout: float | None) -> float:
        if timeout is None:
            return self._shutdown_timeout
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("timeout must be zero or greater")
        return float(timeout)

    def _utc_now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("clock must return a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _diagnostic(
        self,
        code: DiagnosticCode,
        severity: DiagnosticSeverity,
    ) -> Diagnostic:
        return Diagnostic(
            code=code,
            component=DiagnosticComponent.CAPTURE,
            severity=severity,
            occurred_at=self._utc_now(),
        )


def _classify_backend_exception(error: Exception) -> PacketCaptureError:
    if isinstance(error, PacketCaptureError):
        return error
    if isinstance(error, (ImportError, ModuleNotFoundError)):
        return PacketCaptureDependencyUnavailable(
            "The packet capture dependency is unavailable."
        )
    if isinstance(error, PermissionError) or getattr(error, "winerror", None) == 5:
        return PacketCapturePermissionDenied(
            "Packet capture permission was denied."
        )
    if isinstance(error, FileNotFoundError) or getattr(error, "errno", None) == 19:
        return PacketCaptureInterfaceUnavailable(
            "The selected capture interface is unavailable."
        )
    return PacketCaptureTransientError("Packet capture failed temporarily.")


def _resolve_scapy_interface(
    conf: object,
    resolve_iface: Callable[[str], object],
    interface_id: str,
) -> object:
    """Resolve the NS-019 stable Windows adapter GUID in Scapy's own table.

    Scapy's generic resolver primarily compares display and pcap network names.
    On Windows its interface objects also retain the IP Helper adapter GUID used
    by NS-019.  Matching that field avoids a second OS discovery mechanism and
    keeps the ``NetworkContext`` identity authoritative.
    """

    try:
        return resolve_iface(interface_id)
    except (KeyError, ValueError):
        pass
    except OSError as error:
        raise PacketCaptureTransientError(
            "The capture interface could not be inspected."
        ) from error

    interfaces = getattr(conf, "ifaces", None)
    values = getattr(interfaces, "values", None)
    if callable(values):
        normalized_id = interface_id.casefold()
        for candidate in values():
            identities = (
                getattr(candidate, "guid", None),
                getattr(candidate, "network_name", None),
                getattr(candidate, "name", None),
            )
            if any(
                isinstance(value, str) and value.casefold() == normalized_id
                for value in identities
            ):
                return candidate
    raise PacketCaptureInterfaceUnavailable(
        "The selected capture interface is unavailable."
    )


def _packet_observation(
    packet: object,
    context: NetworkContext,
    observed_at: datetime,
    *,
    arp_parser: ArpParser = parse_arp_packet,
    dns_parser: DnsParser = parse_dns_packet,
) -> PacketObservation:
    captured_length = len(packet)  # type: ignore[arg-type]
    if isinstance(captured_length, bool) or not isinstance(captured_length, int):
        raise TypeError("packet length must be an integer")
    if not 0 <= captured_length <= MAX_CAPTURED_PACKET_BYTES:
        raise ValueError("packet length is outside the supported bound")

    raw_wire_length = getattr(packet, "wirelen", None)
    if raw_wire_length is None:
        original_length = captured_length
    elif isinstance(raw_wire_length, bool) or not isinstance(raw_wire_length, int):
        raise TypeError("packet wire length must be an integer")
    else:
        original_length = max(captured_length, raw_wire_length)

    observation = PacketObservation(
        interface_id=context.interface_id,
        interface_index=context.interface_index,
        network_fingerprint=context.fingerprint,
        observed_at=observed_at,
        captured_length=captured_length,
        original_length=original_length,
        link_layer=_link_layer(packet),
        network_layer=_network_layer(packet),
    )
    arp = arp_parser(packet, observation)
    dns = dns_parser(packet, observation)
    if arp is None and dns is None:
        return observation
    return replace(observation, arp=arp, dns=dns)


def _has_layer(packet: object, layer_name: str) -> bool:
    haslayer = getattr(packet, "haslayer", None)
    if not callable(haslayer):
        return False
    return bool(haslayer(layer_name))


def _link_layer(packet: object) -> LinkLayerProtocol:
    if _has_layer(packet, "Ether") or _has_layer(packet, "Ethernet"):
        return LinkLayerProtocol.ETHERNET
    if _has_layer(packet, "Loopback"):
        return LinkLayerProtocol.LOOPBACK
    return LinkLayerProtocol.OTHER


def _network_layer(packet: object) -> NetworkLayerProtocol:
    if _has_layer(packet, "ARP"):
        return NetworkLayerProtocol.ARP
    if _has_layer(packet, "IP"):
        return NetworkLayerProtocol.IPV4
    if _has_layer(packet, "IPv6"):
        return NetworkLayerProtocol.IPV6
    return NetworkLayerProtocol.OTHER


__all__ = (
    "CaptureBackend",
    "ScapyCaptureBackend",
    "ScapyCaptureWorker",
    "SnifferHandle",
)
