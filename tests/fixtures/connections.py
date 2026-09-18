"""Controlled loopback socket fixtures for opt-in Windows integration tests."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
import socket
from threading import Event

import pytest


LOOPBACK_IPV4 = "127.0.0.1"
SOCKET_SETUP_TIMEOUT = 2.0


@dataclass(slots=True)
class LocalTcpConnection:
    """A listener and both ends of one established loopback connection."""

    listener: socket.socket
    client: socket.socket
    server: socket.socket
    connected: Event = field(default_factory=Event)
    cleaned_up: Event = field(default_factory=Event)

    @property
    def listener_endpoint(self) -> tuple[str, int]:
        address, port = self.listener.getsockname()
        return str(address), int(port)

    @property
    def client_endpoint(self) -> tuple[str, int]:
        address, port = self.client.getsockname()
        return str(address), int(port)

    @property
    def closed(self) -> bool:
        return all(
            current.fileno() == -1
            for current in (self.client, self.server, self.listener)
        )

    def close(self) -> None:
        """Close every owned socket idempotently and record verified cleanup."""

        for current in (self.client, self.server):
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for current in (self.client, self.server, self.listener):
            current.close()
        if self.closed:
            self.cleaned_up.set()


def _open_local_tcp_connection() -> LocalTcpConnection:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server: socket.socket | None = None
    try:
        listener.settimeout(SOCKET_SETUP_TIMEOUT)
        listener.bind((LOOPBACK_IPV4, 0))
        listener.listen(1)

        client.settimeout(SOCKET_SETUP_TIMEOUT)
        client.connect(listener.getsockname())
        server, _ = listener.accept()

        listener.settimeout(None)
        client.settimeout(None)
        server.settimeout(None)
        connection = LocalTcpConnection(
            listener=listener,
            client=client,
            server=server,
        )
        connection.connected.set()
        return connection
    except BaseException:
        client.close()
        if server is not None:
            server.close()
        listener.close()
        raise


@pytest.fixture
def local_tcp_connection() -> Iterator[LocalTcpConnection]:
    """Keep a loopback connection open until its test has finished."""

    connection = _open_local_tcp_connection()
    try:
        yield connection
    finally:
        connection.close()
        assert connection.cleaned_up.is_set()
        assert connection.closed


__all__ = ("LocalTcpConnection", "local_tcp_connection")
