"""Temporary Linux guest-only one-address TCP echo endpoint for NS-101."""

from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time


def main():
    if sys.platform != "linux" or len(sys.argv) != 4:
        raise SystemExit(64)
    ip, port, receipt = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3])
    address = IPv4Address(ip)
    private = tuple(IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if str(address) != ip or not any(address in n for n in private) or not 1024 <= port <= 65535:
        raise SystemExit(64)
    stopped = False
    def stop(signum, frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    record = {"pid": os.getpid(), "ip": ip, "port": port, "state": "LISTENING", "connections": 0,
              "script_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
              "start_ticks": Path(f"/proc/{os.getpid()}/stat").read_text().split(") ", 1)[1].split()[19]}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((ip, port))
        listener.listen(8)
        listener.settimeout(1)
        receipt.write_text(json.dumps(record), encoding="utf-8")
        deadline = time.monotonic() + 900
        while not stopped and time.monotonic() < deadline:
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            with client:
                client.settimeout(3)
                try:
                    if client.recv(1) == b"N":
                        client.sendall(b"N")
                        record["connections"] += 1
                except (TimeoutError, OSError):
                    pass
            receipt.write_text(json.dumps(record), encoding="utf-8")
    record["state"] = "STOPPED"
    receipt.write_text(json.dumps(record), encoding="utf-8")


if __name__ == "__main__":
    main()
