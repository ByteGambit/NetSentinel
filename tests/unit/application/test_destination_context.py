"""NS-065 synthetic, offline destination context contracts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime
from pathlib import Path
import socket
import urllib.request

import pytest

from netsentinel.application.services.destination_context import DestinationContextResolver
from netsentinel.bootstrap import create_destination_context_resolver
from netsentinel.domain.destination_context import (
    DestinationAddressKind as Kind, DestinationContext, DestinationContextStatus as Status,
    DestinationDatasetSource,
)
from netsentinel.infrastructure import local_destination_dataset as module
from netsentinel.infrastructure.local_destination_dataset import LocalDestinationDataset
from netsentinel.shared.config import AppConfig, load_config_values
from netsentinel.shared.diagnostics import DestinationDatasetStatus as Health


HEADER = "netsentinel-destination-context\t1\tSynthetic registry\t2026-10\tCC0-1.0\n"
ROWS = (
    "8.8.0.0/16\t64500\tExample Network\tUS\n"
    "8.8.8.0/24\t64501\tSpecific Network\tDE\n"
    "2606:4700::/32\t13335\tExample v6\tGB\n"
)


def dataset(tmp_path: Path, rows: str = ROWS, header: str = HEADER) -> Path:
    path = tmp_path / "synthetic.tsv"
    path.write_text(header + rows, encoding="utf-8")
    return path


def resolver(path: Path) -> tuple[LocalDestinationDataset, DestinationContextResolver]:
    provider = LocalDestinationDataset(path)
    return provider, DestinationContextResolver(provider, cache_capacity=2)


def test_ipv4_ipv6_overlap_provenance_and_unknown(tmp_path: Path) -> None:
    provider, service = resolver(dataset(tmp_path))
    assert provider.diagnostic().status is Health.AVAILABLE
    assert provider.diagnostic().record_count == 3
    broad = service.resolve("8.8.4.4")
    specific = service.resolve("8.8.8.8")
    v6 = service.resolve("2606:4700::1111")
    assert (broad.asn, broad.country_code) == (64500, "US")
    assert (specific.asn, specific.as_name, specific.country_code) == (64501, "Specific Network", "DE")
    assert (v6.asn, v6.country_code, v6.ip) == (13335, "GB", "2606:4700::1111")
    assert specific.source is not None
    assert (specific.source.name, specific.source.version, specific.source.license) == (
        "Synthetic registry", "2026-10", "CC0-1.0",
    )
    assert specific.source.loaded_at.tzinfo is UTC
    unknown = service.resolve("9.9.9.9")
    assert unknown.status is Status.UNKNOWN and unknown.source == specific.source
    assert unknown.asn is None and unknown.country_code is None
    assert service.resolve("9.9.9.9") == unknown
    assert service.cache_size <= 2


@pytest.mark.parametrize("ip,kind", [
    ("10.1.2.3", Kind.PRIVATE), ("172.16.0.1", Kind.PRIVATE),
    ("192.168.1.1", Kind.PRIVATE), ("fc00::1", Kind.PRIVATE),
    ("127.0.0.1", Kind.SPECIAL), ("169.254.1.1", Kind.SPECIAL),
    ("224.0.0.1", Kind.SPECIAL), ("0.0.0.0", Kind.SPECIAL),
    ("255.255.255.255", Kind.SPECIAL), ("::1", Kind.SPECIAL),
    ("fe80::1", Kind.SPECIAL), ("ff02::1", Kind.SPECIAL),
    ("2001:db8::1", Kind.SPECIAL), ("203.0.113.1", Kind.SPECIAL),
    ("::ffff:8.8.8.8", Kind.SPECIAL),
])
def test_nonpublic_addresses_never_reach_provider(ip: str, kind: Kind) -> None:
    class NeverLookup(LocalDestinationDataset):
        def lookup(self, ip: str) -> DestinationContext:
            raise AssertionError("non-public lookup")

    result = DestinationContextResolver(NeverLookup()).resolve(ip)
    assert result.kind is kind and result.status is Status.NOT_APPLICABLE
    assert result.source is None and result.asn is None and result.country_code is None


def test_no_dataset_bad_path_and_invalid_input_are_typed(tmp_path: Path) -> None:
    no_dataset = create_destination_context_resolver()
    assert no_dataset.resolve("8.8.8.8").status is Status.NOT_CONFIGURED
    assert no_dataset.diagnostic().status is Health.NOT_CONFIGURED
    missing = create_destination_context_resolver(AppConfig(destination_dataset_path=str(tmp_path / "missing")))
    assert missing.resolve("8.8.8.8").status is Status.DATASET_UNAVAILABLE
    assert missing.diagnostic().status is Health.LOAD_FAILED
    assert "missing" not in repr(missing.diagnostic())
    assert load_config_values({"destination_dataset_path": "\\\\server\\share\\data"}).config.destination_dataset_path is None
    with pytest.raises(ValueError):
        no_dataset.resolve("bad ip")


@pytest.mark.parametrize("rows,health", [
    ("bad row\n", Health.INVALID_DATASET),
    ("8.8.8.0/24\t64500\tGood\tUS\n8.8.8.0/24\t64501\tOther\tGB\n", Health.INVALID_DATASET),
    ("8.8.8.0/24\t64500\tGood\tZZ\n", Health.INVALID_DATASET),
    ("8.8.8.0/24\t64500\t" + "x" * 257 + "\tUS\n", Health.INVALID_DATASET),
    ("8.8.8.0/24\t0\tGood\tUS\n", Health.INVALID_DATASET),
    ("8.8.8.0/24\t4294967296\tGood\tUS\n", Health.INVALID_DATASET),
])
def test_invalid_rows_are_sanitized(tmp_path: Path, rows: str, health: Health) -> None:
    provider = LocalDestinationDataset(dataset(tmp_path, rows))
    assert provider.diagnostic().status is health
    assert provider.lookup("8.8.8.8").status is Status.DATASET_UNAVAILABLE
    assert rows.strip() not in repr(provider.diagnostic())


def test_version_line_file_and_record_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provider = LocalDestinationDataset(dataset(tmp_path, header=HEADER.replace("\t1\t", "\t2\t")))
    assert provider.diagnostic().status is Health.UNSUPPORTED_VERSION
    monkeypatch.setattr(module, "MAX_DATASET_LINE_BYTES", 20)
    assert provider.reload(dataset(tmp_path)).status is Health.INVALID_DATASET
    monkeypatch.setattr(module, "MAX_DATASET_LINE_BYTES", 2048)
    monkeypatch.setattr(module, "MAX_DATASET_BYTES", 64)
    assert provider.reload(dataset(tmp_path)).status is Health.INVALID_DATASET
    monkeypatch.setattr(module, "MAX_DATASET_BYTES", 16 * 1024 * 1024)
    monkeypatch.setattr(module, "MAX_DATASET_RECORDS", 1)
    assert provider.reload(dataset(tmp_path)).status is Health.INVALID_DATASET


def test_reload_is_atomic_and_invalidates_cache(tmp_path: Path) -> None:
    path = dataset(tmp_path)
    provider, service = resolver(path)
    old = service.resolve("8.8.8.8")
    path.write_text(HEADER.replace("2026-10", "2026-11") + "8.8.8.0/24\t64502\tNew\tFR\n", encoding="utf-8")
    assert provider.reload(path).status is Health.AVAILABLE
    new = service.resolve("8.8.8.8")
    assert new.asn == 64502 and new.source is not None and new.source.version == "2026-11"
    assert old.asn == 64501
    path.write_text("SECRET bad data", encoding="utf-8")
    diagnostic = provider.reload(path)
    assert diagnostic.status is Health.AVAILABLE and diagnostic.last_reload_error is Health.INVALID_DATASET
    assert service.resolve("8.8.8.8") == new
    provider.reload(None)
    assert service.resolve("8.8.8.8").status is Status.NOT_CONFIGURED


def test_model_validation_immutability_and_no_verdict() -> None:
    source = DestinationDatasetSource("Test", "1", "CC0", datetime.now(UTC))
    for bad in (0, True, 4_294_967_296):
        with pytest.raises(ValueError):
            DestinationContext("8.8.8.8", Kind.PUBLIC, Status.MATCHED, bad, None, "US", source)
    with pytest.raises(ValueError):
        DestinationContext("8.8.8.8", Kind.PUBLIC, Status.MATCHED, 64500, "x" * 257, "US", source)
    with pytest.raises(ValueError):
        DestinationContext("8.8.8.8", Kind.PUBLIC, Status.MATCHED, 64500, None, "us", source)
    result = DestinationContext("8.8.8.8", Kind.PUBLIC, Status.MATCHED, 64500, None, "US", source)
    with pytest.raises(FrozenInstanceError):
        result.asn = 64501  # type: ignore[misc]
    assert not {"risk", "score", "malicious", "process", "domain"} & {field.name for field in fields(DestinationContext)}


def test_concurrent_offline_lookup_and_no_dns_dependency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("network I/O")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    _, service = resolver(dataset(tmp_path))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(service.resolve, ["8.8.8.8", "2606:4700::1111", "9.9.9.9"] * 50))
    assert {item.status for item in results} == {Status.MATCHED, Status.UNKNOWN}
    assert service.cache_size <= 2
