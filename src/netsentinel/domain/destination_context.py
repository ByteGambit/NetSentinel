"""Portable local IP context. ASN and country are descriptive, never verdicts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from ipaddress import ip_address


class DestinationAddressKind(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    SPECIAL = "special"


class DestinationContextStatus(str, Enum):
    MATCHED = "matched"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    NOT_CONFIGURED = "not_configured"
    DATASET_UNAVAILABLE = "dataset_unavailable"


def _bounded_text(value: str, maximum: int, label: str) -> None:
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError(f"invalid {label}")


@dataclass(frozen=True, slots=True)
class DestinationDatasetSource:
    name: str
    version: str
    license: str
    loaded_at: datetime

    def __post_init__(self) -> None:
        for label, value, maximum in (
            ("source name", self.name, 128),
            ("source version", self.version, 64),
            ("source license", self.license, 256),
        ):
            _bounded_text(value, maximum, label)
        if not isinstance(self.loaded_at, datetime) or self.loaded_at.tzinfo is None:
            raise ValueError("loaded_at must be UTC-aware")
        offset = self.loaded_at.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise ValueError("loaded_at must be UTC-aware")
        object.__setattr__(self, "loaded_at", self.loaded_at.astimezone(UTC))


@dataclass(frozen=True, slots=True)
class DestinationContext:
    ip: str
    kind: DestinationAddressKind
    status: DestinationContextStatus
    asn: int | None = None
    as_name: str | None = None
    country_code: str | None = None
    source: DestinationDatasetSource | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ip, str):
            raise TypeError("ip must be a string")
        object.__setattr__(self, "ip", str(ip_address(self.ip)))
        if not isinstance(self.kind, DestinationAddressKind) or not isinstance(self.status, DestinationContextStatus):
            raise TypeError("invalid destination context kind or status")
        if self.status is DestinationContextStatus.MATCHED:
            if self.kind is not DestinationAddressKind.PUBLIC or self.source is None:
                raise ValueError("matched context requires public IP and source")
            if self.asn is None and self.country_code is None:
                raise ValueError("matched context requires ASN or country")
        elif any(value is not None for value in (self.asn, self.as_name, self.country_code)):
            raise ValueError("unmatched context cannot contain ASN or country")
        if self.status is DestinationContextStatus.NOT_APPLICABLE:
            if self.kind is DestinationAddressKind.PUBLIC or self.source is not None:
                raise ValueError("not applicable requires non-public IP and no source")
        elif self.kind is not DestinationAddressKind.PUBLIC:
            raise ValueError("non-public IP must be not applicable")
        if self.status is DestinationContextStatus.UNKNOWN and self.source is None:
            raise ValueError("unknown public IP requires dataset source")
        if self.status in (DestinationContextStatus.NOT_CONFIGURED, DestinationContextStatus.DATASET_UNAVAILABLE) and self.source is not None:
            raise ValueError("unavailable dataset cannot provide source")
        if self.asn is not None and (type(self.asn) is not int or not 1 <= self.asn <= 4_294_967_295):
            raise ValueError("ASN is outside the 32-bit range")
        if self.as_name is not None:
            _bounded_text(self.as_name, 256, "ASN name")
            if self.asn is None:
                raise ValueError("ASN name requires ASN")
        if self.country_code is not None and (
            not isinstance(self.country_code, str) or len(self.country_code) != 2
            or not self.country_code.isascii() or not self.country_code.isalpha()
            or self.country_code != self.country_code.upper() or self.country_code == "ZZ"
        ):
            raise ValueError("country_code must be two uppercase ASCII letters")
        if self.source is not None and not isinstance(self.source, DestinationDatasetSource):
            raise TypeError("source must be DestinationDatasetSource")
