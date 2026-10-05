"""NS-063 local, bounded DNS association evidence storage."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import sqlite3
from uuid import UUID

from netsentinel.domain.connections import ConnectionNetworkScope, NetworkScopeStatus
from netsentinel.domain.dns import (
    DnsAssociationProvenance, DnsEvidenceId, DnsRecordType, DnsTransport,
    DomainAssociation,
)
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, SQLiteDatabase, transaction
from netsentinel.infrastructure.sqlite.repositories import (
    datetime_to_epoch_microseconds as to_us, epoch_microseconds_to_datetime as from_us,
)

MAX_STORED_ASSOCIATIONS = 100_000
_COLUMNS = (
    "evidence_id, association_index, domain, ip, record_type, provenance, queried_domain, answer_name, "
    "cname_chain_json, observed_at_utc_us, expires_at_utc_us, ttl, answer_ttl, "
    "retention_seconds, network_fingerprint, client_ip, server_ip, transport, "
    "transaction_id, query_at_utc_us"
)


class DnsAssociationRepositoryError(RuntimeError):
    """Sanitized association storage failure."""


def _encode(item: DomainAssociation, index: int) -> tuple[object, ...]:
    chain = json.dumps(item.cname_chain, separators=(",", ":"))
    if len(chain) > 2300 or len(item.cname_chain) > 9 or item.retention_seconds > 3600:
        raise ValueError("association exceeds storage bounds")
    return (
        str(item.evidence_id), index, item.domain, item.ip, item.record_type.value,
        item.provenance.value, item.queried_domain, item.answer_name, chain,
        to_us(item.observed_at), to_us(item.observed_at + timedelta(seconds=item.retention_seconds)),
        item.ttl, item.answer_ttl, item.retention_seconds,
        item.network_fingerprint, item.client_ip, item.server_ip, item.transport.value,
        item.transaction_id, to_us(item.query_at),
    )


def _decode(row: sqlite3.Row) -> DomainAssociation:
    try:
        chain = json.loads(row["cname_chain_json"])
        if not isinstance(chain, list) or len(chain) > 9 or any(not isinstance(name, str) for name in chain):
            raise ValueError("invalid chain")
        item = DomainAssociation(
            domain=row["domain"], ip=row["ip"], record_type=DnsRecordType(row["record_type"]),
            provenance=DnsAssociationProvenance(row["provenance"]),
            queried_domain=row["queried_domain"], answer_name=row["answer_name"],
            cname_chain=tuple(chain), observed_at=from_us(row["observed_at_utc_us"]),
            ttl=row["ttl"], answer_ttl=row["answer_ttl"],
            retention_seconds=row["retention_seconds"],
            network_fingerprint=row["network_fingerprint"], client_ip=row["client_ip"],
            server_ip=row["server_ip"], transport=DnsTransport(row["transport"]),
            transaction_id=row["transaction_id"], query_at=from_us(row["query_at_utc_us"]),
            evidence_id=DnsEvidenceId(UUID(row["evidence_id"])),
        )
        if to_us(item.observed_at + timedelta(seconds=item.retention_seconds)) != row["expires_at_utc_us"]:
            raise ValueError("invalid expiry")
        return item
    except (TypeError, ValueError, KeyError, OverflowError, json.JSONDecodeError):
        raise DnsAssociationRepositoryError("Persisted DNS association is invalid.") from None


def insert_association(connection: sqlite3.Connection, item: DomainAssociation, index: int) -> None:
    if type(index) is not int or not 0 <= index <= 511:
        raise ValueError("association index exceeds the result bound")
    value = _encode(item, index)
    cursor = connection.execute(
        f"INSERT INTO dns_associations ({_COLUMNS}) VALUES ({','.join('?' for _ in value)}) "
        "ON CONFLICT DO NOTHING", value,
    )
    if cursor.rowcount == 0:
        existing = connection.execute(
            f"SELECT {_COLUMNS} FROM dns_associations WHERE evidence_id = ? AND association_index = ?",
            (value[0], value[1]),
        ).fetchone()
        if existing is None or tuple(existing) != value:
            raise ValueError("association identity conflict")


def prune_associations(connection: sqlite3.Connection) -> None:
    """Enforce the hard cap with <=128 deletes; larger overflow rolls back batch."""
    excess = max(0, connection.execute("SELECT COUNT(*) FROM dns_associations").fetchone()[0] - MAX_STORED_ASSOCIATIONS)
    if excess > 128:
        raise ValueError("DNS association quota requires bounded maintenance")
    if excess:
        connection.execute(
            "DELETE FROM dns_associations WHERE rowid IN ("
            "SELECT rowid FROM dns_associations ORDER BY observed_at_utc_us, evidence_id, association_index LIMIT ?)",
            (excess,),
        )


class SQLiteDnsAssociationRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self._database = database

    def get_by_evidence_id(self, evidence_id: DnsEvidenceId, *, limit: int = 512) -> tuple[DomainAssociation, ...]:
        if not isinstance(evidence_id, DnsEvidenceId) or type(limit) is not int or not 1 <= limit <= 512:
            raise ValueError("invalid evidence query")
        try:
            with self._database.connection() as connection:
                rows = connection.execute(
                    f"SELECT {_COLUMNS} FROM dns_associations WHERE evidence_id = ? "
                    "ORDER BY association_index LIMIT ?", (str(evidence_id), limit),
                ).fetchall()
            return tuple(_decode(row) for row in rows)
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsAssociationRepositoryError("DNS association could not be read.") from None

    def active_by_ip(
        self, ip: str, *, network_scope: ConnectionNetworkScope, client_ip: str | None,
        now_utc: datetime, limit: int = 32,
    ) -> tuple[DomainAssociation, ...]:
        from ipaddress import ip_address

        if type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError("limit must be between 1 and 32")
        if now_utc.tzinfo is None or now_utc.utcoffset() != timedelta(0):
            raise ValueError("query clock must be UTC-aware")
        if network_scope.status is not NetworkScopeStatus.RESOLVED or client_ip is None:
            return ()
        address, client = str(ip_address(ip)), str(ip_address(client_ip))
        try:
            with self._database.connection() as connection:
                rows = connection.execute(
                    f"WITH ranked AS (SELECT {_COLUMNS}, ROW_NUMBER() OVER ("
                    "PARTITION BY network_fingerprint, client_ip, domain, ip, provenance, cname_chain_json "
                    "ORDER BY observed_at_utc_us DESC, rowid DESC) AS rank "
                    "FROM dns_associations WHERE network_fingerprint = ? "
                    "AND client_ip = ? AND ip = ? AND expires_at_utc_us > ? "
                    "AND observed_at_utc_us <= ?) "
                    f"SELECT {_COLUMNS} FROM ranked WHERE rank = 1 "
                    "ORDER BY observed_at_utc_us DESC, evidence_id DESC, association_index DESC LIMIT ?",
                    (network_scope.fingerprint, client, address, to_us(now_utc), to_us(now_utc), limit),
                ).fetchall()
            return tuple(_decode(row) for row in rows)
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsAssociationRepositoryError("DNS association could not be read.") from None

    def overlapping_by_ip(
        self, ip: str, *, network_scope: ConnectionNetworkScope, client_ip: str | None,
        first_seen: datetime, last_seen: datetime, limit: int = 32,
    ) -> tuple[DomainAssociation, ...]:
        """Evidence valid at any point in an observed connection interval."""
        from ipaddress import ip_address

        if type(limit) is not int or not 1 <= limit <= 32 or first_seen > last_seen:
            raise ValueError("invalid historical association query")
        if any(value.tzinfo is None or value.utcoffset() != timedelta(0) for value in (first_seen, last_seen)):
            raise ValueError("query clocks must be UTC-aware")
        if network_scope.status is not NetworkScopeStatus.RESOLVED or client_ip is None:
            return ()
        address, client = str(ip_address(ip)), str(ip_address(client_ip))
        try:
            with self._database.connection() as connection:
                rows = connection.execute(
                    f"WITH ranked AS (SELECT {_COLUMNS}, ROW_NUMBER() OVER ("
                    "PARTITION BY network_fingerprint, client_ip, domain, ip, provenance, cname_chain_json "
                    "ORDER BY observed_at_utc_us DESC, rowid DESC) AS rank "
                    "FROM dns_associations WHERE network_fingerprint = ? AND client_ip = ? AND ip = ? "
                    "AND observed_at_utc_us <= ? AND expires_at_utc_us > ?) "
                    f"SELECT {_COLUMNS} FROM ranked WHERE rank = 1 "
                    "ORDER BY observed_at_utc_us DESC, "
                    "CASE provenance WHEN 'direct_answer' THEN 0 ELSE 1 END, "
                    "domain, cname_chain_json, evidence_id DESC LIMIT ?",
                    (network_scope.fingerprint, client, address, to_us(last_seen), to_us(first_seen), limit),
                ).fetchall()
            return tuple(_decode(row) for row in rows)
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsAssociationRepositoryError("DNS association could not be read.") from None

    def active_for_restore(self, *, now_utc: datetime, limit: int = 2048) -> tuple[DomainAssociation, ...]:
        if type(limit) is not int or not 1 <= limit <= 2048:
            raise ValueError("limit must be between 1 and 2048")
        if now_utc.tzinfo is None or now_utc.utcoffset() != timedelta(0):
            raise ValueError("query clock must be UTC-aware")
        try:
            with self._database.connection() as connection:
                rows = connection.execute(
                    f"SELECT {_COLUMNS} FROM dns_associations WHERE expires_at_utc_us > ? "
                    "AND observed_at_utc_us <= ? ORDER BY observed_at_utc_us DESC, rowid DESC LIMIT ?",
                    (to_us(now_utc), to_us(now_utc), limit),
                ).fetchall()
            return tuple(_decode(row) for row in rows)
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsAssociationRepositoryError("DNS association could not be read.") from None

    def delete_before(self, cutoff: datetime, limit: int) -> int:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        try:
            with self._database.connection() as connection, transaction(connection):
                return connection.execute(
                    "DELETE FROM dns_associations WHERE rowid IN (SELECT rowid FROM dns_associations "
                    "WHERE observed_at_utc_us < ? ORDER BY observed_at_utc_us, rowid LIMIT ?)",
                    (to_us(cutoff), limit),
                ).rowcount
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsAssociationRepositoryError("DNS association cleanup failed.") from None

    def delete_oldest_over_limit(self, max_rows: int, limit: int) -> int:
        if type(max_rows) is not int or max_rows < 1 or type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("invalid cleanup bound")
        try:
            with self._database.connection() as connection, transaction(connection):
                excess = max(0, connection.execute("SELECT COUNT(*) FROM dns_associations").fetchone()[0] - max_rows)
                if not excess:
                    return 0
                return connection.execute(
                    "DELETE FROM dns_associations WHERE rowid IN (SELECT rowid FROM dns_associations "
                    "ORDER BY observed_at_utc_us, rowid LIMIT ?)", (min(excess, limit),),
                ).rowcount
        except (SQLiteAdapterError, sqlite3.Error, TypeError, ValueError):
            raise DnsAssociationRepositoryError("DNS association cleanup failed.") from None
