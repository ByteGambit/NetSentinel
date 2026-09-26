"""NS-044 bounded aggregate persistence, with no captured frame data."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from netsentinel.application.ports import VlanSummaryDataCorrupt, VlanSummaryRepositoryError
from netsentinel.domain.vlan_summary import VlanBaselineState, VlanIdSummary, VlanSummarySnapshot
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, SQLiteDatabase, transaction
from netsentinel.infrastructure.sqlite.repositories import (
    datetime_to_epoch_microseconds, epoch_microseconds_to_datetime,
)


class SQLiteVlanSummaryRepository:
    """One atomic upsert per observation; at most 64 scopes and 128 VIDs each.

    The oldest scope by last observed UTC time is evicted first, with its key
    breaking ties. No event history or raw packet is stored. A connection is
    opened and closed for each call on the owning inventory worker.
    """

    def __init__(self, database: SQLiteDatabase, *, max_scopes: int = 64) -> None:
        if not isinstance(database, SQLiteDatabase):
            raise TypeError("database must be SQLiteDatabase")
        if type(max_scopes) is not int or not 1 <= max_scopes <= 4096:
            raise ValueError("max_scopes must be 1..4096")
        self._database = database
        self._max_scopes = max_scopes

    def get(self, network_fingerprint: str, interface_id: str,
            interface_index: int) -> VlanSummarySnapshot | None:
        _key(network_fingerprint, interface_id, interface_index)
        try:
            with self._database.connection() as connection:
                return _read(connection, (network_fingerprint, interface_id, interface_index))
        except VlanSummaryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error) as error:
            raise VlanSummaryRepositoryError("VLAN summary could not be read.") from error

    def save(self, summary: VlanSummarySnapshot) -> VlanSummarySnapshot:
        if not isinstance(summary, VlanSummarySnapshot):
            raise TypeError("summary must be VlanSummarySnapshot")
        key = (summary.network_fingerprint, summary.interface_id, summary.interface_index)
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    existing = _read(connection, key)
                    if existing is None:
                        count = connection.execute("SELECT COUNT(*) FROM vlan_summaries").fetchone()[0]
                        if count >= self._max_scopes:
                            connection.execute(
                                """DELETE FROM vlan_summaries WHERE
                                   (network_fingerprint, interface_id, interface_index) IN
                                   (SELECT network_fingerprint, interface_id, interface_index
                                    FROM vlan_summaries ORDER BY last_seen_utc_us,
                                    network_fingerprint, interface_id, interface_index LIMIT ?)""",
                                (count - self._max_scopes + 1,),
                            )
                    elif (existing.baseline_state is not VlanBaselineState.LEARNING and
                          summary.baseline_state is VlanBaselineState.LEARNING):
                        raise VlanSummaryRepositoryError("Learned VLAN baseline cannot regress.")
                    if summary.baseline_state is VlanBaselineState.VERIFIED:
                        if (existing is None or existing.baseline_state is not VlanBaselineState.VERIFIED
                                or summary.verified_at != existing.verified_at):
                            raise VlanSummaryRepositoryError("VLAN verification requires the explicit command.")
                        if summary.learned_vlan_ids != existing.learned_vlan_ids:
                            raise VlanSummaryRepositoryError("Verified VLAN reference cannot change passively.")
                    elif existing is not None and existing.baseline_state is VlanBaselineState.VERIFIED:
                        raise VlanSummaryRepositoryError("Verified VLAN baseline cannot regress.")
                    connection.execute(
                        """INSERT INTO vlan_summaries (
                           network_fingerprint, interface_id, interface_index,
                           first_seen_utc_us, last_seen_utc_us, learning_started_utc_us,
                           baseline_state, untagged_count, tagged_count,
                           priority_tagged_count, reserved_count, stacked_count,
                           overflow_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(network_fingerprint, interface_id, interface_index)
                           DO UPDATE SET first_seen_utc_us=excluded.first_seen_utc_us,
                           last_seen_utc_us=excluded.last_seen_utc_us,
                           learning_started_utc_us=excluded.learning_started_utc_us,
                           baseline_state=excluded.baseline_state,
                           untagged_count=excluded.untagged_count,
                           tagged_count=excluded.tagged_count,
                           priority_tagged_count=excluded.priority_tagged_count,
                           reserved_count=excluded.reserved_count,
                           stacked_count=excluded.stacked_count,
                           overflow_count=excluded.overflow_count""",
                        (*key, datetime_to_epoch_microseconds(summary.first_seen),
                         datetime_to_epoch_microseconds(summary.last_seen),
                         datetime_to_epoch_microseconds(summary.learning_started_at),
                         ("learned" if summary.baseline_state is VlanBaselineState.VERIFIED
                          else summary.baseline_state.value), summary.untagged_count,
                         summary.tagged_count, summary.priority_tagged_count,
                         summary.reserved_count, summary.stacked_count, summary.overflow_count),
                    )
                    connection.execute(
                        """DELETE FROM vlan_id_summaries WHERE network_fingerprint = ?
                           AND interface_id = ? AND interface_index = ?""", key,
                    )
                    connection.executemany(
                        """INSERT INTO vlan_id_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        ((*key, item.vlan_id, item.count,
                          datetime_to_epoch_microseconds(item.first_seen),
                          datetime_to_epoch_microseconds(item.last_seen), int(item.learned))
                         for item in summary.vlan_ids),
                    )
                persisted = _read(connection, key)
                assert persisted is not None
                return persisted
        except VlanSummaryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, ValueError, OverflowError) as error:
            raise VlanSummaryRepositoryError("VLAN summary could not be stored.") from error

    def verify(self, network_fingerprint: str, interface_id: str,
               interface_index: int, verified_at: datetime) -> VlanSummarySnapshot:
        key = (network_fingerprint, interface_id, interface_index)
        _key(*key)
        verified_us = datetime_to_epoch_microseconds(verified_at)
        try:
            with self._database.connection() as connection:
                with transaction(connection):
                    existing = _read(connection, key)
                    if existing is None or existing.baseline_state is VlanBaselineState.LEARNING:
                        raise VlanSummaryRepositoryError("VLAN baseline is not learned.")
                    if existing.baseline_state is VlanBaselineState.VERIFIED:
                        return existing
                    if (existing.overflow_count or not existing.learned_vlan_ids or
                            verified_at < existing.learning_started_at):
                        raise VlanSummaryRepositoryError("VLAN baseline is incomplete.")
                    connection.execute(
                        """UPDATE vlan_summaries SET verified_at_utc_us = ?
                           WHERE network_fingerprint = ? AND interface_id = ?
                           AND interface_index = ? AND verified_at_utc_us IS NULL""",
                        (verified_us, *key),
                    )
                    result = _read(connection, key)
                    assert result is not None
                    return result
        except VlanSummaryRepositoryError:
            raise
        except (SQLiteAdapterError, sqlite3.Error, ValueError, OverflowError) as error:
            raise VlanSummaryRepositoryError("VLAN baseline could not be verified.") from error


def _key(fingerprint: str, interface_id: str, interface_index: int) -> None:
    if (not isinstance(fingerprint, str) or len(fingerprint) != 64 or
            any(c not in "0123456789abcdef" for c in fingerprint) or
            not isinstance(interface_id, str) or not interface_id or
            len(interface_id) > 512 or interface_id != interface_id.casefold() or
            type(interface_index) is not int or interface_index < 0):
        raise ValueError("invalid VLAN scope")


def _read(connection: sqlite3.Connection, key: tuple[str, str, int]) -> VlanSummarySnapshot | None:
    row = connection.execute(
        """SELECT * FROM vlan_summaries WHERE network_fingerprint = ?
           AND interface_id = ? AND interface_index = ?""", key,
    ).fetchone()
    if row is None:
        return None
    items = connection.execute(
        """SELECT * FROM vlan_id_summaries WHERE network_fingerprint = ?
           AND interface_id = ? AND interface_index = ? ORDER BY vlan_id LIMIT 129""", key,
    ).fetchall()
    try:
        verified_at = (epoch_microseconds_to_datetime(row["verified_at_utc_us"])
                       if row["verified_at_utc_us"] is not None else None)
        state = (VlanBaselineState.VERIFIED if verified_at is not None
                 else VlanBaselineState(row["baseline_state"]))
        if verified_at is not None and row["baseline_state"] != "learned":
            raise ValueError("verified VLAN baseline must be learned")
        return VlanSummarySnapshot(
            row["network_fingerprint"], row["interface_id"], row["interface_index"],
            epoch_microseconds_to_datetime(row["first_seen_utc_us"]),
            epoch_microseconds_to_datetime(row["last_seen_utc_us"]),
            epoch_microseconds_to_datetime(row["learning_started_utc_us"]),
            state, row["untagged_count"],
            row["tagged_count"], row["priority_tagged_count"], row["reserved_count"],
            row["stacked_count"], row["overflow_count"],
            tuple(VlanIdSummary(item["vlan_id"], item["count"],
                                 epoch_microseconds_to_datetime(item["first_seen_utc_us"]),
                                 epoch_microseconds_to_datetime(item["last_seen_utc_us"]),
                                 bool(item["learned"])) for item in items),
            verified_at,
        )
    except (TypeError, ValueError, KeyError, IndexError, OverflowError) as error:
        raise VlanSummaryDataCorrupt("Persisted VLAN summary is invalid.") from error


__all__ = ("SQLiteVlanSummaryRepository",)
