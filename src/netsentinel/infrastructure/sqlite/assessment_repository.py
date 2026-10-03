"""NS-078 short transactions on caller-owned, scoped SQLite connections."""

from __future__ import annotations

from datetime import datetime, timedelta
import sqlite3

from netsentinel.domain.risk_assessment import (
    ASSESSMENT_FORMAT_VERSION, MAX_ASSESSMENT_KEY_BYTES, MAX_ASSESSMENT_PAYLOAD_BYTES,
    AssessmentHistory, AssessmentIdentityConflict, AssessmentPersistenceError,
    AssessmentRead, AssessmentReadStatus, AssessmentReferenceState, AssessmentSave,
    AssessmentSnapshot, AssessmentSourceStatus, AssessmentStoragePolicy,
    RiskAssessmentKey, RiskAssessmentRevision, canonical_json, utc_time,
)
from netsentinel.domain.risk_evidence import EvidenceReference, EvidenceReferenceKind, _digest
from netsentinel.infrastructure.sqlite.assessment_codec import decode_value
from netsentinel.infrastructure.sqlite.database import SQLiteAdapterError, SQLiteDatabase, transaction

# Size gates are applied in SQL before transferring untrusted payloads to Python.
_SELECT = """SELECT r.assessment_id, r.revision, r.format_version,
 CASE WHEN length(r.assessed_at) <= 32 THEN r.assessed_at ELSE NULL END AS assessed_at,
 CASE WHEN length(r.content_fingerprint) = 64 THEN r.content_fingerprint ELSE NULL END AS content_fingerprint,
 CASE WHEN length(CAST(r.snapshot AS BLOB)) <= 65536 THEN r.snapshot ELSE NULL END AS snapshot,
 CASE WHEN length(CAST(a.identity_payload AS BLOB)) <= 8192 THEN a.identity_payload ELSE NULL END AS identity_payload,
 CASE WHEN length(a.original_observed_at) <= 32 THEN a.original_observed_at ELSE NULL END AS original_observed_at,
 a.last_revision FROM risk_assessment_revisions r
 JOIN risk_assessments a ON a.assessment_id = r.assessment_id """


class SQLiteAssessmentRepository:
    def __init__(self, database: SQLiteDatabase, policy: AssessmentStoragePolicy | None = None) -> None:
        self._database = database
        self.policy = policy or AssessmentStoragePolicy()

    def save(self, key: RiskAssessmentKey, snapshot: AssessmentSnapshot, assessed_at: datetime) -> AssessmentSave:
        # Validate and encode before opening the transaction.
        RiskAssessmentRevision(key, 1, assessed_at, snapshot)
        identity, payload = canonical_json(key), canonical_json(snapshot)
        fingerprint = snapshot.content_fingerprint
        try:
            with self._database.connection() as connection, transaction(connection):
                parent = connection.execute(
                    "SELECT identity_payload, original_observed_at, last_revision FROM risk_assessments WHERE assessment_id = ?",
                    (key.assessment_id,),
                ).fetchone()
                if parent is not None:
                    if parent[0] != identity or parent[1] != key.original_observed_at.isoformat(timespec="microseconds"):
                        raise AssessmentIdentityConflict("Stored assessment identity is inconsistent.")
                    if type(parent[2]) is not int or not 1 <= parent[2] < 2**63 - 1:
                        raise AssessmentPersistenceError("Stored assessment revision counter is invalid.")
                    duplicate = connection.execute(
                        _SELECT + "WHERE r.assessment_id = ? AND r.content_fingerprint = ? LIMIT 1",
                        (key.assessment_id, fingerprint),
                    ).fetchone()
                    if duplicate is not None:
                        read = self._decode(connection, duplicate)
                        if read.status is not AssessmentReadStatus.FOUND or read.revision is None:
                            raise AssessmentPersistenceError("Stored duplicate assessment is invalid.")
                        return AssessmentSave(read.revision, False)
                    number = parent[2] + 1
                else:
                    count = connection.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0]
                    if count >= self.policy.max_assessments:
                        self._delete_assessments(connection, min(count - self.policy.max_assessments + 1,
                                                                self.policy.cleanup_chunk_size // self.policy.max_revisions))
                        if connection.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0] >= self.policy.max_assessments:
                            raise AssessmentPersistenceError("Assessment quota requires cleanup.")
                    number = 1
                    connection.execute(
                        "INSERT INTO risk_assessments (assessment_id, original_observed_at, identity_payload, last_revision) VALUES (?, ?, ?, ?)",
                        (key.assessment_id, key.original_observed_at.isoformat(timespec="microseconds"), identity, number),
                    )
                connection.execute(
                    "INSERT INTO risk_assessment_revisions (assessment_id, revision, format_version, assessed_at, content_fingerprint, snapshot) VALUES (?, ?, ?, ?, ?, ?)",
                    (key.assessment_id, number, ASSESSMENT_FORMAT_VERSION, utc_time(assessed_at).isoformat(timespec="microseconds"), fingerprint, payload),
                )
                connection.execute("UPDATE risk_assessments SET last_revision = ? WHERE assessment_id = ?", (number, key.assessment_id))
                # Prune at most one row per normal append; counter never rewinds.
                count = connection.execute("SELECT COUNT(*) FROM risk_assessment_revisions WHERE assessment_id = ?", (key.assessment_id,)).fetchone()[0]
                excess = count - self.policy.max_revisions
                if excess > 0:
                    if excess > self.policy.cleanup_chunk_size:
                        raise AssessmentPersistenceError("Assessment revision quota requires cleanup.")
                    connection.execute(
                        "DELETE FROM risk_assessment_revisions WHERE assessment_id = ? AND revision IN (SELECT revision FROM risk_assessment_revisions WHERE assessment_id = ? ORDER BY revision LIMIT ?)",
                        (key.assessment_id, key.assessment_id, excess),
                    )
            return AssessmentSave(RiskAssessmentRevision(key, number, assessed_at, snapshot), True)
        except (SQLiteAdapterError, sqlite3.Error):
            raise AssessmentPersistenceError("Assessment could not be persisted.") from None

    def latest(self, assessment_id: str) -> AssessmentRead:
        _digest(assessment_id)
        try:
            with self._database.connection() as connection, transaction(connection):
                row = connection.execute(_SELECT + "WHERE r.assessment_id = ? ORDER BY r.revision DESC LIMIT 1", (assessment_id,)).fetchone()
                if row is None:
                    parent = connection.execute("SELECT 1 FROM risk_assessments WHERE assessment_id = ?", (assessment_id,)).fetchone()
                    return AssessmentRead(AssessmentReadStatus.CORRUPT if parent else AssessmentReadStatus.NOT_FOUND)
                return self._decode(connection, row, latest=True)
        except (SQLiteAdapterError, sqlite3.Error):
            return AssessmentRead(AssessmentReadStatus.UNAVAILABLE)

    def history(self, assessment_id: str, *, limit: int = 8) -> AssessmentHistory:
        _digest(assessment_id)
        if type(limit) is not int or not 1 <= limit <= self.policy.max_revisions:
            raise ValueError("assessment history limit exceeds quota")
        try:
            with self._database.connection() as connection, transaction(connection):
                rows = connection.execute(_SELECT + "WHERE r.assessment_id = ? ORDER BY r.revision DESC LIMIT ?", (assessment_id, limit + 1)).fetchall()
                if not rows:
                    parent = connection.execute("SELECT 1 FROM risk_assessments WHERE assessment_id = ?", (assessment_id,)).fetchone()
                    return AssessmentHistory(AssessmentReadStatus.CORRUPT if parent else AssessmentReadStatus.NOT_FOUND)
                entries = tuple(self._decode(connection, row, latest=(i == 0)) for i, row in enumerate(rows[:limit]))
                # Missing older numbers also represent pruned history.
                oldest = rows[-1]["revision"]
                truncated = len(rows) > limit or type(oldest) is not int or oldest > 1
                return AssessmentHistory(AssessmentReadStatus.FOUND, entries, truncated)
        except (SQLiteAdapterError, sqlite3.Error):
            return AssessmentHistory(AssessmentReadStatus.UNAVAILABLE)

    def _decode(self, connection: sqlite3.Connection, row: sqlite3.Row, *, latest: bool = False) -> AssessmentRead:
        try:
            if type(row["format_version"]) is not int or row["format_version"] < 1:
                raise ValueError("invalid format version")
            if row["format_version"] != ASSESSMENT_FORMAT_VERSION:
                return AssessmentRead(AssessmentReadStatus.UNSUPPORTED_VERSION)
            key = decode_value(row["identity_payload"], RiskAssessmentKey, MAX_ASSESSMENT_KEY_BYTES)
            snapshot = decode_value(row["snapshot"], AssessmentSnapshot, MAX_ASSESSMENT_PAYLOAD_BYTES)
            if key.assessment_id != row["assessment_id"] or key.original_observed_at.isoformat(timespec="microseconds") != row["original_observed_at"] or snapshot.content_fingerprint != row["content_fingerprint"]:
                raise ValueError("snapshot identity/integrity mismatch")
            if type(row["last_revision"]) is not int or row["last_revision"] < row["revision"] or (latest and row["last_revision"] != row["revision"]):
                raise ValueError("inconsistent revision counter")
            revision = RiskAssessmentRevision(key, row["revision"], datetime.fromisoformat(row["assessed_at"]), snapshot)
            refs = {key.observation_reference}
            refs.update(r for e in snapshot.evidence for r in e.references)
            states = tuple(AssessmentReferenceState(r, self._source_status(connection, r)) for r in sorted(refs, key=lambda r: (r.kind.value, str(r.value))))
            return AssessmentRead(AssessmentReadStatus.FOUND, revision, states)
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError, AttributeError):
            return AssessmentRead(AssessmentReadStatus.CORRUPT)

    @staticmethod
    def _source_status(connection: sqlite3.Connection, reference: EvidenceReference) -> AssessmentSourceStatus:
        # Supported canonical source stores only. Absence cannot distinguish
        # retention from a source that failed to persist; do not invent either.
        if reference.kind is EvidenceReferenceKind.DNS_EVIDENCE:
            query = "SELECT 1 FROM dns_history WHERE evidence_id = ? LIMIT 1"
        elif reference.kind is EvidenceReferenceKind.CONNECTION_LIFECYCLE:
            query = "SELECT 1 FROM connection_history WHERE lifecycle_id = ? LIMIT 1"
        elif reference.kind is EvidenceReferenceKind.MONITORING_SESSION:
            query = "SELECT 1 FROM connection_history WHERE monitoring_session_id = ? LIMIT 1"
        else:
            return AssessmentSourceStatus.UNRESOLVED
        row = connection.execute(query, (str(reference.value),)).fetchone()
        return AssessmentSourceStatus.AVAILABLE if row else AssessmentSourceStatus.SOURCE_EXPIRED_OR_UNAVAILABLE

    def _delete_assessments(self, connection: sqlite3.Connection, limit: int, cutoff: str | None = None) -> int:
        rows = connection.execute(
            "SELECT assessment_id FROM risk_assessments WHERE (? IS NULL OR original_observed_at <= ?) ORDER BY original_observed_at, assessment_id LIMIT ?",
            (cutoff, cutoff, limit),
        ).fetchall()
        deleted = 0
        for row in rows:
            count = connection.execute("SELECT COUNT(*) FROM risk_assessment_revisions WHERE assessment_id = ?", (row[0],)).fetchone()[0]
            if deleted + count > self.policy.cleanup_chunk_size:
                break
            connection.execute("DELETE FROM risk_assessments WHERE assessment_id = ?", (row[0],))
            deleted += count
        return deleted

    def cleanup(self, now: datetime) -> int:
        now = utc_time(now)
        cutoff = (now - timedelta(days=self.policy.retention_days)).isoformat(timespec="microseconds")
        try:
            with self._database.connection() as connection, transaction(connection):
                return self._delete_assessments(connection, self.policy.cleanup_chunk_size // self.policy.max_revisions, cutoff)
        except (SQLiteAdapterError, sqlite3.Error):
            raise AssessmentPersistenceError("Assessment cleanup could not be completed.") from None
