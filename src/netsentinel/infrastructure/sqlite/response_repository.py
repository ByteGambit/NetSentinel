"""NS-102 durable custody. Bounded codecs/queries and short CAS transactions.

The advisory file lock serializes explicit response callers across threads and
processes, is released by the OS on crash, and never holds a SQLite transaction.
Per-user writable custody does NOT authenticate a malicious privileged admin.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
import json
import sqlite3
import sys
from uuid import UUID, uuid4

from netsentinel.domain.response import (
    FirewallRemoveRequest, ResponseAction, ResponseConfirmation,
    ResponseOutcome, ResponseReason, ResponseResult, ResponseRuleState,
    deserialize_owned_firewall_manifest, deserialize_prepared_firewall_claim,
    deserialize_response_command, serialize_owned_firewall_manifest,
    serialize_prepared_firewall_claim, serialize_response_command, _decode_time, _unique,
)
from netsentinel.domain.response_lifecycle import (
    MAX_RESPONSE_ACTIVE_RULES, MAX_RESPONSE_AUDIT_ROWS, MAX_RESPONSE_OPERATIONS,
    MAX_RESPONSE_RECONCILE_BATCH, ResponseAuditEvent, ResponseAuditRecord,
    ResponseLifecycleDiagnostics, ResponseOperation, ResponseOperationConflict,
    ResponseOperationStatus, ResponseReconciliation, ResponseRemovalPurpose, ResponseStorageError,
)
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase, SQLiteAdapterError, transaction


def _time(value: datetime | None) -> str | None:
    return value.isoformat(timespec="microseconds") if value is not None else None


def _payload(value: object, limit: int) -> bytes:
    result = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not 1 <= len(result) <= limit:
        raise ResponseStorageError("Response payload exceeds storage bound.")
    return result


def _load(value: object, limit: int) -> object:
    if type(value) is not bytes or not 1 <= len(value) <= limit:
        raise ValueError("invalid bounded response payload")
    return json.loads(value.decode("utf-8"), object_pairs_hook=_unique)


def _request_payload(operation: ResponseOperation) -> bytes:
    if operation.claim is not None:
        return serialize_prepared_firewall_claim(operation.claim)
    request = operation.request
    if type(request) is not FirewallRemoveRequest:
        raise ValueError("missing removal provenance")
    return _payload({
        "version": 1, "command": json.loads(serialize_response_command(request.command)),
        "confirmation": {"fingerprint": request.confirmation.command_fingerprint,
                         "confirmed_at": _time(request.confirmation.confirmed_at)},
        "manifest": json.loads(serialize_owned_firewall_manifest(request.manifest)),
    }, 32768)


def _decode_request(payload: bytes, action: ResponseAction):
    if action is ResponseAction.CREATE:
        claim = deserialize_prepared_firewall_claim(payload)
        return claim.creation, claim
    values = _load(payload, 32768)
    if type(values) is not dict or set(values) != {"version", "command", "confirmation", "manifest"} or values["version"] != 1:
        raise ValueError("invalid removal payload")
    confirmation = values["confirmation"]
    if type(confirmation) is not dict or set(confirmation) != {"fingerprint", "confirmed_at"}:
        raise ValueError("invalid removal confirmation")
    request = FirewallRemoveRequest(
        deserialize_response_command(_payload(values["command"], 16384)),
        ResponseConfirmation(confirmation["fingerprint"], _decode_time(confirmation["confirmed_at"])),
        deserialize_owned_firewall_manifest(_payload(values["manifest"], 16384)),
    )
    return request, None


def _result_payload(result: ResponseResult | None) -> bytes | None:
    return (_payload({"outcome": result.outcome.value, "reason": result.reason.value,
                      "rule_state": result.rule_state.value}, 512) if result is not None else None)


# SQLite bounds before Python materialization, including corrupt/hostile DB rows.
_SELECT = """SELECT
CASE WHEN length(operation_id)=36 THEN operation_id END AS operation_id,
CASE WHEN length(rule_id)=36 THEN rule_id END AS rule_id,
CASE WHEN length(action)<=6 THEN action END AS action,
CASE WHEN length(fingerprint)=64 THEN fingerprint END AS fingerprint,
CASE WHEN typeof(request)='blob' AND length(request) BETWEEN 1 AND 32768 THEN request END AS request,
CASE WHEN typeof(manifest)='blob' AND length(manifest) BETWEEN 1 AND 16384 THEN manifest END AS manifest,
manifest IS NOT NULL AS has_manifest,
CASE WHEN length(witness)=64 THEN witness END AS witness,
CASE WHEN length(lifetime)<=32 THEN lifetime END AS lifetime,
CASE WHEN length(status)<=32 THEN status END AS status,
CASE WHEN length(reconciliation)<=32 THEN reconciliation END AS reconciliation,
CASE WHEN typeof(result)='blob' AND length(result) BETWEEN 1 AND 512 THEN result END AS result,
result IS NOT NULL AS has_result,
CASE WHEN length(updated_at)<=40 THEN updated_at END AS updated_at,
CASE WHEN attempt_at IS NULL OR length(attempt_at)<=40 THEN attempt_at END AS attempt_at,
CASE WHEN reconciled_at IS NULL OR length(reconciled_at)<=40 THEN reconciled_at END AS reconciled_at,
CASE WHEN expires_at IS NULL OR length(expires_at)<=40 THEN expires_at END AS expires_at,
CASE WHEN length(purpose)<=8 THEN purpose END AS purpose,
revision FROM response_operations"""


class SQLiteResponseLifecycleRepository:
    def __init__(self, database: SQLiteDatabase, store_id: UUID | None = None) -> None:
        if store_id is not None and (type(store_id) is not UUID or store_id.int == 0):
            raise ValueError("response store requires exact nonzero UUID")
        self._database = database
        try:
            with database.connection() as connection, transaction(connection):
                row = connection.execute("""SELECT CASE WHEN length(store_id)=36 THEN store_id END AS store_id
                    FROM response_store WHERE singleton=1""").fetchone()
                if row is None:
                    if (connection.execute("SELECT count(*) FROM response_operations").fetchone()[0]
                            or connection.execute("SELECT count(*) FROM response_store").fetchone()[0]):
                        raise ResponseStorageError("Response custody has no valid store identity.")
                    self._store_id = store_id if store_id is not None else uuid4()
                    connection.execute("INSERT INTO response_store VALUES (1, ?)", (str(self.store_id),))
                else:
                    persisted = UUID(row["store_id"])
                    if persisted.int == 0 or str(persisted) != row["store_id"]:
                        raise ValueError("invalid response store identity")
                    self._store_id = persisted
                if store_id is not None and self._store_id != store_id:
                    raise ResponseOperationConflict("Response store identity mismatch.")
        except (sqlite3.Error, SQLiteAdapterError, ValueError, TypeError, AttributeError):
            raise ResponseStorageError("Response storage unavailable.") from None

    @property
    def store_id(self) -> UUID:
        return self._store_id

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        # One fixed lock per database, not an unbounded global lock registry.
        path = self._database.path.with_suffix(self._database.path.suffix + ".response.lock")
        try:
            lock_file = path.open("a+b")
        except OSError:
            raise ResponseStorageError("Response coordination unavailable.") from None
        locked = False
        try:
            lock_file.seek(0)
            if sys.platform == "win32":
                import msvcrt
                if path.stat().st_size == 0:
                    lock_file.write(b"\0")
                    lock_file.flush()
                lock_file.seek(0)
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise ResponseOperationConflict("Response store is busy.") from None
            else:
                import fcntl
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise ResponseOperationConflict("Response store is busy.") from None
            locked = True
            self._validate_custody()
            yield
        finally:
            if locked:
                if sys.platform == "win32":
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()

    def _validate_custody(self) -> None:
        """Fail closed for corrupt retained custody before ANY coordinator call.

        Admission bounds total operations; decode in64-row SQL pages outside
        a write transaction. An unrelated new command cannot bypass a corrupt
        pending/ownership record. Audit is not ownership authority.
        """
        with self._connection() as connection:
            count = connection.execute("SELECT count(*) FROM response_operations").fetchone()[0]
            if count > MAX_RESPONSE_OPERATIONS:
                raise ResponseStorageError("Response custody capacity is invalid.")
            cursor = ""
            for _ in range(MAX_RESPONSE_OPERATIONS // MAX_RESPONSE_RECONCILE_BATCH + 1):
                rows = connection.execute(_SELECT + " WHERE operation_id>? ORDER BY operation_id LIMIT ?",
                    (cursor, MAX_RESPONSE_RECONCILE_BATCH)).fetchall()
                if not rows:
                    return
                for row in rows:
                    self._decode(row)
                cursor = rows[-1]["operation_id"]
                if len(rows) < MAX_RESPONSE_RECONCILE_BATCH:
                    return
            raise ResponseStorageError("Response custody scan exceeds bound.")

    def _decode(self, row: sqlite3.Row) -> ResponseOperation:
        if type(row["revision"]) is not int or row["revision"] < 1:
            raise ValueError("invalid durable response revision")
        action = ResponseAction(row["action"])
        request, claim = _decode_request(row["request"], action)
        manifest = deserialize_owned_firewall_manifest(row["manifest"]) if row["has_manifest"] else None
        result = None
        if row["has_result"]:
            values = _load(row["result"], 512)
            if type(values) is not dict or set(values) != {"outcome", "reason", "rule_state"}:
                raise ValueError("invalid durable outcome")
            result = ResponseResult(request.command.command_id, action, ResponseOutcome(values["outcome"]),
                                    ResponseReason(values["reason"]), ResponseRuleState(values["rule_state"]))
        operation = ResponseOperation(
            request, claim, manifest, ResponseOperationStatus(row["status"]), ResponseReconciliation(row["reconciliation"]),
            result, _decode_time(row["updated_at"]),
            _decode_time(row["attempt_at"]) if row["attempt_at"] is not None else None,
            _decode_time(row["reconciled_at"]) if row["reconciled_at"] is not None else None,
            _decode_time(row["expires_at"]) if row["expires_at"] is not None else None,
            ResponseRemovalPurpose(row["purpose"]), row["revision"],
        )
        if (row["operation_id"] != str(operation.operation_id) or row["rule_id"] != str(operation.command.rule_id)
                or row["fingerprint"] != operation.command.fingerprint
                or operation.command.origin_store_id != self.store_id
                or row["witness"] != (claim.witness if claim is not None else None)
                or row["lifetime"] != operation.command.spec.lifetime.kind.value):
            raise ValueError("durable response summaries disagree")
        return operation

    @contextmanager
    def _connection(self):
        try:
            with self._database.connection() as connection:
                row = connection.execute("SELECT store_id FROM response_store WHERE singleton=1").fetchone()
                if row is None or row["store_id"] != str(self.store_id):
                    raise ResponseOperationConflict("Response store identity mismatch.")
                yield connection
        except ResponseStorageError:
            raise
        except (sqlite3.Error, SQLiteAdapterError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise ResponseStorageError("Response storage unavailable or invalid.") from None

    def get(self, operation_id: UUID) -> ResponseOperation | None:
        if type(operation_id) is not UUID:
            raise TypeError("exact operation UUID required")
        with self._connection() as connection:
            row = connection.execute(_SELECT + " WHERE operation_id=?", (str(operation_id),)).fetchone()
            return self._decode(row) if row is not None else None

    def has_verified_removal(self, rule_id: UUID) -> bool:
        if type(rule_id) is not UUID:
            raise TypeError("exact rule UUID required")
        with self._connection() as connection:
            return self._verified_removal(connection, rule_id)

    def _verified_removal(self, connection: sqlite3.Connection, rule_id: UUID) -> bool:
        # Validate the complete durable OS receipt, rather than trust a summary
        # bit. This tombstone also covers the OS_VERIFIED finalization crash gap.
        row = connection.execute(_SELECT + """ WHERE rule_id=? AND action='remove'
            AND status IN ('verified','os_verified')
            ORDER BY updated_at DESC,operation_id DESC LIMIT 1""", (str(rule_id),)).fetchone()
        if row is None:
            return False
        record = self._decode(row)
        return record.result is not None and record.result.outcome is ResponseOutcome.VERIFIED

    def page(self, *, after: UUID | None = None, limit: int = 64) -> tuple[ResponseOperation, ...]:
        if type(limit) is not int or not 1 <= limit <= MAX_RESPONSE_RECONCILE_BATCH:
            raise ValueError("invalid reconciliation page bound")
        if after is not None and type(after) is not UUID:
            raise TypeError("exact operation cursor required")
        with self._connection() as connection:
            rows = connection.execute(_SELECT + " WHERE operation_id>? ORDER BY operation_id LIMIT ?",
                                      (str(after) if after is not None else "", limit)).fetchall()
            return tuple(self._decode(row) for row in rows)

    def save(self, operation: ResponseOperation, event: ResponseAuditEvent) -> ResponseOperation:
        if type(operation) is not ResponseOperation or type(event) is not ResponseAuditEvent:
            raise TypeError("exact lifecycle transition required")
        if operation.command.origin_store_id != self.store_id:
            raise ResponseOperationConflict("Response store identity mismatch.")
        request = _request_payload(operation)
        manifest = serialize_owned_firewall_manifest(operation.manifest) if operation.manifest is not None else None
        with self._connection() as connection, transaction(connection):
            row = connection.execute(_SELECT + " WHERE operation_id=?", (str(operation.operation_id),)).fetchone()
            old = self._decode(row) if row is not None else None
            if old is not None:
                if (old.revision != operation.revision or old.request != operation.request or old.claim != operation.claim
                        or old.purpose != operation.purpose or old.expires_at != operation.expires_at
                        or (old.manifest is not None and old.manifest != operation.manifest)):
                    raise ResponseOperationConflict("Response operation revision or provenance conflict.")
            else:
                if operation.revision != 0 or operation.status is not ResponseOperationStatus.PREPARED:
                    raise ResponseOperationConflict("Response operation must begin with durable intent.")
                if operation.result is not None or operation.attempt_at is not None or operation.reconciled_at is not None:
                    raise ResponseOperationConflict("Response operation cannot start with completion evidence.")
                count = connection.execute("SELECT count(*) FROM response_operations").fetchone()[0]
                if count >= MAX_RESPONSE_OPERATIONS:
                    raise ResponseOperationConflict("Response operation capacity reached.")
                if operation.command.action is ResponseAction.CREATE:
                    if operation.manifest is not None:
                        raise ResponseOperationConflict("PREPARED cannot start with finalized ownership.")
                    active = connection.execute("""SELECT count(*) FROM response_operations
                        WHERE action='create' AND reconciliation NOT IN ('removed','not_materialized')""").fetchone()[0]
                    if active >= MAX_RESPONSE_ACTIVE_RULES:
                        raise ResponseOperationConflict("Response ownership capacity reached.")
                    # Reserve at least one future confirmed cleanup operation
                    # per installed/unresolved rule, including this new CREATE.
                    # Bounded history must not admit the last CREATE at the cost
                    # of all remaining Undo/rollback admission capacity.
                    if count + active + 2 > MAX_RESPONSE_OPERATIONS:
                        raise ResponseOperationConflict("Response cleanup operation capacity must be reserved.")
                else:
                    creator = connection.execute(_SELECT + " WHERE operation_id=? AND action='create'",
                                                 (str(operation.command.rule_id),)).fetchone()
                    if creator is None or self._decode(creator).manifest != operation.manifest:
                        raise ResponseOperationConflict("REMOVE requires this store's finalized ownership.")
                    if self._verified_removal(connection, operation.command.rule_id):
                        raise ResponseOperationConflict("Finalized removal makes this ownership archival.")
                    other_cleanup_reservations = connection.execute("""SELECT count(*)
                        FROM response_operations creation
                        WHERE creation.action='create' AND creation.rule_id!=?
                          AND creation.reconciliation NOT IN ('removed','not_materialized')
                          AND NOT EXISTS (SELECT 1 FROM response_operations removal
                              WHERE removal.action='remove' AND removal.rule_id=creation.rule_id)""",
                        (str(operation.command.rule_id),)).fetchone()[0]
                    if count + 1 + other_cleanup_reservations > MAX_RESPONSE_OPERATIONS:
                        raise ResponseOperationConflict("Other rules' first cleanup capacity must be reserved.")
            next_operation = replace(operation, revision=operation.revision + 1)
            values = (
                str(operation.command.rule_id), operation.command.action.value, operation.command.fingerprint, request,
                manifest, operation.claim.witness if operation.claim is not None else None,
                operation.command.spec.lifetime.kind.value, operation.status.value, operation.reconciliation.value,
                _result_payload(operation.result), _time(operation.updated_at), _time(operation.attempt_at),
                _time(operation.reconciled_at), _time(operation.expires_at), operation.purpose.value,
                next_operation.revision, str(operation.operation_id),
            )
            if old is None:
                connection.execute("""INSERT INTO response_operations
                    (rule_id,action,fingerprint,request,manifest,witness,lifetime,status,reconciliation,result,
                    updated_at,attempt_at,reconciled_at,expires_at,purpose,revision,operation_id)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", values)
            else:
                connection.execute("""UPDATE response_operations SET rule_id=?,action=?,fingerprint=?,request=?,
                    manifest=?,witness=?,lifetime=?,status=?,reconciliation=?,result=?,updated_at=?,attempt_at=?,
                    reconciled_at=?,expires_at=?,purpose=?,revision=? WHERE operation_id=?""", values)
            connection.execute("""INSERT INTO response_audit
                (operation_id,rule_id,action,at,event,status,reconciliation,outcome) VALUES (?,?,?,?,?,?,?,?)""",
                (str(operation.operation_id), str(operation.command.rule_id), operation.command.action.value,
                 _time(operation.updated_at), event.value, operation.status.value, operation.reconciliation.value,
                 operation.result.outcome.value if operation.result is not None else None))
            # Ownership and idempotency records are NEVER pruned with audit.
            connection.execute("""DELETE FROM response_audit WHERE sequence IN
                (SELECT sequence FROM response_audit ORDER BY sequence DESC LIMIT -1 OFFSET ?)""",
                (MAX_RESPONSE_AUDIT_ROWS,))
            return next_operation

    def audit(self, *, after_sequence: int = 0, limit: int = 100) -> tuple[ResponseAuditRecord, ...]:
        if type(after_sequence) is not int or after_sequence < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid response audit page")
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM response_audit WHERE sequence>? ORDER BY sequence LIMIT ?",
                                      (after_sequence, limit)).fetchall()
            return tuple(ResponseAuditRecord(
                row["sequence"], UUID(row["operation_id"]), UUID(row["rule_id"]), ResponseAction(row["action"]),
                _decode_time(row["at"]), ResponseAuditEvent(row["event"]), ResponseOperationStatus(row["status"]),
                ResponseReconciliation(row["reconciliation"]),
                ResponseOutcome(row["outcome"]) if row["outcome"] is not None else None,
            ) for row in rows)

    def diagnostics(self) -> ResponseLifecycleDiagnostics:
        with self._connection() as connection:
            row = connection.execute("""SELECT
                count(CASE WHEN action='create' AND manifest IS NOT NULL
                    AND reconciliation IN ('exact','promoted') AND NOT EXISTS (
                        SELECT 1 FROM response_operations removal
                        WHERE removal.rule_id=response_operations.rule_id AND removal.action='remove'
                        AND removal.status IN ('verified','os_verified')) THEN 1 END) AS owned,
                count(CASE WHEN status IN ('prepared','attempt','os_verified') THEN 1 END) AS pending,
                count(CASE WHEN status IN ('partial','unknown') THEN 1 END) AS unknown,
                count(DISTINCT CASE WHEN reconciliation IN ('external_missing','external_modified','externally_disabled')
                    THEN rule_id END) AS drift,
                count(CASE WHEN purpose='expiry' AND status!='verified' THEN 1 END) AS expiry,
                count(CASE WHEN reconciled_at IS NOT NULL AND reconciliation='unknown' THEN 1 END) AS errors
                FROM response_operations""").fetchone()
            last = connection.execute("""SELECT reconciled_at,reconciliation FROM response_operations
                WHERE reconciled_at IS NOT NULL ORDER BY reconciled_at DESC,operation_id DESC LIMIT 1""").fetchone()
            return ResponseLifecycleDiagnostics(row["owned"], row["pending"], row["unknown"], row["drift"], row["expiry"],
                _decode_time(last["reconciled_at"]) if last is not None else None,
                ResponseReconciliation(last["reconciliation"]) if last is not None else None, row["errors"])
