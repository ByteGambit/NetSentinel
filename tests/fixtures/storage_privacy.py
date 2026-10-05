"""Synthetic NS-095 storage fixtures; no user data or live traffic."""

from datetime import UTC, datetime
from uuid import UUID

from netsentinel.infrastructure.sqlite.repositories import datetime_to_epoch_microseconds as us

NOW = datetime(2026, 10, 6, 10, 0, 0, 123456, tzinfo=UTC)


def connection(database, number, at, *, active=False, gap=False):
    identity = str(UUID(int=number))
    stamp = us(at)
    with database.connection() as c:
        c.execute("INSERT INTO connection_history(id,protocol,local_address,local_port,remote_address,remote_port,process_status,connection_state,first_seen_utc_us,last_seen_utc_us,closed_at_utc_us,close_reason,lifecycle_id,monitoring_session_id,observation_gap) "
                  "VALUES(?,'tcp','192.0.2.123',5000,'203.0.113.123',443,'unavailable','established',?,?,?,?,?,?,?)",
                  (identity, stamp, stamp, None if active else stamp,
                   None if active else 'not_observed', identity, str(UUID(int=1000)), int(gap)))
    return identity


def dns(database, number, at):
    identity = str(UUID(int=number))
    stamp = us(at)
    with database.connection() as c:
        c.execute("INSERT INTO dns_history(id,status,network_fingerprint,transport,client_ip,client_port,server_ip,server_port,transaction_id,questions_json,query_at_utc_us,event_at_utc_us,truncated,answers_json,retry_count,evidence_id,qname) "
                  "VALUES(?,'timed_out',?,'udp','192.0.2.123',5000,'192.0.2.53',53,1,'[]',?,?,0,'[]',0,?,'private.example')",
                  (identity, "a" * 64, stamp, stamp, identity))
    return identity


def alert(database, number, at, *, state='open', assessment=None):
    from dataclasses import replace
    from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
    from datetime import timedelta
    from tests.fixtures.notifications import candidate

    value = candidate(number)
    value = replace(value, evidence=replace(value.evidence, observed_at=at, assessment=assessment))
    record, _ = SQLiteAlertRepository(database).record(value, at, timedelta(seconds=120))
    with database.connection() as c:
        c.execute("UPDATE alerts SET status = ? WHERE id = ?", (state, str(record.id)))
    return record


def count(database, table):
    with database.connection() as c:
        return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
