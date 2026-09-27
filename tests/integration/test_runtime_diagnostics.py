"""NS-047 startup config through dormant components and real temporary SQLite."""

from netsentinel.bootstrap import (
    collect_diagnostics, create_desktop_engine, create_dns_history_writer,
    create_monitoring_engine, create_packet_capture,
)
from netsentinel.shared.config import load_config_values
from netsentinel.shared.diagnostics import DatabaseStatus, EngineState


class NoNetworkProvider:
    def get_contexts(self):
        raise AssertionError("configuration must not inspect a live network")


def test_configured_dormant_capture_and_real_database_diagnostics(tmp_path):
    config = load_config_values({"capture_queue_capacity": 7, "polling_interval": 0.2}).config
    capture = create_packet_capture(context_provider=NoNetworkProvider(), config=config)
    engine = create_monitoring_engine(config=config)
    db_path = tmp_path / "runtime.sqlite3"
    snapshot = collect_diagnostics(engine, capture=capture, database_path=db_path)
    assert snapshot.engine.state is EngineState.STOPPED
    assert snapshot.capture.queue_capacity == 7
    assert snapshot.database.status is DatabaseStatus.AVAILABLE
    assert snapshot.database.history_rows == 0
    assert not snapshot.capture.worker_alive
    db_path.unlink()  # The diagnostics connection was closed on Windows too.


def test_config_reaches_existing_history_and_dns_queues_without_starting_them(tmp_path):
    config = load_config_values({
        "history_queue_capacity": 9, "history_batch_size": 8,
        "dns_queue_capacity": 11, "dns_batch_size": 8,
    }).config
    engine = create_desktop_engine(config=config, database_path=tmp_path / "history.sqlite3")
    dns = create_dns_history_writer(config=config, database_path=tmp_path / "dns.sqlite3")
    assert engine.persistence_health_snapshot().queue_capacity == 9
    assert dns.health_snapshot().queue_capacity == 11
    assert not (tmp_path / "history.sqlite3").exists()
    assert not (tmp_path / "dns.sqlite3").exists()
