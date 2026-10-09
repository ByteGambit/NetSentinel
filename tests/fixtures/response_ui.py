"""Synthetic NS-103 fixtures. Native firewall APIs are never constructed."""

from netsentinel.application.services.response_ui import ResponseSelection, ResponseUiService
from tests.integration.test_response_lifecycle import setup, another_create  # noqa: F401
from tests.unit.domain.test_response import command


def selection():
    c = command()
    return ResponseSelection(c.spec.program_path, c.spec.remote_ip, c.spec.transport.value,
                             c.spec.remote_port, c.source)


def ui_service(environment):
    _, repo, _, clock, lifecycle = environment
    return ResponseUiService(repo, lifecycle=lifecycle, file_identity=lambda _: command().file_identity, clock=clock)
