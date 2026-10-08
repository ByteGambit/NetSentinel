"""NS-100 review preflight. No firewall executor, elevation, persistence or UI."""

from datetime import datetime

from netsentinel.application.ports import ResponsePrivilegeProbe
from netsentinel.domain.connections import ObservationQuality
from netsentinel.domain.response import (
    ResponseAction, ResponseCommand, ResponseConfirmation, ResponseOutcome, ResponsePrivilegeAssessment,
    ResponsePrivilegeStatus, ResponseReason, ResponseResult, ResponseSourceStatus, confirmation_matches,
)


class ResponseContractReview:
    """One injected read-only assessment, after an exact local confirmation.

    REVALIDATION_REQUIRED is not permission to write. A future trusted component
    must independently validate intent, local target, ownership and durable audit.
    This review neither authenticates a caller nor dispatches a response command.
    """

    def __init__(self, privilege: ResponsePrivilegeProbe) -> None:
        self._privilege = privilege

    def review(self, command: ResponseCommand, confirmation: ResponseConfirmation | None,
               now: datetime) -> ResponseResult:
        if type(command) is not ResponseCommand:
            raise TypeError("response review requires an exact typed command")
        reason = ResponseReason.CONFIRMATION_REQUIRED
        if confirmation is not None:
            if not confirmation_matches(command, confirmation, now):
                reason = ResponseReason.STALE_CONFIRMATION
            elif command.action is ResponseAction.CREATE and (
                command.source.status is not ResponseSourceStatus.AVAILABLE
                or command.source.quality is ObservationQuality.FAILED
            ):
                reason = ResponseReason.TARGET_UNAVAILABLE
            else:
                try:
                    assessment = self._privilege.assess(command)
                    if type(assessment) is not ResponsePrivilegeAssessment:
                        reason = ResponseReason.BOUNDARY_UNAVAILABLE
                    else:
                        reason = ResponseReason(assessment.status.value)
                except Exception:
                    # A failed probe is not a write grant; raw exception stays private.
                    reason = ResponseReason.BOUNDARY_UNAVAILABLE
        return ResponseResult(command.command_id, command.action, ResponseOutcome.NOT_ATTEMPTED, reason)


class UnavailableResponsePrivilege:
    """Default fail-closed boundary. No OS probe or UAC; not wired into startup."""

    def assess(self, command: ResponseCommand) -> ResponsePrivilegeAssessment:
        if type(command) is not ResponseCommand:
            raise TypeError("privilege review requires an exact typed command")
        return ResponsePrivilegeAssessment(ResponsePrivilegeStatus.BOUNDARY_UNAVAILABLE)
