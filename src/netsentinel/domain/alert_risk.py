"""Small durable assessment pointer; no scoring snapshot or second lifecycle."""

from dataclasses import dataclass
from enum import Enum

from netsentinel.domain.connections import NetworkScopeStatus


class AlertWriteIntent(str, Enum):
    OCCURRENCE = "occurrence"
    REASSESSMENT = "reassessment"


@dataclass(frozen=True, slots=True)
class AlertAssessmentReference:
    assessment_id: str
    revision: int
    network_status: NetworkScopeStatus | None

    def __post_init__(self) -> None:
        if (not isinstance(self.assessment_id, str) or len(self.assessment_id) != 64
                or any(c not in "0123456789abcdef" for c in self.assessment_id)):
            raise ValueError("assessment reference requires a canonical digest")
        if type(self.revision) is not int or not 1 <= self.revision <= 2**63 - 1:
            raise ValueError("assessment revision must be bounded and positive")
        if self.network_status is not None and not isinstance(self.network_status, NetworkScopeStatus):
            raise TypeError("network status must be typed or host-scoped")
