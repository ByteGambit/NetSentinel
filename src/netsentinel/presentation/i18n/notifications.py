"""Translate the privacy-approved semantic notification at submission time."""

from netsentinel.application.services.notifications import DesktopNotificationRequest
from netsentinel.domain.risk_scoring import RiskSeverity
from netsentinel.presentation.i18n.text import translate


def notification_text(request: DesktopNotificationRequest) -> tuple[str, str]:
    body = {
        RiskSeverity.LOW: translate('Notifications', 'Low severity network security alert detected. Open NetSentinel to review details.'),
        RiskSeverity.MEDIUM: translate('Notifications', 'Medium severity network security alert detected. Open NetSentinel to review details.'),
        RiskSeverity.HIGH: translate('Notifications', 'High severity network security alert detected. Open NetSentinel to review details.'),
        RiskSeverity.INFO: translate('Notifications', 'Info severity network security alert detected. Open NetSentinel to review details.'),
    }[request.severity]
    return translate('Notifications', 'NetSentinel security alert'), body
