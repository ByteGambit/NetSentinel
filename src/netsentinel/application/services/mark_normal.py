"""NS-082 immutable preview and explicit worker-owned local preference commands."""

from dataclasses import dataclass, field, replace
from datetime import datetime
from uuid import UUID, uuid4

from netsentinel.application.services.baseline_detail import BaselineDetailRequest
from netsentinel.application.services.preferences import ScopedPreferenceService
from netsentinel.domain.application_identity import ApplicationIdentityQuality
from netsentinel.domain.preferences import (
    DestinationKind, PreferenceDefinition, PreferenceDestination, PreferenceLifetime,
    PreferenceMatchContext, PreferenceOrigin, PreferencePage, PreferenceResult,
    PreferenceResultStatus, PreferenceSelector, ScopedPreference,
)
from netsentinel.domain.risk_evidence import EvidenceScope, EvidenceSubject, EvidenceSubjectKind

BEHAVIOR_RULES = (
    ("destination_ip_novelty_rarity", "Destination novelty / rarity"),
    ("observed_appearance_frequency", "Observed appearance frequency"),
    ("destination_window_diversity", "Destination window diversity"),
    ("observed_appearance_periodicity", "Observed appearance periodicity"),
)
EFFECT_TEXT = (
    "This preference suppresses future matching alert/notification eligibility for the selected "
    "behavior scope while active. It does not declare the application safe, delete evidence, "
    "change historical risk scores, reset the baseline, or modify the firewall. "
    "The current alert remains unchanged. Expiry/revoke does not replay past suppressed signals."
)


@dataclass(frozen=True, slots=True)
class BehaviorPreferenceContext:
    match: PreferenceMatchContext = field(repr=False)
    display_name: str = field(repr=False)
    network_text: str = field(repr=False)


def behavior_context(request: BaselineDetailRequest, rule_id: str) -> BehaviorPreferenceContext:
    if rule_id not in dict(BEHAVIOR_RULES):
        raise ValueError("Select a supported behavior rule.")
    app = request.application
    if app.identity.quality is not ApplicationIdentityQuality.STABLE:
        raise ValueError("Stable application identity unavailable; PID/name/provisional identity cannot persist.")
    subject = EvidenceSubject(EvidenceSubjectKind.APPLICATION, application=app.identity,
                              revision=app.revision, ip_address=request.remote_ip)
    scope = EvidenceScope.from_connection(request.network)
    network = request.network
    description = f"{network.status.value}; {network.fingerprint or 'no resolved fingerprint'}"
    if network.status.value == "unknown":
        description += "; Current network could not be resolved."
    elif network.status.value == "ambiguous":
        description += "; Current network scope is ambiguous."
    if network.interface_id:
        description += f"; interface {network.interface_id}; index {network.interface_index}"
        description += "; observed context, not a proven physical network or route"
    return BehaviorPreferenceContext(PreferenceMatchContext(rule_id, subject, scope),
                                     request.display_name[:256], description)


def scope_choices(context: BehaviorPreferenceContext) -> tuple[PreferenceSelector, ...]:
    """Narrow first; only explicit progressive broadening, always app AND rule."""
    match = context.match
    subject = match.subject
    if subject.application is None or subject.application.quality is not ApplicationIdentityQuality.STABLE:
        return ()
    destination = None
    if subject.ip_address is not None:
        destination = PreferenceDestination(DestinationKind.IPV6 if ":" in subject.ip_address else
                                            DestinationKind.IPV4, subject.ip_address)
    revision = subject.revision if subject.revision and subject.revision.known else None
    exact = PreferenceSelector(subject.application, revision, destination,
                               match.scope.network_fingerprint, match.rule_id)
    choices = [exact]
    for changes in ({"application_revision": None}, {"network_fingerprint": None}, {"destination": None}):
        value = replace(choices[-1], **changes)
        if value != choices[-1]:
            choices.append(value)
    return tuple(choices)


def selector_text(selector: PreferenceSelector) -> str:
    return "\n".join((
        f"Rule: {selector.rule_id or 'Any'}",
        f"Application identity: {selector.application.key if selector.application else 'Any'}",
        f"Revision: {selector.application_revision.digest if selector.application_revision else 'Any revision (exact binary revision unavailable or explicitly omitted)'}",
        f"Destination: {selector.destination.value if selector.destination else 'Any destination'}",
        f"Network: {selector.network_fingerprint or 'Any network (host-wide for this selected behavior)'}",
    ))


@dataclass(frozen=True, slots=True)
class MarkNormalPreview:
    context: BehaviorPreferenceContext = field(repr=False)
    definition: PreferenceDefinition = field(repr=False)
    preference_id: UUID = field(default_factory=uuid4)

    @property
    def text(self) -> str:
        lifetime = self.definition.lifetime
        expiry = lifetime.expires_at
        warning = ""
        if self.definition.selector != scope_choices(self.context)[0]:
            warning = "\nBroader scope: this can affect more future behavior than the narrow default."
        return (f"Selected behavior for: {self.context.display_name}\n" + selector_text(self.definition.selector)
                + f"\nCurrent network scope: {self.context.network_text}\n"
                + (f"Expires: {expiry.isoformat()} (UTC)" if expiry else "Lifetime: Permanent (explicit choice)")
                + f"\nReason: {self.definition.reason}\n{EFFECT_TEXT}" + warning)


def preview_mark_normal(context: BehaviorPreferenceContext, selector: PreferenceSelector,
                        lifetime: PreferenceLifetime, reason: str, *, now: datetime) -> MarkNormalPreview:
    if selector not in scope_choices(context):
        raise ValueError("Invalid selected behavior scope.")
    if lifetime.expires_at is not None and lifetime.expires_at <= now:
        raise ValueError("Expiry must be in the future.")
    return MarkNormalPreview(context, PreferenceDefinition(selector, lifetime, reason))


class MarkNormalCommandService:
    def __init__(self, preferences: ScopedPreferenceService) -> None:
        self._preferences = preferences

    def relevant(self, context: BehaviorPreferenceContext, *, now: datetime) -> PreferencePage:
        try:
            return self._preferences.find_candidates((context.match,), evaluated_at=now, limit=32)
        except Exception:
            return PreferencePage(PreferenceResultStatus.UNAVAILABLE)

    def save(self, preview: MarkNormalPreview, *, now: datetime) -> PreferenceResult:
        try:
            # Validate the captured scope again; never rebuild from a live selection.
            preview_mark_normal(preview.context, preview.definition.selector,
                                preview.definition.lifetime, preview.definition.reason, now=now)
            return self._preferences.create(preview.definition, origin=PreferenceOrigin.MANUAL_USER,
                                            now=now, preference_id=preview.preference_id, deduplicate=True)
        except (TypeError, ValueError):
            return PreferenceResult(PreferenceResultStatus.INVALID)
        except Exception:
            return PreferenceResult(PreferenceResultStatus.UNAVAILABLE)

    def revoke(self, preference: ScopedPreference, *, now: datetime) -> PreferenceResult:
        try:
            return self._preferences.revoke(preference.preference_id, expected_revision=preference.revision,
                                            reason="User revoked selected behavior preference",
                                            origin=PreferenceOrigin.MANUAL_USER, now=now)
        except Exception:
            return PreferenceResult(PreferenceResultStatus.UNAVAILABLE)
