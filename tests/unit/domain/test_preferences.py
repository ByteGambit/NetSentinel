"""NS-080 selector, lifetime and immutable audit contract acceptance."""

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta, timezone
from uuid import uuid4

import pytest

from netsentinel.domain.application_identity import ApplicationIdentity, ApplicationIdentityEvidence, ApplicationIdentityQuality
from netsentinel.domain.connections import NetworkScopeStatus, ProcessInfoStatus
from netsentinel.domain.preferences import (
    MAX_PREFERENCE_REASON, DestinationKind, PreferenceAuditAction,
    PreferenceDestination, PreferenceLifetime, PreferenceLifetimeKind, PreferenceSelector,
    PreferenceStatus, PreferenceStoragePolicy, ScopedPreference, selector_matches,
)
from tests.fixtures.preferences import NOW, ORIGIN, FP, RULE, application, context, definition, destination, revision


@pytest.mark.parametrize("selector", [
    PreferenceSelector(application=application()),
    PreferenceSelector(destination=destination()),
    PreferenceSelector(network_fingerprint=FP),
    PreferenceSelector(rule_id=RULE),
    PreferenceSelector(application=application(), destination=destination()),
    PreferenceSelector(application=application(), network_fingerprint=FP),
    PreferenceSelector(application=application(), application_revision=revision(), destination=destination(), network_fingerprint=FP, rule_id=RULE),
])
def test_all_dimensions_and_combinations_match(selector):
    assert selector_matches(selector, context(rev=revision()))


@pytest.mark.parametrize("changed", [
    {"app": application("c:\\other\\browser.exe")}, {"rev": revision("c" * 64)},
    {"rev": revision(None)}, {"rev": None}, {"ip": "203.0.113.11"},
    {"ip": "::ffff:203.0.113.10"}, {"network": "d" * 64},
    {"status": NetworkScopeStatus.UNKNOWN}, {"status": NetworkScopeStatus.AMBIGUOUS},
    {"rule": RULE + "_extra"},
])
def test_combined_and_never_cross_matches(changed):
    selector = PreferenceSelector(application(), revision(), destination(), FP, RULE)
    values = {"rev": revision(), **changed}
    assert not selector_matches(selector, context(**values))


@pytest.mark.parametrize("status", [NetworkScopeStatus.UNKNOWN, NetworkScopeStatus.AMBIGUOUS])
def test_omitted_network_can_match_unresolved_context(status):
    assert selector_matches(PreferenceSelector(rule_id=RULE), context(status=status))
    assert not selector_matches(PreferenceSelector(network_fingerprint=FP), context(status=status))


def test_application_only_spans_artifact_revisions_and_unknown_hash():
    s = PreferenceSelector(application=application())
    assert all(selector_matches(s, context(rev=r)) for r in (revision(), revision("c" * 64), revision(None), None))
    assert not selector_matches(s, context(app=application("c:\\other\\browser.exe")))


def test_ipv6_canonical_and_kind_separation():
    full = destination("2001:0DB8:0000:0000:0000:0000:0000:0001")
    assert full == destination("2001:db8::1")
    assert selector_matches(PreferenceSelector(destination=full), context(ip="2001:db8::1"))
    assert not selector_matches(PreferenceSelector(destination=full), context())
    assert not selector_matches(PreferenceSelector(destination=destination()), context(ip="::ffff:203.0.113.10"))
    assert destination().value == "203.0.113.10"


@pytest.mark.parametrize("kwargs", [
    {}, {"rule_id": ""}, {"rule_id": "a" * 65}, {"rule_id": "Rule"},
    {"rule_id": "rule*"}, {"rule_id": "rule.test"}, {"rule_id": "x' OR 1=1"},
    {"network_fingerprint": "bad"}, {"network_fingerprint": "A" * 64},
    {"application_revision": revision()}, {"application": "browser.exe"},
    {"application": 123}, {"destination": "203.0.113.10"},
    {"application": application("relative.exe")}, {"application": application("C:\\Apps\\Browser.exe")},
    {"application": application("c:\\apps\\..\\browser.exe")},
    {"application": application("c:\\" + "x" * 4096)},
    {"application": application(), "application_revision": revision(None)},
])
def test_malformed_selectors(kwargs):
    with pytest.raises((ValueError, TypeError)):
        PreferenceSelector(**kwargs)


def test_provisional_and_unknown_application_are_not_persistent():
    provisional = ApplicationIdentity(ApplicationIdentityQuality.PROVISIONAL, "instance:v1:7:1",
                                      ApplicationIdentityEvidence.PROCESS_INSTANCE, ProcessInfoStatus.ACCESS_DENIED)
    unknown = ApplicationIdentity(ApplicationIdentityQuality.UNKNOWN, None, ApplicationIdentityEvidence.NONE, ProcessInfoStatus.ACCESS_DENIED)
    for app in (provisional, unknown):
        with pytest.raises(ValueError):
            PreferenceSelector(application=app)


@pytest.mark.parametrize("kind,value", [
    (DestinationKind.IPV4, "bad"), (DestinationKind.IPV4, "2001:db8::1"),
    (DestinationKind.IPV6, "203.0.113.10"), (DestinationKind.IPV6, "fe80::1%3"),
    (DestinationKind.IPV6, ":::1"), (DestinationKind.IPV4, "999.0.0.1"),
    (DestinationKind.IPV4, "203.0.113.010"), ("ipv4", "203.0.113.10"),
    (DestinationKind.IPV4, "example.org"), (DestinationKind.IPV4, "203.0.113.0/24"),
])
def test_invalid_destination_kinds(kind, value):
    with pytest.raises(ValueError):
        PreferenceDestination(kind, value)


@pytest.mark.parametrize("kind,expiry", [
    (None, None), ("permanent", None), (PreferenceLifetimeKind.PERMANENT, NOW),
    (PreferenceLifetimeKind.EXPIRES_AT, None),
    (PreferenceLifetimeKind.EXPIRES_AT, NOW.replace(tzinfo=None)),
    (PreferenceLifetimeKind.EXPIRES_AT, NOW.astimezone(timezone(timedelta(hours=3)))),
])
def test_lifetime_must_be_explicit_utc(kind, expiry):
    with pytest.raises((TypeError, ValueError)):
        PreferenceLifetime(kind, expiry)
    with pytest.raises(TypeError):
        PreferenceLifetime()


def snapshot(content=None, **changes):
    p = ScopedPreference(uuid4(), 1, content or definition(), NOW, ORIGIN, NOW, ORIGIN,
                         PreferenceAuditAction.CREATE, PreferenceStatus.ACTIVE)
    return replace(p, **changes) if changes else p


def test_expiry_boundary_permanent_and_revoked_are_distinct():
    p = snapshot()
    expiry = p.definition.lifetime.expires_at
    assert p.status_at(expiry - timedelta(microseconds=1)) is PreferenceStatus.ACTIVE
    assert p.status_at(expiry) is PreferenceStatus.EXPIRED
    assert p.status_at(expiry + timedelta(seconds=1)) is PreferenceStatus.EXPIRED
    permanent = snapshot(definition(permanent=True))
    assert permanent.status_at(NOW + timedelta(days=36500)) is PreferenceStatus.ACTIVE
    revoked = replace(p, revision=2, action=PreferenceAuditAction.REVOKE, status=PreferenceStatus.REVOKED)
    assert revoked.status_at(NOW) is PreferenceStatus.REVOKED
    assert revoked.status_at(expiry + timedelta(days=1)) is PreferenceStatus.REVOKED
    with pytest.raises(ValueError):
        p.status_at(NOW.replace(tzinfo=None))


@pytest.mark.parametrize("reason", ["", " ", "x" * 513, "line\nnext", "tab\tnext", "nul\x00", "del\x7f", "control\x85", "line\u2028next"])
def test_reason_bounds(reason):
    with pytest.raises(ValueError):
        definition(reason=reason)


def test_reason_plain_text_fingerprint_and_immutability():
    d = definition(reason="x" * MAX_PREFERENCE_REASON)
    assert len(d.reason) == MAX_PREFERENCE_REASON
    assert definition(reason="<b>local plain text</b>").reason.startswith("<b>")
    assert definition().content_fingerprint == definition().content_fingerprint
    assert replace(d, reason="changed").content_fingerprint != d.content_fingerprint
    with pytest.raises(FrozenInstanceError):
        d.reason = "changed"
    assert "local plain text" not in repr(definition(reason="local plain text"))


def test_absent_application_destination_and_host_scope_cannot_invent_matches():
    from netsentinel.domain.preferences import PreferenceMatchContext
    from netsentinel.domain.risk_evidence import EvidenceScope, EvidenceScopeKind, EvidenceSubject, EvidenceSubjectKind
    ctx = PreferenceMatchContext(RULE, EvidenceSubject(EvidenceSubjectKind.NETWORK), EvidenceScope(EvidenceScopeKind.HOST))
    assert selector_matches(PreferenceSelector(rule_id=RULE), ctx)
    assert not selector_matches(PreferenceSelector(application=application()), ctx)
    assert not selector_matches(PreferenceSelector(destination=destination()), ctx)
    assert not selector_matches(PreferenceSelector(network_fingerprint=FP), ctx)


@pytest.mark.parametrize("changes", [
    {"revision": 0}, {"revision": True}, {"revision": -1},
    {"action": PreferenceAuditAction.EDIT}, {"status": PreferenceStatus.EXPIRED},
    {"recorded_at": NOW - timedelta(seconds=1)}, {"created_at": NOW.replace(tzinfo=None)},
    {"format_version": 2}, {"action_origin": "manual_user"}, {"preference_id": "uuid"},
])
def test_revision_contract_rejects_invalid_audit(changes):
    with pytest.raises((ValueError, TypeError)):
        snapshot(**changes)


@pytest.mark.parametrize("changes", [
    {"max_active_preferences": 257}, {"max_preferences": 1025}, {"max_revisions": 65},
    {"max_audit_revisions": 16385}, {"max_revisions": 1}, {"max_preferences": 1},
    {"max_active_preferences": True}, {"max_audit_revisions": 0},
])
def test_storage_policy_hard_bounds(changes):
    with pytest.raises(ValueError):
        PreferenceStoragePolicy(**changes)
