"""NS-082 pure scope mapping and immutable preview validation."""

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest

from netsentinel.application.services.baseline_detail import baseline_detail_request
from netsentinel.application.services.mark_normal import (
    BEHAVIOR_RULES, behavior_context, preview_mark_normal, scope_choices,
)
from netsentinel.domain.connections import ConnectionNetworkScope, ProcessInfo, ProcessIdentity, ProcessInfoStatus
from netsentinel.domain.preferences import PreferenceLifetime, PreferenceLifetimeKind, PreferenceSelector, selector_matches
from tests.fixtures.mark_normal import context, preview, request
from tests.fixtures.preferences import NOW, RULE, application


@pytest.mark.parametrize("rule", [item[0] for item in BEHAVIOR_RULES])
@pytest.mark.parametrize("ip,canonical", [("203.0.113.10", "203.0.113.10"), ("2001:0db8::1", "2001:db8::1")])
def test_narrow_scope_canonical_and_all_dimensions_visible(rule, ip, canonical):
    c = behavior_context(request(remote=ip), rule)
    choices = scope_choices(c)
    s = choices[0]
    p = preview_mark_normal(c, s, PreferenceLifetime(PreferenceLifetimeKind.PERMANENT), "<b>plain</b>", now=NOW)
    assert s.application.key == application().key
    assert s.application_revision.digest == "b" * 64
    assert s.destination.value == canonical
    assert s.network_fingerprint == "a" * 64 and s.rule_id == rule
    assert all(selector_matches(s, c.match) for s in choices)
    assert all(s.application and s.rule_id for s in choices)
    for text in (rule, canonical, application().key, "b" * 64, "a" * 64, "Permanent", "<b>plain</b>"):
        assert text in p.text
    with pytest.raises(FrozenInstanceError):
        p.definition = None


@pytest.mark.parametrize("network", [ConnectionNetworkScope.unknown(), ConnectionNetworkScope.ambiguous()])
def test_unresolved_network_is_explicit_host_wide_and_never_fake(network):
    p = preview(network=network)
    assert p.definition.selector.network_fingerprint is None
    assert network.status.value in p.text and "Any network (host-wide" in p.text
    assert all(s.network_fingerprint is None for s in scope_choices(p.context))


def test_unknown_revision_and_absent_destination_not_fabricated():
    p = preview(digest=None, remote=None)
    assert p.definition.selector.application_revision is None
    assert p.definition.selector.destination is None
    assert "exact binary revision unavailable" in p.text and "Any destination" in p.text


@pytest.mark.parametrize("known_time", [None, NOW])
@pytest.mark.parametrize("name", [None, "browser"])
def test_pid_name_or_provisional_application_never_persists(known_time, name):
    process = ProcessInfo(identity=ProcessIdentity(12, known_time), name=name,
                          status=ProcessInfoStatus.AVAILABLE if name else ProcessInfoStatus.NOT_FOUND)
    r = baseline_detail_request(process, request().network, "203.0.113.10")
    with pytest.raises(ValueError, match="Stable application"):
        behavior_context(r, RULE)


def test_same_name_different_path_and_exact_revision_distinct():
    a = preview()
    b = preview(app=application(r"c:\other\browser.exe"))
    assert a.context.display_name == b.context.display_name
    assert a.definition.selector.application != b.definition.selector.application
    assert not selector_matches(a.definition.selector, b.context.match)
    assert not selector_matches(a.definition.selector, context(digest="c" * 64).match)
    assert selector_matches(scope_choices(a.context)[1], context(digest="c" * 64).match)


@pytest.mark.parametrize("reason", ["", " ", "a" * 513, "line\nline", "line\rline", "tab\t", "\u2028", "\x00"])
def test_invalid_reason_rejected_without_io(reason):
    with pytest.raises(ValueError):
        preview(reason=reason)


def test_broad_scope_explicit_warning_and_never_global():
    c = context()
    assert "Broader scope" not in preview().text
    assert "Broader scope" in preview(scope_index=1).text
    with pytest.raises(ValueError):
        preview_mark_normal(c, PreferenceSelector(rule_id=RULE),
                            PreferenceLifetime(PreferenceLifetimeKind.PERMANENT), "Reason", now=NOW)
    with pytest.raises(ValueError):
        behavior_context(request(), "invented_rule")
    with pytest.raises(ValueError):
        PreferenceSelector()


def test_expiry_absolute_and_effect_preserves_history():
    expiry = NOW + timedelta(hours=24)
    p = preview(lifetime=PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, expiry), reason="a" * 512)
    assert expiry.isoformat() in p.text and p.definition.lifetime.expires_at == expiry
    for phrase in ("future matching", "safe", "delete evidence", "historical risk scores", "reset the baseline",
                   "firewall", "current alert remains unchanged", "does not replay"):
        assert phrase in p.text
    with pytest.raises(ValueError):
        preview(lifetime=PreferenceLifetime(PreferenceLifetimeKind.EXPIRES_AT, NOW))
    with pytest.raises(TypeError):
        replace(p.definition, lifetime=None)
