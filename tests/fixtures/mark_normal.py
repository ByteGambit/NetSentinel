"""Offline selected behavior context for NS-082."""

from netsentinel.application.services.baseline_detail import BaselineDetailRequest
from netsentinel.application.services.mark_normal import behavior_context, preview_mark_normal, scope_choices
from netsentinel.domain.application_identity import ApplicationScope
from netsentinel.domain.connections import ConnectionNetworkScope, NetworkScopeStatus, NetworkAttributionMethod
from netsentinel.domain.preferences import PreferenceLifetime, PreferenceLifetimeKind
from tests.fixtures.preferences import application, revision, NOW, RULE

NETWORK = ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "a" * 64, "Ethernet", 1,
                                 NetworkAttributionMethod.LOCAL_ADDRESS_MATCH)


def request(*, app=None, network=NETWORK, remote="203.0.113.10", digest="b" * 64, name="browser"):
    return BaselineDetailRequest(ApplicationScope(app or application(), revision(digest)), name, network, remote)


def context(**kwargs):
    return behavior_context(request(**kwargs), RULE)


def preview(*, lifetime=None, scope_index=0, reason="Expected behavior", **kwargs):
    c = context(**kwargs)
    return preview_mark_normal(c, scope_choices(c)[scope_index],
                               lifetime or PreferenceLifetime(PreferenceLifetimeKind.PERMANENT), reason, now=NOW)
