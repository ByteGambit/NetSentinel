"""NS-101 structured Windows Firewall Automation boundary, lazy pywin32 binding.

No shell, registry edits, generated makepy cache, global COM object or elevation.
INetFwRule3 support is mandatory: absent property access fails closed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from ipaddress import ip_interface
import re
import sys
from threading import get_ident
from typing import Any

from netsentinel.domain.response import (
    FirewallReadStatus, FirewallRuleSnapshot, ResponseProfile, ResponseTransport,
)
from netsentinel.infrastructure.windows_response_firewall import FirewallApiError

MAX_ENUMERATED_RULES = 16_384
POLICY_IID = "{98325047-C671-4174-8D81-DEFCD3F03186}"
RULE3_IID = "{B21563FF-D696-4222-AB46-4E89B73AB34A}"
PROFILES = {ResponseProfile.DOMAIN: 1, ResponseProfile.PRIVATE: 2, ResponseProfile.PUBLIC: 4}
PROTOCOLS = {ResponseTransport.TCP: 6, ResponseTransport.UDP: 17}

# All supported ownership fields. No property lookup uses caller-supplied names.
TEXT_PROPERTIES = {
    "name": "Name", "description": "Description", "grouping": "Grouping",
    "service_name": "ServiceName", "local_addresses": "LocalAddresses",
    "local_ports": "LocalPorts", "icmp_types_and_codes": "IcmpTypesAndCodes",
    "interface_types": "InterfaceTypes", "local_app_package_id": "LocalAppPackageId",
    "local_user_owner": "LocalUserOwner", "local_user_authorized_list": "LocalUserAuthorizedList",
    "remote_user_authorized_list": "RemoteUserAuthorizedList",
    "remote_machine_authorized_list": "RemoteMachineAuthorizedList",
}
NULL_BSTR_FIELDS = {"description", "grouping", "service_name", "icmp_types_and_codes",
                   "local_app_package_id", "local_user_owner", "local_user_authorized_list",
                   "remote_user_authorized_list", "remote_machine_authorized_list"}


def _integer(value: object) -> int:
    if type(value) is not int:
        raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
    return value


def _text(value: object, *, nullable: bool = False) -> str:
    if value is None and nullable:
        return ""  # A successfully retrieved NULL BSTR denotes empty text.
    if type(value) is not str:
        raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
    return value


def _host(value: object) -> str:
    text = _text(value)
    if "/" in text:
        # Windows may render a literal as a full host mask. No subnet expansion.
        try:
            address = ip_interface(text)
            if address.network.prefixlen != address.max_prefixlen:
                raise ValueError
            return str(address.ip)
        except ValueError:
            raise FirewallApiError(FirewallReadStatus.UNSUPPORTED) from None
    return text


def snapshot(rule: Any, expected: FirewallRuleSnapshot) -> FirewallRuleSnapshot:
    """Independent complete getter mapping; expected contributes lifetime only.

    Values outside the frozen writable spec cannot be represented as a partial
    equality snapshot. They are UNSUPPORTED, which also refuses removal.
    """
    protocol = _integer(rule.Protocol)
    profile = _integer(rule.Profiles)
    if (protocol not in PROTOCOLS.values() or profile not in PROFILES.values()
            or _integer(rule.Direction) != 2 or _integer(rule.Action) != 0):
        raise FirewallApiError(FirewallReadStatus.UNSUPPORTED)
    remote_ports = _text(rule.RemotePorts)
    if re.fullmatch(r"[1-9][0-9]{0,4}", remote_ports) is None:
        raise FirewallApiError(FirewallReadStatus.UNSUPPORTED)
    try:
        spec = replace(expected.spec, program_path=_text(rule.ApplicationName),
                       remote_ip=_host(rule.RemoteAddresses), remote_port=int(remote_ports),
                       transport=next(k for k, v in PROTOCOLS.items() if v == protocol),
                       profile=next(k for k, v in PROFILES.items() if v == profile))
        text_values = {field: _text(getattr(rule, prop), nullable=field in NULL_BSTR_FIELDS)
                       for field, prop in TEXT_PROPERTIES.items()}
        interfaces = rule.Interfaces
        if interfaces is None:
            interfaces = ()  # Successfully retrieved VT_EMPTY, no interface filter.
        if type(interfaces) is not tuple:
            raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
        return FirewallRuleSnapshot(spec=spec, **text_values, enabled=rule.Enabled,
            interfaces=interfaces, edge_traversal=rule.EdgeTraversal,
            edge_traversal_options=_integer(rule.EdgeTraversalOptions),
            secure_flags=_integer(rule.SecureFlags))
    except (ValueError, TypeError):
        raise FirewallApiError(FirewallReadStatus.UNSUPPORTED) from None


def classify_error(error: Exception) -> FirewallApiError:
    """Discard exception text/targets, retaining only known HRESULT classification."""
    if isinstance(error, FirewallApiError):
        return error
    code = getattr(error, "hresult", None)
    detail = getattr(error, "excepinfo", None)
    if type(detail) is tuple and len(detail) == 6 and type(detail[5]) is int and detail[5]:
        code = detail[5]  # Automation's underlying SCODE, not DISP_E_EXCEPTION.
    code = code & 0xFFFFFFFF if type(code) is int else None
    if isinstance(error, PermissionError) or code == 0x80070005:
        return FirewallApiError(FirewallReadStatus.ACCESS_DENIED, definite_failure=True)
    if code in {0x80004002, 0x80020003, 0x80020006, 0x80010106} or isinstance(error, AttributeError):
        return FirewallApiError(FirewallReadStatus.UNSUPPORTED, definite_failure=True)
    if isinstance(error, (ImportError, OSError)) or code in {0x80040154, 0x80070424, 0x800706D9}:
        return FirewallApiError(FirewallReadStatus.BACKEND_UNAVAILABLE)
    if code in {0x80070057, 0x8000FFFF}:
        return FirewallApiError(FirewallReadStatus.INVALID_REQUEST, definite_failure=True)
    # RPC/service loss or generic exceptions during a mutation may be uncertain.
    return FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)


class ComFirewallApi:
    """Thread-confined Automation objects; never exposed via ResponseFirewall."""

    def __init__(self, pythoncom: Any, dispatch: Any) -> None:
        self._com = pythoncom
        self._dispatch = dispatch
        self._thread = get_ident()
        self._policy = self._typed(dispatch("HNetCfg.FwPolicy2"), POLICY_IID)

    def _check_thread(self) -> None:
        if get_ident() != self._thread:
            raise FirewallApiError(FirewallReadStatus.UNSUPPORTED, definite_failure=True)

    def _typed(self, value: Any, iid: str) -> Any:
        # Explicit QI proves the full interface exists; use the IDispatch gateway
        # on THAT pointer so Rule3 fields are not silently substituted.
        pointer = value._oleobj_.QueryInterface(self._com.MakeIID(iid), self._com.IID_IDispatch)
        return self._dispatch(pointer)

    def matching(self, name: str, spec: FirewallRuleSnapshot) -> tuple[FirewallRuleSnapshot, ...]:
        self._check_thread()
        try:
            rules = self._policy.Rules  # Fresh collection and enumeration, never Item(name).
            count = _integer(rules.Count)
            if not 0 <= count <= MAX_ENUMERATED_RULES:
                raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
            matches: list[Any] = []
            seen = 0
            for rule in rules:
                seen += 1
                if seen > MAX_ENUMERATED_RULES:
                    raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
                rule_name = _text(rule.Name)
                if not rule_name or len(rule_name) > 4096:
                    raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
                if rule_name.casefold() == name.casefold():
                    matches.append(rule)
                    if len(matches) == 2:
                        raise FirewallApiError(FirewallReadStatus.DUPLICATE, definite_failure=True)
            if seen != count or _integer(rules.Count) != count:
                raise FirewallApiError(FirewallReadStatus.READ_UNAVAILABLE)
            return tuple(snapshot(self._typed(rule, RULE3_IID), spec) for rule in matches)
        except Exception as error:
            raise classify_error(error) from None

    def add(self, rule: FirewallRuleSnapshot, before_submit: Callable[[], None]) -> None:
        self._check_thread()
        try:
            detached = self._typed(self._dispatch("HNetCfg.FWRule"), RULE3_IID)
            detached.Protocol = PROTOCOLS[rule.spec.transport]  # Protocol before ports.
            detached.Name = rule.name
            detached.Description = rule.description
            detached.ApplicationName = rule.spec.program_path
            detached.RemoteAddresses = rule.spec.remote_ip
            detached.RemotePorts = str(rule.spec.remote_port)
            detached.LocalAddresses = rule.local_addresses
            detached.LocalPorts = rule.local_ports
            detached.Profiles = PROFILES[rule.spec.profile]
            detached.Direction = 2  # NET_FW_RULE_DIR_OUT
            detached.Action = 0  # NET_FW_ACTION_BLOCK
            detached.Enabled = True
            detached.InterfaceTypes = "All"
            detached.EdgeTraversal = False
            detached.EdgeTraversalOptions = 0
            # Other restrictions remain detached API defaults, verified rather
            # than invented (some setters are illegal for TCP/UDP rules).
            if snapshot(detached, rule) != rule:
                raise FirewallApiError(FirewallReadStatus.UNSUPPORTED, definite_failure=True)
            # Construction/property calls can take time. Check again at submission.
            if self.matching(rule.name, rule):
                raise FirewallApiError(FirewallReadStatus.DUPLICATE, definite_failure=True)
            rules = self._policy.Rules
            # Callback is outside native exception mapping: a dispatch refusal
            # must retain its typed reason and must not look like an OS attempt.
        except Exception as error:
            raise classify_error(error) from None
        before_submit()
        try:
            rules.Add(detached)
        except Exception as error:
            raise classify_error(error) from None

    def remove(self, rule: FirewallRuleSnapshot, before_submit: Callable[[], None]) -> None:
        self._check_thread()
        try:
            # Recheck at the narrow native mutation boundary as well. COM still
            # provides no compare-and-delete primitive against external edits.
            if self.matching(rule.name, rule) != (rule,):
                raise FirewallApiError(FirewallReadStatus.DUPLICATE, definite_failure=True)
            rules = self._policy.Rules
        except Exception as error:
            raise classify_error(error) from None
        before_submit()
        try:
            rules.Remove(rule.name)
        except Exception as error:
            raise classify_error(error) from None

    def close(self) -> None:
        self._check_thread()
        self._policy = None
        self._dispatch = None
        self._com = None


@contextmanager
def session() -> Iterator[ComFirewallApi]:
    """Own one balanced STA apartment on the calling worker; no thread sharing.

    An incompatible existing MTA returns UNSUPPORTED; no apartment switching or
    retry. pywin32 is optional and lazy. Import/construction performs no writes.
    """
    if sys.platform != "win32":
        raise FirewallApiError(FirewallReadStatus.UNSUPPORTED)
    initialized = False
    api = None
    try:
        import pythoncom
        from win32com.client.dynamic import Dispatch
        pythoncom.CoInitializeEx(pythoncom.COINIT_APARTMENTTHREADED)
        initialized = True
        api = ComFirewallApi(pythoncom, Dispatch)
    except Exception as error:
        if initialized:
            pythoncom.CoUninitialize()
        raise classify_error(error) from None
    try:
        yield api
    finally:
        if api is not None:
            api.close()
        if initialized:
            pythoncom.CoUninitialize()
