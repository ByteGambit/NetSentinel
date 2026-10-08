"""NS-100 port shape and framework boundary checks; no native adapter exists."""

import ast
import inspect
from typing import get_type_hints

from netsentinel.application.ports import ResponseFirewall
from netsentinel.domain import response
from netsentinel.domain.response import (
    FirewallCreateRequest, FirewallCreateResult, FirewallReadResult, FirewallRemoveRequest,
    OwnedFirewallRuleManifest, ResponseResult,
)


def test_firewall_port_requires_typed_manifest_handoff_not_names_or_com_objects():
    assert get_type_hints(ResponseFirewall.create) == {"request": FirewallCreateRequest, "return": FirewallCreateResult}
    assert get_type_hints(ResponseFirewall.read) == {"manifest": OwnedFirewallRuleManifest, "return": FirewallReadResult}
    assert get_type_hints(ResponseFirewall.remove) == {"request": FirewallRemoveRequest, "return": ResponseResult}
    assert set(name for name in ResponseFirewall.__dict__ if not name.startswith("_")) == {"create", "read", "remove"}


def test_ownership_contract_is_framework_independent_and_has_no_storage_or_native_io():
    tree = ast.parse(inspect.getsource(response))
    allowed_roots = {"__future__", "dataclasses", "datetime", "enum", "hashlib", "ipaddress", "json", "re", "unicodedata", "uuid", "netsentinel"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] in allowed_roots for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed_roots
            if node.module.startswith("netsentinel."):
                assert node.module.startswith("netsentinel.domain.")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"open", "exec", "eval", "__import__"}
