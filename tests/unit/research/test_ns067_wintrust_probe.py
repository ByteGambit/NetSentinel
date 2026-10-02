"""Fake WinTrust outcomes for the isolated NS-067 research classifier."""

from tools.research.ns067_wintrust_probe import OFFLINE_FLAGS, research_category


def test_offline_flags_include_cache_only_and_no_revocation() -> None:
    assert OFFLINE_FLAGS & 0x1000
    assert OFFLINE_FLAGS & 0x10


def test_catalog_only_is_not_called_unsigned() -> None:
    catalogs: list[dict[str, object]] = [{"found": True, "trust": "0x00000000"}]
    assert research_category("0x800B0100", catalogs) == "catalog_trusted_under_offline_policy"


def test_invalid_embedded_and_no_catalog_stays_invalid() -> None:
    catalogs: list[dict[str, object]] = [{"found": False}, {"found": False}]
    assert research_category("0x80096010", catalogs) == "embedded_signature_invalid"


def test_missing_catalog_lookup_does_not_become_unsigned() -> None:
    catalogs: list[dict[str, object]] = [{"error": "acquire:5"}]
    assert research_category("0x800B0100", catalogs) == "catalog_lookup_unavailable"


def test_unsupported_non_pe_distinct_from_no_signature() -> None:
    catalogs: list[dict[str, object]] = [{"found": False}, {"found": False}]
    assert research_category("0x800B0003", catalogs) == "unsupported_subject_form"
    assert research_category("0x800B0100", catalogs) == "no_signature_in_tested_paths"


def test_found_but_untrusted_catalog_stays_unverified() -> None:
    catalogs: list[dict[str, object]] = [{"found": True, "trust": "0x800B0109"}]
    assert research_category("0x800B0100", catalogs) == "catalog_present_but_unverified"
