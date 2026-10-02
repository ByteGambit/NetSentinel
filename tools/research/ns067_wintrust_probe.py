"""NS-067 only: offline, read-only WinTrust probe. Never imported by NetSentinel.

Run on explicit local files only. The probe does not execute or load a target.
It intentionally reports raw Windows codes for research, not a product verdict.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from time import perf_counter


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


GENERIC_VERIFY_V2 = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                         (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pInfo", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPWSTR),
                ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]


class PROVIDER_CERT_HEAD(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]


class CERT_CONTEXT_HEAD(ctypes.Structure):
    _fields_ = [("dwCertEncodingType", wintypes.DWORD), ("pbCertEncoded", ctypes.c_void_p),
                ("cbCertEncoded", wintypes.DWORD), ("pCertInfo", ctypes.c_void_p),
                ("hCertStore", wintypes.HANDLE)]


class PROVIDER_SGNR_HEAD(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("sftVerifyAsOf", wintypes.FILETIME),
                ("csCertChain", wintypes.DWORD), ("pasCertChain", ctypes.c_void_p),
                ("dwSignerType", wintypes.DWORD), ("psSigner", ctypes.c_void_p),
                ("dwError", wintypes.DWORD), ("csCounterSigners", wintypes.DWORD)]


WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
OFFLINE_FLAGS = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL


def _signer_evidence(state: wintypes.HANDLE) -> dict[str, object]:
    if not state:
        return {"signers": []}
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    provider = wintrust.WTHelperProvDataFromStateData
    provider.argtypes = [wintypes.HANDLE]
    provider.restype = ctypes.c_void_p
    get_signer = wintrust.WTHelperGetProvSignerFromChain
    get_signer.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    get_signer.restype = ctypes.c_void_p
    get_cert = wintrust.WTHelperGetProvCertFromChain
    get_cert.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    get_cert.restype = ctypes.c_void_p
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    get_name = crypt32.CertGetNameStringW
    get_name.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                         ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    get_name.restype = wintypes.DWORD
    prov = provider(state)
    if not prov:
        return {"signers": [], "provider_state": "unavailable"}
    signers: list[dict[str, object]] = []
    for index in range(8):
        signer = get_signer(prov, index, False, 0)
        if not signer:
            break
        signer_head = ctypes.cast(signer, ctypes.POINTER(PROVIDER_SGNR_HEAD)).contents
        ticks = (signer_head.sftVerifyAsOf.dwHighDateTime << 32) | signer_head.sftVerifyAsOf.dwLowDateTime
        verify_as_of = (datetime(1601, 1, 1, tzinfo=timezone.utc)
                        + timedelta(microseconds=ticks // 10)).isoformat() if ticks else None
        context = {"index": index, "verify_as_of": verify_as_of,
                   "counter_signers": signer_head.csCounterSigners,
                   "signer_error": f"0x{signer_head.dwError:08X}"}
        if signer_head.csCounterSigners:
            counter = get_signer(prov, index, True, 0)
            if counter:
                counter_head = ctypes.cast(counter, ctypes.POINTER(PROVIDER_SGNR_HEAD)).contents
                context["first_counter_signer_error"] = f"0x{counter_head.dwError:08X}"
        cert_ptr = get_cert(signer, 0)
        if not cert_ptr:
            signers.append({**context, "certificate": "unavailable"})
            continue
        cert_head = ctypes.cast(cert_ptr, ctypes.POINTER(PROVIDER_CERT_HEAD)).contents
        if not cert_head.pCert:
            signers.append({**context, "certificate": "unavailable"})
            continue
        cert_context = ctypes.cast(cert_head.pCert, ctypes.POINTER(CERT_CONTEXT_HEAD)).contents
        if cert_context.cbCertEncoded > 65536 or not cert_context.pbCertEncoded:
            signers.append({**context, "certificate": "invalid_size"})
            continue
        name = ctypes.create_unicode_buffer(512)
        get_name(cert_head.pCert, 4, 0, None, name, len(name))
        subject = name.value
        get_name(cert_head.pCert, 4, 1, None, name, len(name))
        issuer = name.value
        der = ctypes.string_at(cert_context.pbCertEncoded, cert_context.cbCertEncoded)
        signers.append({**context, "subject": subject, "issuer": issuer,
                        "certificate_sha256": sha256(der).hexdigest()})
    return {"signers": signers, "signer_cap_reached": len(signers) == 8}


def _verify(info: ctypes.Structure, choice: int) -> tuple[str, float, dict[str, object]]:
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    call = wintrust.WinVerifyTrust
    call.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
    call.restype = ctypes.c_long  # LONG, not an HRESULT success predicate.
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(data)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = choice
    data.pInfo = ctypes.addressof(info)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = OFFLINE_FLAGS
    started = perf_counter()
    try:
        code = call(wintypes.HWND(-1), ctypes.byref(GENERIC_VERIFY_V2), ctypes.byref(data))
        elapsed = perf_counter() - started
        evidence = _signer_evidence(data.hWVTStateData)
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        call(wintypes.HWND(-1), ctypes.byref(GENERIC_VERIFY_V2), ctypes.byref(data))
    return f"0x{code & 0xFFFFFFFF:08X}", round(elapsed * 1000, 3), evidence


def _embedded(path: str) -> tuple[str, float, dict[str, object]]:
    info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    return _verify(info, WTD_CHOICE_FILE)


def _catalog(path: str) -> list[dict[str, object]]:
    """Bounded SHA256/SHA1 catalog lookup using catalog-specific file hashes."""
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    acquire = wintrust.CryptCATAdminAcquireContext2
    acquire.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p,
                        wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
    acquire.restype = wintypes.BOOL
    calc = wintrust.CryptCATAdminCalcHashFromFileHandle2
    calc.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                     ctypes.c_void_p, wintypes.DWORD]
    calc.restype = wintypes.BOOL
    enum = wintrust.CryptCATAdminEnumCatalogFromHash
    enum.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                     wintypes.DWORD, ctypes.c_void_p]
    enum.restype = wintypes.HANDLE
    catalog_info = wintrust.CryptCATCatalogInfoFromContext
    catalog_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
    catalog_info.restype = wintypes.BOOL
    release_cat = wintrust.CryptCATAdminReleaseCatalogContext
    release_cat.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
    release_cat.restype = wintypes.BOOL
    release_admin = wintrust.CryptCATAdminReleaseContext
    release_admin.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    release_admin.restype = wintypes.BOOL
    import msvcrt

    results: list[dict[str, object]] = []
    for algorithm in ("SHA256", "SHA1"):
        admin = wintypes.HANDLE()
        if not acquire(ctypes.byref(admin), None, algorithm, None, 0):
            results.append({"algorithm": algorithm, "error": f"acquire:{ctypes.get_last_error()}"})
            continue
        try:
            with open(path, "rb") as stream:
                handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
                length = wintypes.DWORD()
                if not calc(admin, handle, ctypes.byref(length), None, 0) or not 0 < length.value <= 128:
                    results.append({"algorithm": algorithm, "error": f"hash-size:{ctypes.get_last_error()}"})
                    continue
                digest = (ctypes.c_ubyte * length.value)()
                if not calc(admin, handle, ctypes.byref(length), digest, 0):
                    results.append({"algorithm": algorithm, "error": f"hash:{ctypes.get_last_error()}"})
                    continue
                raw_match: bool | None = None
                if algorithm == "SHA256":
                    stream.seek(0)
                    raw_match = bytes(digest) == sha256(stream.read()).digest()
                catalog = enum(admin, digest, length, 0, None)
                if not catalog:
                    results.append({"algorithm": algorithm, "found": False,
                                    "equals_raw_sha256": raw_match})
                    continue
                try:
                    cat_info = CATALOG_INFO()
                    cat_info.cbStruct = ctypes.sizeof(cat_info)
                    if not catalog_info(catalog, ctypes.byref(cat_info), 0):
                        results.append({"algorithm": algorithm, "error": f"catalog-info:{ctypes.get_last_error()}"})
                        continue
                    member_tag = bytes(digest).hex().upper()
                    verify_info = WINTRUST_CATALOG_INFO()
                    verify_info.cbStruct = ctypes.sizeof(verify_info)
                    verify_info.pcwszCatalogFilePath = cat_info.wszCatalogFile
                    verify_info.pcwszMemberTag = member_tag
                    verify_info.pcwszMemberFilePath = path
                    verify_info.hMemberFile = handle
                    verify_info.pbCalculatedFileHash = ctypes.addressof(digest)
                    verify_info.cbCalculatedFileHash = length.value
                    verify_info.hCatAdmin = admin
                    status, ms, evidence = _verify(verify_info, WTD_CHOICE_CATALOG)
                    results.append({"algorithm": algorithm, "found": True,
                                    "catalog": Path(cat_info.wszCatalogFile).name,
                                    "trust": status, "ms": ms,
                                    "equals_raw_sha256": raw_match, **evidence})
                finally:
                    release_cat(admin, catalog, 0)
        finally:
            release_admin(admin, 0)
    return results


def research_category(embedded: str, catalogs: list[dict[str, object]]) -> str:
    """Conservative spike-only summary; never a malware or product verdict."""
    if embedded == "0x00000000":
        return "embedded_trusted_under_offline_policy"
    if any(item.get("trust") == "0x00000000" for item in catalogs):
        return "catalog_trusted_under_offline_policy"
    if embedded == "0x80096010":
        return "embedded_signature_invalid"
    if any(item.get("found") is True for item in catalogs):
        return "catalog_present_but_unverified"
    if any("error" in item for item in catalogs):
        return "catalog_lookup_unavailable"
    if embedded == "0x800B0100":
        return "no_signature_in_tested_paths"
    if embedded == "0x800B0003":
        return "unsupported_subject_form"
    return "verification_unavailable"


def probe(path: str) -> dict[str, object]:
    candidate = Path(path)
    if not candidate.is_absolute() or str(candidate).startswith(("\\\\", "//")):
        return {"error": "requires_local_absolute_path"}
    if candidate.is_symlink():
        return {"error": "symlink_rejected"}
    try:
        before = candidate.stat()
    except FileNotFoundError:
        return {"error": "file_not_found"}
    except PermissionError:
        return {"error": "access_denied"}
    if not candidate.is_file():
        return {"error": "not_regular_file"}
    if before.st_size > 32 * 1024 * 1024:
        return {"error": "research_size_cap"}
    embedded, embedded_ms, evidence = _embedded(str(candidate))
    catalogs = _catalog(str(candidate))
    after = candidate.stat()
    return {"file": candidate.name, "size": before.st_size,
            "embedded_trust": embedded, "embedded_ms": embedded_ms,
            "embedded_evidence": evidence,
            "catalogs": catalogs, "research_category": research_category(embedded, catalogs),
            "changed": (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)}


def main() -> None:
    if os.name != "nt":
        raise SystemExit("Windows only")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="explicit local file paths; max 16")
    parser.add_argument("--repeat", type=int, default=1, help="1-5 same-process samples")
    args = parser.parse_args()
    if len(args.paths) > 16:
        parser.error("at most 16 paths")
    if not 1 <= args.repeat <= 5:
        parser.error("repeat must be 1-5")
    for path in args.paths:
        for sample in range(args.repeat):
            print(json.dumps({"sample": sample + 1, **probe(path)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
