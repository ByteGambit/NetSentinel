"""Local, cache-only Windows Authenticode verification. No target execution."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
import ctypes
from ctypes import wintypes
from hashlib import sha256
import msvcrt
import os
from pathlib import Path
import stat
from threading import Lock
from time import monotonic

from netsentinel.domain.connections import MAX_EXECUTABLE_PATH_LENGTH
from netsentinel.domain.executable_signer import (
    ExecutableSigner, LocalTrust, RevocationStatus, SignatureKind,
    SignatureValidation, SignerAvailability as Availability, SignerIdentity,
)


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


ACTION = GUID(0x00AAC56B, 0xCD44, 0x11D0,
              (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))


class FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]


class TRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pInfo", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPWSTR),
                ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]


class CATALOG_TRUST_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]


class PROVIDER_CERT(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]


class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [("dwCertEncodingType", wintypes.DWORD), ("pbCertEncoded", ctypes.c_void_p),
                ("cbCertEncoded", wintypes.DWORD), ("pCertInfo", ctypes.c_void_p),
                ("hCertStore", wintypes.HANDLE)]


class PROVIDER_SIGNER(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("sftVerifyAsOf", wintypes.FILETIME),
                ("csCertChain", wintypes.DWORD), ("pasCertChain", ctypes.c_void_p),
                ("dwSignerType", wintypes.DWORD), ("psSigner", ctypes.c_void_p),
                ("dwError", wintypes.DWORD), ("csCounterSigners", wintypes.DWORD)]


# Revocation is disabled; cache-only retrieval additionally prevents chain/AIA URL fetches.
OFFLINE_FLAGS = 0x10 | 0x1000  # WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
NO_SIGNATURE = 0x800B0100
SUBJECT_UNKNOWN = 0x800B0003
BAD_DIGEST = 0x80096010
UNTRUSTED_CODES = {0x800B0109, 0x800B0111, 0x800B0101, 0x800B010C}
FileKey = tuple[int, int, int, int, str]


def _key(info: os.stat_result, path: str) -> FileKey:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            os.path.normcase(path) if info.st_ino == 0 else "")


class _WindowsTrust:
    """Owns all native pointers; only plain immutable data crosses this boundary."""

    def __init__(self) -> None:
        win = ctypes.WinDLL("wintrust", use_last_error=True)
        crypt = ctypes.WinDLL("crypt32", use_last_error=True)
        self.verify = win.WinVerifyTrust
        self.verify.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(TRUST_DATA)]
        self.verify.restype = ctypes.c_long
        self.provider = win.WTHelperProvDataFromStateData
        self.provider.argtypes = [wintypes.HANDLE]
        self.provider.restype = ctypes.c_void_p
        self.get_signer = win.WTHelperGetProvSignerFromChain
        self.get_signer.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.get_signer.restype = ctypes.c_void_p
        self.get_cert = win.WTHelperGetProvCertFromChain
        self.get_cert.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self.get_cert.restype = ctypes.c_void_p
        self.get_name = crypt.CertGetNameStringW
        self.get_name.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
        self.get_name.restype = wintypes.DWORD
        self.acquire = win.CryptCATAdminAcquireContext2
        self.acquire.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p,
                                 wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
        self.acquire.restype = wintypes.BOOL
        self.calc = win.CryptCATAdminCalcHashFromFileHandle2
        self.calc.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                              ctypes.c_void_p, wintypes.DWORD]
        self.calc.restype = wintypes.BOOL
        self.enum = win.CryptCATAdminEnumCatalogFromHash
        self.enum.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                              wintypes.DWORD, ctypes.c_void_p]
        self.enum.restype = wintypes.HANDLE
        self.cat_info = win.CryptCATCatalogInfoFromContext
        self.cat_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
        self.cat_info.restype = wintypes.BOOL
        self.release_cat = win.CryptCATAdminReleaseCatalogContext
        self.release_cat.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
        self.release_cat.restype = wintypes.BOOL
        self.release_admin = win.CryptCATAdminReleaseContext
        self.release_admin.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.release_admin.restype = wintypes.BOOL

    def _identity(self, state: wintypes.HANDLE) -> tuple[SignerIdentity | None, bool | None]:
        if not state:
            return None, None
        provider = self.provider(state)
        signer = self.get_signer(provider, 0, False, 0) if provider else None
        if not signer:
            return None, None
        head = ctypes.cast(signer, ctypes.POINTER(PROVIDER_SIGNER)).contents
        timestamp = bool(head.csCounterSigners)
        cert = self.get_cert(signer, 0)
        if not cert:
            return None, timestamp
        ptr = ctypes.cast(cert, ctypes.POINTER(PROVIDER_CERT)).contents.pCert
        if not ptr:
            return None, timestamp
        context = ctypes.cast(ptr, ctypes.POINTER(CERT_CONTEXT)).contents
        if not context.pbCertEncoded or not 0 < context.cbCertEncoded <= 65536:
            return None, timestamp
        def name(flags: int) -> str | None:
            buffer = ctypes.create_unicode_buffer(512)
            count = self.get_name(ptr, 4, flags, None, buffer, len(buffer))
            value = buffer.value.strip() if 0 < count <= len(buffer) else ""
            return "".join(c for c in value if ord(c) >= 32)[:511] or None
        fingerprint = sha256(ctypes.string_at(context.pbCertEncoded, context.cbCertEncoded)).hexdigest()
        return SignerIdentity(name(0), name(1), fingerprint), timestamp

    def _verify(self, info: ctypes.Structure, choice: int, kind: SignatureKind) -> tuple[int, ExecutableSigner]:
        data = TRUST_DATA()
        data.cbStruct = ctypes.sizeof(data)
        data.dwUIChoice = 2  # WTD_UI_NONE
        data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        data.dwUnionChoice = choice
        data.pInfo = ctypes.addressof(info)
        data.dwStateAction = 1  # VERIFY
        data.dwProvFlags = OFFLINE_FLAGS
        try:
            code = self.verify(wintypes.HWND(-1), ctypes.byref(ACTION), ctypes.byref(data)) & 0xffffffff
            signer, timestamp = self._identity(data.hWVTStateData)
        finally:
            data.dwStateAction = 2  # CLOSE even after an error/exception
            self.verify(wintypes.HWND(-1), ctypes.byref(ACTION), ctypes.byref(data))
        if code == 0:
            validation, trust = SignatureValidation.VALID, LocalTrust.TRUSTED_LOCAL_POLICY
        elif code == BAD_DIGEST:
            validation, trust = SignatureValidation.INVALID, LocalTrust.UNTRUSTED
        elif code in UNTRUSTED_CODES:
            validation, trust = SignatureValidation.UNKNOWN, LocalTrust.UNTRUSTED
        else:
            validation, trust = SignatureValidation.UNKNOWN, LocalTrust.UNKNOWN
        return code, ExecutableSigner(Availability.AVAILABLE, kind, validation, trust,
                                      RevocationStatus.NOT_CHECKED, signer, timestamp)

    def inspect(self, path: str, handle: wintypes.HANDLE, *, cancelled: Callable[[], bool]) -> ExecutableSigner:
        file_info = FILE_INFO(ctypes.sizeof(FILE_INFO), path, handle, None)
        code, embedded = self._verify(file_info, 1, SignatureKind.EMBEDDED)
        if code not in (NO_SIGNATURE, SUBJECT_UNKNOWN):
            return embedded
        unsupported = code == SUBJECT_UNKNOWN
        lookup_failed = False
        count = 0
        candidate: ExecutableSigner | None = None
        for algorithm in ("SHA256", "SHA1"):
            if cancelled():
                return ExecutableSigner(Availability.CANCELLED)
            admin = wintypes.HANDLE()
            if not self.acquire(ctypes.byref(admin), None, algorithm, None, 0):
                lookup_failed = True
                continue
            try:
                length = wintypes.DWORD()
                if not self.calc(admin, handle, ctypes.byref(length), None, 0) or not 0 < length.value <= 128:
                    lookup_failed = True
                    continue
                digest = (ctypes.c_ubyte * length.value)()
                if not self.calc(admin, handle, ctypes.byref(length), digest, 0):
                    lookup_failed = True
                    continue
                previous = wintypes.HANDLE()
                try:
                    while count < 8:
                        previous_ptr = ctypes.byref(previous) if previous.value else None
                        catalog = self.enum(admin, digest, length.value, 0, previous_ptr)
                        if not catalog:
                            # Enumeration consumes the previous context when
                            # advanced to exhaustion.
                            previous = wintypes.HANDLE()
                            break
                        previous = wintypes.HANDLE(catalog)
                        count += 1
                        info = CATALOG_INFO()
                        info.cbStruct = ctypes.sizeof(info)
                        if not self.cat_info(catalog, ctypes.byref(info), 0):
                            lookup_failed = True
                            continue
                        cat = CATALOG_TRUST_INFO()
                        cat.cbStruct = ctypes.sizeof(cat)
                        cat.pcwszCatalogFilePath = info.wszCatalogFile
                        cat.pcwszMemberTag = bytes(digest).hex().upper()
                        cat.pcwszMemberFilePath = path
                        cat.hMemberFile = handle
                        cat.pbCalculatedFileHash = ctypes.addressof(digest)
                        cat.cbCalculatedFileHash = length.value
                        cat.hCatAdmin = admin
                        _, result = self._verify(cat, 2, SignatureKind.CATALOG)
                        if result.local_trust is LocalTrust.TRUSTED_LOCAL_POLICY:
                            return result
                        # Keep the first rejected membership while looking for a
                        # locally trusted catalog, up to the global cap.
                        if candidate is None:
                            candidate = result
                    if count == 8:
                        lookup_failed = True
                finally:
                    if previous.value:
                        self.release_cat(admin, previous, 0)
            finally:
                self.release_admin(admin, 0)
        if candidate is not None:
            return candidate
        if lookup_failed:
            return ExecutableSigner(Availability.UNAVAILABLE)
        if unsupported:
            return ExecutableSigner(Availability.UNSUPPORTED)
        return ExecutableSigner(Availability.AVAILABLE, SignatureKind.NONE, SignatureValidation.NOT_SIGNED)


class WindowsExecutableSigner:
    """One synchronous adapter call; application service supplies the bounded worker."""

    def __init__(self, *, max_bytes: int = 1_073_741_824, cache_capacity: int = 128,
                 cache_ttl: float = 60.0, clock: Callable[[], float] = monotonic,
                 native: _WindowsTrust | None = None) -> None:
        if max_bytes <= 0 or cache_capacity <= 0 or not 0 < cache_ttl <= 3600:
            raise ValueError("invalid signer bounds")
        self.max_bytes, self.cache_capacity, self.cache_ttl = max_bytes, cache_capacity, cache_ttl
        self._clock = clock
        self._native = native
        self._cache: OrderedDict[FileKey, tuple[float, ExecutableSigner]] = OrderedDict()
        self._lock = Lock()

    @property
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def verify(self, path: str, *, is_cancelled: Callable[[], bool]) -> ExecutableSigner:
        if not isinstance(path, str) or not path or len(path) > MAX_EXECUTABLE_PATH_LENGTH or any(ord(c) < 32 for c in path) or not os.path.isabs(path):
            return ExecutableSigner(Availability.INVALID_PATH)
        if path.startswith(("\\\\", "//")):
            return ExecutableSigner(Availability.REMOTE_PATH)
        if is_cancelled():
            return ExecutableSigner(Availability.CANCELLED)
        try:
            if Path(path).is_symlink():
                return ExecutableSigner(Availability.UNAVAILABLE)
            before = os.stat(path)
            if not stat.S_ISREG(before.st_mode):
                return ExecutableSigner(Availability.INVALID_PATH)
            if before.st_size > self.max_bytes:
                return ExecutableSigner(Availability.TOO_LARGE)
            key = _key(before, path)
            with open(path, "rb") as stream:
                if _key(os.fstat(stream.fileno()), path) != key:
                    return ExecutableSigner(Availability.FILE_CHANGED)
                with self._lock:
                    cached = self._cache.get(key)
                    if cached and self._clock() - cached[0] <= self.cache_ttl:
                        result = cached[1]
                        self._cache.move_to_end(key)
                    else:
                        result = None
                if result is None:
                    native = self._native or _WindowsTrust()
                    handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
                    result = native.inspect(path, handle, cancelled=is_cancelled)
                try:
                    after = os.stat(path)
                except FileNotFoundError:
                    return ExecutableSigner(Availability.FILE_CHANGED)
                if (_key(os.fstat(stream.fileno()), path) != key or _key(after, path) != key):
                    return ExecutableSigner(Availability.FILE_CHANGED)
            if is_cancelled():
                return ExecutableSigner(Availability.CANCELLED)
            if result.availability is Availability.AVAILABLE:
                with self._lock:
                    self._cache[key] = (self._clock(), result)
                    self._cache.move_to_end(key)
                    if len(self._cache) > self.cache_capacity:
                        self._cache.popitem(last=False)
            return result
        except PermissionError:
            return ExecutableSigner(Availability.ACCESS_DENIED)
        except FileNotFoundError:
            return ExecutableSigner(Availability.NOT_FOUND)
        except (IsADirectoryError, NotADirectoryError, ValueError):
            return ExecutableSigner(Availability.INVALID_PATH)
        except (OSError, AttributeError):
            return ExecutableSigner(Availability.UNAVAILABLE)
