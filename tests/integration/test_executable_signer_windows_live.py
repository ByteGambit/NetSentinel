"""Explicit, read-only Windows host trust-store test; never in default suite."""

from __future__ import annotations

import os
from pathlib import Path
import shutil

import pytest

from netsentinel.domain.executable_signer import SignatureKind, SignatureValidation, SignerAvailability
from netsentinel.infrastructure.windows_executable_signer import WindowsExecutableSigner


@pytest.mark.windows_live
def test_embedded_catalog_and_modified_local_copies(tmp_path: Path) -> None:
    signer = WindowsExecutableSigner()
    root = Path(os.environ["WINDIR"])
    embedded = root / "explorer.exe"
    catalog = root / "System32" / "notepad.exe"
    def verify(path: Path):
        return signer.verify(str(path), is_cancelled=lambda: False)
    one, two = verify(embedded), verify(catalog)
    assert one.kind is SignatureKind.EMBEDDED
    assert two.kind is SignatureKind.CATALOG
    assert one.validation is two.validation is SignatureValidation.VALID
    assert one.signer is not None and two.signer is not None
    for source, expected in ((embedded, SignatureKind.EMBEDDED), (catalog, SignatureKind.CATALOG)):
        copy = tmp_path / source.name
        shutil.copyfile(source, copy)
        with copy.open("r+b") as stream:
            stream.seek(200000)
            original = stream.read(1)
            stream.seek(200000)
            stream.write(bytes([original[0] ^ 1]))
        changed = verify(copy)
        if expected is SignatureKind.EMBEDDED:
            assert changed.kind is SignatureKind.EMBEDDED
            assert changed.validation is SignatureValidation.INVALID
        else:
            assert changed.availability is SignerAvailability.AVAILABLE
            assert changed.kind is SignatureKind.NONE


@pytest.mark.windows_live
def test_unsigned_and_non_pe_local_samples(tmp_path: Path) -> None:
    signer = WindowsExecutableSigner()
    unsigned = Path(__file__).parents[2] / ".venv" / "Scripts" / "python.exe"
    if not unsigned.exists():
        pytest.skip("local venv executable unavailable")
    result = signer.verify(str(unsigned), is_cancelled=lambda: False)
    assert result.kind is SignatureKind.NONE
    assert result.validation is SignatureValidation.NOT_SIGNED
    non_pe = tmp_path / "plain.txt"
    non_pe.write_bytes(b"plain")
    assert signer.verify(str(non_pe), is_cancelled=lambda: False).availability is SignerAvailability.UNSUPPORTED
