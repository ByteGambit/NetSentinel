from __future__ import annotations

from netsentinel.domain.executable_signer import (
    ExecutableSigner, LocalTrust, SignatureKind, SignatureValidation,
    SignerAvailability, SignerIdentity,
)
from netsentinel.presentation.widgets.connection_details import ConnectionDetailsWidget


def test_detail_keeps_signature_trust_and_revocation_separate(qtbot) -> None:
    widget = ConnectionDetailsWidget()
    qtbot.addWidget(widget)
    result = ExecutableSigner(SignerAvailability.AVAILABLE, SignatureKind.CATALOG,
                              SignatureValidation.VALID, LocalTrust.TRUSTED_LOCAL_POLICY,
                              signer=SignerIdentity("Example", "Example CA", "b" * 64),
                              timestamp_present=True)
    widget.set_signer_result(result)
    displayed = widget.signer_text.text()
    assert "Signature source: catalog" in displayed
    assert "Signature validation: valid" in displayed
    assert "Local Windows trust: trusted local policy" in displayed
    assert "Revocation: not checked" in displayed
    assert "Example CA" in displayed and "b" * 64 in displayed
    assert "safe application" not in displayed.lower()
