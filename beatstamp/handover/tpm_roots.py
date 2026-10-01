"""
Przypiete korzenie atestacji TPM — HANDOVER_SPEC.md §3.6.

Atestacje Windows Hello (format `tpm`) koncza sie certyfikatem wystawionym przez
Microsoft dla producenta TPM (np. „INTC-KEYID-..." dla Intela), a ten — przez
ponizszy korzen. Korzenia NIE ma w atestacji: musi byc wbudowany w program,
tak jak klucze dziennika w keys.py. Kazdy inny korzen = atestacja odrzucona.

Zrodlo: https://www.microsoft.com/pkiops/certs/Microsoft%20TPM%20Root%20Certificate%20Authority%202014.crt
(adres z rozszerzenia AIA certyfikatow posrednich), pobrany 2026-09-28 i
sprawdzony na prawdziwej atestacji Windows Hello: podpisuje certyfikat
posredni INTC-KEYID-EA95... (sha256WithRSAEncryption). RSA 4096, wazny
2014-12-10 .. 2039-12-10.

LUSTRO: apps/web/static/web/handover/attestation.js (TPM_ROOTS). Zgodnosc
pilnuja wektory i test odcisku ponizej.
"""
from __future__ import annotations

import base64
import hashlib

MICROSOFT_TPM_ROOT_2014_SHA256 = '870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da'
MICROSOFT_TPM_ROOT_2014 = base64.b64decode(
    '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')

if hashlib.sha256(MICROSOFT_TPM_ROOT_2014).hexdigest() != MICROSOFT_TPM_ROOT_2014_SHA256:
    raise RuntimeError('przypiety korzen TPM uszkodzony — odcisk sie nie zgadza')

# (nazwa pokazywana w raporcie, certyfikat DER)
TPM_ROOTS: tuple[tuple[str, bytes], ...] = (
    ('Microsoft TPM Root Certificate Authority 2014', MICROSOFT_TPM_ROOT_2014),
)
