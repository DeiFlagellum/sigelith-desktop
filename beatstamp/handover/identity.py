"""
Karta Sigelith ID, odcisk i zapis powiazania — HANDOVER_SPEC.md §3.

Karta to dwa klucze publiczne wlasciciela: do podpisu (P-256, docelowo w TPM
z Windows Hello) i do szyfrowania (hybryda ML-KEM-768 + X25519). Nie ma w niej
imienia, e-maila ani etykiety — etykieta jest lokalna w ksiazce adresowej.

Sygnatariusz (`Signer`) to wszystko, co umie podpisac komunikat kluczem z
karty. Tutaj sa dwa programowe: `SoftwareSigner` (es256 — zapas bez TPM
i testy) oraz `SoftwareWebAuthnSigner` (es256-webauthn — wylacznie testy
i wektory). Sygnatariusz Windows Hello dochodzi w warstwie aplikacji i spelnia
ten sam protokol.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import date, datetime
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import ec

from .errors import HandoverError
from .primitives import (
    D_BINDING, D_CARD, ENC_ALG, ENC_PUBLIC_LEN, P256_PUBLIC_LEN, SIG_ALGS, VERSION,
    b64decode, b64encode, crockford, enc_public, es256_sign, format_ts, hex32,
    p256_public, p256_public_bytes, parse_day, parse_ts, sha256, signed_message,
    verify_signature, webauthn_sign)
from .rules import check_text

SIG_STORAGES = ('hardware-uv', 'software')
CARD_FIELDS = frozenset({'v', 'type', 'sig_alg', 'sig_key', 'sig_storage', 'enc_alg',
                         'enc_key', 'created', 'sig'})

# Poziom wynika z metody (§3.3) — nie da sie zapisac „voice" z poziomem 1.
BINDING_METHODS = {'qr-in-person': 1, 'signed-document': 2, 'handshake': 3,
                   'voice': 4, 'channel': 5}
BINDING_FIELDS = frozenset({'v', 'type', 'by', 'card', 'level', 'method', 'date',
                            'note', 'sig'})
BINDING_NOTE_MAX = 500


class Signer(Protocol):
    """Cos, co podpisuje komunikat kluczem `sig_key` karty."""

    alg: str
    storage: str

    @property
    def public_bytes(self) -> bytes: ...

    def sign(self, message: bytes) -> object: ...


class SoftwareSigner:
    """Klucz programowy P-256, podpis `es256` (zapas bez TPM; testy)."""

    alg = 'es256'

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None,
                 storage: str = 'software') -> None:
        self._key = private_key or ec.generate_private_key(ec.SECP256R1())
        if not isinstance(self._key.curve, ec.SECP256R1):
            raise ValueError('klucz podpisu musi byc P-256')
        if storage not in SIG_STORAGES:
            raise ValueError(f'sig_storage: {SIG_STORAGES}')
        self.storage = storage

    @classmethod
    def from_bytes(cls, raw: bytes, storage: str = 'software') -> 'SoftwareSigner':
        if len(raw) != 32:
            raise ValueError('klucz prywatny P-256 ma 32 bajty')
        return cls(ec.derive_private_key(int.from_bytes(raw, 'big'), ec.SECP256R1()),
                   storage)

    def to_bytes(self) -> bytes:
        return self._key.private_numbers().private_value.to_bytes(32, 'big')

    @property
    def public_bytes(self) -> bytes:
        return p256_public_bytes(self._key.public_key())

    def sign(self, message: bytes) -> object:
        return b64encode(es256_sign(self._key, message))


class SoftwareWebAuthnSigner(SoftwareSigner):
    """Programowy odpowiednik Windows Hello (`es256-webauthn`) — testy i wektory."""

    alg = 'es256-webauthn'

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None,
                 storage: str = 'software', user_verified: bool = True) -> None:
        super().__init__(private_key, storage)
        self.user_verified = user_verified
        self.sign_count = 1

    def sign(self, message: bytes) -> object:
        sig = webauthn_sign(self._key, message, sign_count=self.sign_count,
                            user_verified=self.user_verified)
        self.sign_count += 1
        return sig


def _require_fields(obj: object, fields: frozenset, code: str) -> dict:
    if not isinstance(obj, dict) or set(obj) != fields:
        missing = sorted(fields - set(obj)) if isinstance(obj, dict) else []
        extra = sorted(set(obj) - fields) if isinstance(obj, dict) else []
        raise HandoverError(code, f'fields: missing {missing}, unexpected {extra}')
    return obj


def fingerprint_text(fingerprint: bytes) -> str:
    """Odcisk do pokazania i porownania glosem: 8 grup po 4 znaki (160 bitow)."""
    text = crockford(fingerprint[:20])
    return '-'.join(text[i:i + 4] for i in range(0, len(text), 4))


@dataclass(frozen=True)
class Card:
    """Karta po weryfikacji podpisu."""

    raw: dict
    fingerprint: bytes
    sig_alg: str
    sig_key: bytes
    storage: str
    enc_key: bytes
    created: datetime

    @property
    def fingerprint_hex(self) -> str:
        return self.fingerprint.hex()

    @property
    def fingerprint_text(self) -> str:
        return fingerprint_text(self.fingerprint)


def make_card(signer: Signer, enc_public_key: bytes, created: datetime) -> dict:
    """Nowa karta podpisana kluczem `signer` (Windows Hello pyta raz, przy tworzeniu)."""
    enc_public(enc_public_key)                       # walidacja przed podpisem
    card = {'v': VERSION, 'type': 'card', 'sig_alg': signer.alg,
            'sig_key': b64encode(signer.public_bytes), 'sig_storage': signer.storage,
            'enc_alg': ENC_ALG, 'enc_key': b64encode(enc_public_key),
            'created': format_ts(created)}
    card['sig'] = signer.sign(signed_message(D_CARD, card))
    read_card(card)
    return card


def read_card(card: object) -> Card:
    """Sprawdza karte (struktura, klucze, podpis) i liczy jej odcisk."""
    _require_fields(card, CARD_FIELDS, 'card-structure')
    try:
        if card['v'] != VERSION or card['type'] != 'card':
            raise HandoverError('card-structure', 'not a sigelith-handover-v1 card')
        if card['sig_alg'] not in SIG_ALGS:
            raise HandoverError('card-structure', f'sig_alg: {SIG_ALGS}')
        if card['sig_storage'] not in SIG_STORAGES:
            raise HandoverError('card-structure', f'sig_storage: {SIG_STORAGES}')
        if card['enc_alg'] != ENC_ALG:
            raise HandoverError('card-structure', f'enc_alg: {ENC_ALG}')
        sig_key = b64decode(card['sig_key'], 'sig_key', P256_PUBLIC_LEN)
        p256_public(sig_key)
        enc_key = b64decode(card['enc_key'], 'enc_key', ENC_PUBLIC_LEN)
        enc_public(enc_key)
        created = parse_ts(card['created'], 'created')
        message = signed_message(D_CARD, card)
    except HandoverError as e:
        raise (e if e.code == 'card-structure' else e.renamed('card-structure')) from None
    try:
        verify_signature(card['sig_alg'], sig_key, message, card['sig'])
    except HandoverError as e:
        raise e.renamed('card-signature') from None
    return Card(raw=card, fingerprint=sha256(message), sig_alg=card['sig_alg'],
                sig_key=sig_key, storage=card['sig_storage'], enc_key=enc_key,
                created=created)


# --- zapis powiazania (§3.4) --------------------------------------------------

@dataclass(frozen=True)
class Binding:
    raw: dict
    digest: bytes
    by: bytes
    card: bytes
    level: int
    method: str
    day: date
    note: str


def make_binding(signer: Signer, recorder: Card, subject: Card, method: str,
                 day: date, note: str = '') -> dict:
    """Zapis „tak sprawdzilem te karte" — podpisany przez zapisujacego."""
    if signer.public_bytes != recorder.sig_key:
        raise HandoverError('signer', 'the signer does not match the recorder card')
    record = {'v': VERSION, 'type': 'binding', 'by': recorder.fingerprint_hex,
              'card': subject.fingerprint_hex, 'level': BINDING_METHODS.get(method, 0),
              'method': method, 'date': day.isoformat(), 'note': note}
    record['sig'] = signer.sign(signed_message(D_BINDING, record))
    read_binding(record, recorder, subject)
    return record


def read_binding(record: object, recorder: Card, subject: Card | None = None) -> Binding:
    _require_fields(record, BINDING_FIELDS, 'binding-structure')
    try:
        if record['v'] != VERSION or record['type'] != 'binding':
            raise HandoverError('binding-structure', 'not a binding record')
        by = hex32(record['by'], 'by')
        card = hex32(record['card'], 'card')
        method = record['method']
        if method not in BINDING_METHODS:
            raise HandoverError('binding-structure', f'method: {sorted(BINDING_METHODS)}')
        level = record['level']
        if type(level) is not int or level != BINDING_METHODS[method]:
            raise HandoverError('binding-structure', 'level does not match the method')
        day = parse_day(record['date'], 'date')
        check_text(record['note'], 'note', BINDING_NOTE_MAX)
        message = signed_message(D_BINDING, record)
    except HandoverError as e:
        raise (e if e.code == 'binding-structure' else e.renamed('binding-structure')) from None
    if not hmac.compare_digest(by, recorder.fingerprint):
        raise HandoverError('binding-recorder', 'the record was made by another card')
    if subject is not None and not hmac.compare_digest(card, subject.fingerprint):
        raise HandoverError('binding-subject', 'the record binds another card')
    try:
        verify_signature(recorder.sig_alg, recorder.sig_key, message, record['sig'])
    except HandoverError as e:
        raise e.renamed('binding-signature') from None
    return Binding(raw=record, digest=sha256(message), by=by, card=card, level=level,
                   method=method, day=day, note=record['note'])


def card_bytes_for_qr(card: Card) -> bytes:
    """QR pokazuje TYLKO odcisk (32 B) — cala karta ma ~2 KB i jedzie plikiem."""
    return card.fingerprint


def same_card(a: Card, b: Card) -> bool:
    return hmac.compare_digest(a.fingerprint, b.fingerprint)


__all__ = ['BINDING_METHODS', 'Binding', 'Card', 'Signer', 'SoftwareSigner',
           'SoftwareWebAuthnSigner', 'fingerprint_text', 'make_binding', 'make_card',
           'read_binding', 'read_card', 'same_card']
