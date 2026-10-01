"""
Pliki i koperty transportowe — HANDOVER_SPEC.md §10.

Paczka i odpowiedz jada kanalami stron (mail, komunikator, folder wymiany,
pendrive), nigdy przez serwer Sigelith. Koperta HPKE do adresata sprawia, ze
dostawca poczty albo chmury widzi tylko rozmiary: ani kart, ani nazw, ani
podgladu. Naglowek pliku nie nazywa adresata — aplikacja z kilkoma kartami
probuje kazdego swojego klucza.
"""
from __future__ import annotations

import io
import shutil
from typing import BinaryIO

from . import jcs
from .errors import HandoverError
from .primitives import (
    D_ENVELOPE, EncKey, HPKE_OVERHEAD, b64url, b64url_decode, hpke_seal)

MAGIC = b'SIGELITH-HANDOVER-1\n'
HEADER_MAX = 1024
ENVELOPE_MAX = 256 * 1024
ANSWER_TEXT_PREFIX = 'sigelith:answer:'
PACKAGE_HEADER_FIELDS = frozenset({'kind', 'envelope_size', 'ciphertext_size'})
ANSWER_HEADER_FIELDS = frozenset({'kind', 'envelope_size'})


def seal_envelope(recipient_enc_key: bytes, obj: dict) -> bytes:
    return hpke_seal(recipient_enc_key, jcs.dumps(obj), D_ENVELOPE)


def open_envelope(keys: list[EncKey], data: bytes) -> dict:
    """Otwiera koperte ktorymkolwiek z kluczy. Tresc musi byc kanonicznym JSON."""
    for key in keys:
        try:
            plain = key.open(data, D_ENVELOPE)
        except HandoverError:
            continue
        try:
            obj = jcs.loads(plain)
        except HandoverError as e:
            raise e.renamed('envelope') from None
        if not isinstance(obj, dict):
            raise HandoverError('envelope', 'the envelope does not hold an object')
        return obj
    raise HandoverError('envelope-not-mine', 'none of my keys opens this envelope')


def _write_header(dst: BinaryIO, header: dict) -> None:
    dst.write(MAGIC + jcs.dumps(header) + b'\n')


def _read_header(src: BinaryIO, kind: str, fields: frozenset) -> dict:
    if src.read(len(MAGIC)) != MAGIC:
        raise HandoverError('file-format', 'not a Sigelith Handover file')
    line = src.readline(HEADER_MAX + 1)
    if not line.endswith(b'\n'):
        raise HandoverError('file-format', 'header line missing or too long')
    try:
        header = jcs.loads(line[:-1], max_bytes=HEADER_MAX)
    except HandoverError as e:
        raise e.renamed('file-format') from None
    if not isinstance(header, dict) or set(header) != fields or header['kind'] != kind:
        raise HandoverError('file-format', f'not a {kind} file')
    size = header['envelope_size']
    if type(size) is not int or not HPKE_OVERHEAD < size <= ENVELOPE_MAX:
        raise HandoverError('file-format', 'envelope size out of range')
    return header


def _read_exact(src: BinaryIO, size: int) -> bytes:
    data = src.read(size)
    if len(data) != size:
        raise HandoverError('file-format', 'the file ends too early')
    return data


def write_package_file(dst: BinaryIO, recipient_enc_key: bytes, offer: dict,
                       ciphertext: BinaryIO, ciphertext_size: int) -> None:
    """Plik paczki: magia, naglowek, koperta z oferta, szyfrogram."""
    envelope = seal_envelope(recipient_enc_key, offer)
    _write_header(dst, {'kind': 'package', 'envelope_size': len(envelope),
                        'ciphertext_size': ciphertext_size})
    dst.write(envelope)
    shutil.copyfileobj(ciphertext, dst)


def read_package_file(src: BinaryIO, keys: list[EncKey]) -> tuple[dict, int]:
    """(oferta, dlugosc szyfrogramu). `src` zostaje ustawiony na poczatku szyfrogramu."""
    header = _read_header(src, 'package', PACKAGE_HEADER_FIELDS)
    size = header['ciphertext_size']
    if type(size) is not int or size < 16:
        raise HandoverError('file-format', 'ciphertext size out of range')
    offer = open_envelope(keys, _read_exact(src, header['envelope_size']))
    return offer, size


def write_answer_file(sender_enc_key: bytes, answer: dict) -> bytes:
    envelope = seal_envelope(sender_enc_key, answer)
    header = jcs.dumps({'kind': 'answer', 'envelope_size': len(envelope)})
    return MAGIC + header + b'\n' + envelope


def read_answer_file(data: bytes, keys: list[EncKey]) -> dict:
    src = io.BytesIO(data)
    header = _read_header(src, 'answer', ANSWER_HEADER_FIELDS)
    envelope = _read_exact(src, header['envelope_size'])
    if src.read(1):
        raise HandoverError('file-format', 'bytes after the envelope')
    return open_envelope(keys, envelope)


CARD_MAGIC = b'SIGELITH-CARD-1\n'
CARD_FILE_MAX = 64 * 1024


def write_card_file(card: dict, attestation: dict | None = None) -> bytes:
    """Plik karty (§3.6): karta i — z wyboru wlasciciela — jej atestacja.

    Karta nie jest tajna (to klucze PUBLICZNE), wiec plik nie ma koperty. Kto
    go dostaje, sprawdza karte (`read_card`) i atestacje (`read_attestation`).
    """
    return CARD_MAGIC + jcs.dumps({'card': card, 'attestation': attestation})


def read_card_file(data: bytes) -> tuple[dict, dict | None]:
    """(karta, atestacja albo None) — tylko ksztalt; podpisy sprawdza wolajacy."""
    if not data.startswith(CARD_MAGIC):
        raise HandoverError('file-format', 'not a Sigelith card file')
    try:
        body = jcs.loads(data[len(CARD_MAGIC):], max_bytes=CARD_FILE_MAX)
    except HandoverError as e:
        raise e.renamed('file-format') from None
    if (not isinstance(body, dict) or set(body) != {'card', 'attestation'}
            or not isinstance(body['card'], dict)
            or not (body['attestation'] is None or isinstance(body['attestation'], dict))):
        raise HandoverError('file-format', 'a card file holds a card and an optional attestation')
    return body['card'], body['attestation']


def answer_text(answer_file: bytes) -> str:
    """Odpowiedz jako tekst do wklejenia w mail albo komunikator."""
    return ANSWER_TEXT_PREFIX + b64url(answer_file)


def parse_answer_text(text: str) -> bytes:
    text = ''.join(text.split())          # zawijanie linii przez klienta poczty
    if not text.startswith(ANSWER_TEXT_PREFIX):
        raise HandoverError('file-format', f'the text must start with {ANSWER_TEXT_PREFIX}')
    return b64url_decode(text[len(ANSWER_TEXT_PREFIX):], 'answer text')
