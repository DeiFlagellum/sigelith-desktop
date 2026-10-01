"""AEAD segmentowy (AES-256-GCM-STREAM) — kontrakt SEAL.md sekcja 5.

LUSTRO `apps/seal/stream.py` (serwer): ta sama konstrukcja, ten sam kod.
Handover (HANDOVER_SPEC.md §2) szyfruje tresc paczki dokladnie tak jak
koperta `beattime-seal-v1`, wiec desktop nie moze miec „wlasnej wersji" —
zgodnosc bajt w bajt pilnuje `tests/test_handover.py: StreamParityTests`
(laduje plik serwera ze sciezki, bez Django).

Konstrukcja STREAM, jak w Tink `AES-GCM-HKDF-STREAMING` i w `age`:

    segment    = 65536 bajtow plaintextu (ostatni krotszy, moze byc pusty)
    nonce      = prefiks (7 B) || licznik (4 B BE, od 0) || last (1 B)
    szyfrogram = konkatenacja AES-256-GCM(k, nonce_i, segment_i, aad)

Kazdy segment niesie wlasny tag, wiec strumien weryfikuje sie w locie i nikt
nie dostaje nieuwierzytelnionego plaintextu. Licznik w nonce blokuje
przestawienie segmentow, flaga `last` blokuje obciecie konca.
"""
from __future__ import annotations

from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEGMENT = 65_536
NONCE_PREFIX_LEN = 7
TAG_LEN = 16
_COUNTER_MAX = 2 ** 32 - 1


def nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if len(prefix) != NONCE_PREFIX_LEN:
        raise ValueError(f'prefiks nonce musi miec {NONCE_PREFIX_LEN} bajtow')
    if not 0 <= counter <= _COUNTER_MAX:
        raise ValueError('licznik segmentow poza zakresem 32 bitow')
    return prefix + counter.to_bytes(4, 'big') + (b'\x01' if last else b'\x00')


def _read_exactly(src: BinaryIO, size: int) -> bytes:
    """Czyta dokladnie `size` bajtow albo mniej, gdy strumien sie skonczyl.

    `read(n)` wolno zwrocic mniej niz n takze przed koncem danych. Bez tej
    petli podzial na segmenty zalezalby od zrodla — i szyfrogram nie bylby
    odtwarzalny.
    """
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = src.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _segments(src: BinaryIO, size: int):
    """Wydaje (dane, czy_ostatni). Zawsze co najmniej jeden segment."""
    current = _read_exactly(src, size)
    while True:
        nxt = _read_exactly(src, size)
        if not nxt:
            yield current, True
            return
        yield current, False
        current = nxt


def ciphertext_size(plaintext_size: int, segment: int = SEGMENT) -> int:
    """Dlugosc szyfrogramu dla danej dlugosci plaintextu (zawsze >= 1 segment)."""
    segments = max(1, -(-plaintext_size // segment))
    return plaintext_size + segments * TAG_LEN


def encrypt(key: bytes, prefix: bytes, aad: bytes, src: BinaryIO, dst: BinaryIO,
            segment: int = SEGMENT) -> int:
    """Szyfruje strumien segmentami. Zwraca dlugosc szyfrogramu w bajtach."""
    aead = AESGCM(key)
    written = 0
    for counter, (chunk, last) in enumerate(_segments(src, segment)):
        blob = aead.encrypt(nonce(prefix, counter, last), chunk, aad)
        dst.write(blob)
        written += len(blob)
    return written


def decrypt(key: bytes, prefix: bytes, aad: bytes, src: BinaryIO, dst: BinaryIO,
            segment: int = SEGMENT) -> int:
    """Odszyfrowuje strumien. Zwraca dlugosc plaintextu w bajtach.

    Plaintext segmentu trafia do `dst` DOPIERO po sprawdzeniu jego tagu.
    """
    aead = AESGCM(key)
    written = 0
    saw_last = False
    for counter, (blob, last) in enumerate(_segments(src, segment + TAG_LEN)):
        if len(blob) < TAG_LEN:
            raise ValueError('szyfrogram obciety: segment krotszy niz sam tag')
        chunk = aead.decrypt(nonce(prefix, counter, last), blob, aad)
        dst.write(chunk)
        written += len(chunk)
        saw_last = last
    if not saw_last:
        raise ValueError('szyfrogram bez segmentu koncowego')
    return written
