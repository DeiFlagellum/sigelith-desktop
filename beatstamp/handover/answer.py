"""
Odpowiedz odbiorcy i reguly nadawcy przed publikacja B — HANDOVER_SPEC.md §6, §7.3-7.4.

Akceptacja jest WARUNKOWA: „wchodzi w zycie w chwili zapisania w dzienniku
czesci klucza z oferty, jesli stanie sie to najpozniej o `valid_until`". Dzieki
temu nadawca nie ma dowodu, dopoki odbiorca nie moze czytac, a odbiorca nie
czyta, dopoki nadawca nie ma dowodu.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta

from .errors import HandoverError
from .identity import Signer
from .package import Offer
from .primitives import (
    D_ANSWER, VERSION, format_ts, hex32, parse_ts, sha256, signed_message,
    verify_signature)

DECISIONS = ('accept', 'refuse')
_COMMON = {'v', 'type', 'decision', 'offer', 'signed_at', 'sig'}
ANSWER_FIELDS = {'accept': frozenset(_COMMON | {'ciphertext_sha256', 'valid_until'}),
                 'refuse': frozenset(_COMMON)}
PUBLISH_MARGIN = timedelta(hours=1)


@dataclass(frozen=True)
class Answer:
    raw: dict
    digest: bytes
    decision: str
    offer_digest: bytes
    ciphertext_sha256: bytes | None
    valid_until: datetime | None
    signed_at: datetime

    @property
    def accepted(self) -> bool:
        return self.decision == 'accept'


def make_answer(signer: Signer, offer: Offer, decision: str, *, log_now: datetime,
                ciphertext_sha256: bytes | None = None) -> dict:
    """Odpowiedz podpisana kluczem odbiorcy (Windows Hello pyta przy `sign`).

    `log_now` to czas DZIENNIKA — od niego liczy sie `valid_until`. Aplikacja
    MUSI ostemplowac skrot odpowiedzi, zanim ja komukolwiek wyda (§6).
    """
    if signer.public_bytes != offer.recipient.sig_key or signer.alg != offer.recipient.sig_alg:
        raise HandoverError('signer', 'the signer does not match the recipient card')
    if decision not in DECISIONS:
        raise HandoverError('answer-structure', f'decision: {DECISIONS}')
    now = log_now.replace(microsecond=0)
    if now >= offer.expires:
        raise HandoverError('offer-expired', 'the offer has expired')
    answer = {'v': VERSION, 'type': 'answer', 'decision': decision,
              'offer': offer.digest.hex(), 'signed_at': format_ts(now)}
    if decision == 'accept':
        if ciphertext_sha256 is None or not hmac.compare_digest(ciphertext_sha256,
                                                                offer.ciphertext_sha256):
            raise HandoverError('answer-ciphertext', 'the recipient does not hold the '
                                'offered ciphertext')
        answer['ciphertext_sha256'] = ciphertext_sha256.hex()
        answer['valid_until'] = format_ts(now + timedelta(seconds=offer.complete_within))
    answer['sig'] = signer.sign(signed_message(D_ANSWER, answer))
    read_answer(answer, offer)
    return answer


def read_answer(answer: object, offer: Offer) -> Answer:
    """Sprawdza odpowiedz na KONKRETNA oferte: struktura, skrot, podpis, termin."""
    decision = answer.get('decision') if isinstance(answer, dict) else None
    fields = ANSWER_FIELDS.get(decision) if isinstance(decision, str) else None
    if fields is None or set(answer) != fields:
        raise HandoverError('answer-structure', 'not an acceptance or a refusal')
    try:
        if answer['v'] != VERSION or answer['type'] != 'answer':
            raise HandoverError('answer-structure', 'not a sigelith-handover-v1 answer')
        offer_digest = hex32(answer['offer'], 'offer')
        signed_at = parse_ts(answer['signed_at'], 'signed_at')
        ciphertext_sha256 = valid_until = None
        if decision == 'accept':
            ciphertext_sha256 = hex32(answer['ciphertext_sha256'], 'ciphertext_sha256')
            valid_until = parse_ts(answer['valid_until'], 'valid_until')
        message = signed_message(D_ANSWER, answer)
    except HandoverError as e:
        raise (e if e.code == 'answer-structure' else e.renamed('answer-structure')) from None
    if not hmac.compare_digest(offer_digest, offer.digest):
        raise HandoverError('answer-offer', 'the answer is for another offer')
    try:
        verify_signature(offer.recipient.sig_alg, offer.recipient.sig_key, message,
                         answer['sig'])
    except HandoverError as e:
        raise e.renamed('answer-signature') from None
    if decision == 'accept':
        assert ciphertext_sha256 is not None and valid_until is not None
        if not hmac.compare_digest(ciphertext_sha256, offer.ciphertext_sha256):
            raise HandoverError('answer-ciphertext', 'the answer names another ciphertext')
        if valid_until > offer.answer_bound:
            raise HandoverError('answer-deadline', 'valid_until is later than the offer allows')
    return Answer(raw=answer, digest=sha256(message), decision=decision,
                  offer_digest=offer_digest, ciphertext_sha256=ciphertext_sha256,
                  valid_until=valid_until, signed_at=signed_at)


def check_publish(answer: Answer, log_now: datetime, *, refused: bool = False) -> None:
    """Czy nadawca moze TERAZ opublikowac B (§7.4). Blad = nie publikowac.

    Margines godziny: stempel dostaje czas serwera, a nie chwile wyslania
    zadania. Publikacja „na styk" moglaby dostac czas po `valid_until` —
    akceptacja nie weszlaby w zycie, a B bylaby juz publiczna.
    """
    if not answer.accepted:
        raise HandoverError('answer-refused', 'the answer is a refusal')
    if refused:
        raise HandoverError('offer-refused', 'the recipient has refused this offer')
    assert answer.valid_until is not None
    if answer.valid_until - log_now < PUBLISH_MARGIN:
        raise HandoverError('answer-deadline-near', 'less than an hour left before '
                            'valid_until')
