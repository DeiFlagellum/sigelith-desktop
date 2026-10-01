"""
Potwierdzenie czasow z pakietu dowodowego POZA kontrola Sigelith.

Werdykt Handover stoi na kwitach dziennika (HANDOVER_SPEC.md §12.1) — to
podpis Sigelith. Strona weryfikatora obiecuje, ze Sigelith Desktop sprawdza
wiecej (HANDOVER.md N16): czy wpis siedzi pod checkpointem, ktory aplikacja
sama zweryfikowala, i ktore niezalezne kopie (GitHub, Internet Archive,
Zenodo) ten checkpoint maja. Robi to ten sam swiadek co dla zwyklych stempli
(witness.py) — tutaj tylko przykladamy go do odpowiedzi zapisanych w pakiecie.

Wynik to informacja, nie warunek werdyktu: swiezy dowod ma kwit od razu,
a checkpoint dopiero po dobie.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import proof, witness
from ..config import json_loads


@dataclass(frozen=True)
class Confirmation:
    checkpoint: int | None          # numer checkpointu obejmujacego wpis
    verified: bool                  # sciezka do checkpointu, ktory aplikacja zweryfikowala
    sources: tuple[str, ...]        # github / wayback / zenodo — maja zgodna kopie

    @property
    def independent(self) -> bool:
        return self.verified and bool(self.sources)


def confirmations(log_texts: dict[str, str], state: witness.WitnessState, *,
                  key_override: str = '') -> dict[str, Confirmation]:
    """Dla kazdego skrotu z mapy `log` pakietu: co wie o nim nasz swiadek."""
    out: dict[str, Confirmation] = {}
    for digest, text in log_texts.items():
        try:
            payload = json_loads(text)
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        result = proof.verify_payload(payload, expected_digest=digest, key_override=key_override)
        witness.enrich_from_payload(result, state, payload)
        pin = witness.pinning(result.checkpoint, state)
        out[digest] = Confirmation(checkpoint=pin.checkpoint, verified=pin.verified,
                                   sources=tuple(pin.sources))
    return out
