"""Wyjatek pakietu Handover ze stalym kodem bledu."""
from __future__ import annotations


class HandoverError(ValueError):
    """Blad formatu, kryptografii albo reguly protokolu.

    `code` jest STALY: uzywaja go testy, zamrozone wektory testowe (ta sama
    lista kodow obowiazuje drugi, niezalezny weryfikator w JS) i interfejs,
    ktory tlumaczy kod na komunikat dla czlowieka. `detail` jest po angielsku
    i sluzy diagnostyce — nie jest tekstem dla uzytkownika.
    """

    def __init__(self, code: str, detail: str = '') -> None:
        super().__init__(f'{code}: {detail}' if detail else code)
        self.code = code
        self.detail = detail

    def renamed(self, code: str) -> 'HandoverError':
        """Ten sam blad pod kodem warstwy wyzej (np. `json-number` -> `offer-structure`).

        Szczegol zostaje, zeby diagnostyka nie gubila przyczyny, ale kod mowi,
        KTORY obiekt jest zly — tego potrzebuje interfejs i weryfikator.
        """
        return HandoverError(code, f'{self.code}: {self.detail}' if self.detail else self.code)
