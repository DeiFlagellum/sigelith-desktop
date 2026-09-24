"""
Odmiana liczebnikow — dla kazdego jezyka interfejsu, nie tylko angielskiego.

Powod istnienia tego modulu jest prosty: „6 wpis(ow)" to nie jest polski.
Tak wyglada tekst przetlumaczony maszynowo z angielskiego, gdzie liczba mnoga
ma jedna forme. Polski ma trzy i wybiera je wedlug reszty z dzielenia:

    1 wpis          — mianownik liczby pojedynczej (dokladnie 1, nie 21!)
    2, 3, 4 wpisy   — forma mnoga „few"  (takze 22, 23, 24, 102, 103…)
    5..21 wpisow    — forma mnoga „many" (i 12, 13, 14 — wyjatek nastolatkow)

Wyjatek dla 12, 13 i 14 jest tym, o co najczesciej rozbijaja sie dorazne
implementacje: 2 → „wpisy", ale 12 → „wpisow", mimo ze obie liczby koncza sie
ta sama cyfra.

SKAD BIORA SIE FORMY

Z katalogu gettext (`ngettext`), tak jak kazdy inny napis — dzieki temu
tlumacz widzi je w `.po` razem z reszta tekstow, a nie w tablicy ukrytej
w kodzie. Regule wyboru formy niesie naglowek `Plural-Forms` katalogu; dla
polskiego jest to dokladnie regula zapisana nizej w `polish_plural`
i identyczna z kategoriami CLDR (one / few / many).

`polish_plural` zostaje w module jako CZYTELNY, sprawdzalny zapis tej reguly:
naglowek `.po` jest jednym wierszem wyrazenia w C, a test
(`PluralTests.test_catalog_rule_matches_the_polish_rule`) porownuje oba
zrodla dla kilkuset liczb. Rozjechanie sie katalogu z ta funkcja przestaje
wtedy byc cicha usterka widoczna dopiero u uzytkownika.
"""
from __future__ import annotations

from .i18n import ngettext

#: Kategorie liczby mnogiej w kolejnosci uzywanej przez gettext.
ONE, FEW, MANY = 0, 1, 2


def polish_plural(count: int, one: str, few: str, many: str) -> str:
    """Wybiera forme rzeczownika dla liczby `count` (sam rzeczownik, bez liczby).

    >>> polish_plural(1, 'wpis', 'wpisy', 'wpisow')
    'wpis'
    >>> polish_plural(3, 'wpis', 'wpisy', 'wpisow')
    'wpisy'
    >>> polish_plural(12, 'wpis', 'wpisy', 'wpisow')
    'wpisow'
    >>> polish_plural(22, 'wpis', 'wpisy', 'wpisow')
    'wpisy'
    """
    return (one, few, many)[polish_plural_index(count)]


def polish_plural_index(count: int) -> int:
    """Kategoria liczby mnogiej po polsku: 0 = one, 1 = few, 2 = many."""
    count = abs(int(count))
    if count == 1:
        return ONE
    if 12 <= count % 100 <= 14:
        return MANY
    if 2 <= count % 10 <= 4:
        return FEW
    return MANY


# UWAGA dla kazdej pozniejszej zmiany: `msgid` musza stac WPROST w wywolaniu
# `ngettext`. Wspolny pomocnik bioracy je w argumencie wygladalby ladniej,
# ale ekstraktor (`tools/extract_messages.py`) czyta kod przez `ast` — widzi
# wtedy tylko nazwe zmiennej i napis nie trafia do katalogu.

def entries(count: int) -> str:
    """'1 entry' / '3 entries' — po polsku '1 wpis' / '3 wpisy' / '12 wpisow'."""
    return ngettext('%(count)s entry', '%(count)s entries',
                    abs(int(count))) % {'count': count}


def files(count: int) -> str:
    """'1 file' / '3 files'."""
    return ngettext('%(count)s file', '%(count)s files',
                    abs(int(count))) % {'count': count}


def characters(count: int) -> str:
    """'1 character' / '3 characters'."""
    return ngettext('%(count)s character', '%(count)s characters',
                    abs(int(count))) % {'count': count}


def steps(count: int) -> str:
    """'1 step' / '3 steps'."""
    return ngettext('%(count)s step', '%(count)s steps',
                    abs(int(count))) % {'count': count}


def minutes(count: int) -> str:
    """'1 minute' / '3 minutes'."""
    return ngettext('%(count)s minute', '%(count)s minutes',
                    abs(int(count))) % {'count': count}
