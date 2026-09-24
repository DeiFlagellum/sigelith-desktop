"""
Czytanie i pisanie katalogow `.po` — w czystym Pythonie.

W srodowisku budowania NIE MA GNU gettext (`xgettext`, `msgfmt`, `msgmerge`)
ani `polib`, a CPython na Windows nie dostarcza `Tools/i18n/pygettext.py`.
Dokladanie ich jako zaleznosci build-time oznaczaloby, ze wydanie da sie
zlozyc tylko na maszynie z doinstalowanym pakietem spoza Pythona — a to
jest dokladnie ta klasa problemow, ktora psuje buildy po roku przerwy.

Ten modul jest wiec wspolna podstawa dla `extract_messages.py`
(kod -> `.pot` -> `.po`) i `compile_catalogs.py` (`.po` -> `.mo`).
Obsluguje to, czego BeatStamp uzywa: napisy zwykle, liczby mnogie
(`msgid_plural` / `msgstr[n]`), znacznik `fuzzy` i wpisy przestarzale.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Znaki, ktore w `.po` zapisuje sie z odwrotnym ukosnikiem.
_ESCAPES = {'\\': '\\\\', '"': '\\"', '\n': '\\n', '\t': '\\t', '\r': '\\r'}
_UNESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\'}


@dataclass
class Entry:
    """Jeden wpis katalogu."""

    msgid: str = ''
    msgid_plural: str = ''
    #: Dla wpisu bez liczby mnogiej: jeden element. Inaczej: po jednym na forme.
    msgstr: list[str] = field(default_factory=lambda: [''])
    #: `plik:linia` — skad napis pochodzi. Tylko komentarz, nie wplywa na `.mo`.
    references: list[str] = field(default_factory=list)
    #: Komentarze dla tlumacza (`#.`), przepisywane do `.po`.
    comments: list[str] = field(default_factory=list)
    fuzzy: bool = False

    @property
    def key(self) -> str:
        """Klucz w pliku `.mo`: `msgid` albo `msgid\\x00msgid_plural`."""
        return f'{self.msgid}\x00{self.msgid_plural}' if self.msgid_plural else self.msgid

    @property
    def translated(self) -> bool:
        """Czy wpis niesie tlumaczenie (kazda forma wypelniona)."""
        return bool(self.msgstr) and all(s != '' for s in self.msgstr)


def escape(text: str) -> str:
    return ''.join(_ESCAPES.get(ch, ch) for ch in text)


def unescape(token: str) -> str:
    """Rozwija fragment w cudzyslowach, np. '"tekst\\\\n"' -> 'tekst\\n'."""
    start, end = token.index('"'), token.rindex('"')
    raw = token[start + 1:end]
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == '\\' and i + 1 < len(raw):
            out.append(_UNESCAPES.get(raw[i + 1], raw[i + 1]))
            i += 2
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def quote(text: str) -> str:
    """Napis jako jeden albo wiele wierszy w cudzyslowach.

    Dlugi tekst lamiemy po znaku nowej linii — tak samo jak `xgettext`.
    Krotki zostaje w jednym wierszu, zeby plik dalo sie czytac.
    """
    if '\n' not in text:
        return f'"{escape(text)}"'
    pieces = text.split('\n')
    lines = ['""']
    for index, piece in enumerate(pieces):
        tail = '' if index == len(pieces) - 1 else '\n'
        if piece or tail:
            lines.append(f'"{escape(piece + tail)}"')
    return '\n'.join(lines)


def parse(text: str) -> list[Entry]:
    """Wczytuje katalog. Wpisy przestarzale (`#~`) sa pomijane.

    Wiersz `msgid` zaczyna NOWY wpis — to jedyny wiarygodny separator w tym
    formacie. Komentarze zbieramy osobno i doklejamy do wpisu, ktory po nich
    nastepuje; probowanie rozpoznawania granicy po komentarzu konczy sie
    sklejeniem calego pliku w jeden wpis, gdy komentarzy nie ma.
    """
    entries: list[Entry] = []
    current: Entry | None = None
    #: 'id' | 'id_plural' | 'str' — dokad trafia ciag dalszy w cudzyslowach.
    state = ''
    plural_index = 0
    comments: list[str] = []
    references: list[str] = []
    fuzzy = False

    def flush() -> None:
        nonlocal current
        if current is not None:
            entries.append(current)
        current = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#~'):
            continue                        # pusty wiersz albo wpis przestarzaly
        if line.startswith('#'):
            if line.startswith('#.'):
                comments.append(line[2:].strip())
            elif line.startswith('#:'):
                references.extend(line[2:].split())
            elif line.startswith('#,') and 'fuzzy' in line:
                fuzzy = True
            continue
        if line.startswith('msgid_plural'):
            if current is not None:
                current.msgid_plural = unescape(line)
                current.msgstr = []
            state = 'id_plural'
            continue
        if line.startswith('msgid'):
            flush()
            current = Entry(msgid=unescape(line), comments=comments,
                            references=references, fuzzy=fuzzy)
            comments, references, fuzzy = [], [], False
            state, plural_index = 'id', 0
            continue
        if line.startswith('msgstr[') and current is not None:
            plural_index = int(line[line.index('[') + 1:line.index(']')])
            while len(current.msgstr) <= plural_index:
                current.msgstr.append('')
            current.msgstr[plural_index] = unescape(line)
            state = 'str'
            continue
        if line.startswith('msgstr') and current is not None:
            current.msgstr = [unescape(line)]
            state, plural_index = 'str', 0
            continue
        if line.startswith('"') and current is not None:
            piece = unescape(line)
            if state == 'id':
                current.msgid += piece
            elif state == 'id_plural':
                current.msgid_plural += piece
            elif state == 'str' and current.msgstr:
                current.msgstr[plural_index] += piece
            continue
    flush()
    return entries


def header_fields(entries: list[Entry]) -> dict[str, str]:
    """Naglowek katalogu (wpis z pustym `msgid`) jako slownik."""
    for entry in entries:
        if entry.msgid == '':
            fields = {}
            for line in entry.msgstr[0].splitlines():
                if ':' in line:
                    name, _, value = line.partition(':')
                    fields[name.strip()] = value.strip()
            return fields
    return {}


def dump(entries: list[Entry]) -> str:
    """Zapisuje katalog w formacie `.po`. Naglowek idzie pierwszy."""
    ordered = ([e for e in entries if e.msgid == '']
               + [e for e in entries if e.msgid != ''])
    out: list[str] = []
    for entry in ordered:
        for comment in entry.comments:
            out.append(f'#. {comment}')
        for reference in entry.references:
            out.append(f'#: {reference}')
        if entry.fuzzy:
            out.append('#, fuzzy')
        out.append(f'msgid {quote(entry.msgid)}')
        if entry.msgid_plural:
            out.append(f'msgid_plural {quote(entry.msgid_plural)}')
            for index, value in enumerate(entry.msgstr):
                out.append(f'msgstr[{index}] {quote(value)}')
        else:
            out.append(f'msgstr {quote(entry.msgstr[0] if entry.msgstr else "")}')
        out.append('')
    return '\n'.join(out)
