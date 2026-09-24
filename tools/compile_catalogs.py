"""
Kompiluje katalogi `.po` do `.mo` — w czystym Pythonie, bez GNU gettext.

    python tools/compile_catalogs.py

Skanuje `locale/<lang>/LC_MESSAGES/*.po` i zapisuje obok `*.mo` w formacie
GNU MO, ktory biblioteka standardowa (`gettext`) czyta natywnie.

Rozni sie od `robocze/compile_po.py` (kompilatora katalogow serwera) jedna
rzecza, ktora tu jest konieczna: OBSLUGA LICZBY MNOGIEJ. Polski ma trzy formy
i bez `msgid_plural`/`msgstr[n]` w `.mo` `ngettext` spadalby do reguly
angielskiej — czyli „12 wpisy" zamiast „12 wpisow". Serwerowy kompilator
przerywa na takim wpisie; ten go zapisuje.

Zasady, ktore pilnuje:

* wpisy z PUSTYM tlumaczeniem sa pomijane → `gettext` spada do `msgid`,
  czyli do angielskiego. Niedokonczony katalog degraduje sie lagodnie,
  zamiast pokazywac puste etykiety;
* wpisy `#, fuzzy` sa pomijane — tlumaczenie niezweryfikowane nie moze
  trafic do wydania tylko dlatego, ze ma tresc (tak samo jak `msgfmt`
  bez `--use-fuzzy`);
* wpis z liczba mnoga wchodzi tylko wtedy, gdy WSZYSTKIE formy sa wypelnione;
  brak jednej formy dawalby pusty napis dokladnie dla tych liczb, ktorych
  tlumacz nie sprawdzil.
"""
from __future__ import annotations

import array
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import po  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
LOCALE = ROOT / 'locale'

#: Liczba magiczna formatu GNU MO (little endian).
MAGIC = 0x950412de


def to_messages(entries: list[po.Entry]) -> dict[str, str]:
    """Wpisy katalogu jako pary klucz -> wartosc w konwencji `.mo`.

    Liczba mnoga: klucz to `msgid\\x00msgid_plural`, wartosc to formy
    sklejone tym samym znakiem. Tak samo robi `msgfmt` i tak samo czyta to
    `gettext.GNUTranslations`.
    """
    messages: dict[str, str] = {}
    for entry in entries:
        if entry.msgid == '':
            messages[''] = entry.msgstr[0] if entry.msgstr else ''
            continue
        if entry.fuzzy or not entry.translated:
            continue
        messages[entry.key] = '\x00'.join(entry.msgstr)
    return messages


def generate_mo(messages: dict[str, str]) -> bytes:
    """Sklada plik `.mo`. Klucze musza byc posortowane — czyta je bisekcja."""
    keys = sorted(k for k, v in messages.items() if v != '' or k == '')
    offsets, ids, strs = [], b'', b''
    for key in keys:
        kb = key.encode('utf-8')
        vb = messages[key].encode('utf-8')
        offsets.append((len(ids), len(kb), len(strs), len(vb)))
        ids += kb + b'\x00'
        strs += vb + b'\x00'
    key_start = 7 * 4 + 16 * len(keys)
    value_start = key_start + len(ids)
    key_offsets, value_offsets = [], []
    for id_offset, id_length, str_offset, str_length in offsets:
        key_offsets += [id_length, id_offset + key_start]
        value_offsets += [str_length, str_offset + value_start]
    out = struct.pack('Iiiiiii', MAGIC, 0, len(keys),
                      7 * 4, 7 * 4 + len(keys) * 8, 0, 0)
    out += array.array('i', key_offsets + value_offsets).tobytes()
    return out + ids + strs


def main() -> int:
    if not LOCALE.is_dir():
        print(f'brak katalogu {LOCALE}', file=sys.stderr)
        return 1
    compiled = 0
    for language in sorted(p.name for p in LOCALE.iterdir() if p.is_dir()):
        directory = LOCALE / language / 'LC_MESSAGES'
        if not directory.is_dir():
            continue
        for source in sorted(directory.glob('*.po')):
            entries = po.parse(source.read_text(encoding='utf-8'))
            messages = to_messages(entries)
            target = source.with_suffix('.mo')
            target.write_bytes(generate_mo(messages))
            total = sum(1 for e in entries if e.msgid)
            done = len(messages) - (1 if '' in messages else 0)
            skipped = sum(1 for e in entries if e.msgid and e.fuzzy)
            note = f', pominieto fuzzy: {skipped}' if skipped else ''
            print(f'{target.relative_to(ROOT)}: {done}/{total} napisow{note}')
            compiled += 1
    if not compiled:
        print('nie znaleziono zadnego pliku .po', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
