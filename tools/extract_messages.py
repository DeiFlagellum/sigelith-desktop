"""
Wyciaga napisy do przetlumaczenia z kodu BeatStamp.

    python tools/extract_messages.py            # locale/beatstamp.pot
    python tools/extract_messages.py --update   # + scala do locale/<lang>/…/*.po

Szuka wywolan `_()`, `gettext()`, `ngettext()` i `N_()` — takze przez modul
(`i18n.gettext(...)`). Odczyt przez `ast`, bez uruchamiania kodu.

DLACZEGO WLASNY EKSTRAKTOR, A NIE `xgettext` ALBO `pyside6-lupdate`

1. `xgettext` nie jest zainstalowany i nie jest czescia Pythona; zaleznosc
   build-time spoza Pythona psuje wydanie skladane po dluzszej przerwie.
2. `pyside6-lupdate` ma cicha pulapke, ktora przy 100+ napisach z wartosciami
   jest kosztowna: F-STRING wewnatrz `tr()` trafia do katalogu jako pozornie
   poprawny wpis `"Zapisano {a}."`, ktory w czasie dzialania NIGDY sie nie
   dopasuje — f-string jest skladany PRZED wywolaniem funkcji tlumaczacej.
   Testy tego nie widza, bo napis wyglada dobrze; widzi to dopiero uzytkownik,
   u ktorego jeden komunikat zostal nieprzetlumaczony.

Dlatego ten ekstraktor PRZERYWA prace, gdy argumentem funkcji tlumaczacej
jest f-string albo cokolwiek innego niz staly napis. To jedyna klasa bledow
w tej warstwie, ktora przechodzi przez komplet testow.
"""
from __future__ import annotations

import argparse
import ast
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import po  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / 'beatstamp'
LOCALE = ROOT / 'locale'
DOMAIN = 'beatstamp'

#: Nazwy funkcji tlumaczacych. `mark`/`N_` oznaczaja napis bez tlumaczenia go
#: w miejscu (napis liczony w czasie importu, tlumaczony przy uzyciu).
SINGULAR = {'_', 'gettext', 'N_', 'mark'}
PLURAL = {'ngettext'}

#: Znacznik w komentarzu, ktory wylacza wiersz z ekstrakcji. Potrzebny
#: dokladnie w jednym miejscu: w `i18n.py`, gdzie same funkcje tlumaczace
#: wywoluja `gettext`/`ngettext` na ZMIENNEJ. To nie jest napis do katalogu,
#: tylko implementacja mechanizmu — a bez tego znacznika ekstraktor slusznie
#: przerywalby prace na wlasnym silniku.
SKIP_MARK = '# i18n: skip'

#: Jezyki, dla ktorych utrzymujemy katalog. Angielski jest jezykiem `msgid`
#: i katalogu nie potrzebuje.
CATALOGS = ('pl', 'de')

PLURAL_FORMS = {
    # Regula CLDR dla polskiego — ta sama, ktora zapisuje `plural.polish_plural`.
    'pl': 'nplurals=3; plural=(n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<12 || n%100>14) ? 1 : 2);',
    'de': 'nplurals=2; plural=(n != 1);',
}


class Collector(ast.NodeVisitor):
    """Zbiera napisy z jednego pliku."""

    def __init__(self, path: Path, skipped: frozenset[int] = frozenset()):
        self.path = path
        self.skipped = skipped
        self.found: list[tuple[str, str, int]] = []      # (msgid, msgid_plural, linia)
        self.problems: list[str] = []

    def _literal(self, node: ast.AST, name: str, line: int) -> str | None:
        """Staly napis albo None + zapisany problem.

        Sasiadujace literaly (`'a' 'b'`) Python skleja juz na poziomie
        skladni, wiec docieraja tu jako jeden `Constant` — konkatenacja
        niejawna, uzywana w tym kodzie szeroko, dziala bez zmian.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        where = f'{self.path.relative_to(ROOT)}:{line}'
        if isinstance(node, ast.JoinedStr):
            self.problems.append(
                f'{where}: f-string wewnatrz {name}() — napis jest skladany PRZED '
                'tlumaczeniem, wiec wpis w katalogu nigdy sie nie dopasuje. '
                'Uzyj {} albo %(nazwa)s i podstaw wartosc PO przetlumaczeniu.')
        else:
            self.problems.append(
                f'{where}: argument {name}() nie jest stalym napisem '
                f'({type(node).__name__}) — nie da sie go wyciagnac do katalogu.')
        return None

    def visit_Call(self, node: ast.Call) -> None:
        if node.lineno in self.skipped:
            self.generic_visit(node)
            return
        func = node.func
        name = (func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute) else '')
        if name in SINGULAR and node.args:
            text = self._literal(node.args[0], name, node.lineno)
            if text is not None:
                self.found.append((text, '', node.lineno))
        elif name in PLURAL and len(node.args) >= 2:
            one = self._literal(node.args[0], name, node.lineno)
            many = self._literal(node.args[1], name, node.lineno)
            if one is not None and many is not None:
                self.found.append((one, many, node.lineno))
        self.generic_visit(node)


def collect() -> tuple[list[po.Entry], list[str]]:
    """Przechodzi caly pakiet. Zwraca (wpisy, problemy)."""
    by_key: dict[tuple[str, str], po.Entry] = {}
    problems: list[str] = []
    for path in sorted(PACKAGE.rglob('*.py')):
        if '__pycache__' in path.parts:
            continue
        source = path.read_text(encoding='utf-8')
        skipped = frozenset(number for number, line
                            in enumerate(source.splitlines(), 1)
                            if SKIP_MARK in line)
        collector = Collector(path, skipped)
        collector.visit(ast.parse(source, filename=str(path)))
        problems.extend(collector.problems)
        for msgid, msgid_plural, line in collector.found:
            if not msgid:
                continue                   # pusty napis to naglowek katalogu
            key = (msgid, msgid_plural)
            entry = by_key.get(key)
            if entry is None:
                entry = po.Entry(msgid=msgid, msgid_plural=msgid_plural,
                                 msgstr=['', '', ''] if msgid_plural else [''])
                by_key[key] = entry
            entry.references.append(f'{path.relative_to(ROOT).as_posix()}:{line}')
    return [by_key[k] for k in sorted(by_key)], problems


def _header(language: str = '') -> po.Entry:
    stamp = time.strftime('%Y-%m-%d %H:%M%z')
    lines = [
        'Project-Id-Version: BeatStamp\\n',
        f'POT-Creation-Date: {stamp}\\n',
        'MIME-Version: 1.0\\n',
        'Content-Type: text/plain; charset=UTF-8\\n',
        'Content-Transfer-Encoding: 8bit\\n',
    ]
    if language:
        lines.insert(2, f'Language: {language}\\n')
        lines.append(f'Plural-Forms: {PLURAL_FORMS[language]}\\n')
    return po.Entry(msgid='', msgstr=[''.join(lines).replace('\\n', '\n')])


def _merge(fresh: list[po.Entry], existing: list[po.Entry], language: str) -> list[po.Entry]:
    """Nowa lista wpisow z zachowanymi tlumaczeniami.

    Napis, ktory zniknal z kodu, znika tez z katalogu: martwe tlumaczenia
    myla tlumacza i ukrywaja, ile pracy naprawde zostalo. Historia jest
    w gicie.
    """
    old = {e.key: e for e in existing if e.msgid}
    forms = int(PLURAL_FORMS[language].split('nplurals=')[1].split(';')[0])
    out = [_header(language)]
    for entry in fresh:
        previous = old.get(entry.key)
        size = forms if entry.msgid_plural else 1
        entry.msgstr = [''] * size
        if previous is not None:
            for index in range(min(size, len(previous.msgstr))):
                entry.msgstr[index] = previous.msgstr[index]
            entry.fuzzy = previous.fuzzy
            entry.comments = previous.comments or entry.comments
        out.append(entry)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--update', action='store_true',
                        help='scal wynik do istniejacych katalogow locale/<lang>/')
    args = parser.parse_args()

    entries, problems = collect()
    if problems:
        print('BLAD — napisow nie da sie wyciagnac:', file=sys.stderr)
        for problem in problems:
            print(f'  {problem}', file=sys.stderr)
        return 2

    LOCALE.mkdir(parents=True, exist_ok=True)
    pot = LOCALE / f'{DOMAIN}.pot'
    pot.write_text(po.dump([_header()] + entries), encoding='utf-8')
    plurals = sum(1 for e in entries if e.msgid_plural)
    print(f'{pot.relative_to(ROOT)}: {len(entries)} napisow '
          f'(w tym {plurals} z liczba mnoga)')

    if args.update:
        for language in CATALOGS:
            target = LOCALE / language / 'LC_MESSAGES' / f'{DOMAIN}.po'
            target.parent.mkdir(parents=True, exist_ok=True)
            old = po.parse(target.read_text(encoding='utf-8')) if target.exists() else []
            merged = _merge([po.Entry(msgid=e.msgid, msgid_plural=e.msgid_plural,
                                      references=list(e.references),
                                      comments=list(e.comments)) for e in entries],
                            old, language)
            target.write_text(po.dump(merged), encoding='utf-8')
            done = sum(1 for e in merged if e.msgid and e.translated)
            print(f'{target.relative_to(ROOT)}: {done}/{len(entries)} przetlumaczonych')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
