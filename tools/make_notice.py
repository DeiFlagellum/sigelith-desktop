"""
Sklada plik `NOTICE` z GOTOWEJ PACZKI.

    python tools/make_notice.py            # zapisuje desktop/NOTICE
    python tools/make_notice.py --check    # tylko sprawdza, czy jest aktualny
    python tools/make_notice.py --print    # wypisuje na ekran, nic nie zapisuje

DLACZEGO Z PACZKI, A NIE RECZNIE

Noty licencyjne pisane recznie starzeja sie po cichu. Aktualizacja PySide6
albo dolozenie jednej zaleznosci zmienia zawartosc paczki o kilkanascie
plikow; plik not zostaje ten sam i nikt tego nie zauwazy, bo nic sie nie
psuje — az do dnia, w ktorym ktos porowna jedno z drugim.

Tutaj kierunek jest odwrotny: zrodlem jest to, co NAPRAWDE lezy w paczce.
Plik bez przypisanej licencji przerywa generowanie (i wywala test), zamiast
zostac przemilczany. Przypisanie robi `tools/licenses.py` — ten sam modul,
z ktorego korzysta `beatstamp.spec` przy wykluczeniach.

„W paczce" znaczy takze „w srodku `.exe`". Nazwy plikow na dysku nie
wymieniaja reportlaba, requests, urllib3, idny ani PySocks — te biblioteki
nie maja tu wlasnego pliku, ich kod jest skompilowany w archiwum wewnatrz
`SigelithDesktop.exe`. Nota, ktora ich nie wymienia, jest nieprawdziwa, a BSD i MIT
wymagaja odtworzenia noty wlasnie w redystrybucji BINARNEJ. Dlatego audyt
czyta takze to archiwum, a pakiet, ktorego nie opisuje zaden skladnik,
przerywa generowanie tak samo jak nieprzypisany plik.

CZEGO TEN PLIK NIE ZASTEPUJE

Not nie da sie streszczic. Apache-2.0 par. 4, MIT i BSD wymagaja
PRZEKAZANIA tekstu licencji, a LGPLv3 par. 4(c) — dostarczenia kopii GNU
GPL i LGPL razem z programem. Dlatego pelne teksty leza w `licenses/`
i ida do paczki (`_internal/licenses/`), a `NOTICE` mowi, ktory tekst
dotyczy ktorego pliku.
"""
from __future__ import annotations

import argparse
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import licenses  # noqa: E402

ROOT = licenses.ROOT
NOTICE = ROOT / 'NOTICE'

#: Szerokosc lamania. Plik czytaja ludzie w Notatniku i w oknie „O programie".
WIDTH = 78

#: Nazwa katalogu wersji przenosnej (`dist/SigelithDesktop`) — tak, jak ja
#: widzi uzytkownik po rozpakowaniu.
PACKAGE_FOLDER = licenses.PACKAGE_DIRS[0].name


def _rule(character: str = '-') -> str:
    return character * WIDTH


def _wrap(text: str, indent: str = '') -> list[str]:
    """Lamanie, ktore NIE TNIE adresow.

    `textwrap` domyslnie lamie dlugie slowa i dzieli po myslnikach — adres
    zrodel Qt rozpada sie wtedy na dwa wiersze i przestaje dzialac po
    skopiowaniu. W pliku, ktorego jedynym zadaniem jest doprowadzic czytelnika
    do zrodel, to nie jest drobiazg. Wiersz dluzszy niz `WIDTH` jest mniejszym
    zlem niz adres, ktory nie prowadzi donikad.
    """
    return textwrap.wrap(text, width=WIDTH, initial_indent=indent,
                         subsequent_indent=indent, break_long_words=False,
                         break_on_hyphens=False) or [indent.rstrip()]


def _file_lines(paths: list[str]) -> list[str]:
    """Pliki pogrupowane katalogami — inaczej lista ponad stu `.qm` zaslania resztę.

    Nazwa kazdego pliku zostaje widoczna. To nie jest ozdoba: caly sens tego
    pliku polega na tym, ze da sie wskazac dowolny plik z paczki i przeczytac,
    na jakiej jest licencji.
    """
    groups: dict[str, list[str]] = {}
    for path in paths:
        directory, _, name = path.rpartition('/')
        groups.setdefault(directory + '/' if directory else '', []).append(name)

    lines: list[str] = []
    for directory in sorted(groups):
        names = ', '.join(sorted(groups[directory]))
        head = f'  {directory or "(package root)"}'
        lines.append(head)
        lines += textwrap.wrap(names, width=WIDTH, initial_indent='    ',
                               subsequent_indent='    ',
                               break_long_words=False, break_on_hyphens=False)
    return lines


def build(package: Path) -> str:
    """Tresc pliku `NOTICE` dla tej paczki."""
    report = licenses.audit(package)
    if report.forbidden:
        listing = ', '.join(f'{path} ({reason.subject})'
                            for path, reason in report.forbidden)
        raise SystemExit(
            f'NIE SKLADAM NOT: w paczce {package} leza pliki, ktorych nie '
            f'powinno tam byc: {listing}')
    if report.unassigned_modules:
        listing = ', '.join(report.unassigned_modules)
        raise SystemExit(
            f'NIE SKLADAM NOT: w archiwum wewnatrz {licenses.EXECUTABLE} leza '
            f'pakiety, ktorych nie opisuje zaden skladnik: {listing}. Dopisz '
            f'je do PYZ_COMPONENTS w tools/licenses.py razem ze skladnikiem '
            f'i tekstem licencji — biblioteka bez wlasnego pliku w paczce ma '
            f'dokladnie te same wymagania co biblioteka z plikiem.')
    if report.unassigned:
        listing = ', '.join(report.unassigned[:12])
        more = '' if len(report.unassigned) <= 12 else f' (i {len(report.unassigned) - 12} wiecej)'
        raise SystemExit(
            f'NIE SKLADAM NOT: {len(report.unassigned)} plikow w paczce '
            f'{package} nie ma przypisanej licencji: {listing}{more}. '
            f'Dopisz regule w tools/licenses.py — nota, ktora przemilcza plik, '
            f'jest gorsza niz jej brak.')

    version = licenses.app_version()
    own = licenses.COMPONENTS['beatstamp']
    lines: list[str] = [
        own.name,
        own.copyright,
        '',
    ]
    lines += _wrap(
        'This file lists every file of the released Sigelith Desktop package, and '
        f'every library compiled into {licenses.EXECUTABLE}, with the license it is '
        'distributed under. It is generated from the built package by '
        'tools/make_notice.py; do not edit it by hand.')
    lines += ['']
    lines += _wrap(
        f'{licenses.EXECUTABLE} is not one program in one license. It is the '
        'PyInstaller bootloader with an archive appended to it, and that '
        'archive holds this program together with its Python dependencies. '
        'Libraries that have no file of their own in the package -- ReportLab, '
        f'requests, urllib3, idna, PySocks -- live there, and {licenses.EXECUTABLE} is '
        'listed among the files of every component whose code is inside it.')
    legal_prefix = licenses.LEGAL_DIR_IN_PACKAGE + '/'
    counted = [path for path in report.files
               if not path.startswith(legal_prefix)]
    lines += ['', f'Package:  {own.name} {version}',
              f'Files:    {len(counted)} (plus the legal documents listed at '
              f'the end)',
              f'Modules:  {len(report.modules)} top-level packages inside '
              f'{licenses.EXECUTABLE}', '']

    # --- Zrodla bibliotek LGPL ---
    lines += [_rule('='), 'SOURCES OF THE LGPL LIBRARIES', _rule('='), '']
    lines += _wrap(
        f'{own.name} uses Qt and PySide6 as shared libraries under the GNU '
        'Lesser General Public License, version 3. That license requires the '
        'source code of the libraries themselves to be available. The exact '
        'versions used to build this package are:')
    lines += ['', f'  Qt {licenses.COMPONENTS["qt"].version}',
              f'    {licenses.QT_SOURCE_URL}',
              '', f'  PySide6 / Shiboken6 {licenses.COMPONENTS["pyside6"].version}',
              f'    {licenses.PYSIDE_SOURCE_URL}', '']
    lines += _wrap(
        'Written offer, valid for at least three years from the date this '
        f'copy of {own.name} was distributed: on request, Adam Koch will supply '
        'to anyone who has this program a complete machine-readable copy of '
        'the source code of the above libraries, and of this version of '
        f'{own.name} itself in the form needed to relink it against them, for '
        'no more than the cost of the distribution. Write to '
        f'{licenses.WRITTEN_OFFER_CONTACT}.')
    lines += ['']
    lines += [_rule('='), 'RELINKING AGAINST YOUR OWN BUILD OF QT',
              _rule('='), '']
    lines += _wrap(
        'Qt and PySide6 are not modified here and they are linked '
        'dynamically. How you put your own build of them under this program '
        'depends on how this copy was installed, and the two ways are not '
        'the same:')
    lines += ['']
    lines += _wrap(
        f'Portable installation (the {PACKAGE_FOLDER} folder with '
        f'{licenses.EXECUTABLE} in it). The libraries sit in the _internal '
        'directory next to the '
        'executable. Replace the corresponding files with your own build of '
        'the same version; nothing else has to be done.', indent='  ')
    lines += ['']
    lines += _wrap(
        'Installation from the Microsoft Store (MSIX). The program is '
        'installed under C:\\Program Files\\WindowsApps, where the files '
        'cannot be replaced: the directory is locked to TrustedInstaller and '
        'the contents of the package are bound to its signature. Nothing can '
        'be swapped in place there, and this notice does not pretend '
        'otherwise. Use the portable release of the same version instead: it '
        'is the same program, built from the same source, with the libraries '
        'in a directory you own. Ask for it with the written offer above, or '
        f'take it from the address of the {own.name} source given under this '
        'program in the component list below.', indent='  ')
    lines += ['']
    lines += _wrap(
        'The full texts of the GNU General Public License v3 and of the GNU '
        'Lesser General Public License v3 are delivered with this program, in '
        f'{licenses.LEGAL_DIR_IN_PACKAGE}/ next to the executable, and in the '
        'licenses/ directory of the source tree.')
    lines += ['']

    # --- Czego tu nie ma ---
    lines += [_rule('='), 'DELIBERATELY NOT IN THIS PACKAGE', _rule('='), '']
    lines += _wrap(
        'Qt is licensed per module, and not every module is available under '
        'the LGPL. The modules below are available only under the GPLv3 or a '
        'commercial Qt license, so they are removed from the package at build '
        'time (beatstamp.spec) and their absence is checked by the test suite '
        '(tests/test_licensing.py):')
    lines += ['']
    seen: set[str] = set()
    for item in licenses.GPL_ONLY:
        if item.subject in seen:
            continue
        seen.add(item.subject)
        lines += _wrap(f'{item.subject} - {item.reason}', indent='  ')
    lines += ['']
    lines += _wrap(
        'These are removed for other reasons. They may be redistributed, but '
        'nothing in the package uses them, and every one of them would put a '
        'further chain of third-party notices into a release that has no use '
        'for it:')
    lines += ['']
    for item in licenses.ORPHANS + licenses.MACHINE_LOCAL + licenses.UNUSED:
        if item.subject in seen:
            continue
        seen.add(item.subject)
        lines += _wrap(f'{item.subject} - {item.reason}', indent='  ')
    lines += ['']

    # --- Skladniki ---
    lines += [_rule('='), 'THIRD-PARTY COMPONENTS', _rule('='), '']
    for key, component in licenses.COMPONENTS.items():
        paths = report.assigned.get(key)
        if not paths:
            continue
        shown = [path for path in paths if not path.startswith(legal_prefix)]
        version_text = component.version or version
        lines += [_rule(), f'{component.name} {version_text}'.strip(),
                  f'License: {component.spdx}', _rule(), '']
        lines += _wrap(component.copyright)
        if component.homepage:
            lines += ['', f'Homepage: {component.homepage}']
        if component.texts:
            texts = ', '.join(f'{licenses.LEGAL_DIR_IN_PACKAGE}/{name}'
                              for name in component.texts)
            lines += ['', *_wrap(f'License text: {texts}')]
        if component.source:
            lines += ['', *_wrap(f'Source: {component.source}')]
        if component.note:
            lines += ['', *_wrap(component.note)]
        lines += ['', f'Files ({len(shown)}):']
        lines += _file_lines(shown)
        lines += ['']

    # --- Dokumenty prawne w samej paczce ---
    lines += [_rule('='), 'LEGAL DOCUMENTS INSIDE THIS PACKAGE', _rule('='), '']
    lines += _wrap(
        f'{legal_prefix}LICENSE, {legal_prefix}NOTICE (this file) and the '
        f'full license texts {legal_prefix}*.txt are part of the package and '
        'are covered by the licenses they quote. They are not listed file by '
        'file above, so that adding a license text does not rewrite this '
        'document.')
    lines += ['']

    return '\n'.join(line.rstrip() for line in lines).rstrip() + '\n'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true',
                        help='nie zapisuje; konczy sie bledem, gdy NOTICE '
                             'rozjechal sie z paczka')
    parser.add_argument('--print', dest='to_stdout', action='store_true',
                        help='wypisuje tresc i nic nie zapisuje')
    parser.add_argument('--package', type=Path, default=None,
                        help='katalog gotowej paczki (domyslnie dist/SigelithDesktop)')
    args = parser.parse_args(argv)

    package = args.package
    if package is None:
        available = licenses.built_packages()
        if not available:
            print('Nie ma z czego skladac not: brak zbudowanej paczki. '
                  'Uruchom najpierw .\\build.ps1', file=sys.stderr)
            return 2
        package = available[0]
    if not licenses.is_package(package):
        print(f'To nie wyglada na paczke Sigelith Desktop: {package}', file=sys.stderr)
        return 2

    content = build(package)

    if args.to_stdout:
        sys.stdout.write(content)
        return 0
    if args.check:
        current = NOTICE.read_text(encoding='utf-8') if NOTICE.is_file() else ''
        if current == content:
            print(f'NOTICE zgodny z paczka {package}')
            return 0
        print(f'NOTICE ROZJECHAL SIE z paczka {package}. '
              f'Uruchom: python tools/make_notice.py', file=sys.stderr)
        return 1

    NOTICE.write_text(content, encoding='utf-8')
    print(f'Zapisano {NOTICE} ({len(content.splitlines())} wierszy) '
          f'z paczki {package}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
