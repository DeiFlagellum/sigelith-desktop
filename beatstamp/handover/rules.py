"""
Reguly tekstu i nazw plikow — HANDOVER_SPEC.md §4.1.

Po co tak scisle: tytul, notatka i nazwy plikow to jedyne, co odbiorca czyta,
zanim zdecyduje o przyjeciu. Znak odwracajacy kierunek tekstu (U+202E) robi
z programu `.exe` plik wygladajacy na `.pdf`; znak sterujacy potrafi rozjechac
okno albo raport PDF; nazwa `CON` albo `plik.txt:ukryty` zachowuje sie na
Windows inaczej, niz wyglada. Piszacy MUSI takich rzeczy nie tworzyc,
czytajacy MUSI je odrzucic — obie strony tym samym kodem.

Celowo NIE odrzucamy znakow nieprzypisanych w Unicode ani calej kategorii Cf:
lista nieprzypisanych zalezy od wersji Unicode w danym jezyku programowania
(Python i przegladarka ocenilyby ten sam napis roznie), a Cf zawiera tez
laczniki emoji (U+200D). Zakazujemy dokladnie tego, co wymienia specyfikacja.
"""
from __future__ import annotations

import re
import unicodedata

from .errors import HandoverError

# Znaki kierunku tekstu (U+061C, U+200E-F, U+202A-E, U+2066-9) i separatory
# linii/akapitow (U+2028-9), ktore rozbijaja wiersz jak znak sterujacy.
FORBIDDEN_CHARS = frozenset(
    [chr(0x061C), chr(0x200E), chr(0x200F), chr(0x2028), chr(0x2029)]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)])

WINDOWS_FORBIDDEN = frozenset('<>:"/\\|?*')
WINDOWS_RESERVED = frozenset(
    ['CON', 'PRN', 'AUX', 'NUL']
    + [f'COM{i}' for i in range(10)] + [f'LPT{i}' for i in range(10)]
    + ['COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³'])

NAME_MAX = 255
MIME_MAX = 127
_MIME = re.compile(r'[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*')


def check_text(value: object, field: str, max_len: int, *, allow_lf: bool = False,
               code: str = 'text') -> str:
    """NFC, bez znakow sterujacych (LF tylko gdy `allow_lf`) i bez znakow kierunku."""
    if not isinstance(value, str):
        raise HandoverError(code, f'{field}: must be a string')
    if len(value) > max_len:
        raise HandoverError(code, f'{field}: longer than {max_len} characters')
    if unicodedata.normalize('NFC', value) != value:
        raise HandoverError(code, f'{field}: not in Unicode NFC')
    for ch in value:
        if ch == '\n' and allow_lf:
            continue
        if ch in FORBIDDEN_CHARS or unicodedata.category(ch) == 'Cc':
            raise HandoverError(code, f'{field}: forbidden character U+{ord(ch):04X}')
    return value


def check_file_name(name: object, field: str = 'file name') -> str:
    """Nazwa pliku, ktora zapisze sie na Windows dokladnie tak, jak wyglada."""
    check_text(name, field, NAME_MAX, code='file-name')
    assert isinstance(name, str)
    if name in ('', '.', '..'):
        raise HandoverError('file-name', f'{field}: empty or dot name')
    bad = WINDOWS_FORBIDDEN.intersection(name)
    if bad:
        raise HandoverError('file-name', f'{field}: forbidden character {min(bad)!r}')
    if name[-1] in '. ':
        raise HandoverError('file-name', f'{field}: ends with a dot or a space')
    base = name.split('.', 1)[0].rstrip(' ').upper()
    if base in WINDOWS_RESERVED:
        raise HandoverError('file-name', f'{field}: reserved device name on Windows')
    return name


def check_mime(value: object, field: str = 'type') -> str:
    if not isinstance(value, str) or len(value) > MIME_MAX or not _MIME.fullmatch(value):
        raise HandoverError('file-type', f'{field}: expected a lowercase media type like '
                            'application/pdf')
    return value


# Rozszerzenia, przed ktorych otwarciem aplikacja ostrzega (§4.1): programy,
# skrypty i dokumenty z makrami. Lista pomocnicza dla interfejsu — nie jest
# czescia formatu i moze rosnac bez zmiany wersji.
RISKY_EXTENSIONS = frozenset({
    'exe', 'com', 'scr', 'pif', 'bat', 'cmd', 'msi', 'msix', 'msp', 'appx', 'appxbundle',
    'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'cpl', 'dll', 'sys',
    'lnk', 'url', 'reg', 'jar', 'iso', 'img', 'vhd', 'vhdx', 'chm', 'docm', 'dotm',
    'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'sldm', 'one', 'library-ms',
    'settingcontent-ms', 'appref-ms', 'application', 'gadget', 'scf', 'inf', 'py', 'pyw'})


def is_risky(name: str) -> bool:
    return '.' in name and name.rsplit('.', 1)[1].lower() in RISKY_EXTENSIONS
