"""
Kanoniczny JSON (JCS, RFC 8785) — podzbior z HANDOVER_SPEC.md §2.

Zapis: klucze ASCII posortowane, bez bialych znakow, tylko liczby calkowite
|n| < 2^53, napisy poprawne w UTF-8. Dla tego podzbioru
`json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False)` daje
dokladnie bajty JCS: Python ucieka te same znaki co RFC 8785 (\\b \\f \\n \\r
\\t, pozostale sterujace jako \\u00xx malymi literami), a porzadek kluczy ASCII
jest ten sam w jednostkach UTF-16 i w punktach kodowych. Tak samo robia
checkpointy dziennika (`logtree.canonical_json`).

Odczyt jest SCISLY. Kazda z ponizszych furtek pozwalalaby, zeby jeden podpis
„znaczyl" dwie rozne rzeczy dla dwoch parserow:

* zdublowany klucz (parsery wybieraja rozne wartosci — pierwsza albo ostatnia),
* liczby zmiennoprzecinkowe, NaN, Infinity (rozne zaokraglenia i zapisy),
* niepoprawny UTF-8 i samotne surogaty, takze zapisane ucieczka `\\ud800`,
* wejscie, ktore NIE jest juz kanoniczne — obiekty protokolu maja dokladnie
  jedna postac bajtowa (`canonical=True`).
"""
from __future__ import annotations

import json

from .errors import HandoverError

MAX_SAFE_INT = 2 ** 53 - 1
PROTOCOL_MAX_BYTES = 64 * 1024
PROTOCOL_MAX_DEPTH = 8


def _check(value, depth: int, max_depth: int, path: str = '$') -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            raise HandoverError('json-number', f'{path}: integer outside +-(2^53-1)')
        return
    if isinstance(value, float):
        raise HandoverError('json-number', f'{path}: floats are not allowed')
    if isinstance(value, str):
        try:
            value.encode('utf-8')
        except UnicodeEncodeError:
            raise HandoverError('json-string', f'{path}: lone surrogate') from None
        return
    if isinstance(value, (list, dict)):
        if depth >= max_depth:
            raise HandoverError('json-depth', f'{path}: nesting deeper than {max_depth}')
        if isinstance(value, list):
            for i, item in enumerate(value):
                _check(item, depth + 1, max_depth, f'{path}[{i}]')
            return
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise HandoverError('json-key', f'{path}: keys must be ASCII strings')
            _check(item, depth + 1, max_depth, f'{path}.{key}')
        return
    raise HandoverError('json-type', f'{path}: type {type(value).__name__} is not allowed')


def dumps(obj, *, max_depth: int = PROTOCOL_MAX_DEPTH) -> bytes:
    """Bajty JCS obiektu. `HandoverError`, gdy obiekt wychodzi poza podzbior."""
    _check(obj, 0, max_depth)
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise HandoverError('json-duplicate', f'duplicate key {key!r}')
        obj[key] = value
    return obj


def _no_float(text: str):
    raise HandoverError('json-number', f'floats are not allowed: {text}')


def _no_constant(name: str):
    raise HandoverError('json-number', f'{name} is not allowed')


def parse_strict(text: str):
    """JSON bez duplikatow kluczy i bez liczb niecalkowitych — ale bez wymogu JCS.

    Dla danych, ktore tworzy ktos inny niz nasz zapis (np. `clientDataJSON`
    uwierzytelniacza WebAuthn): kanonicznosci od nich nie wymagamy, ale
    niejednoznacznosci — nadal nie przepuszczamy.
    """
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_float=_no_float,
                          parse_constant=_no_constant)
    except HandoverError:
        raise
    except (ValueError, RecursionError) as e:
        raise HandoverError('json-syntax', str(e)) from None


def loads(data: bytes, *, max_bytes: int = PROTOCOL_MAX_BYTES,
          max_depth: int = PROTOCOL_MAX_DEPTH, canonical: bool = True):
    """Scisly odczyt. `canonical=True`: wejscie musi byc dokladnie bajtami JCS."""
    if not isinstance(data, (bytes, bytearray)):
        raise HandoverError('json-type', 'expected bytes')
    data = bytes(data)
    if len(data) > max_bytes:
        raise HandoverError('json-size', f'{len(data)} bytes > {max_bytes}')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise HandoverError('json-utf8', 'invalid UTF-8') from None
    obj = parse_strict(text)
    _check(obj, 0, max_depth)
    if canonical and dumps(obj, max_depth=max_depth) != data:
        raise HandoverError('json-canonical', 'input is not canonical JCS')
    return obj
