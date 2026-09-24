"""
Weryfikacja dowodu — cala lokalnie, bez sieci i bez zaufania do serwera.

Tutaj lezy najwazniejsza różnica względem klienta TVS. Stary program wypisywal
to, co przyszlo w odpowiedzi HTTP, i na tym konczyl: "signature" bylo sklejka
`czas.sha256(czegos)`, której nie dało się niczym sprawdzić. Kto kontrolowal
serwer (albo połączenie), kontrolowal tresc certyfikatu.

BeatStamp sprawdza trzy niezależne rzeczy:

1. INKLUZJA (merkle.py) — czy digest naprawdę wisi pod korzeniem tygodnia.
   Czysta arytmetyka: SHA-256 powtorzone `len(proof)` razy.
2. PODPIS (Ed25519) — czy korzeń tygodnia podpisał wlasciciel klucza BeatTime.
3. Tożsamość KLUCZA — czy podpisal klucz z AKTUALNEJ listy kluczy BeatTime
   wbudowanej w aplikacje (keys.py).

Punkt 3 jest tym, co nadaje sens punktowi 2. Serwer zwraca `public_key` razem
z podpisem, więc sam podpis dowodzi tylko tego, ze ktos miał JAKIS klucz —
fałszywy serwer podeslalby wlasna pare i podpis zgadzalby się idealnie.
Podpis sprawdzamy kluczem, który wskazuje odpowiedz, ale o ZAUFANIU decyduje
wylacznie nasza lista — nigdy serwer. Kazda niezgodnosc jest GLOSNA:

* klucz obcy (spoza listy)  -> zastrzezenie, dowód odrzucony;
* klucz WYCOFANY            -> poziom najwyzej „Zarejestrowany" + ostrzezenie,
                              ze trzeba odświeżyć dowód online (serwer ma
                              każdy korzen podpisany ponownie aktualnym
                              kluczem). Wycofany klucz podpisal tez korzenie
                              spoza publicznego rejestru, wiec jego podpis
                              sam niczego nie rozstrzyga;
* wlasny klucz z ustawien   -> uznawany, ale stale widoczny na pasku stanu.

Czego podpis NIE obejmuje: dokladnej chwili stempla. Podpisany jest tekst
`beattime-proof-v1|<tydzien>|<korzen>`, a lisc drzewa to sam skrot — pola
`utc`, `beat` i `seq` sa deklaracja rejestru. Dlatego czas musi lezec W
podpisanym tygodniu (`time_claim_problems`), a interfejs i certyfikat
pokazuja tydzien jako granice potwierdzona podpisem, a dokladna chwile jako
podana przez rejestr. Bez tej kontroli wrogi `.beatproof` z poprawnym
podpisem mogl przestawic `utc` na dowolna wczesniejsza date.

Kotwice zewnetrzne (Bitcoin, bank) to rowniez deklaracje serwera — aplikacja
nie sprawdza pliku .ots. Kotwica bankowa liczy sie tylko wtedy, gdy jej pole
`root` to korzen tego tygodnia (`anchor_confirms`).

Poziom dowodu rosnie w czasie i aplikacja mówi to wprost, zamiast udawac, ze
swiezy stempel jest już zakotwiczony:

    ZAREJESTROWANY  -> tydzień trwa, korzeń jeszcze plynny
    PODPISANY       -> tydzień zamknięty, korzeń zamrożony i podpisany
    ZAKOTWICZONY    -> korzeń w łańcuchu Bitcoin (OpenTimestamps) lub w banku
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from . import beatcore, keys, merkle
from .i18n import _, date_format, format_iso_date, short_date_format

# Aktualny (najnowszy) klucz publiczny BeatTime — nazwa zostaje dla zgodnosci
# i do tekstow dla czlowieka. O zaufaniu NIE decyduje ta stala, tylko pelna
# historia kluczy w keys.py (aktualne vs wycofane).
PINNED_PUBLIC_KEY = keys.primary_key()

# Komunikat podpisywany przez serwer — musi byc identyczny co do bajtu
# (apps/tsa/signing.py: signing_message).
SIGNING_PREFIX = 'beattime-proof-v1'


class Level(str, Enum):
    """Sila dowodu, rosnaca. Kolejnosc ma znaczenie (porownania < i >)."""

    NONE = 'none'            # brak stempla dla tego skrotu
    RECORDED = 'recorded'    # zapisany w logu, tydzien wciaz otwarty
    SIGNED = 'signed'        # korzen tygodnia zamrozony i podpisany Ed25519
    ANCHORED = 'anchored'    # korzen w Bitcoinie lub potwierdzony bankowo

    @property
    def order(self) -> int:
        return _LEVEL_ORDER[self]

    @property
    def label(self) -> str:
        return level_label(self)

    @property
    def description(self) -> str:
        return level_description(self)


_LEVEL_ORDER = {Level.NONE: 0, Level.RECORDED: 1, Level.SIGNED: 2, Level.ANCHORED: 3}


# Etykiety i opisy poziomow sa FUNKCJAMI, nie slownikami modulu. Slownik
# policzony w czasie importu zamrozilby jezyk na tym, ktory obowiazywal przed
# wczytaniem ustawien — a ustawienia czytamy po pierwszym imporcie.

def level_label(level: 'Level') -> str:
    """Krotka nazwa poziomu dowodu."""
    return {
        Level.NONE: _('No stamp'),
        Level.RECORDED: _('Recorded'),
        Level.SIGNED: _('Signed'),
        Level.ANCHORED: _('Anchored'),
    }[level]


def level_description(level: 'Level') -> str:
    """Zdanie wyjasniajace, co ten poziom znaczy i czego jeszcze brakuje."""
    return {
        Level.NONE: _('This digest does not appear in the public BeatTime register.'),
        Level.RECORDED: _(
            'The digest is in the public, append-only register. The current week '
            'is still running, so the Merkle root has not been frozen yet — the '
            'signature and the anchor arrive once it closes (Monday 00:00 UTC).'
        ),
        Level.SIGNED: _(
            'Week closed: the Merkle root is frozen and signed with the BeatTime '
            'Ed25519 key, and the digest was confirmed locally to belong to that '
            'root. The external anchor is on its way.'
        ),
        Level.ANCHORED: _(
            'Highest level: the week root is anchored outside BeatTime — in the '
            'Bitcoin chain (OpenTimestamps) and/or by a bank confirmation. '
            'Undoing this timestamp would require rewriting other parties\' '
            'registers.'
        ),
    }[level]


@dataclass
class VerificationResult:
    """Wynik lokalnej weryfikacji odpowiedzi z /api/proof/*."""

    found: bool = False
    digest: str = ''
    level: Level = Level.NONE

    inclusion_checked: bool = False   # byly dane, zeby w ogole liczyc
    inclusion_ok: bool = False
    signature_checked: bool = False
    signature_ok: bool = False
    key_pinned_ok: bool = False       # podpisal klucz ZAUFANY (keys.py / wlasny)
    # 'current' | 'retired' | 'unknown' | 'override' (keys.SIGNER_*),
    # '' gdy podpisu nie bylo czego sprawdzac.
    signer_status: str = ''

    beat: str = ''
    utc: str = ''
    seq: int | None = None
    week: str = ''
    week_closed: bool = False
    week_root: str = ''
    chain_hash: str = ''
    ots_status: str = 'none'
    ots_height: int | None = None
    anchors: list[dict] = field(default_factory=list)
    public_key: str = ''
    # Podpis PRZECHOWUJEMY, a nie tylko sprawdzamy i wyrzucamy. Bez niego
    # eksport `.beatproof` bylby niekompletny, a dowod bez podpisu korzenia
    # nie da sie zweryfikowac offline — czyli cala funkcja tracilaby sens.
    root_signature: str = ''
    inclusion_proof: list[dict] = field(default_factory=list)

    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def trusted(self) -> bool:
        """Czy WSZYSTKO, co dało się sprawdzić, wypadlo poprawnie.

        Swiezy stempel (tydzień otwarty) jest `trusted` mimo braku podpisu —
        nie ma jeszcze czego sprawdzac i to jest stan normalny, nie usterka.
        Falsz oznacza sprzecznosc: dane przyszly, ale się nie zgadzaja —
        albo podpis kluczem spoza aktualnej listy (dla klucza wycofanego:
        `needs_refresh`, bez zastrzezen, ale tez bez dowodu).
        """
        if not self.found or self.problems:
            return False
        if self.inclusion_checked and not self.inclusion_ok:
            return False
        if self.signature_checked and not (self.signature_ok and self.key_pinned_ok):
            return False
        # Tydzien ZAMKNIETY ma juz zamrozony i podpisany korzen, wiec brak
        # sciezki inkluzji albo podpisu nie jest tu stanem przejsciowym —
        # jest sprzecznoscia. Bez tego warunku „nie bylo czego sprawdzic"
        # bylo rownoznaczne z „sprawdzono i jest dobrze".
        if self.week_closed and not (self.inclusion_checked and self.signature_checked):
            return False
        return True

    @property
    def needs_refresh(self) -> bool:
        """Poprawny podpis, ale kluczem WYCOFANYM — trzeba dociagnac nowy.

        To nie jest falszerstwo (brak zastrzezen), ale tez nie dowod: poziom
        zostaje „Zarejestrowany", dopoki odswiezenie online nie przyniesie
        podpisu aktualnym kluczem.
        """
        return (self.signature_checked and self.signature_ok
                and self.signer_status == keys.SIGNER_RETIRED)

    @property
    def anchor_summary(self) -> str:
        """Kotwice wedlug rejestru — tekst ZWYKLY (wywolujacy escapuje)."""
        parts = []
        if self.ots_status == 'bitcoin':
            parts.append(_('Bitcoin — block %(height)s') % {'height': self.ots_height}
                         if self.ots_height else 'Bitcoin')
        elif self.ots_status == 'pending':
            parts.append(_('OpenTimestamps — waiting for a block'))
        for a in self.anchors:
            bank = str(a.get('bank') or '').strip()
            date = str(a.get('date') or '')[:10]
            if bank:
                text = f'{bank} ({date})' if date else bank
                if str(a.get('status')) == 'confirmed' and not anchor_confirms(
                        a, self.week_root):
                    text += _(' — a different root, not accepted')
                parts.append(text)
        return ' · '.join(parts) if parts else '—'


def verify_ed25519_root(week_key: str, root_hex: str, sig_b64: str,
                        pub_b64: str) -> bool:
    """Czy `sig_b64` to podpis Ed25519 korzenia pod kluczem `pub_b64`.

    Każdy błąd (zły base64, zla dlugosc klucza, zły podpis) to False — nigdy
    wyjątek. Wywolujacy nie ma jak odroznic "nie udało się sprawdzić" od "zle",
    i dobrze: jedno i drugie znaczy "nie uznawaj tego za podpisane".
    """
    if not (week_key and root_hex and sig_b64 and pub_b64):
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        message = f'{SIGNING_PREFIX}|{week_key}|{root_hex}'.encode('utf-8')
        pub = base64.b64decode(pub_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(pub).verify(
            base64.b64decode(sig_b64, validate=True), message
        )
        return True
    except Exception:
        return False


# Formaty pol, ktore trafiaja na ekran i do dokumentow. Celowo waskie:
# wszystko, co nie pasuje, jest ODRZUCANE, a nie escapowane — wartosc spoza
# wzorca i tak nie niesie zadnej sensownej tresci.
_BEAT_RE = re.compile(r'^@\d{3}(?:\.\d{1,3})?$')
_WEEK_RE = re.compile(r'^\d{4}-W\d{2}$')
_UTC_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$')
_OTS_RE = re.compile(r'^(?:none|pending|bitcoin)$')
_B64_RE = re.compile(r'^[A-Za-z0-9+/]{16,512}={0,2}$')


def _clean(value: object, pattern, *, lower: bool = False) -> str:
    """Zwraca wartosc tylko wtedy, gdy pasuje do wzorca; inaczej pusty napis.

    Cicha zamiana na pustke jest tu swiadoma: brak wartosci interfejs
    pokazuje jako „—", co jest uczciwe, a jednoczesnie zadna kontrolka ani
    dokument nie dostaje napisu, ktory moglby zostac zinterpretowany jako
    znacznik. Pola ISTOTNE dowodowo (korzen, podpis, klucz) maja osobna,
    glosna obsluge — ich zle sformatowana wartosc konczy sie zastrzezeniem,
    a nie cichym pominieciem.
    """
    text = str(value or '').strip()
    if lower:
        text = text.lower()
    return text if pattern.match(text) else ''


def _as_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


# Pola kotwicy bankowej. Nazwa banku jest tekstem swobodnym, wiec zamiast
# waskiego wzorca odrzucamy tylko to, co moze byc znacznikiem albo znakiem
# sterujacym — reszta i tak jest escapowana przy wyswietlaniu.
_ANCHOR_BANK_RE = re.compile(r'^[^<>\x00-\x1f\x7f]{1,120}$')
_ANCHOR_DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_ANCHOR_STATUS_RE = re.compile(r'^[a-z_]{1,20}$')
_ANCHOR_REF_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ./_:#-]{0,59}$')
_ANCHOR_URL_RE = re.compile(r'^https://[^\s<>"\'\\]{1,500}$')


def _clean_anchor(anchor: dict) -> dict:
    """Kotwica z odpowiedzi serwera — tylko znane pola o poprawnym formacie."""
    bank = str(anchor.get('bank') or '').strip()
    out = {
        'bank': bank if _ANCHOR_BANK_RE.match(bank) else '',
        'date': _clean(str(anchor.get('date') or '')[:10], _ANCHOR_DATE_RE),
        'status': _clean(anchor.get('status'), _ANCHOR_STATUS_RE),
        'root': _clean(anchor.get('root'), merkle.HEX64, lower=True),
        'bank_reference': _clean(anchor.get('bank_reference'), _ANCHOR_REF_RE),
        'statement_url': _clean(anchor.get('statement_url'), _ANCHOR_URL_RE),
    }
    if 'root_matches_week' in anchor:
        out['root_matches_week'] = anchor.get('root_matches_week') is True
    return out


def anchor_confirms(anchor: object, week_root: str) -> bool:
    """Czy kotwica bankowa potwierdza TEN korzen tygodnia (wedlug rejestru).

    Liczy sie wylacznie kotwica `confirmed`, ktorej pole `root` jest korzeniem
    tego tygodnia — i nigdy taka, dla ktorej sam serwer mowi
    `root_matches_week: false`. Wczesniej wystarczyl status: serwer (albo
    posrednik przekazujacy prawdziwe, podpisane dane) mogl dopisac „kotwice"
    dla dowolnego korzenia i podniesc PODPISANY do ZAKOTWICZONY.
    """
    if not isinstance(anchor, dict) or str(anchor.get('status')) != 'confirmed':
        return False
    if anchor.get('root_matches_week', True) is False:
        return False
    root = str(anchor.get('root') or '').strip().lower()
    return bool(week_root) and root == str(week_root).strip().lower()


# --- Czas stempla a podpisany tydzien ----------------------------------------
#
# Stempel trafia do tygodnia ISO swojej chwili `utc`, a gdy ten tydzien jest
# juz zamkniety (wyscig na granicy tygodnia) — do nastepnego otwartego
# (apps/tsa/models.py: Stamp.record). Czas moze wiec wypasc tuz PRZED
# poczatkiem podpisanego tygodnia, ale nigdy po jego koncu.
WEEK_BOUNDARY_TOLERANCE = timedelta(minutes=5)


def week_bounds(week: object) -> tuple[datetime, datetime] | None:
    """(poczatek, koniec) tygodnia ISO w UTC; koniec to pierwsza chwila PO nim."""
    text = str(week or '').strip()
    if not _WEEK_RE.match(text):
        return None
    year, number = text.split('-W')
    try:
        start = datetime.fromisocalendar(int(year), int(number), 1)
    except ValueError:
        return None
    start = start.replace(tzinfo=timezone.utc)
    return start, start + timedelta(days=7)


def week_range_text(week: object) -> str:
    """'2026-W25' -> '15.06–21.06.2026' (dni tygodnia w UTC); '' gdy zly."""
    bounds = week_bounds(week)
    if bounds is None:
        return ''
    start, end = bounds
    last = end - timedelta(days=1)
    full = date_format()
    if start.year == last.year:
        return f'{start.strftime(short_date_format())}–{last.strftime(full)}'
    return f'{start.strftime(full)}–{last.strftime(full)}'


def week_end_text(week: object) -> str:
    """'2026-W25' -> '22.06.2026, 00:00 UTC' — koniec podpisanego tygodnia."""
    bounds = week_bounds(week)
    return f'{bounds[1].strftime(date_format())}, 00:00 UTC' if bounds else ''


def time_claim_problems(utc: object, beat: object, week: object) -> list[str]:
    """Czy deklarowany czas stempla zgadza sie z podpisanym tygodniem.

    Podpis obejmuje `tydzien|korzen`, a lisc drzewa — sam skrot. `utc` i
    `beat` sa wiec deklaracja rejestru i musza lezec w podpisanym tygodniu,
    a `beat` musi byc tym samym momentem co `utc`. Komunikaty nie powtarzaja
    surowych wartosci z wejscia: trafiaja do etykiet z tekstem wzbogaconym,
    wiec cytujemy tylko wartosci po walidacji formatu.
    """
    problems: list[str] = []
    utc_text = str(utc or '').strip()
    beat_text = str(beat or '').strip()
    week_text = str(week or '').strip()

    dt = None
    if utc_text:
        dt = beatcore.parse_iso_utc(utc_text) if _UTC_RE.match(utc_text) else None
        if dt is None:
            problems.append(_('The stamp time (UTC) has an invalid format.'))

    if beat_text:
        if not _BEAT_RE.match(beat_text):
            problems.append(_('The @beat time has an invalid format.'))
        elif dt is None:
            if not utc_text:
                problems.append(_(
                    'An @beat time was given without a UTC date — such a time '
                    'cannot be checked.'))
        else:
            decimals = len(beat_text.partition('.')[2])
            expected = beatcore.format_beat(beatcore.beats_from_utc(dt), decimals=decimals)
            if beat_text != expected:
                problems.append(
                    _('The @beat time %(beat)s does not match the UTC time '
                      '%(utc)s (it should be %(expected)s).')
                    % {'beat': beat_text, 'utc': beatcore.utc_str(dt),
                       'expected': expected})

    if dt is not None and week_text:
        bounds = week_bounds(week_text)
        if bounds is None:
            problems.append(_(
                'The week of the proof does not exist in the ISO calendar.'))
        elif not (bounds[0] - WEEK_BOUNDARY_TOLERANCE <= dt < bounds[1]):
            problems.append(
                _('The stamp time (%(utc)s) lies outside week %(week)s '
                  '(%(range)s UTC), whose root the proof covers. The signature '
                  'confirms only the week, so a time outside it has no backing '
                  'in the proof — the data is inconsistent.')
                % {'utc': beatcore.utc_str(dt), 'week': week_text,
                   'range': week_range_text(week_text)})
    return problems


def retired_key_warning(public_key: str, week: str, *, hint: str = '') -> str:
    """Komunikat dla podpisu wycofanym kluczem (wspolny dla proof i bundle)."""
    info = keys.retired_info(public_key) or {}
    when = format_iso_date(info.get('retired_on', ''))
    week_part = f' {week}' if week else ''
    hint = hint or _('Refresh the proof online (History -> Refresh statuses, F5) '
                     'to fetch a signature made with the current key.')
    return _(
        'The root of week%(week)s was signed with a BeatTime key retired on '
        '%(when)s. A signature from a retired key is no longer a proof, so the '
        'level stays "Recorded" — the external anchor is also waiting for '
        'confirmation. %(hint)s'
    ) % {'week': week_part, 'when': when, 'hint': hint}


def verify_payload(payload: dict, *, expected_digest: str = '',
                   key_override: str = '') -> VerificationResult:
    """Sprawdza odpowiedź z /api/proof/stamp|verify wyłącznie lokalnie.

    `expected_digest` (skrót policzony z PLIKU u nas) jest porownywany z tym,
    co odesłał serwer. Bez tego porownania serwer moglby odpowiedziec dowodem
    na calkiem inny dokument, a aplikacja pokazalaby zielona ikone.

    `key_override` to opcjonalny WLASNY klucz z ustawien (zaawansowane).
    Pusty = tylko wbudowana lista kluczy z keys.py. Wlasny klucz jest
    uznawany obok listy, ale nigdy nie przywraca klucza wycofanego.
    """
    r = VerificationResult()
    if not isinstance(payload, dict):
        r.problems.append(_('The server answer is not a valid JSON object.'))
        return r

    r.found = bool(payload.get('found', True))
    r.digest = str(payload.get('digest') or '').strip().lower()

    if expected_digest:
        expected = expected_digest.strip().lower()
        if r.digest and r.digest != expected:
            r.problems.append(_(
                'The server answered with a proof for a DIFFERENT digest than '
                'the one sent — the answer was rejected.'
            ))
            r.found = False
            return r
        r.digest = r.digest or expected

    if not r.found:
        return r

    if not merkle.is_digest(r.digest):
        r.problems.append(_('The server returned a digest in an invalid format.'))
        r.found = False
        return r

    # Kazde pole przechodzi przez walidator FORMATU, zanim gdziekolwiek
    # trafi. Powod jest konkretny: te wartosci ida potem do etykiet Qt
    # (tekst wzbogacony) i do `Paragraph` reportlaba (XML). Jedno i drugie
    # interpretuje znaczniki, wiec `week_root` w postaci
    # `<img src="//host/x.png">` zamienialby wystawienie certyfikatu w
    # zapytanie sieciowe do serwera atakujacego — z uwierzytelnieniem SMB
    # po drodze. Kontrola formatu przy granicy zaufania zatrzymuje to raz,
    # zamiast polegac na tym, ze kazde miejsce wyswietlajace zapamieta o
    # escapowaniu.
    r.beat = _clean(payload.get('beat'), _BEAT_RE)
    r.utc = _clean(payload.get('utc'), _UTC_RE)
    r.seq = _as_int(payload.get('seq'))
    r.week = _clean(payload.get('week'), _WEEK_RE)
    r.week_closed = bool(payload.get('week_closed'))
    r.chain_hash = _clean(payload.get('chain_hash'), merkle.HEX64, lower=True)
    r.ots_status = _clean(payload.get('ots_status'), _OTS_RE) or 'none'
    r.ots_height = _as_int(payload.get('ots_bitcoin_height'))
    r.public_key = _clean(payload.get('public_key'), _B64_RE)

    raw_root = str(payload.get('week_root') or '').strip().lower()
    r.week_root = raw_root if merkle.HEX64.match(raw_root) else ''
    if raw_root and not r.week_root:
        r.problems.append(_(
            'The server gave the week root in an invalid format — the answer '
            'was rejected.'))
        return r
    anchors = payload.get('anchors')
    r.anchors = ([_clean_anchor(a) for a in anchors if isinstance(a, dict)]
                 if isinstance(anchors, list) else [])
    proof = payload.get('inclusion_proof')
    if isinstance(proof, list):
        r.inclusion_proof = [s for s in proof if isinstance(s, dict)]

    # --- 0. Deklarowany czas a tydzien ---
    # Podpis nie obejmuje `utc` ani `beat`, wiec bez tej kontroli poprawnie
    # podpisany dowod mogl nosic dowolna wczesniejsza date.
    r.problems.extend(time_claim_problems(r.utc, r.beat, r.week))

    # --- 1. Inkluzja w drzewie tygodnia ---
    if isinstance(proof, list) and r.week_root:
        r.inclusion_checked = True
        r.inclusion_ok = merkle.verify_inclusion(r.digest, r.inclusion_proof, r.week_root)
        if not r.inclusion_ok:
            r.problems.append(_(
                'The inclusion path does NOT lead to the given week root — the '
                'proof data is inconsistent.'
            ))

    # --- 2. Podpis korzenia + 3. tozsamosc klucza ---
    sig = str(payload.get('root_signature') or '')
    r.root_signature = sig
    if sig and r.week_root and r.week:
        r.signature_checked = True
        # Matematyke liczymy kluczem, ktory wskazuje odpowiedz (bez klucza —
        # aktualnym kluczem z listy, zeby zastrzezenie mowilo prawde o
        # samym podpisie). ZAUFANIE rozstrzyga wylacznie keys.py.
        r.signature_ok = verify_ed25519_root(
            r.week, r.week_root, sig, r.public_key or keys.primary_key())
        if not r.signature_ok:
            r.problems.append(_(
                'The Ed25519 signature of the week root is invalid.'))
        r.signer_status = keys.classify(r.public_key, key_override)
        r.key_pinned_ok = r.signer_status in keys.TRUSTED_STATUSES
        if r.signer_status == keys.SIGNER_RETIRED:
            # Nie zastrzezenie (podpis byl kiedys prawdziwy), ale tez nie
            # dowod — ponizej poziom zostaje ograniczony do ZAREJESTROWANY.
            if r.signature_ok:
                r.warnings.append(retired_key_warning(r.public_key, r.week))
        elif r.signer_status == keys.SIGNER_UNKNOWN:
            if not r.public_key:
                r.problems.append(_(
                    'The server did not give a public key for the signature.'))
            else:
                r.problems.append(_(
                    'The server signed the root with a key OTHER than the '
                    'BeatTime keys built into the application. The signature may '
                    'be technically valid, but it does not prove it comes from '
                    'BeatTime.'
                ))

    # --- Poziom dowodu ---
    #
    # Poziom NIE MOZE wyrosnac ponad to, co aplikacja sprawdzila sama.
    #
    # Wczesniejsza wersja tego kodu ustawiala ZAKOTWICZONY na podstawie
    # samego pola `ots_status` z odpowiedzi — a to zwykly napis od serwera,
    # nie dowod. Wystarczylo wiec, zeby podszywajacy sie serwer odpowiedzial
    # `{"ots_status": "bitcoin"}` BEZ korzenia, bez sciezki i bez podpisu:
    # nie bylo czego sprawdzac, wiec nie bylo tez zadnego zastrzezenia, a
    # aplikacja pokazywala zielona plakietke „Najwyzszy poziom" i wystawiala
    # certyfikat PDF z napisem „potwierdzony — blok Bitcoin". Caly model
    # bezpieczenstwa („zaufaj matematyce, nie serwerowi") byl omijany bez
    # dotykania przypietego klucza — bo galaz, ktora ten klucz sprawdza,
    # nigdy nie byla osiagana.
    #
    # Teraz jest odwrotnie: kotwica zewnetrzna moze PODNIESC poziom dopiero
    # ponad dowod, ktory przeszedl pelna kontrole kryptograficzna — z kluczem
    # z AKTUALNEJ listy. Podpis wycofanym kluczem zatrzymuje sie nizej, a
    # kazde zastrzezenie (np. czas spoza podpisanego tygodnia) tez.
    crypto_ok = (r.inclusion_checked and r.inclusion_ok
                 and r.signature_checked and r.signature_ok and r.key_pinned_ok)
    verified = crypto_ok and not r.problems
    # Kotwica bankowa liczy sie tylko dla TEGO korzenia (anchor_confirms).
    claims_anchor = (r.ots_status == 'bitcoin'
                     or any(anchor_confirms(a, r.week_root) for a in r.anchors))
    if any(str(a.get('status')) == 'confirmed' and not anchor_confirms(a, r.week_root)
           for a in r.anchors):
        r.warnings.append(_(
            'The server gave a confirmed bank anchor for a root other than the '
            'root of this week — that anchor was not accepted.'))

    if verified:
        r.level = Level.ANCHORED if claims_anchor else Level.SIGNED
    else:
        r.level = Level.RECORDED
        # Przy wycofanym kluczu ostrzezenie o nim mowi juz, ze kotwica czeka;
        # przy zastrzezeniu mowi to samo zastrzezenie.
        if claims_anchor and not crypto_ok and not r.needs_refresh:
            r.warnings.append(_(
                'The server claims the week root is anchored, but it did not '
                'supply the complete data (inclusion path + signature), so this '
                'could not be confirmed locally. The proof level stays '
                '"Recorded".'
            ))

    # --- Ostrzezenia: prawdziwe, ale nie dyskwalifikujace ---
    if r.week_closed and not sig:
        r.warnings.append(_(
            'The week is closed, but the root has no signature yet. This usually '
            'means the closing is under way.'
        ))
    if not r.inclusion_checked and r.week_closed:
        r.warnings.append(_(
            'The server did not supply an inclusion path — membership in the '
            'root could not be confirmed locally.'
        ))
    return r
