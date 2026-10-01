"""
Certyfikat PDF skladany lokalnie — wzorzec z serwera Sigelith, w jezyku
interfejsu.

Uklad odwzorowuje `apps/tsa/cert.py` z monorepo, żeby dokument z aplikacji
i ten z sigelith.org mowily dokładnie to samo. Roznice względem poprzednika:

* Kod QR jest WEKTOROWY (`reportlab.graphics.barcode.qr`). Stary kod robil go
  biblioteka `qrcode`, zapisywal PNG przez
  `tempfile.NamedTemporaryFile(delete=False)` i nigdy nie kasowal — każdy
  wystawiony certyfikat zostawial smiec w `%TEMP%` na zawsze. Tutaj zaden
  plik posredni nie powstaje, a kod QR jest ostry przy kazdym powiekszeniu.
  (Pillow zostaje w paczce mimo wszystko — `reportlab.lib.utils` importuje je
  bezwarunkowo — ale zadnego obrazu juz nie dekodujemy.)
* Tresc idzie przez katalog tlumaczen i mówi PRAWDE o poziomie dowodu.
  UWAGA: akapity o mocy dowodowej sa tekstem prawnym — ich tlumaczenie
  wymaga korekty, a nie przepisania maszyna. Stary certyfikat
  drukowal "Timestamp 2 (Google)" i "Timestamp 3 (WorldTimeAPI)" jako rzekome
  potwierdzenia — to byly zwykle odczyty czasu z cudzych serwerow, bez
  jakiejkolwiek wartości dowodowej (a WorldTimeAPI już nie istnieje).
* Kazda wartość wstawiana do XML-a `Paragraph` jest escapowana. Nazwa pliku z
  `&` albo `<` wywracala wcześniej generowanie PDF-a.
* Jezyk dokumentu = jezyk interfejsu. Lacinka i cyrylica ida osadzonym
  Interem (`PDF_LANGUAGES`); japonski, koreanski i chinski — czcionka
  systemowa Windows osadzana podzbiorem (`fonts.pdf_script_font`). Bez niej
  oraz po arabsku certyfikat powstaje PO ANGIELSKU: reportlab nie ksztaltuje
  liter arabskich (wyszlyby rozsypane i w odwrotnej kolejnosci).
  Czcionek CID reportlaba (bez osadzania) swiadomie NIE uzywamy: czytnik
  oparty na PDFium (Edge, Chrome) nie pokazywal z nich hangulu wcale.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _xml

import reportlab.rl_config as _rl_config

# Odcinamy reportlabowi SIEC I DYSK, zanim cokolwiek narysujemy.
#
# `Paragraph` reportlaba rozumie `<img src="...">` i rozwiazuje ten adres
# w czasie skladania dokumentu — przez `open()`, a gdy to sie nie uda, przez
# `urlopen()`. Domyslnie `trustedHosts is None`, co w `reportlab.lib.utils`
# oznacza „nie sprawdzaj hosta w ogole", a `trustedSchemes` zawiera http,
# https i file. Znacznik przemycony w danych zamienialby wiec wystawienie
# certyfikatu w zapytanie do serwera atakujacego — a na Windows sciezka UNC
# (`//host/udzial/x.png`) dokladalaby do tego uwierzytelnienie SMB, czyli
# wyciek nazwy konta i skrotu NTLM.
#
# Certyfikat nie ma zadnego zasobu zewnetrznego: kod QR jest rysowany
# wektorowo, tekst to czcionki wbudowane. Puste listy nic wiec nie psuja,
# a zamykaja cala kategorie.
_rl_config.trustedHosts = []
_rl_config.trustedSchemes = []

from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from . import __app_name__, __version__, beatcore, fonts, i18n, keys, merkle, plural, proof
from .config import verify_url
from .hashing import human_size
from .i18n import _, format_iso_date
from .proof import Level

ACCENT = colors.HexColor('#ff5c39')
INK = colors.HexColor('#11151c')
MUTED = colors.HexColor('#5b6472')
LINE = colors.HexColor('#d9dee6')
OK_GREEN = colors.HexColor('#1f8a4c')
WARN = colors.HexColor('#b26a00')
BAD = colors.HexColor('#b3261e')

# Adres weryfikacji w kodzie QR: `config.VERIFY_URL` — jedno miejsce dla
# certyfikatu, historii i okna (tam tez uwaga o ostatecznej sciezce).

#: Jezyki, ktorych pismo ma osadzona czcionka certyfikatu (lacinka, cyrylica).
#: Pozostale dostaja certyfikat po angielsku — patrz naglowek modulu.
PDF_LANGUAGES = frozenset({'pl', 'en', 'de', 'es', 'fr', 'ru', 'tr'})

#: Jezyki, ktorych certyfikat sklada sie czcionka systemowa Windows
#: (`fonts.pdf_script_font`). Bez niej — po angielsku.
CJK_LANGUAGES = frozenset({'ja', 'ko', 'zh'})

#: Jezyki bez spacji miedzy slowami: akapit lamie sie po znakach.
_CHAR_WRAP = frozenset({'ja', 'zh'})


#: Ile znakow nazwy pliku i notatki drukujemy na certyfikacie.
USER_TEXT_MAX = 2000


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + '…'


def certificate_language(language: str | None = None) -> str:
    """Jezyk, w ktorym powstanie certyfikat przy danym jezyku interfejsu."""
    language = language or i18n.current_language()
    if language in PDF_LANGUAGES:
        return language
    if language in CJK_LANGUAGES and fonts.pdf_script_font(language):
        return language
    return i18n.SOURCE_LANGUAGE


def _is_hangul(ch: str) -> bool:
    o = ord(ch)
    return 0x1100 <= o <= 0x11FF or 0x3130 <= o <= 0x318F or 0xAC00 <= o <= 0xD7AF


def _is_kana(ch: str) -> bool:
    o = ord(ch)
    return 0x3040 <= o <= 0x30FF or 0x31F0 <= o <= 0x31FF or 0xFF66 <= o <= 0xFF9F


def _is_cjk(ch: str) -> bool:
    o = ord(ch)
    return (_is_hangul(ch) or _is_kana(ch)
            or 0x2E80 <= o <= 0x2FDF       # rdzenie, znaki opisu
            or 0x3000 <= o <= 0x303F       # interpunkcja CJK
            or 0x3400 <= o <= 0x4DBF       # rozszerzenie A
            or 0x4E00 <= o <= 0x9FFF       # ideogramy
            or 0xF900 <= o <= 0xFAFF       # ideogramy zgodnosci
            or 0xFF00 <= o <= 0xFFEF       # formy pelnej szerokosci
            or 0x20000 <= o <= 0x2FFFF)    # rozszerzenia B-F


def has_cjk(text: str) -> bool:
    return any(_is_cjk(ch) for ch in str(text or ''))


def _script_order(text: str, interface: str) -> list[str]:
    """Kolejnosc czcionek CJK dla tekstu: najpierw po pismie, potem po jezyku.

    Ten sam ideogram ma inny rysunek po japonsku, koreansku i chinsku, wiec
    tekst z kana idzie czcionka japonska, z hangulem — koreanska, a same
    ideogramy — czcionka jezyka INTERFEJSU (japonski uzytkownik moze dostac
    certyfikat po angielsku, ale jego nazwa pliku ma wygladac po japonsku).
    """
    if any(_is_kana(ch) for ch in text):
        first = 'ja'
    elif any(_is_hangul(ch) for ch in text):
        first = 'ko'
    else:
        first = interface if interface in CJK_LANGUAGES else 'zh'
    return [first] + [s for s in ('ja', 'zh', 'ko') if s != first]


def _user_text(text: str, interface: str = '', base_chars=None) -> str:
    """Tekst uzytkownika (nazwa pliku, notatka) jako bezpieczny XML `Paragraph`.

    Znaki CJK dostaja czcionke systemowa, ktora je MA (sprawdzane po mapie
    znakow), reszta zostaje w czcionce certyfikatu — inaczej japonska nazwa
    pliku drukowala sie jako rzad kwadratow. Znak, ktorego nie ma ZADNA
    czcionka (pismo arabskie, emoji), drukuje sie jako „?": czytnik PDF
    pokazuje brakujacy znak jako NIC, a certyfikat nie moze po cichu gubic
    fragmentu notatki. Arabskiego nie da sie wiernie wydrukowac bez
    ksztaltowania liter i porzadku bidi, ktorych reportlab sam nie robi.
    `base_chars` — mapa znakow czcionki tekstu (None = nie sprawdzaj).
    """
    text = str(text or '')
    candidates = []
    if has_cjk(text):
        candidates = [f for f in (fonts.pdf_script_font(s)
                                  for s in _script_order(text, interface)) if f]

    def font_of(ch: str) -> tuple[str, str]:
        if _is_cjk(ch):
            for font in candidates:
                if ord(ch) in font['chars']:
                    return font['regular'], ch
        if base_chars is None or ch.isspace() or ord(ch) in base_chars:
            return '', ch
        return '', '?'

    out: list[str] = []
    run: list[str] = []
    current = ''
    for original in text:
        name, ch = font_of(original)
        if run and name != current:
            chunk = _xml(''.join(run))
            out.append(f'<font name="{current}">{chunk}</font>' if current else chunk)
            run = []
        current = name
        run.append(ch)
    if run:
        chunk = _xml(''.join(run))
        out.append(f'<font name="{current}">{chunk}</font>' if current else chunk)
    return ''.join(out)


def _qr(url: str, size_mm: float = 34) -> Drawing:
    """Kod QR jako grafika wektorowa — ostry przy każdym powiekszeniu."""
    widget = QrCodeWidget(url)
    bounds = widget.getBounds()
    w, h = bounds[2] - bounds[0], bounds[3] - bounds[1]
    side = size_mm * mm
    drawing = Drawing(side, side, transform=[side / w, 0, 0, side / h, 0, 0])
    drawing.add(widget)
    return drawing


# Stany wpisu na certyfikacie. Liczone OD NOWA z danych wpisu (`_assess`),
# a nie przepisywane z zapisanego pola `level`: wpis historii to zwykly plik
# tekstowy, a wynik weryfikacji zalezy od dzisiejszej listy kluczy i od
# wlasnego klucza w ustawieniach.
STATE_LEGACY = 'legacy'          # archiwum starego klienta TVS
STATE_RETIRED = 'retired'        # podpis kluczem wycofanym — do odswiezenia
STATE_UNKNOWN = 'unknown'        # podpis kluczem spoza listy — niewiazacy
STATE_UNVERIFIED = 'unverified'  # dane nie przeszly kontroli lokalnej
STATE_ANCHORED = 'anchored'
STATE_SIGNED = 'signed'
STATE_CLOSING = 'closing'        # tydzien zamkniety, podpis jeszcze nie dotarl
STATE_OPEN = 'open'              # tydzien trwa
_PROVEN = frozenset({STATE_ANCHORED, STATE_SIGNED})


def _signer_status(entry, key_override: str = '') -> str:
    """keys.SIGNER_* dla podpisu korzenia w tym wpisie; '' gdy podpisu brak."""
    if not getattr(entry, 'root_signature', ''):
        return ''
    return keys.classify(str(getattr(entry, 'public_key', '') or ''), key_override)


def _verified(entry) -> bool:
    """Wynik ostatniej kontroli lokalnej (Entry.verified_ok / Result.trusted)."""
    value = getattr(entry, 'verified_ok', None)
    if value is None:
        value = getattr(entry, 'trusted', False)
    return bool(value)


def _assess(entry, key_override: str = '') -> tuple[str, str]:
    """(STATE_*, keys.SIGNER_*) — co ten certyfikat moze uczciwie poswiadczyc.

    Poziom „Podpisany"/„Zakotwiczony" wymaga naraz: podpisu korzenia kluczem,
    ktory DZIS uznajemy (lista wbudowana albo wlasny klucz z ustawien),
    udanej kontroli lokalnej i czasu lezacego w podpisanym tygodniu. Brak
    ktoregokolwiek zdejmuje poziom — takze gdy wpis twierdzi inaczej.
    """
    status = _signer_status(entry, key_override)
    if str(getattr(entry, 'source', '') or '') == 'tvs-legacy':
        return STATE_LEGACY, status
    if status == keys.SIGNER_RETIRED:
        return STATE_RETIRED, status
    if status == keys.SIGNER_UNKNOWN:
        return STATE_UNKNOWN, status
    verified = _verified(entry)
    has_sig = bool(status)
    week_closed = bool(getattr(entry, 'week_closed', False))
    time_ok = not proof.time_claim_problems(
        getattr(entry, 'utc', ''), getattr(entry, 'beat', ''), getattr(entry, 'week', ''))
    level = _level_of(entry)
    if not time_ok or (has_sig and not verified):
        return STATE_UNVERIFIED, status
    if has_sig and level.order >= Level.SIGNED.order:
        return (STATE_ANCHORED if level is Level.ANCHORED else STATE_SIGNED), status
    if week_closed and not has_sig:
        return STATE_CLOSING, status
    if not verified or week_closed:
        return STATE_UNVERIFIED, status
    return STATE_OPEN, status


def _level_line(entry, key_override: str = '') -> tuple[str, colors.Color]:
    state, _status = _assess(entry, key_override)
    if state == STATE_LEGACY:
        return _('TVS ARCHIVE — entry from the old client, without verifiable '
                 'proof'), WARN
    # Wycofany klucz nigdy nie daje wyzszego poziomu — takze gdy wpis
    # z historii (zwykly plik tekstowy) twierdzi inaczej.
    if state == STATE_RETIRED:
        return _('RECORDED — root signed with a retired key, the proof needs '
                 'refreshing'), WARN
    if state == STATE_UNKNOWN:
        return _('UNCONFIRMED — root signed with a key outside the Sigelith '
                 'list, signature not binding'), BAD
    if state == STATE_UNVERIFIED:
        return _('UNCONFIRMED — the proof did not pass the local check'), BAD
    if state == STATE_ANCHORED:
        return _('ANCHORED — the week root is preserved outside Sigelith'), OK_GREEN
    if state == STATE_SIGNED:
        return _('SIGNED — the week root is frozen and signed with Ed25519'), OK_GREEN
    if state == STATE_CLOSING:
        return _('RECORDED — week closed, the root signature is on its way'), WARN
    return _('RECORDED — the week is still running, the anchor is on its '
             'way'), WARN


def _level_of(entry) -> Level:
    raw = getattr(entry, 'level', '')
    raw = raw.value if hasattr(raw, 'value') else str(raw or '')
    try:
        return Level(raw)
    except ValueError:
        return Level.RECORDED


def _signature_text(entry, key_override: str = '') -> str:
    state, status = _assess(entry, key_override)
    if not status:
        if getattr(entry, 'week_closed', False):
            return _('no root signature')
        return _('waiting for the week to close')
    if status == keys.SIGNER_RETIRED:
        info = keys.retired_info(str(getattr(entry, 'public_key', '') or '')) or {}
        return _('Ed25519 — with a key retired on %(when)s, signature not '
                 'binding') % {'when': format_iso_date(info.get('retired_on', ''))}
    if status == keys.SIGNER_UNKNOWN:
        return _('Ed25519 — with a key outside the Sigelith list, signature not '
                 'binding')
    if state not in _PROVEN:
        return _('Ed25519 — the signature was not confirmed by the local check')
    if status == keys.SIGNER_OVERRIDE:
        return _('Ed25519 — root signed with YOUR OWN key from the settings '
                 '(outside the built-in list), checked locally')
    return _('Ed25519 — root signed with a Sigelith key, checked locally')


def _coverage_text(entry, state: str) -> str:
    """Co podpis faktycznie obejmuje: TYDZIEN, nie dokladna chwile.

    Podpisany jest tekst `beattime-proof-v1|<tydzien>|<korzen>`, a lisc drzewa
    to sam skrot — `utc`/`beat` sa deklaracja rejestru. Uczciwy certyfikat
    pokazuje wiec tydzien jako granice potwierdzona podpisem.
    """
    week = str(getattr(entry, 'week', '') or '')
    week_range = proof.week_range_text(week)
    if state in _PROVEN and week_range:
        return _('week %(week)s (%(range)s UTC) — root signed and checked: the '
                 'document existed no later than %(end)s. The exact moment '
                 'within that week is given by the Sigelith register.') % {
                     'week': week, 'range': week_range,
                     'end': proof.week_end_text(week)}
    if state == STATE_OPEN and week_range:
        return _('week %(week)s is still running — the signature will cover it '
                 'once it closes; the exact time is given by the Sigelith '
                 'register.') % {'week': week}
    return _('none — the time comes from the register alone, without '
             'confirmation by a signature.')


def _ots_text(entry, state: str = STATE_OPEN) -> str:
    """OpenTimestamps — deklaracja rejestru; aplikacja nie sprawdza pliku .ots."""
    status = str(getattr(entry, 'ots_status', 'none') or 'none')
    height = getattr(entry, 'ots_height', None)
    if status in ('bitcoin', 'pending') and state not in _PROVEN:
        # Kotwica niczego nie podnosi, gdy sam korzen nie jest potwierdzony.
        return _('not binding — root without a confirmed Sigelith signature')
    if status == 'bitcoin':
        where = (_('Bitcoin block %(height)s') % {'height': height} if height
                 else _('the Bitcoin chain'))
        week = str(getattr(entry, 'week', '') or '')
        ots = (_(' — .ots file for independent verification: '
                 'sigelith.org/api/proof/ots/%(week)s') % {'week': week}
               if proof.week_bounds(week) else '')
        return _('confirmed according to the register — %(where)s%(ots)s') % {
            'where': where, 'ots': ots}
    if status == 'pending':
        return _('submitted to the OpenTimestamps calendars, waiting for a block')
    if getattr(entry, 'week_closed', False):
        return _('not submitted yet')
    return _('— (the week is still running)')


def _anchor_text(entry, state: str = STATE_OPEN) -> str:
    """Kotwice bankowe — deklaracja rejestru; tekst XML (wartosci escapowane)."""
    anchors = getattr(entry, 'anchors', None) or []
    week_root = str(getattr(entry, 'week_root', '') or '')
    lines = []
    for a in anchors:
        if not isinstance(a, dict):
            continue
        bank = _xml(str(a.get('bank') or ''))
        date = _xml(str(a.get('date') or '')[:10])
        raw_status = str(a.get('status') or '')
        if raw_status == 'confirmed':
            if state not in _PROVEN:
                status = _('not binding — root without a confirmed Sigelith '
                           'signature')
            elif not proof.anchor_confirms(a, week_root):
                status = _('concerns a root other than the week root — not '
                           'accepted')
            else:
                status = _('confirmed according to the register')
        elif raw_status == 'pending':
            status = _('pending')
        else:
            status = _xml(raw_status)
        line = ' · '.join(p for p in (bank, date, status) if p)
        ref = _xml(str(a.get('bank_reference') or ''))
        if ref:
            line += _(' · confirmation no. %(ref)s') % {'ref': ref}
        lines.append(line)
    return '<br/>'.join(lines) if lines else '—'


def _wrap_hex(value: str, width: int = 32) -> str:
    """Lamie dlugi ciag hex, żeby nie wychodzil poza margines strony.

    Courier 8.5 pt miesci ~48 znakow w kolumnie wartości; 64-znakowy skrót
    bez zlamania był w starym certyfikacie ucinany przez krawedz strony.
    """
    value = _xml(value or '')
    return '<br/>'.join(value[i:i + width] for i in range(0, len(value), width)) or '—'


def _bound_text(bound: dict | None) -> str:
    """Granica czasu po ludzku: zrodlo, chwila, blok/przelew (tekst ZWYKLY)."""
    from . import witness
    if not isinstance(bound, dict) or not bound:
        return ''
    moment = witness.bound_moment(bound)
    when = (f'{beatcore.local_str(moment)} ({beatcore.utc_str(moment)})'
            if moment else '')
    source = bound.get('source')
    if source == 'bitcoin_block':
        what = _('Bitcoin block %(height)s named in checkpoint #%(n)s') % {
            'height': bound.get('height', '?'), 'n': bound.get('checkpoint', '?')}
    elif source == 'opentimestamps':
        what = _('OpenTimestamps — Bitcoin block %(height)s') % {
            'height': bound.get('height', '?')}
    elif source == 'bank':
        what = _('bank transfer %(bank)s, booked %(date)s') % {
            'bank': bound.get('bank', ''), 'date': bound.get('date', '')}
    else:
        return ''
    return f'{when} — {what}' if when else what


def _copies_text(entry, witness_state) -> str:
    """Kopie checkpointu u osob trzecich, ktore aplikacja sama porownala."""
    from . import witness
    cp = getattr(entry, 'checkpoint', None) or {}
    if not cp.get('verified') or witness_state is None:
        return ''
    pin = witness.pinning(cp, witness_state)
    names = {'github': 'GitHub', 'wayback': 'Internet Archive', 'zenodo': 'Zenodo'}
    done = [names[s] for s in pin.sources]
    if not done:
        return _('not published yet — they follow in their own rhythm (GitHub '
                 'weekly, Internet Archive weekly, Zenodo quarterly)')
    return _('identical copies checked by Sigelith Desktop at: %(list)s') % {
        'list': ', '.join(done)}


def build_certificate(entry, *, key_override: str = '', witness_state=None) -> bytes:
    """Składa certyfikat PDF dla wpisu historii. Zwraca bajty gotowe do zapisu.

    Jezyk dokumentu wybiera `certificate_language()`; szczegoly w `_build`.
    """
    interface = i18n.current_language()
    language = certificate_language(interface)
    if language == interface:
        return _build(entry, key_override=key_override, witness_state=witness_state,
                      interface=interface)
    with i18n.temporary(language):
        return _build(entry, key_override=key_override, witness_state=witness_state,
                      interface=interface)


def _build(entry, *, key_override: str = '', witness_state=None,
           interface: str = '') -> bytes:
    """Certyfikat w BIEZACYM jezyku — wolac przez `build_certificate`.

    `entry` to `history.Entry` albo `proof.VerificationResult` — oba maja te
    same nazwy pol, więc certyfikat nie musi wiedziec, skad dane pochodza.
    `key_override` to wlasny klucz z ustawien: poziom na certyfikacie jest
    liczony od nowa wedlug DZISIEJSZEGO zaufania (`_assess`), nie przepisany
    z wpisu.
    """
    digest = str(getattr(entry, 'digest', '') or '')
    # Skrót z historii mógł zostać podmieniony poza aplikacją (plik
    # `history.json` jest zwykłym tekstem w katalogu użytkownika), więc
    # zanim trafi gdziekolwiek POZA escapowaną treść dokumentu, sprawdzamy
    # jego format. Dwa takie miejsca istnieją i żadne nie przechodzi przez
    # `_xml`: metadane PDF-a oraz adres zakodowany w kodzie QR. Ten drugi
    # jest istotniejszy — kod QR jest zaproszeniem do kliknięcia, a nikt nie
    # czyta go wzrokiem przed zeskanowaniem.
    digest_is_valid = merkle.is_digest(digest)
    # Pole notatki przyjmuje 32 767 znakow, a od ~12 000 reportlab nie
    # miesci akapitu na stronie (LayoutError). Na certyfikacie wystarcza
    # poczatek — pelna tresc zostaje w historii i w pliku .beatproof.
    file_name = _clip(str(getattr(entry, 'file_name', '') or ''), USER_TEXT_MAX)
    note = _clip(str(getattr(entry, 'note', '') or ''), USER_TEXT_MAX)
    week = str(getattr(entry, 'week', '') or '')
    week_root = str(getattr(entry, 'week_root', '') or '')
    seq = getattr(entry, 'seq', None)
    public_key = str(getattr(entry, 'public_key', '') or '')
    proof_steps = getattr(entry, 'inclusion_proof', None) or []
    utc_dt = beatcore.parse_iso_utc(str(getattr(entry, 'utc', '') or ''))

    now = datetime.now(timezone.utc)
    gen_beat = beatcore.format_beat(beatcore.beats_from_utc(now), decimals=2)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=14 * mm, bottomMargin=12 * mm,
        title=_('Sigelith — proof of existence %(digest)s') % {
            'digest': digest[:12] if digest_is_valid else _('unknown')},
        author=__app_name__, subject=_('Timestamp certificate'),
        creator=f'{__app_name__} {__version__}',
    )

    ss = getSampleStyleSheet()
    # Czcionki TrueType osadzane w dokumencie (`fonts.py`): bazowe czcionki
    # PDF nie maja polskich liter i zamienialy je na kwadraty.
    f = fonts.pdf_fonts()
    document_language = i18n.current_language()
    script = (fonts.pdf_script_font(document_language)
              if document_language in CJK_LANGUAGES else None)
    if script:
        # Tekst w czcionce systemowej; skroty i klucze zostaja w JetBrains Mono.
        f = dict(f, regular=script['regular'], medium=script['regular'],
                 bold=script['bold'])
    base_chars = fonts.pdf_chars(f['regular'])
    base = ParagraphStyle('base', parent=ss['Normal'], fontName=f['regular'],
                          wordWrap='CJK' if document_language in _CHAR_WRAP else None)
    brand = ParagraphStyle('brand', parent=base, fontName=f['bold'],
                           fontSize=15, leading=18, textColor=ACCENT, spaceAfter=3)
    title = ParagraphStyle('title', parent=base, fontName=f['bold'],
                           fontSize=20, leading=24, textColor=INK, spaceBefore=2, spaceAfter=4)
    sub = ParagraphStyle('sub', parent=base, fontSize=9.5, leading=13, textColor=MUTED)
    body = ParagraphStyle('body', parent=base, fontSize=9.5, textColor=INK, leading=14)
    label = ParagraphStyle('label', parent=base, fontName=f['medium'], fontSize=8.5,
                           textColor=MUTED)
    val = ParagraphStyle('val', parent=base, fontSize=9.2, textColor=INK, leading=12.4)
    # Tekst CJK nie ma spacji miedzy slowami: lamanie po znakach.
    val_cjk = ParagraphStyle('val_cjk', parent=val, wordWrap='CJK')
    mono = ParagraphStyle('mono', parent=base, fontName=f['mono'], fontSize=8.5,
                          textColor=INK, leading=11)
    foot = ParagraphStyle('foot', parent=base, fontSize=7.5, textColor=MUTED, leading=11)
    cap = ParagraphStyle('cap', parent=base, fontSize=7.5, textColor=MUTED,
                         alignment=TA_CENTER)

    state, _signer = _assess(entry, key_override)
    level_text, level_color = _level_line(entry, key_override)
    badge = ParagraphStyle('badge', parent=base, fontName=f['bold'],
                           fontSize=9.5, leading=13, textColor=level_color)
    note_style = ParagraphStyle('note', parent=base, fontSize=8.5, leading=12,
                                textColor=ACCENT, leftIndent=8, borderPadding=2)

    story = []
    # Kod QR w naglowku, obok tytulu: certyfikat miesci sie wtedy na jednej
    # stronie takze z trzema czasami i checkpointem (2.2). Na drugiej
    # stronie ladowal sam kod — czyli dokladnie to, co ktos skanuje.
    qr_caption = (_('Scan to verify at sigelith.org/proof')
                  if digest_is_valid else
                  _('The digest in this entry has an invalid format — the QR '
                    'code was skipped'))
    qr_content = (_qr(verify_url(digest), 27) if digest_is_valid
                  else Paragraph('!', cap))
    qr_block = Table([[qr_content], [Paragraph(qr_caption, cap)]],
                     colWidths=[34 * mm])
    qr_block.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    # Marka uslugi, ktora wystawia dowod. „@ BeatTime" (do 2.2.0) nazywalo
    # usluge nazwa zapisu czasu; czas @beat zostaje w tresci certyfikatu.
    heading = [Paragraph('Sigelith', brand),
               Paragraph(_('Proof of existence of a document'), title),
               Paragraph(_('Timestamp certificate · sigelith.org'), sub)]
    head = Table([[heading, qr_block]], colWidths=[None, 36 * mm])
    head.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(head)
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width='100%', thickness=1.4, color=ACCENT, spaceAfter=9))

    if state in (STATE_UNKNOWN, STATE_UNVERIFIED, STATE_LEGACY):
        story.append(Paragraph(_(
            'This document describes an entry whose proof was <b>not '
            'confirmed</b> by the local check. <b>It does not certify a '
            'timestamp</b> — the values below are merely the data stored in the '
            'entry.'), body))
    else:
        story.append(Paragraph(_(
            'This certificate attests that the document with the SHA-256 digest '
            'given below was registered in the public, append-only Sigelith '
            'register at the moment shown — in <b>@beat</b> time (1000 beats per '
            'day, anchored in UTC). The document itself <b>never left the '
            'computer</b>: only its cryptographic digest went to the register.'),
            body))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        _('Proof level: %(level)s') % {'level': _xml(level_text)}, badge))
    story.append(Spacer(1, 10))

    def kv(text, flowable):
        return [Paragraph(text, label), flowable]

    rows = []
    if file_name:
        size = getattr(entry, 'file_size', 0) or 0
        shown = _user_text(file_name, interface, base_chars) + (f' ({_xml(human_size(size))})' if size else '')
        rows.append(kv(_('Document'), Paragraph(
            shown, val_cjk if has_cjk(file_name) else val)))
    rows.append(kv(_('SHA-256 digest'), Paragraph(_wrap_hex(digest), mono)))
    # Jedna chwila w trzech zapisach — w jednym wierszu. Osobne wiersze
    # wypychaly stopke certyfikatu na druga strone.
    rows.append(kv(_('Moment of stamping'), Paragraph(
        '<b>%s</b> · %s · UTC %s' % (
            _xml(str(getattr(entry, 'beat', '') or '—')),
            _xml(beatcore.local_str(utc_dt) + beatcore.zone_suffix(utc_dt)),
            _xml(beatcore.utc_str(utc_dt))), val)))
    bounds = getattr(entry, 'time_bounds', None) or {}
    earliest = _bound_text(bounds.get('not_before'))
    latest = _bound_text(bounds.get('not_after'))
    if earliest and state not in (STATE_UNKNOWN, STATE_UNVERIFIED, STATE_LEGACY):
        rows.append(kv(_('Not earlier than'), Paragraph(_xml(earliest), val)))
    if latest and state not in (STATE_UNKNOWN, STATE_UNVERIFIED, STATE_LEGACY):
        rows.append(kv(_('Not later than'), Paragraph(_xml(latest), val)))
    rows.append(kv(_('Confirmed by signature'),
                   Paragraph(_xml(_coverage_text(entry, state)), val)))
    if seq is not None:
        rows.append(kv(_('Register no.'), Paragraph('#%s' % _xml(str(seq)), val)))
    if week:
        week_state = (_('closed') if getattr(entry, 'week_closed', False)
                      else _('open'))
        week_range = proof.week_range_text(week)
        shown_week = f'{_xml(week)} ({week_state})'
        if week_range:
            shown_week += f' · {_xml(week_range)} UTC'
        rows.append(kv(_('Week'), Paragraph(shown_week, val)))
    if week_root:
        rows.append(kv(_('Merkle root of the week'),
                       Paragraph(_wrap_hex(week_root), mono)))
    if proof_steps:
        rows.append(kv(_('Inclusion path'), Paragraph(
            _('%(steps)s to the week root')
            % {'steps': plural.steps(len(proof_steps))}, val)))
    rows.append(kv(_('Root signature'), Paragraph(
        _xml(_signature_text(entry, key_override)), val)))
    if public_key:
        rows.append(kv(_('Public key'), Paragraph(_xml(public_key), mono)))
    rows.append(kv('Bitcoin (OpenTimestamps)',
                   Paragraph(_xml(_ots_text(entry, state)), val)))
    rows.append(kv(_('Bank anchor'), Paragraph(_anchor_text(entry, state), val)))
    cp = getattr(entry, 'checkpoint', None) or {}
    if cp.get('n') and state not in (STATE_UNKNOWN, STATE_UNVERIFIED, STATE_LEGACY):
        cp_text = (_('#%(n)s — the path of this entry to its signed root was '
                     'checked by Sigelith Desktop (file hash %(hash)s)')
                   if cp.get('verified') else
                   _('#%(n)s — the path of this entry was NOT confirmed'))
        rows.append(kv(_('Log checkpoint'), Paragraph(_xml(cp_text % {
            'n': cp.get('n'), 'hash': str(cp.get('hash') or '')[:16] + '…'}), val)))
        copies = _copies_text(entry, witness_state)
        if copies:
            rows.append(kv(_('Independent copies'), Paragraph(_xml(copies), val)))
    if note:
        rows.append(kv(_('Note'), Paragraph(
            _user_text(note, interface, base_chars), val_cjk if has_cjk(note) else val)))

    table = Table(rows, colWidths=[40 * mm, None])
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3.2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.2),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.4, LINE),
    ]))
    story.append(table)
    story.append(Spacer(1, 10))

    if state == STATE_RETIRED:
        retired = keys.retired_info(public_key) or {}
        story.append(Paragraph(_(
            '<b>The proof needs refreshing.</b> The root of this week was signed '
            'with a Sigelith key retired on %(when)s — such a signature is no '
            'longer binding. Sigelith has re-signed every published root with '
            'the current key: refresh the proof in Sigelith Desktop (History -> Refresh '
            'statuses) and issue the certificate again. <b>The timestamp itself '
            'does not change.</b>')
            % {'when': _xml(format_iso_date(retired.get('retired_on', '')))},
            note_style))
        story.append(Spacer(1, 12))
    elif state in (STATE_UNKNOWN, STATE_UNVERIFIED):
        story.append(Paragraph(
            _('<b>The proof did not pass the local check.</b> ')
            + (_('The week root was signed with a key outside the Sigelith key '
                 'list built into the application — such a signature does not '
                 'prove its origin. ')
               if state == STATE_UNKNOWN else
               _('The inclusion path, the root signature or the stamp time do '
                 'not agree with the proof data. '))
            + _('Refresh the proof in Sigelith Desktop (History -> Refresh statuses, '
                'F5) and issue the certificate again. <b>Until then this '
                'document certifies nothing.</b>'), note_style))
        story.append(Spacer(1, 12))
    elif state == STATE_LEGACY:
        story.append(Paragraph(_(
            '<b>Entry from the archive of the old TVS client.</b> Its former '
            '"signature" is a concatenation of a time and a digest that cannot '
            'be verified. Stamp the file again in Sigelith Desktop to get a proof that '
            'can be checked independently.'), note_style))
        story.append(Spacer(1, 12))
    elif state in (STATE_OPEN, STATE_CLOSING):
        story.append(Paragraph(_(
            '<b>The proof is not closed yet.</b> The Ed25519 signature, the '
            'Bitcoin attestation (OpenTimestamps) and the bank anchor are added '
            '<i>after the current week closes</i> (the coming Monday, 00:00 '
            'UTC). Issue the certificate again after that date — the fields '
            'will fill in. <b>The timestamp itself will no longer change.</b>'),
            note_style))
        story.append(Spacer(1, 12))

    story.append(Spacer(1, 6))
    story.append(HRFlowable(width='100%', thickness=0.6, color=LINE, spaceAfter=6))
    story.append(Paragraph(_(
        'How to check independently: compute the SHA-256 of your document and '
        'enter the result at <b>sigelith.org/proof</b>. The weekly Merkle root '
        'is signed with an Ed25519 key and anchored outside Sigelith — in the '
        'Bitcoin chain (OpenTimestamps) and by an independent bank '
        'confirmation. The certificate attests <i>the existence of the document '
        'at a given moment</i> and its integrity — it does not attest '
        'authorship or the truth of the content.'), foot))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        _('Certificate issued %(utc)s (%(beat)s) by Sigelith Desktop %(version)s · '
          'sigelith.org') % {'utc': _xml(beatcore.utc_str(now)),
                              'beat': _xml(gen_beat),
                              'version': _xml(__version__)}, foot))

    doc.build(story)
    return buffer.getvalue()


def default_filename(entry) -> str:
    """Domyślna nazwa pliku PDF — po dokumencie, inaczej po skrócie."""
    from pathlib import Path
    digest = str(getattr(entry, 'digest', '') or '')
    # Skrót z historii mógł zostać podmieniony poza aplikacją (plik
    # `history.json` jest zwykłym tekstem w katalogu użytkownika), więc
    # zanim trafi gdziekolwiek POZA escapowaną treść dokumentu, sprawdzamy
    # jego format. Dwa takie miejsca istnieją i żadne nie przechodzi przez
    # `_xml`: metadane PDF-a oraz adres zakodowany w kodzie QR. Ten drugi
    # jest istotniejszy — kod QR jest zaproszeniem do kliknięcia, a nikt nie
    # czyta go wzrokiem przed zeskanowaniem.
    digest_is_valid = merkle.is_digest(digest)
    file_name = str(getattr(entry, 'file_name', '') or '')
    stem = Path(file_name).stem if file_name else ''
    # Awaryjny rdzen nazwy jest TLUMACZONY, ale bez znakow diakrytycznych:
    # trafia do nazwy pliku, a te wedruja miedzy systemami plikow.
    stem = stem or (digest[:16] if digest else _('certificate'))
    return f'{stem}_sigelith.pdf'
