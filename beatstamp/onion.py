"""
Biezacy adres uslugi .onion Sigelith — pobierany z serwisu i zapamietywany.

Od 3.0.0 program nie musi znac adresu .onion na zawsze z gory: serwis ogłasza
go pod `/api/onion/` (format `sigelith-onion-v1` — ten sam adres, co naglowek
`Onion-Location` na stronie). W trybie Tor program pyta:

1. ZNANY adres .onion (zapamietany, a za pierwszym razem wbudowany
   `config.ONION_BASE_URL`) — przez Tor, bez wychodzenia do zwyklego
   internetu. Adres .onion sam uwierzytelnia usluge (jest jej kluczem
   publicznym), wiec nikt po drodze nie podsunie innej odpowiedzi.
2. Gdy tamten nie odpowiada (np. zostal wycofany) — `https://sigelith.org`
   rowniez przez Tor; tozsamosc serwera potwierdza wtedy TLS.

Przyjmujemy wylacznie poprawny adres v3 (dlugosc, alfabet, wersja 3, suma
kontrolna SHA3-256) i zapamietujemy go w ustawieniach (`onion_url`,
`onion_checked`). Wbudowany adres zostaje awaryjnym: bez sieci, bez Tora albo
przy bledzie program dziala dokladnie jak dotad.

Po co: zmiana adresu .onion (nowy klucz uslugi) nie wymaga nowego wydania
programu w Microsoft Store — zainstalowane kopie przestawiaja sie same.

Moduł celowo NIE importuje `config` na poziomie modulu (config importuje
stad walidacje adresu); adres serwisu bierzemy leniwie w `discover`.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

log = logging.getLogger(__name__)

#: Identyfikator formatu odpowiedzi `/api/onion/` (apps/api/views.OnionView).
FORMAT = 'sigelith-onion-v1'
PATH = '/api/onion/'

#: Jak czesto sprawdzac adres (w trybie Tor, przy starcie programu).
REFRESH_EVERY = timedelta(hours=24)

#: Odpowiedz to kilka linijek JSON-a; wieksza = cos jest nie tak.
MAX_BYTES = 4096

#: Tor bywa wolny (zestawienie obwodu do uslugi ukrytej to zwykle kilka-kilkanascie
#: sekund), wiec czekamy dluzej niz przy zwyklych zapytaniach — ale nie dluzej:
#: pula zadan ma jeden watek i czynnosc uzytkownika nie moze na to czekac.
TIMEOUT = (20.0, 20.0)

_ALPHABET = frozenset('abcdefghijklmnopqrstuvwxyz234567')
_SUFFIX = '.onion'


def is_v3_host(host: object) -> bool:
    """Czy to poprawny adres uslugi Tor v3 (`<56 znakow base32>.onion`).

    Sprawdzamy to, co Tor: 35 bajtow = klucz publiczny (32) + suma kontrolna
    (2) + wersja (1, zawsze 3), suma = SHA3-256(".onion checksum" | klucz |
    wersja)[:2]. Tylko male litery — tak zapisujemy i porownujemy adresy.
    """
    if not isinstance(host, str) or not host.endswith(_SUFFIX):
        return False
    label = host[:-len(_SUFFIX)]
    if len(label) != 56 or not set(label) <= _ALPHABET:
        return False
    try:
        raw = base64.b32decode(label.upper())
    except (binascii.Error, ValueError):
        return False
    pub, checksum, version = raw[:32], raw[32:34], raw[34:35]
    if version != b'\x03':
        return False
    return hashlib.sha3_256(b'.onion checksum' + pub + version).digest()[:2] == checksum


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or '').lower()
    except ValueError:
        return ''


def is_v3_url(url: object) -> bool:
    """`http://<adres v3>.onion` bez sciezki, portu i danych logowania."""
    if not isinstance(url, str) or not url:
        return False
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    return (parsed.scheme == 'http' and port is None and not parsed.username
            and parsed.path in ('', '/') and not parsed.query and not parsed.fragment
            and is_v3_host(parsed.hostname or ''))


def url_for(host: str) -> str:
    return f'http://{host}'


def parse(data: object) -> str | None:
    """Adres z odpowiedzi `/api/onion/` albo None, gdy cokolwiek sie nie zgadza."""
    if not isinstance(data, dict) or data.get('format') != FORMAT:
        return None
    host = data.get('onion')
    if not isinstance(host, str):
        return None
    host = host.strip().lower()
    return host if is_v3_host(host) else None


def due(checked: str, now: datetime | None = None) -> bool:
    """Czy pora sprawdzic adres (`checked` = ISO 8601 UTC ostatniego sukcesu)."""
    now = now or datetime.now(timezone.utc)
    try:
        last = datetime.fromisoformat(checked)
    except (TypeError, ValueError):
        return True
    if last.tzinfo is None:
        return True
    # Data z przyszlosci (przestawiony zegar) nie moze zablokowac sprawdzania.
    return now - last >= REFRESH_EVERY or last > now + timedelta(minutes=5)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def discover(settings, session=None) -> str | None:
    """Biezacy adres bazowy `http://<v3>.onion` albo None.

    Zawsze przez proxy Tor z ustawien — takze zapytanie do sigelith.org:
    uzytkownik trybu Tor nie chce, zeby serwer poznal jego adres IP.
    `session` tylko dla testow (domyslnie `requests`).
    """
    from .config import DEFAULT_BASE_URL

    sources = []
    for base in (settings.onion_base_url, DEFAULT_BASE_URL):
        if base and base not in sources:
            sources.append(base)
    for base in sources:
        try:
            host = _fetch(base, settings, session)
        except Exception as e:           # noqa: BLE001 — siec, JSON, proxy
            log.info('onion: %s nie odpowiada: %s', base, e)
            continue
        if host:
            log.info('onion: biezacy adres %s (zrodlo: %s)', host, base)
            return url_for(host)
        log.info('onion: %s nie podal poprawnego adresu', base)
    return None


def _fetch(base: str, settings, session=None) -> str | None:
    if session is None:
        import requests
        session = requests
    onion = host_of(base).endswith(_SUFFIX)
    if onion:
        verify: object = False            # HTTP przez Tor — tu nie ma TLS
    else:
        import certifi
        verify = certifi.where()
    proxy = settings.tor_proxy
    response = session.get(
        base.rstrip('/') + PATH,
        proxies={'http': proxy, 'https': proxy},
        timeout=TIMEOUT,
        verify=verify,
        allow_redirects=False,
        stream=True,
        headers={'Accept': 'application/json'},
    )
    try:
        if response.status_code != 200:
            return None
        body = response.raw.read(MAX_BYTES + 1, decode_content=True)
    finally:
        response.close()
    if len(body) > MAX_BYTES:
        return None
    return parse(json.loads(body.decode('utf-8')))
