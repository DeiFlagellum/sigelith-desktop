"""
Klient HTTP publicznego API Sigelith (sigelith.org/api/proof/*; te same
sciezki dzialaja pod beattime.live — to ta sama instancja).

Zastepuje cztery osobne, doraznie sklecone wywolania `requests` z poprzednika:
`TVS_API_STAMP`, `get_google_http_time()`, `get_worldtimeapi_time()` i brak
jakiejkolwiek weryfikacji. Dwa z tych zrodel byly wywolywane SYNCHRONICZNIE
w watku GUI (kazde z limitem 5 s), a `worldtimeapi.org` jest dzis martwy —
kazde stemplowanie placilo więc podwojnym zamrozeniem okna za dane, które i
tak nie mialy wartości dowodowej.

Zasady, które ten modul egzekwuje:

* do sieci idzie Wyłącznie 64-znakowy skrót — nigdy plik, nazwa ani ścieżka;
* na clearnecie tylko HTTPS z pełna weryfikacja łańcucha CA (certifi);
* kazde zapytanie ma limit czasu — nie ma wywolania, które może wisiec;
* odpowiedź ma twardy limit rozmiaru — zlosliwy albo zepsuty serwer nie
  wyczerpie pamieci klienta strumieniem bez konca;
* bledy sieci wracaja jako `ApiError` z komunikatem W JEZYKU INTERFEJSU,
  gotowym do pokazania czlowiekowi — bez surowego `str(e)` z biblioteki.
"""
from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import LocationParseError, ReadTimeoutError
from urllib3.util import connection as _urllib3_connection
from urllib3.util.retry import Retry
from urllib3.util.timeout import _DEFAULT_TIMEOUT as _URLLIB3_DEFAULT_TIMEOUT

from . import __version__, merkle
from .config import Settings, json_loads
from .i18n import _

log = logging.getLogger(__name__)

# Odpowiedzi tego API to kilobajty JSON-a. 8 MB to zapas o trzy rzedy
# wielkosci i jednoczesnie sufit, ktorego zaden poprawny payload nie dotknie.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Limit czasu: (nawiazanie polaczenia, oczekiwanie na dane). Rozdzielone,
# bo to dwie rozne awarie — martwy host poznajemy w 5 s, a wolna odpowiedz
# ma prawo potrwac dluzej.
CONNECT_TIMEOUT = 5.0

#: Ile czekamy na polaczenie z JEDNYM adresem serwera, zanim sprobujemy
#: nastepnego — patrz `_create_connection`.
FALLBACK_CONNECT_SECONDS = 1.5

#: Pomiar zegara: najwyzej tyle prob, konczymy wczesniej, gdy obieg jest krotki.
SYNC_SAMPLES = 3
SYNC_GOOD_ROUND_TRIP = 0.3

#: Przekierowania u osob trzecich (GitHub oddaje pliki wydan przez dwa).
MAX_REDIRECTS = 5

#: Rodzina adresow (IPv4/IPv6), ktora ostatnio zadzialala dla danego hosta.
_FAMILY_THAT_WORKED: dict[str, int] = {}
#: Fabryka gniazd — podmieniana w testach.
_socket_factory = socket.socket


def _interleave(infos: list, preferred: int | None) -> list:
    """Adresy na przemian z obu rodzin, zaczynajac od `preferred`.

    Bez wskazowki zaczynamy od rodziny, ktora system podal jako pierwsza
    (Windows stosuje RFC 6724, wiec zwykle IPv6).
    """
    if not infos:
        return []
    families = {info[0] for info in infos}
    first = preferred if preferred in families else infos[0][0]
    ours = [info for info in infos if info[0] == first]
    other = [info for info in infos if info[0] != first]
    ordered = []
    while ours or other:
        if ours:
            ordered.append(ours.pop(0))
        if other:
            ordered.append(other.pop(0))
    return ordered


def _create_connection(address, timeout=_URLLIB3_DEFAULT_TIMEOUT, source_address=None,
                       socket_options=None):
    """Zamiennik `urllib3.util.connection.create_connection` („Happy Eyeballs").

    urllib3 probuje adresow z DNS po kolei i na KAZDY czeka pelny limit
    polaczenia. W sieci z zepsutym IPv6 (router oglasza IPv6, a ruch nie
    przechodzi — czeste u operatorow i w sieciach firmowych) kazdy rekord
    AAAA to 5 s ciszy: pomiar 2026-09-27 — beattime.live +5 s, mempool.space
    (7 rekordow AAAA) 35 s, w tym czasie stemplowanie stalo w kolejce.

    Tutaj adresy ida NA PRZEMIAN z obu rodzin (RFC 8305, wersja sekwencyjna),
    kazdy poza ostatnim dostaje najwyzej `FALLBACK_CONNECT_SECONDS`, a rodzina,
    ktora zadzialala, idzie przy tym hoscie pierwsza. Zdrowa siec niczego nie
    zauwaza: pierwszy adres laczy sie w milisekundach.
    """
    host, port = address
    if host.startswith('['):
        host = host.strip('[]')
    try:
        host.encode('idna')
    except UnicodeError:
        raise LocationParseError(f"'{host}', label empty or too long") from None
    family = _urllib3_connection.allowed_gai_family()
    infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    ordered = _interleave(infos, _FAMILY_THAT_WORKED.get(host))
    error: OSError | None = None
    for index, (af, socktype, proto, _canonname, sockaddr) in enumerate(ordered):
        last = index == len(ordered) - 1
        attempt = timeout
        if not last:
            if timeout is _URLLIB3_DEFAULT_TIMEOUT or timeout is None:
                attempt = FALLBACK_CONNECT_SECONDS
            else:
                attempt = min(float(timeout), FALLBACK_CONNECT_SECONDS)
        sock = None
        try:
            sock = _socket_factory(af, socktype, proto)
            _urllib3_connection._set_socket_options(sock, socket_options)
            if attempt is not _URLLIB3_DEFAULT_TIMEOUT:
                sock.settimeout(attempt)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            # Po polaczeniu wraca limit wywolujacego — obowiazuje dalej odczyt.
            sock.settimeout(socket.getdefaulttimeout()
                            if timeout is _URLLIB3_DEFAULT_TIMEOUT else timeout)
            _FAMILY_THAT_WORKED[host] = af
            return sock
        except OSError as e:
            error = e
            if sock is not None:
                sock.close()
    if error is not None:
        raise error
    raise OSError('getaddrinfo returns an empty list')


# urllib3 siega po `connection.create_connection` przy KAZDYM nowym polaczeniu
# (urllib3/connection.py, `_new_conn`), wiec podmiana dziala dla calego
# procesu — takze dla requests. Polaczen przez SOCKS (Tor) to nie dotyczy:
# PySocks laczy sie z lokalnym proxy wlasna funkcja.
_urllib3_connection.create_connection = _create_connection


class _Retry(Retry):
    """`Retry` z gornym limitem na naglowek Retry-After.

    urllib3 czeka tyle, ile kaze serwer — bez limitu. Watek roboczy jest
    jeden, wiec „Retry-After: 120" zatrzymywal wszystko na dwie minuty. Po
    `RETRY_AFTER_MAX` sekundach i tak konczy sie proba, a uzytkownik dostaje
    czytelny komunikat z czasem od serwera.
    """

    RETRY_AFTER_MAX = 30.0

    def get_retry_after(self, response):
        seconds = super().get_retry_after(response)
        return None if seconds is None else min(float(seconds), self.RETRY_AFTER_MAX)

# Kontrakt okna podziekowan (apps/support/views.py: SupportersThanksView,
# straznik w apps/support/tests_desktop_contract.py). Sciezka stoi TUTAJ,
# a nie w `supporters.py`, zeby ten modul nie musial importowac tamtego:
# zaleznosc idzie w jedna strone (`supporters` -> `api`).
SUPPORTERS_THANKS_PATH = '/api/supporters/thanks'

#: Naglowek User-Agent KAZDEGO zapytania (API i osoby trzecie). Nazwa
#: programu bez spacji (RFC 9110: product = token) i adres, pod ktorym
#: operator serwera albo archiwum znajdzie, kto pyta.
USER_AGENT = f'SigelithDesktop/{__version__} (+https://sigelith.org)'


class ApiError(Exception):
    """Błąd komunikacji z API, z trescia gotowa dla uzytkownika."""

    def __init__(self, message: str, *, status: int | None = None,
                 retry_after: int | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.retry_after = retry_after


@dataclass(frozen=True)
class SyncResult:
    """Wynik /api/sync/ — do wyliczenia dryfu zegara lokalnego."""

    server_unix_ms: int
    round_trip_seconds: float
    offset_seconds: float   # dodatni = zegar lokalny SPOZNIONY wzgledem serwera


class BeatTimeClient:
    """Sesja HTTP do API Sigelith. Bezpieczna do uzycia z watkow roboczych.

    Nazwa klasy zostaje z czasow, gdy usluga nazywala sie BeatTime proof —
    uzywaja jej testy i moduly w calym pakiecie.

    Jedna instancja utrzymuje pule polaczen, więc kolejne stemple nie placa za
    nowy uscisk TLS — przy stemplowaniu katalogu to różnica rzedu sekund.
    `requests.Session` jest bezpieczna dla watkow na poziomie wysyłania zapytań
    (kazde ma własny obiekt odpowiedzi), a puli polaczen pilnuje urllib3.
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        # Ponawiamy tylko to, co ma sens ponawiac: chwilowe bledy serwera i
        # przekroczony limit zapytan. Blad 4xx (poza 429) ponawiany w kolko
        # bylby tylko halasem — i szybciej wyczerpalby limit.
        self._session = self._new_session(_Retry(
            total=3,
            connect=3,
            read=2,
            status=2,
            backoff_factor=0.6,               # 0.6 s, 1.2 s, 2.4 s
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({'GET', 'POST'}),
            respect_retry_after_header=True,
            raise_on_status=False,
        ))
        # Zapytania, w ktorych kod odpowiedzi JEST trescia (stan potoku: 503
        # przy alercie) — ponawiamy tylko nieudane polaczenie, nie status.
        self._session_once = self._new_session(_Retry(
            total=2, connect=2, read=0, status=0, backoff_factor=0.6,
            raise_on_status=False))
        # Osoby trzecie (GitHub, Internet Archive, Zenodo, eksploratory
        # Bitcoina): bez ponawiania. To kontrola w tle, ktora i tak wroci za
        # kwadrans — a indeks CDX archiwum potrafi odpowiadac po 15 s, wiec
        # trzy proby to prawie minuta zajetego watku.
        self._external = self._new_session(_Retry(
            total=1, connect=1, read=0, status=0, redirect=0, raise_on_status=False))

    @staticmethod
    def _new_session(retry: Retry) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'application/json',
        })
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        return session

    def close(self) -> None:
        for session in (self._session, self._session_once, self._external):
            session.close()

    def __enter__(self) -> 'BeatTimeClient':
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- Warstwa transportu -------------------------------------------------

    def _url(self, path: str) -> str:
        base = self._settings.effective_base_url
        url = f"{base.rstrip('/')}/{path.lstrip('/')}"
        scheme = urlparse(url).scheme
        host = urlparse(url).hostname or ''
        # HTTP dopuszczamy WYLACZNIE dla uslugi ukrytej, gdzie szyfruje Tor.
        # Bez tego warunku wpisanie 'http://' w ustawieniach po cichu zdjeloby
        # szyfrowanie z calego ruchu.
        if scheme != 'https' and not host.endswith('.onion'):
            raise ApiError(_(
                'The server address must start with https:// — an unencrypted '
                'connection is allowed only for an .onion address.'
            ))
        return url

    def _request(self, method: str, path: str, *, json_body: dict | None = None,
                 params: dict | None = None, expect_json: bool = True,
                 retry_status: bool = True) -> tuple[int, Any]:
        url = self._url(path)
        timeout = (CONNECT_TIMEOUT, max(3.0, float(self._settings.timeout_seconds)))
        session = self._session if retry_status else self._session_once
        try:
            response = session.request(
                method,
                url,
                json=json_body,
                params=params,
                timeout=timeout,
                proxies=self._settings.proxies,
                verify=self._settings.verify_tls,
                allow_redirects=False,   # przekierowanie moglo by zejsc z HTTPS
                stream=True,             # rozmiar sprawdzamy PRZED wczytaniem
            )
        except requests.exceptions.SSLError as e:
            log.warning('TLS: %s', e)
            raise ApiError(_(
                'The server certificate could not be verified. The connection '
                'was aborted. Check whether something is intercepting the '
                'traffic (corporate firewall, antivirus with HTTPS inspection).'
            )) from e
        except requests.exceptions.ProxyError as e:
            log.warning('proxy: %s', e)
            if self._settings.use_tor:
                raise ApiError(_(
                    'No connection to the Tor proxy at %(proxy)s. Start Tor Browser '
                    'or the tor service, or turn off Tor mode in the settings.'
                ) % {'proxy': self._settings.tor_proxy}) from e
            # Proxy z ustawien Windows albo ze zmiennej HTTPS_PROXY (requests
            # czyta oba) — typowo siec firmowa. Komunikat o Torze, ktory
            # padal tu do 2.2.0 przy KAZDYM proxy, wprowadzal w blad.
            raise ApiError(_(
                'No connection through the proxy server set on this computer '
                '(Windows proxy settings or the HTTPS_PROXY variable). Check '
                'those settings or ask your network administrator.')) from e
        except requests.exceptions.ConnectTimeout as e:
            log.warning('połączenie: przekroczony czas nawiązania: %s', e)
            raise ApiError(_(
                'The server did not answer in time (limit %(seconds)s s to '
                'connect).') % {'seconds': f'{CONNECT_TIMEOUT:.0f}'}) from e
        except requests.exceptions.ReadTimeout as e:
            log.warning('połączenie: brak odpowiedzi w czasie: %s', e)
            raise ApiError(_(
                'The server accepted the connection but sent no answer in '
                'time.')) from e
        except requests.exceptions.ConnectionError as e:
            log.warning('połączenie: %s', e)
            # Po wyczerpaniu ponowien odczytu requests zglasza ConnectionError,
            # nie ReadTimeout — przyczyna siedzi w MaxRetryError.reason.
            reason = getattr(e.args[0], 'reason', None) if e.args else None
            if isinstance(reason, ReadTimeoutError):
                raise ApiError(_(
                    'The server accepted the connection but sent no answer in '
                    'time.')) from e
            raise ApiError(_(
                'No connection to sigelith.org. Check your internet access '
                'and firewall settings.')) from e
        except requests.exceptions.RequestException as e:
            log.warning('zapytanie: %s', e)
            raise ApiError(_('HTTP request error: %(kind)s.')
                           % {'kind': type(e).__name__}) from e

        with response:
            if response.is_redirect or response.is_permanent_redirect:
                raise ApiError(_(
                    'The server tried to redirect the request — rejected for '
                    'security reasons.'))
            body = self._read_capped(response)
            if response.status_code == 429:
                retry_after = _int_or_none(response.headers.get('Retry-After'))
                # Limit 20/min dotyczy WYLACZNIE stemplowania; pozostale
                # adresy maja wlasne (apps/tsa, DEFAULT_THROTTLE_RATES).
                limit = (_('The API request limit was exceeded (20 stamps per minute '
                           'per IP address). ')
                         if path.rstrip('/').endswith('/api/proof/stamp') else
                         _('The server received too many requests from this '
                           'address. '))
                raise ApiError(
                    limit
                    + (_('Try again in %(seconds)s s.') % {'seconds': retry_after}
                       if retry_after else _('Wait a moment.')),
                    status=429, retry_after=retry_after,
                )
            if not expect_json:
                return response.status_code, body
            return response.status_code, self._json_answer(response.status_code, body)

    @staticmethod
    def _json_answer(status: int, body: bytes) -> Any:
        """Tresc odpowiedzi jako JSON — te same bledy dla kazdej metody."""
        if status >= 500:
            raise ApiError(
                _('The Sigelith server returned error %(code)s. Try again '
                  'in a moment.') % {'code': status},
                status=status)
        try:
            data = json_loads(body.decode('utf-8'))
        except (UnicodeDecodeError, ValueError) as e:
            raise ApiError(
                _('The server sent back an answer that cannot be read as '
                  'JSON.'), status=status) from e
        if status >= 400:
            detail = ''
            if isinstance(data, dict):
                detail = str(data.get('error') or data.get('detail') or '')
            raise ApiError(
                detail or _('The server rejected the request (HTTP '
                            '%(code)s).') % {'code': status},
                status=status)
        return data

    @staticmethod
    def _read_capped(response: requests.Response) -> bytes:
        """Wczytuje tresc, przerywajac po przekroczeniu limitu.

        `response.content` wczytalby wszystko, co serwer zechce wyslac —
        serwer zlosliwy albo zepsuty moglby strumieniowac bez konca, az do
        wyczerpania pamieci procesu. Naglowek `Content-Length` sam w sobie
        nie wystarcza, bo przy `Transfer-Encoding: chunked` go nie ma, a
        podany rozmiar nie jest niczym wiazacym.
        """
        declared = _int_or_none(response.headers.get('Content-Length'))
        if declared is not None and declared > MAX_RESPONSE_BYTES:
            raise ApiError(_(
                'The server answer is unnaturally large — aborted.'))
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(64 * 1024):
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ApiError(_(
                    'The server answer exceeded the allowed size — the download '
                    'was aborted.'))
            chunks.append(chunk)
        return b''.join(chunks)

    # --- Warstwa API --------------------------------------------------------

    def stamp(self, digest: str) -> tuple[dict, bool]:
        """Rejestruje skrót w publicznym logu. Zwraca (payload, czy_nowy).

        Operacja jest idempotentna po stronie serwera: ponowne ostemplowanie
        tego samego skrótu zwraca PIERWOTNY znacznik czasu i HTTP 200 zamiast
        201. To wlasciwosc, nie usterka — pierwszy stempel wygrywa i nie da
        się "odświeżyć" daty na starszym dokumencie.
        """
        digest = _require_digest(digest)
        status, data = self._request('POST', '/api/proof/stamp', json_body={'digest': digest})
        if not isinstance(data, dict):
            raise ApiError(_(
                'The server returned an answer in an unexpected format.'))
        return data, status == 201

    def verify(self, digest: str) -> dict:
        """Odpytuje o istniejacy stempel. `{'found': False}` gdy go nie ma."""
        return self.verify_raw(digest)[1]

    def verify_raw(self, digest: str) -> tuple[bytes, dict]:
        """Jak `verify`, ale oddaje tez tresc odpowiedzi DOKLADNIE tak, jak przyszla.

        Pakiet dowodowy Handover (HANDOVER_SPEC.md §11.1) zapisuje odpowiedz
        /api/proof/verify „as received": podpisany jest w niej tylko kwit
        (§9.2), a weryfikator czyta ten sam tekst co my. Ta sama sciezka HTTP
        co zawsze (Tor, limit rozmiaru, odmowa przekierowan, 429).
        """
        digest = _require_digest(digest)
        status, body = self._request('GET', '/api/proof/verify', params={'digest': digest},
                                     expect_json=False)
        data = self._json_answer(status, body)
        if not isinstance(data, dict):
            raise ApiError(_(
                'The server returned an answer in an unexpected format.'))
        return body, data

    def latest_root(self) -> dict:
        """Ostatni Zamknięty korzeń tygodnia wraz z podpisem."""
        _status, data = self._request('GET', '/api/proof/root/latest')
        return data if isinstance(data, dict) else {}

    def health(self) -> dict:
        """Stan usługi: baza, cache, dryf zegara serwera względem NTP."""
        _status, data = self._request('GET', '/api/health/')
        return data if isinstance(data, dict) else {}

    def supporters_thanks(self) -> dict:
        """Surowa odpowiedz kontraktu okna podziekowan (`supporters.parse`).

        Idzie ta sama droga co reszta zapytan, wiec dziedziczy wszystko, co
        ta klasa juz gwarantuje: tryb Tor i proxy z ustawien, limit czasu,
        zakaz przekierowan i SUFIT ROZMIARU odpowiedzi. To ostatnie ma tu
        znaczenie szczegolne: liste nazw przysyla serwer, a jej dlugosci nic
        po naszej stronie nie ogranicza z gory.

        Walidacja ksztaltu nalezy do `supporters.parse` — ten poziom odpowiada
        wylacznie za transport.
        """
        _status, data = self._request('GET', SUPPORTERS_THANKS_PATH)
        if not isinstance(data, dict):
            raise ApiError(_(
                'The server returned an answer in an unexpected format.'))
        return data

    def sync(self) -> SyncResult:
        """Mierzy roznice miedzy zegarem lokalnym a serwerem (model SNTP).

        Offset liczymy z polowy czasu obiegu, tak jak robi to klient SNTP.
        Dalej aplikacja tyka lokalnie — inaczej niż poprzednik, który przy
        Każdym pliku szedl po czas do dwoch serwisow HTTP, blokujac przy tym
        okno.

        Pomiar powtarzamy (do `SYNC_SAMPLES` razy) i bierzemy ten z NAJKROTSZYM
        obiegiem. Pierwsze zapytanie sesji placi za DNS, polaczenie TCP i
        uscisk TLS — w sieci z zepsutym IPv6 takze za probe IPv6 — wiec jego
        obieg bywa o sekundy dluzszy od prawdziwego, a polowa tej roznicy
        wchodzi w offset. Przy starcie programu dawalo to falszywe
        ostrzezenie „zegar rozjechany" (+2,7 s; diagnostyka 2026-09-27).
        Kolejne proby ida juz gotowym polaczeniem.
        """
        import time
        best: tuple[float, int, float] | None = None
        for attempt in range(SYNC_SAMPLES):
            try:
                t0 = time.time()
                _status, data = self._request('GET', '/api/sync/')
                t1 = time.time()
                server_ms = self._sync_time(data)
            except ApiError:
                if best is None:
                    raise
                break
            if best is None or t1 - t0 < best[0]:
                best = (t1 - t0, server_ms, t1)
            if attempt >= 1 and best[0] <= SYNC_GOOD_ROUND_TRIP:
                break
        rtt, server_ms, t1 = best
        # Szacowany czas serwera w chwili ODBIORU odpowiedzi to moment jego
        # odpowiedzi + droga powrotna (polowa obiegu).
        server_now = server_ms / 1000.0 + rtt / 2.0
        return SyncResult(
            server_unix_ms=server_ms,
            round_trip_seconds=rtt,
            offset_seconds=server_now - t1,
        )

    @staticmethod
    def _sync_time(data: object) -> int:
        if not isinstance(data, dict) or 'server_unix_ms' not in data:
            raise ApiError(_('The server did not return a synchronisation time.'))
        try:
            return int(data['server_unix_ms'])
        except (TypeError, ValueError) as e:
            raise ApiError(_('The server returned a time in an invalid '
                             'format.')) from e

    def certificate_pdf(self, digest: str) -> bytes:
        """Oficjalny certyfikat PDF wystawiony przez serwer (404 gdy brak).

        Alternatywa dla certyfikatu skladanego lokalnie: ten jest podpisany
        trescia serwera i wyglada identycznie jak ten z sigelith.org/proof.
        Limit po stronie serwera jest ostry (10/min) — to kosztowny endpoint.
        """
        digest = _require_digest(digest)
        status, body = self._request('GET', f'/api/proof/cert/{digest}', expect_json=False)
        if status == 404:
            raise ApiError(_(
                'This digest has no stamp yet, so there is no certificate for '
                'it on the server.'), status=404)
        if status >= 400:
            raise ApiError(_('The server did not issue a certificate (HTTP '
                             '%(code)s).') % {'code': status}, status=status)
        if not body.startswith(b'%PDF'):
            raise ApiError(_(
                'The server sent back data that is not a PDF file.'))
        return body

    # --- Dziennik publiczny (LOG.md) ------------------------------------------

    def entries(self, start: int, limit: int = 1000) -> dict:
        """Strona dziennika: `{'entries': [...], 'next': seq | None}`."""
        _status, data = self._request(
            'GET', '/api/proof/entries',
            params={'from': max(1, int(start)), 'limit': max(1, min(1000, int(limit)))})
        if not isinstance(data, dict) or not isinstance(data.get('entries'), list):
            raise ApiError(_(
                'The server returned an answer in an unexpected format.'))
        return data

    def checkpoint_latest(self) -> dict | None:
        """Ostatni checkpoint (rozpakowany) albo None, gdy jeszcze zadnego nie ma."""
        try:
            _status, data = self._request('GET', '/api/proof/checkpoints/latest')
        except ApiError as e:
            if e.status == 404:
                return None
            raise
        return data if isinstance(data, dict) else None

    def checkpoint(self, n: int) -> dict | None:
        """Checkpoint nr `n` w postaci API (stan OTS, czasy blokow, kopie)."""
        try:
            _status, data = self._request('GET', f'/api/proof/checkpoints/{int(n)}')
        except ApiError as e:
            if e.status == 404:
                return None
            raise
        return data if isinstance(data, dict) else None

    def checkpoint_file(self, n: int) -> bytes:
        """DOKLADNE bajty pliku checkpointu — to na nich sprawdza sie podpis."""
        name = f'{int(n):06d}.json'
        status, body = self._request('GET', f'/checkpoints/{name}', expect_json=False)
        if status >= 400:
            raise ApiError(_('The checkpoint file could not be downloaded (HTTP '
                             '%(code)s).') % {'code': status}, status=status)
        return body

    def consistency(self, first: int, second: int) -> dict:
        """Dowod spojnosci RFC 9162 miedzy dwoma opublikowanymi rozmiarami."""
        _status, data = self._request(
            'GET', '/api/proof/consistency',
            params={'first': int(first), 'second': int(second)})
        if not isinstance(data, dict) or not isinstance(data.get('proof'), list):
            raise ApiError(_(
                'The server returned an answer in an unexpected format.'))
        return data

    def week(self, week_key: str) -> dict | None:
        """Dane tygodnia (`/api/proof/weeks/<week>`) albo None.

        None znaczy „ten serwer nie zna takiego adresu" — endpoint doszedl
        2026-09-26, wiec starsza instancja odpowiada 404 strona HTML. Tryb
        prywatny ma na to droge zapasowa (`witness.PrivateVerifier`).
        """
        try:
            _status, data = self._request('GET', f'/api/proof/weeks/{week_key}')
        except ApiError as e:
            if e.status == 404:
                return None
            raise
        return data if isinstance(data, dict) else None

    def proof_status(self) -> dict:
        """Stan potoku dowodowego (`/api/proof/status`).

        HTTP 503 to tutaj TRESC, nie awaria: serwer odpowiada nim, gdy ktores
        sprawdzenie ma stan `alert` (apps/tsa/views_log.py, ProofStatusView),
        a cialo niesie pelny stan. Do 2.2.0 503 szedl w ponawianie, konczyl
        sie bledem i panel pokazywal dalej stary wynik „11 z 11".
        """
        status, body = self._request('GET', '/api/proof/status', expect_json=False,
                                     retry_status=False)
        if status not in (200, 503):
            raise ApiError(_('The server rejected the request (HTTP '
                             '%(code)s).') % {'code': status}, status=status)
        try:
            data = json_loads(body.decode('utf-8'))
        except (UnicodeDecodeError, ValueError) as e:
            raise ApiError(_('The server sent back an answer that cannot be read as '
                             'JSON.'), status=status) from e
        return data if isinstance(data, dict) else {}

    # --- Osoby trzecie --------------------------------------------------------

    def fetch_external(self, url: str, *, max_bytes: int = 2 * 1024 * 1024,
                       accept: str = '*/*') -> bytes | None:
        """Pobiera plik od OSOBY TRZECIEJ (GitHub, Internet Archive, Zenodo...).

        Zasady inne niz przy API Sigelith, bo inny jest cel:

        * przekierowania SA dozwolone (GitHub wydaje pliki wydan przez
          przekierowanie na swoj serwer plikow), ale KAZDY krok musi byc
          HTTPS z pelna weryfikacja certyfikatu — zejscie na HTTP przerywa;
        * niczego nie wysylamy poza samym adresem: zadnego skrotu, zadnego
          naglowka z danymi uzytkownika;
        * 404 to zwykla odpowiedz „tego jeszcze nie opublikowano" — wraca
          jako None, a nie jako blad.

        Zwracane bajty sa danymi, nie prawda: wywolujacy sprawdza je sam
        (hash, podpis), zanim cokolwiek z nich wyniknie.
        """
        if not url.lower().startswith('https://'):
            raise ApiError(_('Only HTTPS addresses can be used.'))
        timeout = (CONNECT_TIMEOUT, max(3.0, float(self._settings.timeout_seconds)))
        current = url
        try:
            # Przekierowania prowadzimy SAMI: adres kolejnego kroku sprawdzamy
            # PRZED zapytaniem. `allow_redirects=True` sprawdzal je dopiero po
            # fakcie — krok `http://` zdazyl juz pojsc otwartym tekstem.
            for _hop in range(MAX_REDIRECTS + 1):
                response = self._external.get(
                    current, timeout=timeout, proxies=self._settings.proxies,
                    verify=_ca_bundle(), allow_redirects=False, stream=True,
                    headers={'Accept': accept})
                if not response.is_redirect:
                    break
                target = urljoin(current, response.headers.get('Location') or '')
                response.close()
                if not target.lower().startswith('https://'):
                    raise ApiError(_('%(host)s redirected to an unencrypted address '
                                     '— rejected.') % {'host': urlparse(current).hostname})
                current = target
            else:
                raise ApiError(_('%(host)s redirected too many times.')
                               % {'host': urlparse(url).hostname or url})
        except requests.exceptions.RequestException as e:
            log.info('osoba trzecia %s: %s', urlparse(current).hostname, e)
            raise ApiError(_('No connection to %(host)s.')
                           % {'host': urlparse(current).hostname or url}) from e
        with response:
            if response.status_code == 404:
                return None
            if response.status_code >= 400:
                raise ApiError(_('%(host)s answered with error %(code)s.')
                               % {'host': urlparse(url).hostname,
                                  'code': response.status_code},
                               status=response.status_code)
            declared = _int_or_none(response.headers.get('Content-Length'))
            if declared is not None and declared > max_bytes:
                raise ApiError(_('The file from %(host)s is unnaturally large.')
                               % {'host': urlparse(url).hostname})
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(64 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise ApiError(_('The file from %(host)s is unnaturally large.')
                                   % {'host': urlparse(url).hostname})
                chunks.append(chunk)
            return b''.join(chunks)

    def ots_proof(self, week_key: str) -> bytes:
        """Dowód OpenTimestamps (.ots) dla tygodnia — do niezaleznej kontroli.

        Plik `.ots` weryfikuje się narzędziem `ots verify` (klient
        OpenTimestamps), całkowicie poza Sigelith i poza ta aplikacja. To
        koncowy punkt łańcucha zaufania: dowód, ze korzeń tygodnia istniał
        przed konkretnym blokiem Bitcoina.
        """
        week_key = str(week_key or '').strip()
        if not week_key:
            raise ApiError(_('No week identifier was given.'))
        status, body = self._request('GET', f'/api/proof/ots/{week_key}', expect_json=False)
        if status == 404:
            raise ApiError(_('Week %(week)s has no OpenTimestamps proof yet.')
                           % {'week': week_key}, status=404)
        if status >= 400:
            raise ApiError(_('The .ots proof could not be downloaded (HTTP '
                             '%(code)s).') % {'code': status}, status=status)
        return body


def _ca_bundle() -> str:
    """Magazyn CA dla osob trzecich — ZAWSZE certifi, takze w trybie Tor.

    `Settings.verify_tls` zwraca False dla uslugi `.onion` Sigelith (tam
    tozsamosc niesie sam adres). Osoby trzecie sa zwyklymi adresami HTTPS
    i przez Tora tez ida z pelna weryfikacja certyfikatu.
    """
    import certifi
    return certifi.where()


def _require_digest(digest: str) -> str:
    value = str(digest or '').strip().lower()
    if not merkle.is_digest(value):
        raise ApiError(_(
            'A digest must be exactly 64 hexadecimal characters (SHA-256).'))
    return value


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
