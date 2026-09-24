"""
Klient HTTP publicznego API BeatTime (beattime.live/api/proof/*).

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
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__, merkle
from .config import Settings
from .i18n import _

log = logging.getLogger(__name__)

# Odpowiedzi tego API to kilobajty JSON-a. 8 MB to zapas o trzy rzedy
# wielkosci i jednoczesnie sufit, ktorego zaden poprawny payload nie dotknie.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Limit czasu: (nawiazanie polaczenia, oczekiwanie na dane). Rozdzielone,
# bo to dwie rozne awarie — martwy host poznajemy w 5 s, a wolna odpowiedz
# ma prawo potrwac dluzej.
CONNECT_TIMEOUT = 5.0

# Kontrakt okna podziekowan (apps/support/views.py: SupportersThanksView,
# straznik w apps/support/tests_desktop_contract.py). Sciezka stoi TUTAJ,
# a nie w `supporters.py`, zeby ten modul nie musial importowac tamtego:
# zaleznosc idzie w jedna strone (`supporters` -> `api`).
SUPPORTERS_THANKS_PATH = '/api/supporters/thanks'


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
    """Sesja HTTP do API BeatTime. Bezpieczna do uzycia z watkow roboczych.

    Jedna instancja utrzymuje pule polaczen, więc kolejne stemple nie placa za
    nowy uscisk TLS — przy stemplowaniu katalogu to różnica rzedu sekund.
    `requests.Session` jest bezpieczna dla watkow na poziomie wysyłania zapytań
    (kazde ma własny obiekt odpowiedzi), a puli polaczen pilnuje urllib3.
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': f'BeatStamp/{__version__} (+https://beattime.live)',
            'Accept': 'application/json',
        })
        # Ponawiamy tylko to, co ma sens ponawiac: chwilowe bledy serwera i
        # przekroczony limit zapytan. Blad 4xx (poza 429) ponawiany w kolko
        # bylby tylko halasem — i szybciej wyczerpalby limit.
        retry = Retry(
            total=3,
            connect=3,
            read=2,
            status=2,
            backoff_factor=0.6,               # 0.6 s, 1.2 s, 2.4 s
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({'GET', 'POST'}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
        self._session.mount('https://', adapter)
        self._session.mount('http://', adapter)

    def close(self) -> None:
        self._session.close()

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
                 params: dict | None = None, expect_json: bool = True) -> tuple[int, Any]:
        url = self._url(path)
        timeout = (CONNECT_TIMEOUT, max(3.0, float(self._settings.timeout_seconds)))
        try:
            response = self._session.request(
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
            raise ApiError(_(
                'No connection to the Tor proxy at %(proxy)s. Start Tor Browser '
                'or the tor service, or turn off Tor mode in the settings.'
            ) % {'proxy': self._settings.tor_proxy}) from e
        except requests.exceptions.ConnectTimeout as e:
            raise ApiError(_(
                'The server did not answer in time (limit %(seconds)s s to '
                'connect).') % {'seconds': f'{CONNECT_TIMEOUT:.0f}'}) from e
        except requests.exceptions.ReadTimeout as e:
            raise ApiError(_(
                'The server accepted the connection but sent no answer in '
                'time.')) from e
        except requests.exceptions.ConnectionError as e:
            log.warning('połączenie: %s', e)
            raise ApiError(_(
                'No connection to beattime.live. Check your internet access '
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
                raise ApiError(
                    _('The API request limit was exceeded (20 stamps per minute '
                      'per IP address). ')
                    + (_('Try again in %(seconds)s s.') % {'seconds': retry_after}
                       if retry_after else _('Wait a moment.')),
                    status=429, retry_after=retry_after,
                )
            if not expect_json:
                return response.status_code, body
            if response.status_code >= 500:
                raise ApiError(
                    _('The BeatTime server returned error %(code)s. Try again '
                      'in a moment.') % {'code': response.status_code},
                    status=response.status_code)
            try:
                data = json.loads(body.decode('utf-8'))
            except (UnicodeDecodeError, ValueError) as e:
                raise ApiError(
                    _('The server sent back an answer that cannot be read as '
                      'JSON.'), status=response.status_code) from e
            if response.status_code >= 400:
                detail = ''
                if isinstance(data, dict):
                    detail = str(data.get('error') or data.get('detail') or '')
                raise ApiError(
                    detail or _('The server rejected the request (HTTP '
                                '%(code)s).') % {'code': response.status_code},
                    status=response.status_code)
            return response.status_code, data

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
        digest = _require_digest(digest)
        _status, data = self._request('GET', '/api/proof/verify', params={'digest': digest})
        if not isinstance(data, dict):
            raise ApiError(_(
                'The server returned an answer in an unexpected format.'))
        return data

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

        Serwer odpytywany jest RAZ; offset liczymy z polowy czasu obiegu, tak
        jak robi to klient SNTP. Dalej aplikacja tyka lokalnie — inaczej niż
        poprzednik, który przy Każdym pliku szedl po czas do dwoch serwisow
        HTTP, blokujac przy tym okno.
        """
        import time
        t0 = time.time()
        _status, data = self._request('GET', '/api/sync/')
        t1 = time.time()
        if not isinstance(data, dict) or 'server_unix_ms' not in data:
            raise ApiError(_('The server did not return a synchronisation time.'))
        try:
            server_ms = int(data['server_unix_ms'])
        except (TypeError, ValueError) as e:
            raise ApiError(_('The server returned a time in an invalid '
                             'format.')) from e
        rtt = t1 - t0
        # Szacowany czas serwera w chwili ODBIORU odpowiedzi to moment jego
        # odpowiedzi + droga powrotna (polowa obiegu).
        server_now = server_ms / 1000.0 + rtt / 2.0
        return SyncResult(
            server_unix_ms=server_ms,
            round_trip_seconds=rtt,
            offset_seconds=server_now - t1,
        )

    def certificate_pdf(self, digest: str) -> bytes:
        """Oficjalny certyfikat PDF wystawiony przez serwer (404 gdy brak).

        Alternatywa dla certyfikatu skladanego lokalnie: ten jest podpisany
        trescia serwera i wyglada identycznie jak ten z beattime.live/proof.
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

    def ots_proof(self, week_key: str) -> bytes:
        """Dowód OpenTimestamps (.ots) dla tygodnia — do niezaleznej kontroli.

        Plik `.ots` weryfikuje się narzędziem `ots verify` (klient
        OpenTimestamps), całkowicie poza BeatTime i poza ta aplikacja. To
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
