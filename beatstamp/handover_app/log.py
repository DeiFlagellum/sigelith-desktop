"""
Dziennik Sigelith dla Handover — `service.LogClient` na kliencie aplikacji.

Wszystko idzie przez `api.BeatTimeClient`: te same ustawienia (Tor, limity,
odmowa przekierowan) co stemplowanie plikow. Czas „teraz" to czas DZIENNIKA
(pomiar `/api/sync/`), nie zegar komputera — od niego licza sie terminy
oferty i odpowiedzi (HANDOVER_SPEC.md §6).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from ..api import BeatTimeClient


class ClientLog:
    """`client` albo funkcja zwracajaca AKTUALNEGO klienta — okno glowne tworzy
    nowego po zmianie ustawien polaczenia (Tor, adres serwera)."""

    def __init__(self, client: BeatTimeClient | Callable[[], BeatTimeClient]) -> None:
        self._client = client

    @property
    def client(self) -> BeatTimeClient:
        return self._client() if callable(self._client) else self._client

    def now(self) -> datetime:
        sync = self.client.sync()
        seconds = sync.server_unix_ms / 1000.0 + sync.round_trip_seconds / 2.0
        return datetime.fromtimestamp(seconds, timezone.utc)

    def stamp(self, digest: bytes) -> dict:
        payload, _created = self.client.stamp(digest.hex())
        return payload

    def verify_text(self, digest: bytes) -> str | None:
        body, data = self.client.verify_raw(digest.hex())
        if data.get('found') is not True:
            return None
        return body.decode('utf-8')

    def entries(self, from_seq: int) -> list[dict]:
        page = self.client.entries(from_seq)
        return [e for e in page['entries'] if isinstance(e, dict)]
