"""
Sigelith Desktop (do wersji 2.2.0: BeatStamp) — znacznik czasu dla plikow lokalnych.

Klient desktopowy (Qt/PySide6) Sigelith — publicznej infrastruktury
proof-of-existence (sigelith.org; do 2026-09-27 „BeatTime proof" pod
beattime.live, ta sama instancja, ten sam dziennik i ten sam klucz).
Zapis czasu to po prostu .beat (@beat, 1000 beatow na dobe); nazwa BeatTime
zostala tylko w nazwach aplikacji zegarowych w Google Play (decyzja
wlasciciela 2026-09-27 wieczorem). Zastepuje wczesniejszego klienta TVS
(timevaultsecure.com/codegate), który opieral dowód na zaufaniu do
odpowiedzi serwera.

Różnica jest zasadnicza i przechodzi przez cały kod:

    TVS                          Sigelith Desktop / Sigelith
    ---------------------------  --------------------------------------
    "signature" = czas.sha256    korzeń Merkle tygodnia podpisany Ed25519
    brak weryfikacji u klienta   pełna weryfikacja OFFLINE (merkle.py)
    3 źródła czasu przez HTTP    jedno źródło + wykrywanie dryfu zegara
    zaufaj serwerowi             zaufaj matematyce + Bitcoin + bank

Plik uzytkownika NIGDY nie opuszcza komputera — do sieci idzie wyłącznie
64-znakowy skrót SHA-256 liczony lokalnie.

Katalog pakietu nazywa sie nadal `beatstamp/` (importy, testy serwera
ladujace `beatstamp/keys.py` ze sciezki) — zmiana nazwy to osobny krok,
patrz ROZWOJ.md, „Sigelith Desktop (2026-09-27)".
"""

__version__ = '3.0.2'
#: Nazwa programu widoczna dla uzytkownika (tytuly okien, Qt, dziennik).
#: Marka — NIE tlumaczy sie jej w zadnym jezyku.
__app_name__ = 'Sigelith Desktop'
__app_display__ = 'Sigelith Desktop — znacznik czasu @beat'
__publisher__ = 'Sigelith'
__website__ = 'https://sigelith.org'
