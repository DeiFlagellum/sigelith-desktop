"""
BeatStamp — znacznik czasu @beat dla plików lokalnych.

Klient desktopowy (Qt/PySide6) publicznej warstwy proof-of-existence
projektu BeatTime (beattime.live). Zastepuje wczesniejszego klienta TVS
(timevaultsecure.com/codegate), który opieral dowód na zaufaniu do
odpowiedzi serwera.

Różnica jest zasadnicza i przechodzi przez cały kod:

    TVS                          BeatStamp / BeatTime
    ---------------------------  --------------------------------------
    "signature" = czas.sha256    korzeń Merkle tygodnia podpisany Ed25519
    brak weryfikacji u klienta   pełna weryfikacja OFFLINE (merkle.py)
    3 źródła czasu przez HTTP    jedno źródło + wykrywanie dryfu zegara
    zaufaj serwerowi             zaufaj matematyce + Bitcoin + bank

Plik uzytkownika NIGDY nie opuszcza komputera — do sieci idzie wyłącznie
64-znakowy skrót SHA-256 liczony lokalnie.
"""

__version__ = '2.1.0'
__app_name__ = 'BeatStamp'
__app_display__ = 'BeatStamp — znacznik czasu @beat'
__publisher__ = 'BeatTime'
__website__ = 'https://beattime.live'
