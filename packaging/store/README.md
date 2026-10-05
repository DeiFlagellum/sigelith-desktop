# Karta Sigelith Desktop w Microsoft Store

Teksty karty w 11 językach paczki MSIX (en-us, pl-pl, de-de, es-es, fr-fr,
ru-ru, tr-tr, ja-jp, ko-kr, zh-cn, ar-sa) — stan 2026-10-05, wersja 3.0.2.

| plik | co to jest |
|---|---|
| `listing.json` | wszystkie pola karty dla każdego języka — źródło dla narzędzia CSV |
| `listing/<język>.txt` | to samo do czytania i ręcznego wklejania |
| `fill_listing_csv.py` | wpisuje `listing.json` i zrzuty do eksportu z Partner Center |

Zdania wspólne ze stroną `/desktop/` pochodzą z jej katalogów tłumaczeń
(te same słowa w Sklepie i na stronie). Test `tests/test_store_listing.py`
pilnuje limitów Partner Center, języków zgodnych z `AppxManifest.xml` i
dyscypliny twierdzeń z HANDOVER_SPEC.md §0.4 (bez „qualified”, „registered
delivery”, nazw usług pocztowych).

## Pola karty (Partner Center → Store listings → język)

| pole | skąd | limit |
|---|---|---|
| Short description | `short_description` | 1000, widoczne 270 — mieścimy się |
| Description | `description` | 10 000, zwykły tekst, **bez adresów URL** |
| What's new in this version | `whats_new` | 1500; od 3.0.1 (przy pierwszym zgłoszeniu było puste) |
| Product features | `features` (14) | do 20 × 200 |
| Screenshots | `screenshots` + `captions` (5) | PNG ≥ 1366×768; podpis ≤ 200 |
| Store logos → 1:1 App tile icon | `logo/tile-300.png` — skrypt CSV pomniejsza `../beatstamp-icon.png` | 300×300; plakat 2:3, okładka 1:1 i baner 16:9 są dla gier — puste |
| Additional system requirements → Recommended hardware | `recommended_hardware` | do 11 × 200 |
| Keywords | `search_terms` (7) | do 7 × 40 znaków, razem ≤ 21 różnych słów |
| Copyright and trademark info | `copyright` | 200 |

Zrzuty każdy język wymaga osobno (nawet te same pliki). Leżą w
`robocze/desktop_shots/store/<jezyk>/01-stamp.png … 05-evidence.png`
(1920×1080, poza gitem). Odtworzenie — wszystkie języki na platformie
`windows` (DirectWrite, okna nie pokazują się na ekranie):

    set SHOTS_PLATFORM=windows
    desktop\.venv\Scripts\python.exe robocze\desktop_shots.py --langs en,de,pl,es,fr,ru,tr,ja,ko,zh,ar

Ten sam przebieg odświeża zrzuty strony `/desktop/` (`apps/web/static/web/desktop/*.webp`).

## Wszystkie języki naraz (CSV)

Partner Center przyjmuje tylko CSV z własnego eksportu (kolumny Field / ID /
Type muszą zostać). Kolejność:

1. Partner Center → aplikacja → *Store listings* → **Export listing** → `eksport.csv`.
2. `python desktop\packaging\store\fill_listing_csv.py eksport.csv robocze\desktop_shots\store karta`
3. **Import listings → Import folder** → katalog `karta`.

Skrypt wypisuje pola, których nie znalazł w eksporcie — Microsoft zmienia
czasem ich nazwy; wtedy te pola trzeba uzupełnić ręcznie z `listing/<język>.txt`.

## Poza kartą (Properties) — do wpisania raz

- Privacy policy URL: `https://sigelith.org/privacy/` (sekcja 9 obejmuje
  Sigelith Desktop i Time Vault Backup).
- Website: `https://sigelith.org/desktop/`.
- Support contact — do decyzji (adres e-mail albo strona kontaktu).
- System requirements: Windows 10 22H2 lub Windows 11, x64; Windows Hello —
  zalecane (Handover).
- Kwestionariusz IARC: aplikacja nie ma czatu ani publicznego udostępniania;
  paczki Handover użytkownicy przesyłają sobie sami (e-mail, pendrive,
  wspólny folder) — serwer Sigelith ich nie widzi. Odpowiedzi — przy
  wypełnianiu, zgodnie z tym stanem.
