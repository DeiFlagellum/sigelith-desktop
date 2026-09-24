"""
Generuje komplet logo dla paczki MSIX z jednego pliku `beatstamp.ico`.

Po co osobny skrypt zamiast wrzucenia gotowych plikow do repozytorium:
Microsoft Store wymaga kilkudziesieciu wariantow TEGO SAMEGO obrazka
(kafelek maly, sredni, szeroki, duzy, logo Sklepu, ikona listy aplikacji —
kazdy w piecu skalach interfejsu plus osobne rozmiary docelowe dla paska
zadan). Trzymanie ich recznie konczy sie tak, ze po zmianie ikony aplikacji
polowa kafelkow zostaje przy starej — a widac to dopiero po instalacji
paczki, u uzytkownika. Tutaj zrodlem jest jeden plik i jedna komenda.

URUCHOMIENIE (z katalogu `desktop/`):

    .venv\\Scripts\\python.exe packaging\\make_logos.py

Wynik: `packaging/Assets/*.png`. Skrypt wywoluje tez `build_msix.ps1`, wiec
zwykle nie trzeba uruchamiac go osobno.

OGRANICZENIE, ktore trzeba znac: najwiekszy obraz w `beatstamp.ico` ma
256x256 pikseli. Najwieksze warianty kafelkow (np. `Square310x310` w skali
400%, czyli 1240 px) sa z niego POWIEKSZANE i beda miekkie. Skrypt wypisuje
ostrzezenie przy kazdym takim pliku. To nie blokuje ani zbudowania paczki,
ani zgloszenia do Sklepu — duze kafelki sa opcjonalne i wiekszosc
uzytkownikow nigdy ich nie zobaczy — ale jesli ikona ma kiedys powstac
w wyzszej rozdzielczosci, wystarczy podmienic zrodlo i uruchomic to ponownie.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:                                    # pragma: no cover
    raise SystemExit('Brak biblioteki Pillow. Zainstaluj srodowisko:\n'
                     '  .venv\\Scripts\\python.exe -m pip install -r requirements-dev.txt')

HERE = Path(__file__).resolve().parent
SOURCE_ICON = HERE.parent / 'beatstamp.ico'
ASSETS = HERE / 'Assets'

#: Skale interfejsu, ktore Windows potrafi wybrac dla kafelkow. 100% to
#: rozmiar bazowy; `scale-200` to ekran o podwojonej gestosci pikseli.
SCALES = (100, 125, 150, 200, 400)

#: Rozmiary bazowe (szerokosc, wysokosc) dla skali 100%.
TILES = {
    'Square44x44Logo': (44, 44),
    'Square71x71Logo': (71, 71),
    'Square150x150Logo': (150, 150),
    'Square310x310Logo': (310, 310),
    'Wide310x150Logo': (310, 150),
    'StoreLogo': (50, 50),
}

#: `Square44x44Logo` sluzy tez za ikone na liscie aplikacji, w pasku zadan
#: i w wynikach wyszukiwania — a tam Windows prosi o KONKRETNY rozmiar
#: w pikselach, nie o skale. Bez tych wariantow system przeskalowuje
#: najblizszy dostepny i ikona w pasku zadan wyglada na rozmyta.
TARGET_SIZES = (16, 24, 32, 48, 256)

#: Udzial wysokosci kafelka, ktory zajmuje grafika. Wytyczne Microsoftu dla
#: kafelkow mowia o marginesie — logo wypelniajace kafelek po brzegi kloci
#: sie z sasiadami i wyglada na przyciete. Ikona listy aplikacji (44x44)
#: i rozmiary docelowe sa odwrotnie: maja byc pelne, bo system rysuje je
#: w malym kwadracie i kazdy pusty piksel to strata czytelnosci.
TILE_FILL = 0.66


def load_source() -> Image.Image:
    """Najwiekszy obraz z pliku .ico, jako RGBA."""
    if not SOURCE_ICON.is_file():
        raise SystemExit(f'Brak pliku zrodlowego: {SOURCE_ICON}')
    with Image.open(SOURCE_ICON) as ico:
        # `Image.open` na .ico daje najmniejszy obraz. Rozmiar wybieramy sami.
        largest = max(ico.ico.sizes())
        ico.size = largest
        image = ico.convert('RGBA')
    print(f'zrodlo: {SOURCE_ICON.name}, najwiekszy obraz {largest[0]}x{largest[1]}')
    return image


def render(source: Image.Image, width: int, height: int, fill: float) -> Image.Image:
    """Grafika wyśrodkowana na przezroczystym płótnie `width` x `height`.

    Przezroczyste tlo, a nie kolor marki: kafelek dostaje tlo z manifestu
    (`BackgroundColor`), a ikona w pasku zadan i na liscie aplikacji musi byc
    przezroczysta, bo lezy na tle, ktorego nie znamy — jasnym albo ciemnym,
    zaleznie od motywu systemu.
    """
    side = math.ceil(min(width, height) * fill)
    side = max(side, 1)
    art = source.resize((side, side), Image.LANCZOS)
    canvas = Image.new('RGBA', (width, height), (0, 0, 0, 0))
    canvas.paste(art, ((width - side) // 2, (height - side) // 2), art)
    return canvas


def save(image: Image.Image, name: str, upscaled: bool) -> None:
    path = ASSETS / name
    image.save(path, format='PNG', optimize=True)
    note = '  (POWIEKSZANE ponad rozdzielczosc zrodla)' if upscaled else ''
    print(f'  {name:<46} {image.width}x{image.height}{note}')


def main() -> int:
    source = load_source()
    source_side = source.width
    ASSETS.mkdir(parents=True, exist_ok=True)
    for stale in ASSETS.glob('*.png'):
        stale.unlink()

    upscaled_count = 0
    for name, (base_w, base_h) in TILES.items():
        # Ikona listy aplikacji ma byc pelna; kafelki — z marginesem.
        fill = 1.0 if name == 'Square44x44Logo' else TILE_FILL
        for scale in SCALES:
            # `ceil`, nie `round`: Microsoft podaje rozmiary zaokraglane
            # w gore (71 px w skali 150% to 107, nie 106), a Python zaokragla
            # polowki do liczby PARZYSTEJ — `round(62.5)` daje 62, czyli
            # StoreLogo w skali 125% o piksel mniejszy niz w specyfikacji.
            width = math.ceil(base_w * scale / 100)
            height = math.ceil(base_h * scale / 100)
            needed = math.ceil(min(width, height) * fill)
            upscaled = needed > source_side
            upscaled_count += int(upscaled)
            suffix = '' if scale == 100 else f'.scale-{scale}'
            save(render(source, width, height, fill), f'{name}{suffix}.png', upscaled)

    for size in TARGET_SIZES:
        image = render(source, size, size, 1.0)
        save(image, f'Square44x44Logo.targetsize-{size}.png', size > source_side)
        # Wariant „unplated": Windows rysuje ikone w pasku zadan BEZ podkladki
        # w kolorze akcentu. Bez tego pliku pasek zadan dostaje ikone na
        # kolorowym kwadracie, ktory nie pasuje do reszty paska.
        save(image, f'Square44x44Logo.targetsize-{size}_altform-unplated.png',
             size > source_side)

    count = len(list(ASSETS.glob('*.png')))
    print(f'\nZapisano {count} plikow w {ASSETS}')
    if upscaled_count:
        print(f'UWAGA: {upscaled_count} wariantow powstalo przez POWIEKSZENIE obrazu '
              f'{source_side}x{source_side} — beda miekkie.\n'
              '       Zeby to poprawic, potrzebna jest ikona w wyzszej '
              'rozdzielczosci (zrodlo: beatstamp.ico).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
