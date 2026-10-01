"""
Rysuje ikone programu od zera: wzorzec 2048 px i plik `beatstamp.ico`.
(Ikona jest jeszcze ikona BeatStampa — nowa ikona Sigelith Desktop to
otwarte zadanie; nazwy plikow zostaja do tej zmiany.)

Po co: do 2026-09-27 jedynym zrodlem byl `beatstamp.ico`, ktorego najwiekszy
obraz ma 256 px. Duze kafelki Sklepu (np. `Square310x310` w skali 400%, czyli
1240 px, z grafika 819 px) powstawaly przez POWIEKSZENIE i byly miekkie.
Tu ikona jest opisana parametrami, wiec da sie ja narysowac w dowolnym
rozmiarze bez utraty ostrosci.

Parametry odtworzono z dotychczasowej ikony: jej ramki okazaly sie
pomniejszeniami (LANCZOS) wzorca 1024 px — kwadrat 32..992 z promieniem
rogow 204 i znak „@" z Segoe UI Semibold o szerokosci 608. Rysunek z tych
parametrow rozni sie od starej ramki 256 px srednio o 1/255 na kanal, czyli
to ta sama ikona, tylko ostrzejsza.

URUCHOMIENIE (z katalogu `desktop/`, tylko po zmianie wygladu ikony):

    .venv\\Scripts\\python.exe packaging\\make_icon.py

Wynik: `packaging/beatstamp-icon.png` (wzorzec 2048 px, z niego
`make_logos.py` robi kafelki Sklepu) i `beatstamp.ico` (ramki 16–256 px dla
pliku .exe i okna). Oba pliki sa w repozytorium, wiec zwykle budowanie nie
potrzebuje tego skryptu ani czcionki Segoe UI.

CZCIONKA: Segoe UI Semibold jest czcionka systemowa Windows. Skrypt czyta ja
z `%WINDIR%\\Fonts` tylko po to, by narysowac znak; w paczce jest wylacznie
obrazek, nie plik czcionki — tak samo jak w dotychczasowej ikonie.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:                                    # pragma: no cover
    raise SystemExit('Brak biblioteki Pillow. Zainstaluj srodowisko:\n'
                     '  .venv\\Scripts\\python.exe -m pip install -r requirements-dev.txt')

HERE = Path(__file__).resolve().parent
MASTER = HERE / 'beatstamp-icon.png'
ICO = HERE.parent / 'beatstamp.ico'

#: Wszystkie wymiary ponizej sa w jednostkach plotna 1024 x 1024.
GRID = 1024
#: Krawedzie kwadratu (lewa/gorna i prawa/dolna) i promien jego rogow.
SQUARE = (32, 992)
RADIUS = 204
#: Akcent marki — ten sam co `ui/theme.py` (ACCENT) i certyfikat PDF.
COLOR = (0xFF, 0x5C, 0x39)
GLYPH = '@'
GLYPH_FONT = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Fonts' / 'seguisb.ttf'
#: Szerokosc tuszu znaku; znak jest wysrodkowany na srodku kwadratu.
GLYPH_WIDTH = 608

#: Najwiekszy kafelek potrzebuje 819 px grafiki (1240 px x 0,66), wiec
#: 2048 px zostawia zapas takze na grafiki karty w Sklepie.
MASTER_SIZE = 2048
#: Ramki pliku .ico — te same co w dotychczasowej ikonie.
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
#: Pillow rysuje zaokraglony prostokat BEZ wygladzania krawedzi; rysujemy
#: wiec w rozmiarze 4x wiekszym i pomniejszamy.
SUPERSAMPLE = 4


def _ink_box(font: ImageFont.FreeTypeFont) -> tuple[int, int, int, int]:
    """Prostokat samego tuszu znaku wzgledem punktu, w ktorym go rysujemy.

    Nie `font.getbbox()`: ten liczy od punktu zaczepienia i z odstepami
    bocznymi znaku, wiec „@" wyszedlby przesuniety. `getmask2` daje maske
    tuszu RAZEM z jej przesunieciem wzgledem punktu rysowania.
    """
    mask, (dx, dy) = font.getmask2(GLYPH, mode='L')
    left, top, right, bottom = mask.getbbox()
    return dx + left, dy + top, dx + right, dy + bottom


def _glyph_font(pixels_per_unit: float) -> ImageFont.FreeTypeFont:
    """Czcionka w rozmiarze, w ktorym tusz znaku ma GLYPH_WIDTH jednostek."""
    if not GLYPH_FONT.is_file():
        raise SystemExit(f'Brak czcionki {GLYPH_FONT} (Segoe UI Semibold z Windows).')
    probe_size = 1000
    left, _, right, _ = _ink_box(ImageFont.truetype(str(GLYPH_FONT), probe_size))
    size = round(probe_size * GLYPH_WIDTH * pixels_per_unit / (right - left))
    return ImageFont.truetype(str(GLYPH_FONT), size)


def render(size: int) -> Image.Image:
    """Ikona `size` x `size`, RGBA, przezroczyste tlo poza kwadratem."""
    big = size * SUPERSAMPLE
    k = big / GRID
    low, high = SQUARE

    square = Image.new('L', (big, big), 0)
    # Wspolrzedne konca sa w Pillow WLACZNE, stad `- 1`: kwadrat zajmuje
    # piksele od low*k do high*k - 1, czyli jest symetryczny wzgledem srodka.
    ImageDraw.Draw(square).rounded_rectangle(
        (low * k, low * k, high * k - 1, high * k - 1), radius=RADIUS * k, fill=255)

    font = _glyph_font(k)
    left, top, right, bottom = _ink_box(font)
    centre = (low + high) / 2 * k
    glyph = Image.new('L', (big, big), 0)
    # Punkt rysowania CALKOWITY: przy ulamkowym Pillow przesuwa maske
    # o czesc piksela i przesuniecie z `_ink_box` przestaje sie zgadzac.
    ImageDraw.Draw(glyph).text(
        (round(centre - (left + right) / 2), round(centre - (top + bottom) / 2)),
        GLYPH, font=font, fill=255)

    square = square.resize((size, size), Image.LANCZOS)
    glyph = glyph.resize((size, size), Image.LANCZOS)
    colour = Image.composite(Image.new('RGB', (size, size), (255, 255, 255)),
                             Image.new('RGB', (size, size), COLOR), glyph)
    icon = colour.convert('RGBA')
    icon.putalpha(square)
    return icon


def main() -> int:
    master = render(MASTER_SIZE)
    master.save(MASTER, format='PNG', optimize=True)
    print(f'wzorzec: {MASTER.name} {MASTER_SIZE}x{MASTER_SIZE}, '
          f'{MASTER.stat().st_size // 1024} KB')

    # Ramki pomniejszane z wzorca tak samo jak w dotychczasowej ikonie
    # (LANCZOS). `append_images` sprawia, ze Pillow zapisuje DOKLADNIE te
    # obrazy, zamiast pomniejszac po swojemu.
    frames = [master.resize((s, s), Image.LANCZOS) for s in ICO_SIZES]
    frames[-1].save(ICO, format='ICO', sizes=[(s, s) for s in ICO_SIZES],
                    append_images=frames[:-1])
    print(f'ikona:   {ICO.name} ({", ".join(str(s) for s in ICO_SIZES)} px), '
          f'{ICO.stat().st_size // 1024} KB')
    return 0


if __name__ == '__main__':
    sys.exit(main())
