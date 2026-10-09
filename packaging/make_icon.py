"""
Rysuje ikone programu od zera: wzorzec 2048 px i plik `beatstamp.ico`.

ZNAK (od 2026-10-06): pierscien stu kresek z logo Sigelith
(`apps/web/static/web/favicon.svg`) i ptaszek w srodku, bialy na
pomaranczowym kwadracie — wersja C, wybor wlasciciela. Do 2026-10-06 ikona
byl znak „@" po BeatStampie; Microsoft Store odrzucil z nia Sigelith Desktop
3.0.2 wedlug zasady 10.1.1.11 On Device Tiles („ikona nie odnosi sie do
produktu"). Nazwy plikow (`beatstamp-icon.png`, `beatstamp.ico`) zostaja:
odwoluja sie do nich budowanie, licencje i testy.

Po co: do 2026-09-27 jedynym zrodlem byl `beatstamp.ico`, ktorego najwiekszy
obraz ma 256 px. Duze kafelki Sklepu (np. `Square310x310` w skali 400%, czyli
1240 px, z grafika 819 px) powstawaly przez POWIEKSZENIE i byly miekkie.
Tu ikona jest opisana parametrami, wiec da sie ja narysowac w dowolnym
rozmiarze bez utraty ostrosci.

URUCHOMIENIE (z katalogu `desktop/`, tylko po zmianie wygladu ikony):

    .venv\\Scripts\\python.exe packaging\\make_icon.py

Wynik: `packaging/beatstamp-icon.png` (wzorzec 2048 px, z niego
`make_logos.py` robi kafelki Sklepu) i `beatstamp.ico` (ramki 16–256 px dla
pliku .exe i okna), a takze `apps/web/static/web/desktop/app-icon-96.png`
(ikona na stronach /desktop/ i /backup/). Wszystkie sa w repozytorium, wiec
zwykle budowanie nie potrzebuje tego skryptu.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:                                    # pragma: no cover
    raise SystemExit('Brak biblioteki Pillow. Zainstaluj srodowisko:\n'
                     '  .venv\\Scripts\\python.exe -m pip install -r requirements-dev.txt')

HERE = Path(__file__).resolve().parent
MASTER = HERE / 'beatstamp-icon.png'
ICO = HERE.parent / 'beatstamp.ico'
#: Ikona programu na stronie (/desktop/ i „siostra" na /backup/).
WEB_ICON = HERE.parents[1] / 'apps' / 'web' / 'static' / 'web' / 'desktop' / 'app-icon-96.png'
WEB_ICON_SIZE = 96

#: Wszystkie wymiary ponizej sa w jednostkach plotna 1024 x 1024.
GRID = 1024
#: Krawedzie kwadratu (lewa/gorna i prawa/dolna) i promien jego rogow.
SQUARE = (32, 992)
RADIUS = 204
#: Akcent marki — ten sam co `ui/theme.py` (ACCENT) i certyfikat PDF.
COLOR = (0xFF, 0x5C, 0x39)
INK = (0xFF, 0xFF, 0xFF)

#: Pierscien: sto kresek jak w logo strony. Promienie (wewnetrzny,
#: zewnetrzny) maja proporcje favicon.svg (85,7 i 120 na 300) przeliczone na
#: kwadrat 960 jednostek; kreski sa grubsze niz w logo strony, zeby nie
#: znikaly w kafelkach i na pasku zadan.
TICKS = 100
RING = (274, 384)
TICK_WIDTH = 11
#: Kreski akcentu: w logo strony piec rozowych od godziny 9 w strone 12
#: (numeracja od godziny 12, zgodnie ze wskazowkami zegara). Na pomaranczowym
#: tle — granat tla logo strony.
ACCENT_TICKS = range(75, 80)
ACCENT_COLOR = (0x0B, 0x0D, 0x12)
#: Ptaszek: punkty lamanej (obrys wysrodkowany w 512, 512) i grubosc kreski.
CHECK = ((387, 514), (473, 598), (637, 426))
CHECK_WIDTH = 64

#: Najwiekszy kafelek potrzebuje 819 px grafiki (1240 px x 0,66), wiec
#: 2048 px zostawia zapas takze na grafiki karty w Sklepie.
MASTER_SIZE = 2048
#: Ramki pliku .ico — te same co w dotychczasowej ikonie.
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
#: Pillow rysuje BEZ wygladzania krawedzi; rysujemy wiec w rozmiarze 4x
#: wiekszym i pomniejszamy.
SUPERSAMPLE = 4


def _stroke(draw: ImageDraw.ImageDraw, points, width: float, k: float) -> None:
    """Lamana z zaokraglonymi koncami i zlaczami (jak `stroke-linecap="round"`)."""
    pts = [(x * k, y * k) for x, y in points]
    draw.line(pts, fill=255, width=round(width * k), joint='curve')
    r = width * k / 2
    for x, y in (pts[0], pts[-1]):
        draw.ellipse((x - r, y - r, x + r, y + r), fill=255)


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

    ink = Image.new('L', (big, big), 0)
    accent = Image.new('L', (big, big), 0)
    draw_ink, draw_accent = ImageDraw.Draw(ink), ImageDraw.Draw(accent)
    centre = (low + high) / 2
    inner, outer = RING
    for i in range(TICKS):
        angle = math.tau * i / TICKS
        dx, dy = math.sin(angle), -math.cos(angle)
        tick = ((centre + inner * dx, centre + inner * dy),
                (centre + outer * dx, centre + outer * dy))
        _stroke(draw_accent if i in ACCENT_TICKS else draw_ink, tick, TICK_WIDTH, k)
    _stroke(draw_ink, CHECK, CHECK_WIDTH, k)

    square = square.resize((size, size), Image.LANCZOS)
    ink = ink.resize((size, size), Image.LANCZOS)
    accent = accent.resize((size, size), Image.LANCZOS)
    colour = Image.new('RGB', (size, size), COLOR)
    colour = Image.composite(Image.new('RGB', (size, size), ACCENT_COLOR), colour, accent)
    colour = Image.composite(Image.new('RGB', (size, size), INK), colour, ink)
    icon = colour.convert('RGBA')
    icon.putalpha(square)
    return icon


def main() -> int:
    master = render(MASTER_SIZE)
    master.save(MASTER, format='PNG', optimize=True)
    print(f'wzorzec: {MASTER.name} {MASTER_SIZE}x{MASTER_SIZE}, '
          f'{MASTER.stat().st_size // 1024} KB')

    # Ramki pomniejszane z wzorca (LANCZOS). `append_images` sprawia, ze
    # Pillow zapisuje DOKLADNIE te obrazy, zamiast pomniejszac po swojemu.
    frames = [master.resize((s, s), Image.LANCZOS) for s in ICO_SIZES]
    frames[-1].save(ICO, format='ICO', sizes=[(s, s) for s in ICO_SIZES],
                    append_images=frames[:-1])
    print(f'ikona:   {ICO.name} ({", ".join(str(s) for s in ICO_SIZES)} px), '
          f'{ICO.stat().st_size // 1024} KB')

    if WEB_ICON.parent.is_dir():
        master.resize((WEB_ICON_SIZE, WEB_ICON_SIZE), Image.LANCZOS).save(
            WEB_ICON, format='PNG', optimize=True)
        print(f'strona:  {WEB_ICON.name} {WEB_ICON_SIZE}x{WEB_ICON_SIZE}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
