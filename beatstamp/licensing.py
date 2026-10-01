"""
Spis skladnikow do okna „Licencje i noty" — czytany z pliku NOTICE.

Zrodlem jest `NOTICE` dostarczany z programem (`_internal/licenses/NOTICE`),
a nie osobna lista w kodzie. NOTICE sklada `tools/make_notice.py` z GOTOWEJ
paczki, wiec okno pokazuje dokladnie to, co w niej lezy — lista wpisana
recznie rozjechalaby sie z paczka przy pierwszej aktualizacji biblioteki.

Z kodu pochodzi tylko jedno: zdanie „do czego ten skladnik sluzy w tym
programie", w jezyku interfejsu. Tego NOTICE nie mowi, a uzytkownik pyta
wlasnie o to.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .i18n import N_, translate

_RULE = re.compile(r'^-{20,}$')
_SECTION = re.compile(r'^={20,}$')
_TEXT_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\.txt')


@dataclass
class NoticeComponent:
    title: str                      # „Qt 6.11.2"
    license: str                    # SPDX
    copyright: str = ''
    homepage: str = ''
    source: str = ''
    texts: list[str] = field(default_factory=list)
    note: str = ''

    @property
    def name(self) -> str:
        """Tytul bez numeru wersji (ostatnie slowo, jesli zaczyna sie od cyfry)."""
        head, _sep, tail = self.title.rpartition(' ')
        return head if head and tail[:1].isdigit() else self.title

    @property
    def version(self) -> str:
        head, _sep, tail = self.title.rpartition(' ')
        return tail if head and tail[:1].isdigit() else ''


def parse_notice(text: str) -> list[NoticeComponent]:
    """Sekcja THIRD-PARTY COMPONENTS pliku NOTICE -> lista skladnikow."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines)
                     if line.strip() == 'THIRD-PARTY COMPONENTS')
    except StopIteration:
        return []
    components: list[NoticeComponent] = []
    i = start + 1
    current: NoticeComponent | None = None
    body: list[str] = []

    def finish() -> None:
        if current is None:
            return
        paragraphs, chunk = [], []
        for line in body:
            if line.strip():
                chunk.append(line.strip())
            elif chunk:
                paragraphs.append(' '.join(chunk))
                chunk = []
        if chunk:
            paragraphs.append(' '.join(chunk))
        notes = []
        for paragraph in paragraphs:
            if paragraph.startswith('Homepage:'):
                current.homepage = paragraph.split(':', 1)[1].strip()
            elif paragraph.startswith('License text:'):
                current.texts = _TEXT_NAME.findall(paragraph)
            elif paragraph.startswith('Source:'):
                current.source = paragraph.split(':', 1)[1].strip()
            elif paragraph.startswith('Files ('):
                break
            elif not current.copyright:
                current.copyright = paragraph
            else:
                notes.append(paragraph)
        current.note = '\n\n'.join(notes)
        components.append(current)

    while i < len(lines):
        line = lines[i]
        if _SECTION.match(line.strip()) and i > start + 1 and current is not None \
                and i + 1 < len(lines) and not _RULE.match(lines[i + 1].strip()):
            break
        if (_RULE.match(line.strip()) and i + 3 < len(lines)
                and lines[i + 2].startswith('License:') and _RULE.match(lines[i + 3].strip())):
            finish()
            current = NoticeComponent(title=lines[i + 1].strip(),
                                      license=lines[i + 2].split(':', 1)[1].strip())
            body = []
            i += 4
            continue
        if current is not None:
            body.append(line)
        i += 1
    finish()
    return components


# Do czego skladnik sluzy — po poczatku nazwy z NOTICE. Kolejnosc ma
# znaczenie: dluzsze przedrostki przed krotszymi.
PURPOSES: tuple[tuple[str, str], ...] = (
    ('Sigelith Desktop', N_('This program. Its source code is public under the Apache '
                     'License 2.0.')),
    ('PyInstaller', N_('Starts the program and unpacks its code — the '
                       'executable file SigelithDesktop.exe itself.')),
    ('PySide6', N_('Connects the Python code of the program to Qt.')),
    ('Shiboken6', N_('The bridge between Python and C++ used by PySide6.')),
    ('Qt', N_('The whole user interface: windows, buttons, text and drawing.')),
    ('PDFium', N_('Required by a Qt image plugin that comes with Qt. Sigelith Desktop '
                  'does not open PDF files with it.')),
    ('Mesa', N_('Software drawing, used only on computers without a working '
                'graphics driver.')),
    ('Python', N_('The runtime the program is written in.')),
    ('OpenSSL', N_('Encryption of the HTTPS connections and the cryptography '
                   'behind the signature checks.')),
    ('libffi', N_('Lets Python call Windows system libraries.')),
    ('Pillow', N_('An image library that ReportLab needs.')),
    ('ReportLab', N_('Draws the PDF certificate and its QR code.')),
    ('requests', N_('HTTP connections to sigelith.org and to the independent '
                    'archives.')),
    ('urllib3', N_('The HTTP transport under requests.')),
    ('idna', N_('International domain names in addresses.')),
    ('PySocks', N_('The optional connection through the Tor network.')),
    ('cryptography', N_('Checks the Ed25519 signatures of the week roots and of '
                        'the log checkpoints.')),
    ('cffi', N_('A binding the cryptography library is built on.')),
    ('charset-normalizer', N_('Recognises text encodings for requests.')),
    ('certifi', N_('The list of trusted root certificates for HTTPS.')),
    ('Inter', N_('The typeface of the interface and of the PDF certificate.')),
    ('Bootstrap Icons', N_('The icons of the interface.')),
    ('JetBrains Mono', N_('The typeface of the digests, of the clock and of the '
                          'technical data.')),
    ('Microsoft', N_('Standard Windows runtime libraries.')),
)


def purpose(component: NoticeComponent) -> str:
    for prefix, text in PURPOSES:
        if component.title.startswith(prefix):
            return translate(text)
    return ''


def notice_path(directory: Path) -> Path | None:
    """NOTICE w paczce lezy w `licenses/`, a w drzewie zrodel — pietro wyzej."""
    for candidate in (Path(directory) / 'NOTICE', Path(directory).parent / 'NOTICE'):
        if candidate.is_file():
            return candidate
    return None


def load(directory: Path) -> list[NoticeComponent]:
    path = notice_path(directory)
    if path is None:
        return []
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    return parse_notice(text)
