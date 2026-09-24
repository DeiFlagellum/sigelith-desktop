"""
Spis tego, co naprawde lezy w paczce BeatStampa — i na jakiej licencji.

JEDNO ZRODLO PRAWDY

Ten modul czytaja TRZY rzeczy i zadna z nich nie ma wlasnej kopii listy:

* `beatstamp.spec` — wyrzuca z paczki pliki z `EXCLUDED` (zanim PyInstaller
  cokolwiek skopiuje, a nie kasowaniem po kompilacji: plik skasowany po
  kompilacji wraca przy kazdej nastepnej i nikt tego nie zauwaza);
* `tests/test_licensing.py` — przeglada ZBUDOWANA paczke i przewraca sie,
  gdy pojawi sie w niej plik zakazany albo plik bez przypisanej licencji;
* `tools/make_notice.py` — sklada z tego plik `NOTICE`.

Rozjazd miedzy „co wykluczamy", „co sprawdzamy" i „co deklarujemy w notach"
jest dokladnie ta usterka, ktorej nie widac: paczka moze miec komplet not
i JEDNOCZESNIE zawierac plik, ktorego zadna z nich nie opisuje.

DLACZEGO Z PACZKI, A NIE Z `requirements.txt`

`requirements.txt` wymienia zaleznosci Pythona. W paczce lezy natomiast to,
co PyInstaller ZEBRAL: caly Qt (ktorego nie ma w requirements jako osobna
pozycja), OpenSSL i libffi z wydania CPythona, biblioteki uruchomieniowe
Microsoftu, wlasny program rozruchowy PyInstallera wkompilowany w `.exe`.
Lista z requirements mowilaby wiec o czyms innym niz to, co uzytkownik
dostaje — i przemilczalaby akurat te skladniki, ktorych licencje maja
najostrzejsze wymagania (LGPL Qt, GPL programu rozruchowego).

PLIK TO NIE ZAWSZE SKLADNIK

Przez dlugi czas ten modul patrzyl WYLACZNIE na nazwy plikow na dysku —
i dlatego oglaszal caly `BeatStamp.exe` jako „nasz kod plus program
rozruchowy". To bylo nieprawda: w `.exe` siedzi archiwum PYZ, a w nim
kilkaset modulow cudzego kodu (reportlab, requests, urllib3, idna,
PySocks, PIL, cryptography, certifi...). Kazdy z nich ma wlasny wymog noty
w redystrybucji BINARNEJ, a redystrybucja binarna to wlasnie ten plik.
Dlatego `audit()` czyta takze zawartosc PYZ (`pyz_packages`) i przypisuje
`BeatStamp.exe` do skladnikow, ktorych kod naprawde w nim lezy. Pakiet
najwyzszego poziomu, ktorego nie zna `PYZ_COMPONENTS`, przerywa generowanie
not tak samo jak nieprzypisany plik.

BIALE LISTY, NIE LAPACZE

Wzorzec `Qt6*.dll -> qt (LGPL-3.0-only)` chronil przed plikiem BEZ noty,
ale nie przed plikiem z nota FALSZYWA: nowy modul Qt dostepny wylacznie na
GPLv3 (Qt MQTT, Qt CoAP, Qt OPC UA, cokolwiek dojdzie w nastepnym wydaniu)
wpadalby w ten wzorzec i zostawal ogloszony jako LGPL. Lista zakazow
(`GPL_ONLY`) starzeje sie z kazdym wydaniem Qt; lista zezwolen nie. Dlatego
nazwy bibliotek Qt, wtyczek Qt i modulow rozszerzen CPythona sa wypisane
z nazwy — kazdy NOWY plik laduje w `unassigned` i wymaga swiadomej decyzji.

CO TO ZNACZY „ZAKAZANY"

Qt jest udostepniane modulami i NIE KAZDY modul ma te sama licencje.
Qt Virtual Keyboard (klawiatura ekranowa) jest dostepny wylacznie na GPLv3
albo komercyjnie — wciagniety do paczki zamkniete-zrodlowej albo
apache'owej jest naruszeniem, ktorego nie widac w zadnym tescie
funkcjonalnym, bo klawiatura po prostu lezy nieuzywana w katalogu.
Dlatego lista `GPL_ONLY` jest sprawdzana przy kazdym uruchomieniu testow,
a nie „przy okazji wydania".
"""
from __future__ import annotations

import sys
import zipfile
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Katalogi z gotowymi paczkami. Pierwszy to wynik `build.ps1`, drugi to
#: kopia robocza dla MSIX (`packaging/build_msix.ps1`) — ta druga trafia do
#: Sklepu, wiec musi przechodzic dokladnie te same kontrole.
PACKAGE_DIRS = (ROOT / 'dist' / 'BeatStamp', ROOT / 'dist' / 'msix')

#: Nazwa wstecznie zgodna — `beatstamp.spec` i starsze skrypty czytaja
#: `PACKAGES` jako katalogi.
PACKAGES = PACKAGE_DIRS

#: Gdzie leza gotowe pliki `.msix`. To ICH tresc trafia do Sklepu, a nie
#: tresc katalogu `dist/msix`: przepakowanie katalogu bez ponownego
#: `MakeAppx` (albo odwrotnie) rozjezdza jedno z drugim i zaden test
#: patrzacy tylko na katalog tego nie zobaczy.
MSIX_DIR = ROOT / 'dist'
MSIX_PATTERN = 'BeatStamp-*.msix'

#: Katalog z pelnymi tekstami licencji w repozytorium.
LICENSES_DIR = ROOT / 'licenses'

#: Gdzie te same teksty leza w GOTOWEJ PACZCE. LGPLv3 par. 4(c) mowi
#: o DOSTARCZENIU kopii GNU GPL i LGPL razem z programem — nie o linku
#: do nich. Repozytorium moze kiedys zniknac albo zmienic adres; katalog
#: obok pliku .exe jest u uzytkownika zawsze. Otwiera go przycisk w oknie
#: „O programie".
LEGAL_DIR_IN_PACKAGE = '_internal/licenses'

#: Gdzie sa zrodla bibliotek LGPL. LGPLv3 par. 4(d) daje wybor: albo
#: dolaczyc zrodla, albo wskazac miejsce, z ktorego kazdy moze je pobrac,
#: albo zlozyc TRWALA PISEMNA OFERTE ich wydania. Robimy jedno i drugie —
#: adres moze kiedys zniknac, oferta nie.
QT_SOURCE_URL = ('https://download.qt.io/archive/qt/6.9/6.9.1/single/'
                 'qt-everywhere-src-6.9.1.tar.xz')
PYSIDE_SOURCE_URL = ('https://download.qt.io/official_releases/QtForPython/'
                     'pyside6/PySide6-6.9.1-src/'
                     'pyside-setup-everywhere-src-6.9.1.tar.xz')
WRITTEN_OFFER_CONTACT = 'kontakt@advena-partners.com'

#: Adres publicznego repozytorium BeatStampa. PUSTY, dopoki repozytorium nie
#: istnieje — i to jest swiadome. Zmyslony albo „tymczasowy" adres w pliku
#: not jest gorszy niz jego brak: czytelnik, ktory go nie znajdzie, traci
#: jedyna sciezke do zrodel, a LGPLv3 par. 4(d)(0) opiera sie wlasnie na
#: dostepnosci kodu aplikacji. Dopoki jest pusty, te sciezke niesie TRWALA
#: PISEMNA OFERTA — dlatego oferta w `NOTICE` obejmuje takze kod aplikacji,
#: a nie tylko zrodla Qt i PySide6.
BEATSTAMP_SOURCE_URL = ''


# --- Opis skladnika ---------------------------------------------------------

@dataclass(frozen=True)
class Component:
    """Jeden skladnik paczki: biblioteka albo grupa plikow jednego wydawcy."""

    name: str
    version: str
    spdx: str
    copyright: str
    homepage: str = ''
    #: Pliki z pelnym tekstem licencji w `licenses/` (moze byc kilka:
    #: LGPLv3 nie jest samodzielnym tekstem — jest zestawem dodatkowych
    #: pozwolen do GPLv3 i bez GPLv3 nie da sie go przeczytac).
    texts: tuple[str, ...] = ()
    #: Skad wziac zrodla. Wymagane przy LGPL, poza tym uzyteczne.
    source: str = ''
    #: Zdanie, ktore trzeba powiedziec wprost, bo sama nazwa licencji go
    #: nie niesie (wyjatek dla programu rozruchowego, propagacja NOTICE).
    note: str = ''


COMPONENTS: dict[str, Component] = {
    'beatstamp': Component(
        name='BeatStamp',
        version='',                       # uzupelniane z `beatstamp.__version__`
        spdx='Apache-2.0',
        copyright='Copyright 2026 Adam Koch',
        homepage='https://beattime.live',
        texts=('Apache-2.0.txt',),
        source=(f'{BEATSTAMP_SOURCE_URL}'
                if BEATSTAMP_SOURCE_URL else
                'The source code of this program is in the desktop/ directory '
                'of the BeatTime source tree. Until the public address of '
                'that repository is published, the written offer in the '
                '"Sources of the LGPL libraries" section covers it: on '
                'request, Adam Koch will supply the complete source of this '
                'version of the program, in the form needed to relink it '
                'against your own build of Qt and PySide6.'),
        note='When BeatStamp is installed from the Microsoft Store, the '
             'package additionally contains its MSIX manifest, the '
             'application logos generated from the program icon and the '
             'compiled .pri resources. Those files are part of this program '
             'and are covered by the same license.',
    ),
    'pyinstaller': Component(
        name='PyInstaller bootloader and runtime modules',
        version='6.14.2',
        spdx='GPL-2.0-or-later WITH Bootloader-exception',
        copyright='Copyright (c) 2010-2023, PyInstaller Development Team; '
                  'Copyright (c) 2005-2009, Giovanni Bajo; '
                  'based on previous work copyright (c) 2002 '
                  'McMillan Enterprises, Inc.',
        homepage='https://pyinstaller.org/',
        texts=('PyInstaller-bootloader.txt', 'GPL-2.0.txt'),
        source='https://github.com/pyinstaller/pyinstaller',
        note='BeatStamp.exe is the PyInstaller bootloader with an archive '
             'appended to it. The archive holds this program, its Python '
             'dependencies and a few PyInstaller runtime modules; everything '
             'that is inside it is listed under its own component in this '
             'file, with BeatStamp.exe named among that component\'s files. '
             'The bootloader is licensed under the GNU GPL v2 or later WITH '
             'the bootloader exception, which expressly permits linking or '
             'embedding the compiled bootloader into programs under other '
             'licenses, including proprietary ones. The exception does not '
             'extend the GPL to the rest of BeatStamp.exe.',
    ),
    'qt': Component(
        name='Qt',
        # Nota przepisana DOSLOWNIE z zasobu wersji `Qt6Core.dll` (pole
        # `LegalCopyright`). LGPLv3 par. 4(c) mowi o dolaczeniu noty
        # copyright BIBLIOTEKI, a nie noty przez nas zredagowanej — rok,
        # ktorego w zasobie nie ma, byl dopisany, nie przepisany.
        version='6.9.1',
        spdx='LGPL-3.0-only',
        copyright='Copyright (C) The Qt Company Ltd. and other contributors.',
        homepage='https://www.qt.io/',
        texts=('LGPL-3.0.txt', 'GPL-3.0.txt', 'Qt-third-party.txt'),
        source=f'{QT_SOURCE_URL} (the complete source of the exact version '
               f'used here). A written offer to supply that source is in the '
               f'"Sources of the LGPL libraries" section of this file.',
        note='Qt is used as a shared library and is not modified. How to '
             'relink the program against your own build of Qt depends on how '
             'this copy was installed; see the "Relinking against your own '
             'build of Qt" section above. Qt vendors and compiles in '
             'third-party code of its own -- PCRE2, FreeType, HarfBuzz, '
             'libpng, zlib, libjpeg-turbo, libtiff, libwebp, OpenJPEG and ICU '
             'were found in the binaries of this package. Complying with the '
             'LGPL does not discharge their own notice requirements, so their '
             'copyright notices and license texts are in '
             'Qt-third-party.txt next to this file. The FreeType License asks '
             'for this sentence: "Portions of this software are copyright (c) '
             '2025 The FreeType Project (https://freetype.org). All rights '
             'reserved."',
    ),
    'pyside6': Component(
        name='PySide6 (Qt for Python)',
        version='6.9.1',
        spdx='LGPL-3.0-only',
        copyright='Copyright (C) 2025 The Qt Company Ltd.',
        homepage='https://doc.qt.io/qtforpython/',
        texts=('LGPL-3.0.txt', 'GPL-3.0.txt'),
        source=f'{PYSIDE_SOURCE_URL} (the complete source of the exact version '
               f'used here). A written offer to supply that source is in the '
               f'"Sources of the LGPL libraries" section of this file.',
    ),
    'shiboken6': Component(
        name='Shiboken6',
        version='6.9.1',
        spdx='LGPL-3.0-only',
        copyright='Copyright (C) 2025 The Qt Company Ltd.',
        homepage='https://doc.qt.io/qtforpython/shiboken6/',
        texts=('LGPL-3.0.txt', 'GPL-3.0.txt'),
        source=f'{PYSIDE_SOURCE_URL} (Shiboken6 is part of the PySide6 source '
               f'package).',
    ),
    'pdfium': Component(
        name='PDFium',
        version='as shipped inside Qt 6.9.1 (Qt6Pdf)',
        spdx='BSD-3-Clause AND Apache-2.0',
        copyright='Copyright 2014 The PDFium Authors. All rights reserved.',
        homepage='https://pdfium.googlesource.com/pdfium/',
        texts=('PDFium.txt',),
        source=f'{QT_SOURCE_URL} (PDFium is vendored in the Qt source tree, '
               f'under qtwebengine/src/3rdparty).',
        note='Qt6Pdf.dll is built from PDFium and carries its third-party '
             'notices. It is in the package because the Qt image plugin '
             'qpdf.dll depends on it.',
    ),
    'mesa': Component(
        name='Mesa 3D (llvmpipe software OpenGL) with LLVM',
        version='Mesa 11.2.2 with LLVM 3.6.2, as shipped in the Qt release',
        spdx='MIT AND NCSA',
        copyright='Copyright (C) 1999-2007 Brian Paul. All Rights Reserved. '
                  'Copyright (c) 2003-2014 University of Illinois at '
                  'Urbana-Champaign. All rights reserved.',
        homepage='https://www.mesa3d.org/',
        texts=('Mesa.txt', 'NCSA.txt'),
        note='opengl32sw.dll is loaded only on machines without a usable '
             'OpenGL driver. The llvmpipe driver links LLVM statically, and '
             'the build string inside the file reads "llvm-mc (based on LLVM '
             '3.6.2)". LLVM was relicensed to Apache-2.0 WITH LLVM-exception '
             'only with LLVM 9; the 3.6 series is under the University of '
             'Illinois/NCSA Open Source License, whose text is in NCSA.txt '
             'next to this file.',
    ),
    'cpython': Component(
        name='Python (CPython)',
        version='3.12.10',
        spdx='PSF-2.0',
        copyright='Copyright (c) 2001-2025 Python Software Foundation. '
                  'All Rights Reserved.',
        homepage='https://www.python.org/',
        texts=('Python-PSF.txt',),
        source='https://www.python.org/downloads/release/python-31210/',
        note='The CPython distribution incorporates third-party code (among '
             'others Expat, libffi, bzip2, XZ Utils/liblzma and libmpdec). '
             'Their notices are in the Python license text shipped next to '
             'this file; the extension modules built from them are listed '
             'above under this component.',
    ),
    # OpenSSL jest w tej paczce DWA RAZY, w dwoch roznych wersjach: jeden
    # przychodzi z wydania CPythona jako osobne biblioteki, drugi jest
    # WKOMPILOWANY w `_rust.pyd` z koła cryptography. Jeden skladnik
    # opisujacy „OpenSSL 3.0.16" byl wiec zdaniem nieprawdziwym o polowie
    # paczki — a Apache-2.0 par. 4 wymaga atrybucji dla KAZDEJ
    # rozpowszechnianej kopii.
    'openssl': Component(
        name='OpenSSL',
        version='3.0.16 (the build shipped with CPython 3.12.10)',
        spdx='Apache-2.0',
        copyright='Copyright 1998-2025 The OpenSSL Project Authors. '
                  'Copyright (c) 1995-1998 Eric A. Young, Tim J. Hudson. '
                  'All rights reserved.',
        homepage='https://www.openssl.org/',
        texts=('Apache-2.0.txt',),
        source='https://github.com/openssl/openssl',
        note='Attribution required by section 4 of the Apache License 2.0: '
             'this product includes software developed by the OpenSSL Project '
             'for use in the OpenSSL Toolkit (https://www.openssl.org/), and '
             'cryptographic software written by Eric Young.',
    ),
    'openssl-cryptography': Component(
        name='OpenSSL',
        version='3.5.1 (statically linked into the cryptography wheel)',
        spdx='Apache-2.0',
        copyright='Copyright 1998-2025 The OpenSSL Project Authors. '
                  'Copyright (c) 1995-1998 Eric A. Young, Tim J. Hudson. '
                  'All rights reserved.',
        homepage='https://www.openssl.org/',
        texts=('Apache-2.0.txt',),
        source='https://github.com/openssl/openssl',
        note='A second, different build of OpenSSL. It is not a file of its '
             'own: it is compiled into _rust.pyd, which carries the version '
             'string "OpenSSL 3.5.1 1 Jul 2025" and the OpenSSL assembler '
             'routines, and which imports neither libcrypto-3.dll nor '
             'libssl-3.dll. Attribution required by section 4 of the Apache '
             'License 2.0: this product includes software developed by the '
             'OpenSSL Project for use in the OpenSSL Toolkit '
             '(https://www.openssl.org/), and cryptographic software written '
             'by Eric Young.',
    ),
    'libffi': Component(
        name='libffi',
        version='as shipped with CPython 3.12.10 (libffi-8.dll)',
        spdx='MIT',
        copyright='Copyright (c) 1996-2022 Anthony Green, Red Hat, Inc and '
                  'others.',
        homepage='https://sourceware.org/libffi/',
        texts=('Python-PSF.txt',),
        note='The full libffi license text is part of the Python license file '
             'shipped next to this one.',
    ),
    'pillow': Component(
        name='Pillow',
        version='12.3.0',
        spdx='MIT-CMU',
        copyright='Copyright (c) 1997-2011 by Secret Labs AB; '
                  'Copyright (c) 1995-2011 by Fredrik Lundh and contributors; '
                  'Copyright (c) 2010-2025 by Jeffrey A. Clark and '
                  'contributors.',
        homepage='https://python-pillow.github.io/',
        texts=('Pillow.txt',),
        note='Pillow is in the package because reportlab.lib.utils imports it '
             'unconditionally; BeatStamp itself draws the QR code as vectors. '
             'The binary modules statically link libtiff, libjpeg-turbo, '
             'zlib-ng, OpenJPEG, libwebp, Little CMS and FreeType; the '
             'notices of all of them are in the license text named above, '
             'which is the LICENSE file of the Pillow wheel verbatim. The '
             'AVIF module, which would have added the AOMedia AV1 encoder and '
             'dav1d on top of that, is removed from the package (see '
             '"Deliberately not in this package"). libimagequant, the only '
             'GPL component Pillow can be built with, is NOT in this build: '
             'PIL.features reports it as not installed and no imagequant '
             'symbol appears in the binaries.',
    ),
    'reportlab': Component(
        name='ReportLab PDF Toolkit',
        version='4.4.2',
        spdx='BSD-3-Clause',
        copyright='Copyright (c) 2000-2024, ReportLab Inc. All rights '
                  'reserved.',
        homepage='https://www.reportlab.com/',
        texts=('reportlab.txt',),
        source='https://pypi.org/project/reportlab/4.4.2/',
        note='BeatStamp draws the PDF certificate with reportlab. The library '
             'is not a file of its own in this package: its 159 modules are '
             'compiled into the archive inside BeatStamp.exe.',
    ),
    'requests': Component(
        name='requests',
        version='2.32.4',
        spdx='Apache-2.0',
        copyright='Copyright Kenneth Reitz and the requests contributors.',
        homepage='https://requests.readthedocs.io/',
        texts=('Apache-2.0.txt', 'requests-NOTICE.txt'),
        source='https://pypi.org/project/requests/2.32.4/',
        note='Section 4 of the Apache License 2.0 requires this attribution '
             'notice to travel with every copy of the work, including the '
             'copy compiled into BeatStamp.exe.',
    ),
    'urllib3': Component(
        name='urllib3',
        version='2.5.0',
        spdx='MIT',
        copyright='Copyright (c) 2008-2020 Andrey Petrov and contributors.',
        homepage='https://urllib3.readthedocs.io/',
        texts=('urllib3.txt',),
        source='https://pypi.org/project/urllib3/2.5.0/',
        note='The HTTP transport under requests. Compiled into '
             'BeatStamp.exe.',
    ),
    'idna': Component(
        name='idna',
        version='3.20',
        spdx='BSD-3-Clause',
        copyright='Copyright (c) 2013-2026, Kim Davies and contributors. '
                  'All rights reserved.',
        homepage='https://github.com/kjd/idna',
        texts=('idna.txt',),
        source='https://pypi.org/project/idna/3.20/',
        note='Internationalised domain names for requests. Compiled into '
             'BeatStamp.exe.',
    ),
    'pysocks': Component(
        name='PySocks',
        version='1.7.1',
        spdx='BSD-3-Clause',
        copyright='Copyright 2006 Dan-Haim. All rights reserved.',
        homepage='https://github.com/Anorov/PySocks',
        texts=('PySocks.txt',),
        source='https://pypi.org/project/PySocks/1.7.1/',
        note='The SOCKS5 proxy support that requests uses when BeatStamp '
             'talks to the register over Tor. Compiled into BeatStamp.exe.',
    ),
    'cryptography': Component(
        name='cryptography',
        version='45.0.5',
        spdx='Apache-2.0 OR BSD-3-Clause',
        copyright='Copyright (c) Individual contributors.',
        homepage='https://cryptography.io/',
        texts=('Apache-2.0.txt', 'cryptography-rust-crates.txt'),
        note='The package also carries its own license files at '
             '_internal/cryptography-45.0.5.dist-info/licenses/. Its binary '
             'module _rust.pyd is a statically linked Rust binary: the crates '
             'compiled into it, with their versions and licenses, are listed '
             'in cryptography-rust-crates.txt next to this file, and the '
             'OpenSSL build inside it is a separate component above.',
    ),
    'cffi': Component(
        name='cffi',
        version='2.1.1',
        spdx='MIT-0',
        copyright='Copyright (c) 2012-2025 Armin Rigo, Maciej Fijalkowski and '
                  'contributors.',
        homepage='https://cffi.readthedocs.io/',
        texts=('cffi.txt',),
    ),
    'charset-normalizer': Component(
        name='charset-normalizer',
        version='3.5.1',
        spdx='MIT',
        copyright='Copyright (c) 2025 TAHRI Ahmed R.',
        homepage='https://github.com/jawah/charset_normalizer',
        texts=('charset-normalizer.txt',),
    ),
    'certifi': Component(
        name='certifi (Mozilla CA bundle)',
        version='2025.07.14',
        spdx='MPL-2.0',
        copyright='Copyright (c) 2013 Kenneth Reitz. The bundled list of root '
                  'certificates is maintained by the Mozilla Foundation.',
        homepage='https://github.com/certifi/python-certifi',
        # Sam plik LICENSE certifi jest tylko NOTA BLOKOWA MPL („if a copy of
        # the MPL was not distributed with this file..."). Pelnego tekstu
        # licencji w paczce nie bylo, a certifi jest rozpowszechniane takze
        # w postaci wykonywalnej (MPL par. 3.2), bo jego kod lezy w PYZ.
        texts=('certifi.txt', 'MPL-2.0.txt'),
        source='https://github.com/certifi/python-certifi',
    ),
    'msvc': Component(
        name='Microsoft Visual C++ runtime',
        version='from the Visual C++ Redistributable used to build the '
                'dependencies',
        spdx='LicenseRef-Microsoft-Redistributable',
        copyright='Copyright (c) Microsoft Corporation. All rights reserved.',
        homepage='https://learn.microsoft.com/cpp/windows/'
                 'latest-supported-vc-redist',
        note='Redistributable files, shipped under the redistribution rights '
             'granted by the Microsoft Visual Studio license terms. Not open '
             'source.',
    ),
    'ucrt': Component(
        name='Microsoft Universal C Runtime',
        version='from the Windows SDK / Windows 11',
        spdx='LicenseRef-Microsoft-Redistributable',
        copyright='Copyright (c) Microsoft Corporation. All rights reserved.',
        homepage='https://learn.microsoft.com/cpp/windows/'
                 'universal-crt-deployment',
        note='ucrtbase.dll and the api-ms-win-* forwarders are the app-local '
             'deployment of the Universal CRT, shipped under the '
             'redistribution rights granted by the Windows SDK license terms. '
             'Not open source.',
    ),
}


# --- Czego w paczce byc NIE MOZE --------------------------------------------

@dataclass(frozen=True)
class Excluded:
    """Plik, ktory nie ma prawa trafic do paczki, i powod."""

    pattern: str
    subject: str
    reason: str
    #: 'gpl' — licencja zabrania; 'orphan' — wchodzil tylko jako zaleznosc
    #: czegos z 'gpl'; 'machine' — PyInstaller znalazl go na maszynie
    #: budujacej, a nie w przypietej zaleznosci; 'unused' — dziala, wolno go
    #: wydac, ale nic go nie uzywa, a niesie wlasny lancuch not.
    kind: str = 'gpl'


#: Moduly Qt dostepne WYLACZNIE na GPLv3 albo komercyjnie. Reszta Qt, ktorej
#: uzywamy, jest na LGPLv3 — i to jest cala roznica miedzy programem, ktory
#: wolno wydac na Apache-2.0, a programem, ktorego nie wolno.
#:
#: Lista jest szersza niz to, co dzis wchodzilo do paczki, celowo: wpisanie
#: `PySide6.QtCharts` do zaleznosci jest jedna linijka, a skutek licencyjny
#: jest taki sam jak przy klawiaturze ekranowej.
GPL_ONLY = (
    Excluded('Qt6VirtualKeyboard.dll', 'Qt Virtual Keyboard',
             'available only under GPLv3 or a commercial Qt license '
             '(an on-screen keyboard; nothing in BeatStamp uses it)'),
    Excluded('qtvirtualkeyboardplugin.dll', 'Qt Virtual Keyboard',
             'the platform input context plugin of Qt Virtual Keyboard; '
             'same license as the module itself'),
    Excluded('Qt6Charts.dll', 'Qt Charts',
             'available only under GPLv3 or a commercial Qt license'),
    Excluded('Qt6ChartsQml.dll', 'Qt Charts',
             'available only under GPLv3 or a commercial Qt license'),
    Excluded('Qt6DataVisualization.dll', 'Qt Data Visualization',
             'available only under GPLv3 or a commercial Qt license'),
    Excluded('Qt6DataVisualizationQml.dll', 'Qt Data Visualization',
             'available only under GPLv3 or a commercial Qt license'),
    Excluded('Qt6Graphs.dll', 'Qt Graphs',
             'available only under GPLv3 or a commercial Qt license'),
    Excluded('Qt6GraphsWidgets.dll', 'Qt Graphs',
             'available only under GPLv3 or a commercial Qt license'),
)

#: Biblioteki, ktore PyInstaller sciagal WYLACZNIE jako zaleznosc klawiatury
#: ekranowej. Sprawdzone przez odczyt tablic importow z gotowej paczki
#: (`pefile`): `Qt6Quick.dll` importowal tylko `Qt6VirtualKeyboard.dll`,
#: caly stos QML wisial pod `Qt6Quick.dll`, a `Qt6OpenGL.dll` pod nim.
#: Zadna z nich nie jest juz nikomu w paczce potrzebna — pilnuje tego
#: `tests/test_licensing.py`, ktory czyta importy KAZDEGO pozostalego pliku.
#:
#: Same w sobie sa na LGPLv3 i wolno je wydawac; lezaly w paczce jako
#: dwanascie megabajtow martwego kodu i dodatkowa powierzchnia ataku.
ORPHANS = (
    Excluded('Qt6Quick.dll', 'Qt Quick',
             'entered the package only as a dependency of Qt Virtual Keyboard',
             kind='orphan'),
    Excluded('Qt6Qml.dll', 'Qt QML',
             'entered the package only as a dependency of Qt Virtual Keyboard',
             kind='orphan'),
    Excluded('Qt6QmlMeta.dll', 'Qt QML',
             'entered the package only as a dependency of Qt Virtual Keyboard',
             kind='orphan'),
    Excluded('Qt6QmlModels.dll', 'Qt QML',
             'entered the package only as a dependency of Qt Virtual Keyboard',
             kind='orphan'),
    Excluded('Qt6QmlWorkerScript.dll', 'Qt QML',
             'entered the package only as a dependency of Qt Virtual Keyboard',
             kind='orphan'),
    Excluded('Qt6OpenGL.dll', 'Qt OpenGL',
             'entered the package only as a dependency of Qt Quick',
             kind='orphan'),
    Excluded('qopensslbackend.dll', 'Qt TLS backend for OpenSSL',
             'the OpenSSL libraries it loads were removed from the package, '
             'so it can never load; Qt falls back to the Schannel backend, '
             'which stays',
             kind='orphan'),
)

#: Pliki, ktore dzialaja i wolno je wydac, ale nikt ich nie uzywa — a niosa
#: wlasny, osobny lancuch not licencyjnych.
#:
#: `_avif` to kodek AVIF Pillow. W srodku ma kompletny koder AOMedia AV1
#: 3.14.1 i dekoder dav1d, czyli BSD-2-Clause plus Alliance for Open Media
#: Patent License 1.0 — noty, ktorych nie ma nawet w pliku LICENSE samego
#: Pillow. Pillow jest w paczce tylko dlatego, ze `reportlab.lib.utils`
#: importuje go bezwarunkowo; certyfikat PDF rysujemy wektorowo i zadnego
#: obrazu AVIF program nigdy nie otwiera. `PIL.AvifImagePlugin` importuje
#: ten modul w `try/except ImportError` i bez niego po prostu oglasza brak
#: obslugi AVIF.
UNUSED = (
    # Wzorzec, a nie pelna nazwa: `_avif.cp312-win_amd64.pyd` przestaloby
    # pasowac przy pierwszej zmianie wersji Pythona, plik wrocilby do paczki
    # i zaden test by tego nie zauwazyl — bo regula `_internal/PIL/**`
    # przypisalaby go grzecznie do Pillow.
    Excluded('_avif*.pyd', 'Pillow AVIF codec',
             'carries a full AOMedia AV1 encoder (3.14.1) and dav1d inside, '
             'with their own BSD and patent-license notices, for a format '
             'this program never reads or writes',
             kind='unused'),
)

#: OpenSSL, ktory PyInstaller znalazl w `C:\\Windows\\System32` maszyny
#: budujacej. Robi to swiadomie: hak Qt szuka bibliotek OpenSSL dla
#: `QtNetwork` po sciezkach systemowych. Skutek jest jednak taki, ze
#: ZAWARTOSC WYDANIA ZALEZY OD TEGO, CO KTOS MA ZAINSTALOWANE — na tej
#: maszynie byl to OpenSSL 3.4.1, na innej nie bedzie go wcale.
#:
#: Do niczego nie sluzyly: zaden plik w paczce ich nie importuje (BeatStamp
#: nie uzywa `QtNetwork`, a HTTPS idzie przez `requests` i `_ssl`, czyli
#: przez OpenSSL 3.0.16 z wydania CPythona, ktory zostaje). Na Windows Qt
#: i tak uzywa Schannela.
MACHINE_LOCAL = (
    Excluded('libcrypto-3-x64.dll', 'OpenSSL for QtNetwork',
             'picked up from the build machine system directory, not from a '
             'pinned dependency; nothing in the package links against it',
             kind='machine'),
    Excluded('libssl-3-x64.dll', 'OpenSSL for QtNetwork',
             'picked up from the build machine system directory, not from a '
             'pinned dependency; nothing in the package links against it',
             kind='machine'),
)

EXCLUDED = GPL_ONLY + ORPHANS + MACHINE_LOCAL + UNUSED


# --- Przypisanie licencji do plikow -----------------------------------------

#: Biblioteki Qt, ktore wolno miec w paczce. WYPISANE Z NAZWY, a nie
#: `Qt6*.dll`: lapacz z gwiazdka oglosilby kazdy nowy modul Qt jako
#: LGPL-3.0-only, takze taki, ktory jest dostepny wylacznie na GPLv3 albo
#: komercyjnie (Qt MQTT, Qt CoAP, Qt OPC UA, Qt Quick 3D...). Czarna lista
#: `GPL_ONLY` zostaje jako druga, niezalezna bariera, ale starzeje sie
#: z kazdym wydaniem Qt — ta lista nie.
QT_LIBRARIES = ('Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Network.dll', 'Qt6Pdf.dll',
                'Qt6Svg.dll', 'Qt6Widgets.dll')

#: Wtyczki Qt, ktore wolno miec w paczce — ze sciezka, bo katalog wtyczki
#: mowi, do czego sluzy.
QT_PLUGINS = (
    'generic/qtuiotouchplugin.dll',
    'iconengines/qsvgicon.dll',
    'imageformats/qgif.dll',
    'imageformats/qicns.dll',
    'imageformats/qico.dll',
    'imageformats/qjpeg.dll',
    'imageformats/qsvg.dll',
    'imageformats/qtga.dll',
    'imageformats/qtiff.dll',
    'imageformats/qwbmp.dll',
    'imageformats/qwebp.dll',
    'networkinformation/qnetworklistmanager.dll',
    'platforms/qdirect2d.dll',
    'platforms/qminimal.dll',
    'platforms/qoffscreen.dll',
    'platforms/qwindows.dll',
    'styles/qmodernwindowsstyle.dll',
    'tls/qcertonlybackend.dll',
    'tls/qschannelbackend.dll',
)

#: Moduly rozszerzen PySide6.
PYSIDE_MODULES = ('QtCore.pyd', 'QtGui.pyd', 'QtNetwork.pyd', 'QtWidgets.pyd')

#: Moduly rozszerzen z wydania CPythona, ktore leza w korzeniu `_internal`.
#: Te z osobnymi regulami (`_ssl`, `_hashlib`, `_ctypes`, `_cffi_backend`)
#: sa opisane nizej, bo maja po dwa skladniki albo nie sa CPythonem.
CPYTHON_MODULES = ('_asyncio.pyd', '_bz2.pyd', '_decimal.pyd',
                   '_elementtree.pyd', '_lzma.pyd', '_multiprocessing.pyd',
                   '_overlapped.pyd', '_queue.pyd', '_socket.pyd', '_wmi.pyd',
                   'pyexpat.pyd', 'select.pyd', 'unicodedata.pyd')


def _named(prefix: str, names: tuple[str, ...], keys: tuple[str, ...]
           ) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Jedna regula na nazwe — zamiast jednego wzorca na wszystkie."""
    return tuple((f'{prefix}{name}', keys) for name in names)


#: Wzorzec -> skladniki. KOLEJNOSC MA ZNACZENIE: wygrywa pierwszy pasujacy,
#: wiec szczegolne wzorce (`Qt6Pdf.dll`) stoja przed ogolnymi.
#:
#: Skladnikow moze byc kilka: `_ssl.pyd` to modul CPythona zlinkowany
#: z OpenSSL-em, a `_rust.pyd` to cryptography ORAZ wkompilowany w nia
#: OpenSSL 3.5.1. Nota, ktora wymienia tylko jedna z tych licencji, jest
#: niepelna dokladnie tam, gdzie to boli.
RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ('BeatStamp.exe', ('beatstamp', 'pyinstaller')),
    ('_internal/beatstamp.ico', ('beatstamp',)),
    ('_internal/locale/**', ('beatstamp',)),
    (f'{LEGAL_DIR_IN_PACKAGE}/**', ('beatstamp',)),

    # Dodatki, ktore dokłada dopiero pakowanie MSIX (`dist/msix`): manifest,
    # logo wygenerowane z naszej ikony i skompilowane zasoby `.pri`.
    ('AppxManifest.xml', ('beatstamp',)),
    ('Assets/**', ('beatstamp',)),
    ('resources*.pri', ('beatstamp',)),

    # Pliki, ktore do paczki `.msix` dokłada dopiero `MakeAppx`: mapa blokow
    # i spis typow zawartosci. Sa liczone z NASZEJ zawartosci i nie niosa
    # cudzego kodu.
    ('AppxBlockMap.xml', ('beatstamp',)),
    # `[[]` i `[]]` to sposob, w jaki `fnmatch` zapisuje DOSLOWNY nawias
    # kwadratowy; `[Content_Types].xml` bylby klasa znakow i pasowalby do
    # `c.xml`, a nie do pliku o tej nazwie.
    ('[[]Content_Types[]].xml', ('beatstamp',)),
    ('AppxSignature.p7x', ('beatstamp',)),
    ('AppxMetadata/**', ('beatstamp',)),

    # --- Qt i wiazania Pythona ---
    ('_internal/PySide6/Qt6Pdf.dll', ('qt', 'pdfium')),
    ('_internal/PySide6/plugins/imageformats/qpdf.dll', ('qt', 'pdfium')),
    ('_internal/PySide6/opengl32sw.dll', ('mesa',)),
    ('_internal/PySide6/MSVCP140*.dll', ('msvc',)),
    ('_internal/PySide6/VCRUNTIME140*.dll', ('msvc',)),
    *_named('_internal/PySide6/', QT_LIBRARIES, ('qt',)),
    *_named('_internal/PySide6/plugins/', QT_PLUGINS, ('qt',)),
    ('_internal/PySide6/translations/**', ('qt',)),
    ('_internal/PySide6/pyside6.abi3.dll', ('pyside6',)),
    *_named('_internal/PySide6/', PYSIDE_MODULES, ('pyside6',)),
    ('_internal/shiboken6/MSVCP140*.dll', ('msvc',)),
    ('_internal/shiboken6/VCRUNTIME140*.dll', ('msvc',)),
    ('_internal/shiboken6/Shiboken.pyd', ('shiboken6',)),
    ('_internal/shiboken6/shiboken6.abi3.dll', ('shiboken6',)),

    # --- Biblioteki Pythona ---
    ('_internal/PIL/**', ('pillow',)),
    ('_internal/charset_normalizer/**', ('charset-normalizer',)),
    # PRZED ogolna regula cryptography: `_rust.pyd` niesie WKOMPILOWANY
    # OpenSSL 3.5.1, inny niz ten z wydania CPythona.
    ('_internal/cryptography/hazmat/bindings/_rust.pyd',
     ('cryptography', 'openssl-cryptography')),
    ('_internal/cryptography/**', ('cryptography',)),
    ('_internal/cryptography-*.dist-info/**', ('cryptography',)),
    ('_internal/certifi/**', ('certifi',)),
    ('_internal/_cffi_backend*.pyd', ('cffi',)),

    # --- Wydanie CPythona: interpreter i to, z czym jest zlinkowany ---
    ('_internal/libcrypto-3.dll', ('openssl',)),
    ('_internal/libssl-3.dll', ('openssl',)),
    ('_internal/libffi-8.dll', ('libffi',)),
    ('_internal/_ssl.pyd', ('cpython', 'openssl')),
    ('_internal/_hashlib.pyd', ('cpython', 'openssl')),
    ('_internal/_ctypes.pyd', ('cpython', 'libffi')),
    ('_internal/python3.dll', ('cpython',)),
    ('_internal/python312.dll', ('cpython',)),
    ('_internal/base_library.zip', ('cpython',)),
    *_named('_internal/', CPYTHON_MODULES, ('cpython',)),

    # --- Biblioteki uruchomieniowe Microsoftu ---
    ('_internal/MSVCP140*.dll', ('msvc',)),
    ('_internal/VCRUNTIME140*.dll', ('msvc',)),
    ('_internal/ucrtbase.dll', ('ucrt',)),
    ('_internal/api-ms-win-*.dll', ('ucrt',)),
)


# --- Dopasowanie sciezek ----------------------------------------------------

def normalise(path: object) -> str:
    """Sciezka w jednej postaci: ukosniki w przod, bez `./` na poczatku.

    PyInstaller sklada nazwy docelowe separatorem systemu, a paczke
    przegladamy przez `pathlib` — bez tego kroku ten sam plik mialby dwie
    rozne nazwy i wzorzec pasowalby raz na dwa razy.
    """
    text = str(path).replace('\\', '/')
    while text.startswith('./'):
        text = text[2:]
    return text.strip('/')


def matches(pattern: str, path: object) -> bool:
    """Czy sciezka pasuje do wzorca.

    Dwie postacie wzorca, obie potrzebne:

    * bez ukosnika (`Qt6VirtualKeyboard.dll`) — dopasowanie do SAMEJ NAZWY
      pliku, gdziekolwiek lezy. Tak wygladaja wpisy zakazane: plik zakazany
      jest zakazany takze wtedy, gdy Qt przeniesie go do innego katalogu;
    * ze ukosnikiem (`_internal/PySide6/Qt6*.dll`) — dopasowanie zakotwiczone
      w korzeniu paczki, segment po segmencie. `*` NIE przechodzi przez
      ukosnik (inaczej `_internal/*.pyd` lapaloby `_internal/PIL/_imaging.pyd`
      i przypisywaloby Pillow licencje CPythona), a `**` przechodzi przez
      dowolna liczbe katalogow.
    """
    text = normalise(path)
    if '/' not in pattern:
        return fnmatchcase(text.rsplit('/', 1)[-1].lower(), pattern.lower())
    return _match_parts(pattern.lower().split('/'), text.lower().split('/'))


def _match_parts(patterns: list[str], parts: list[str]) -> bool:
    if not patterns:
        return not parts
    if patterns[0] == '**':
        if len(patterns) == 1:
            return True
        return any(_match_parts(patterns[1:], parts[index:])
                   for index in range(len(parts) + 1))
    if not parts or not fnmatchcase(parts[0], patterns[0]):
        return False
    return _match_parts(patterns[1:], parts[1:])


def excluded_reason(path: object) -> Excluded | None:
    """Czy ten plik ma byc z paczki wyrzucony (i dlaczego)."""
    for item in EXCLUDED:
        if matches(item.pattern, path):
            return item
    return None


def components_for(path: object) -> tuple[str, ...]:
    """Skladniki, ktorych licencje obejmuja ten plik. Puste = nieprzypisany."""
    for pattern, keys in RULES:
        if matches(pattern, path):
            return keys
    return ()


# --- Co lezy WEWNATRZ `BeatStamp.exe` ---------------------------------------

#: Nazwa pliku wykonywalnego — i jednoczesnie archiwum z reszta programu.
EXECUTABLE = 'BeatStamp.exe'

#: Pakiet najwyzszego poziomu z archiwum PYZ -> skladniki. Stdlib nie jest
#: tu wymieniona z nazwy: rozpoznaje ja `sys.stdlib_module_names` i caly
#: idzie do `cpython`. Pakiet spoza tej mapy i spoza stdlib przerywa
#: generowanie not — dokladnie tak samo jak plik bez przypisanej licencji.
PYZ_COMPONENTS: dict[str, tuple[str, ...]] = {
    'beatstamp': ('beatstamp',),
    'beatstamp_main': ('beatstamp',),
    'PIL': ('pillow',),
    'PySide6': ('pyside6',),
    'shiboken6': ('shiboken6',),
    'certifi': ('certifi',),
    'charset_normalizer': ('charset-normalizer',),
    'cryptography': ('cryptography',),
    'idna': ('idna',),
    'reportlab': ('reportlab',),
    'requests': ('requests',),
    'socks': ('pysocks',),
    'sockshandler': ('pysocks',),
    'urllib3': ('urllib3',),
    '_pyi_rth_utils': ('pyinstaller',),
}


def pyz_packages(read_exe) -> list[str]:
    """Pakiety najwyzszego poziomu z archiwum PYZ w `BeatStamp.exe`.

    Czyta GOTOWY plik, nie `requirements.txt` i nie liste importow z kodu.
    Powod jest ten sam co przy calym module: liczy sie to, co uzytkownik
    dostaje. reportlab, requests, urllib3, idna i PySocks nie maja w paczce
    ani jednego wlasnego pliku — ich kod lezy skompilowany wlasnie tutaj,
    a kazda z tych licencji wymaga noty takze w postaci binarnej.

    `read_exe` to funkcja bez argumentow, ktora zwraca zawartosc
    `BeatStamp.exe` w bajtach — dzieki temu ta sama droga dziala dla paczki
    w katalogu i dla archiwum `.msix`.
    """
    import tempfile

    # Import leniwy: `tools/licenses.py` czyta takze `beatstamp.spec`
    # (tam PyInstaller jest z definicji) i testy (venv deweloperski), ale
    # sam modul ma dac sie zaimportowac wszedzie.
    from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader

    with tempfile.TemporaryDirectory(prefix='beatstamp-pyz-') as workdir:
        exe = Path(workdir) / EXECUTABLE
        exe.write_bytes(read_exe())
        archive = CArchiveReader(str(exe))
        pyz = Path(workdir) / 'PYZ.pyz'
        pyz.write_bytes(archive.extract('PYZ.pyz'))
        names = list(ZlibArchiveReader(str(pyz)).toc)
    return sorted({name.split('.')[0] for name in names})


def components_for_module(top_level: str) -> tuple[str, ...]:
    """Skladniki, ktorych licencje obejmuja ten pakiet z PYZ."""
    if top_level in PYZ_COMPONENTS:
        return PYZ_COMPONENTS[top_level]
    if top_level in sys.stdlib_module_names:
        return ('cpython',)
    return ()


# --- Przeglad gotowej paczki ------------------------------------------------

@dataclass
class Audit:
    """Wynik przejrzenia jednej zbudowanej paczki."""

    package: Path
    files: list[str] = field(default_factory=list)
    #: (sciezka, powod) — plik, ktorego nie powinno tu byc.
    forbidden: list[tuple[str, Excluded]] = field(default_factory=list)
    #: Sciezki bez przypisanej licencji.
    unassigned: list[str] = field(default_factory=list)
    #: klucz skladnika -> sciezki.
    assigned: dict[str, list[str]] = field(default_factory=dict)
    #: Pakiety najwyzszego poziomu znalezione w archiwum wewnatrz `.exe`.
    modules: list[str] = field(default_factory=list)
    #: Pakiety z tego archiwum, ktorych nie opisuje zaden skladnik.
    unassigned_modules: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.forbidden or self.unassigned
                    or self.unassigned_modules)


def is_package(path: Path) -> bool:
    """Czy to jest gotowa paczka BeatStampa — katalog albo plik `.msix`."""
    if path.is_dir():
        return (path / EXECUTABLE).is_file()
    if path.is_file() and path.suffix.lower() == '.msix':
        try:
            with zipfile.ZipFile(path) as archive:
                return any(normalise(name) == EXECUTABLE
                           for name in archive.namelist())
        except (OSError, zipfile.BadZipFile):
            return False
    return False


def package_files(package: Path) -> list[str]:
    """Wszystkie pliki paczki, sciezkami wzglednymi, posortowane.

    Paczka to katalog `dist/BeatStamp` albo `dist/msix` — albo gotowy plik
    `.msix`, czyli ten artefakt, ktory NAPRAWDE trafia do Sklepu. Katalog
    i archiwum moga sie rozjechac (przepakowanie jednego bez drugiego),
    a kontrola, ktora oglada tylko katalog, tego nie zobaczy.
    """
    if package.is_dir():
        return sorted(normalise(item.relative_to(package))
                      for item in package.rglob('*') if item.is_file())
    with zipfile.ZipFile(package) as archive:
        return sorted(normalise(item.filename) for item in archive.infolist()
                      if not item.is_dir())


def read_package_file(package: Path, relpath: str) -> bytes:
    """Zawartosc jednego pliku z paczki — z katalogu albo z archiwum."""
    if package.is_dir():
        return (package / relpath).read_bytes()
    with zipfile.ZipFile(package) as archive:
        wanted = normalise(relpath).lower()
        for item in archive.infolist():
            if normalise(item.filename).lower() == wanted:
                return archive.read(item)
    raise FileNotFoundError(f'{relpath} nie ma w {package}')


def audit(package: Path) -> Audit:
    """Przeglada paczke: co zakazane, co bez licencji, co do jakiego skladnika.

    Dwa przejscia, bo paczka ma dwa pietra. Pierwsze to pliki na dysku.
    Drugie to zawartosc `BeatStamp.exe`: kazdy pakiet z archiwum PYZ
    dopisuje `BeatStamp.exe` do listy plikow swojego skladnika, wiec nota
    przy reportlabie czy requests wskazuje plik, w ktorym ten kod naprawde
    lezy — zamiast przemilczec go dlatego, ze nie ma wlasnej nazwy.
    """
    result = Audit(package=package)
    for relpath in package_files(package):
        result.files.append(relpath)
        banned = excluded_reason(relpath)
        if banned is not None:
            result.forbidden.append((relpath, banned))
            continue
        keys = components_for(relpath)
        if not keys:
            result.unassigned.append(relpath)
            continue
        for key in keys:
            result.assigned.setdefault(key, []).append(relpath)

    if EXECUTABLE not in result.files:
        return result
    result.modules = pyz_packages(
        lambda: read_package_file(package, EXECUTABLE))
    for top_level in result.modules:
        keys = components_for_module(top_level)
        if not keys:
            result.unassigned_modules.append(top_level)
            continue
        for key in keys:
            paths = result.assigned.setdefault(key, [])
            if EXECUTABLE not in paths:
                paths.append(EXECUTABLE)
    for paths in result.assigned.values():
        paths.sort()
    return result


def app_version() -> str:
    """Wersja BeatStampa, czytana Z PLIKU, bez importu pakietu.

    `tools/` musi dzialac takze tam, gdzie PySide6 nie jest zainstalowane
    (a `import beatstamp` w kazdej chwili moze przestac byc niewinny).
    """
    text = (ROOT / 'beatstamp' / '__init__.py').read_text(encoding='utf-8')
    for line in text.splitlines():
        if line.startswith('__version__'):
            return line.split('=', 1)[1].strip().strip('\'"')
    return ''


def built_packages() -> list[Path]:
    """Paczki, ktore naprawde sa zbudowane (moze nie byc zadnej).

    Razem z katalogami takze gotowe pliki `.msix` z `dist/` — bo to ich
    zawartosc jedzie do Sklepu. Katalog `dist/msix` jest zrodlem, z ktorego
    `MakeAppx` sklada archiwum; zgodnosc jednego z drugim nie jest dana raz
    na zawsze i nie ma powodu sprawdzac tylko jednego z nich.
    """
    found = [path for path in PACKAGE_DIRS if is_package(path)]
    found += [path for path in sorted(MSIX_DIR.glob(MSIX_PATTERN))
              if is_package(path)]
    return found
