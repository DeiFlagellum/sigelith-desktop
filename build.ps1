# Pełna kompilacja Sigelith Desktop: testy → katalog programu → weryfikacja.
#
# Wynikiem jest KATALOG `dist\SigelithDesktop\`, nie pojedynczy plik. Powód jest
# w nagłówku `beatstamp.spec` (punkt 0): plik jednoplikowy rozpakowuje się
# przy każdym starcie do `%TEMP%`, a Smart App Control w Windows 11 blokuje
# uruchamianie niepodpisanych plików — podpis paczki MSIX obejmuje zawartość
# paczki, a nie to, co aplikacja wypakuje sobie potem do katalogu tymczasowego.
#
# Trzeci krok nie jest ozdobą. Testy jednostkowe działają na kodzie ŹRÓDŁOWYM
# i z definicji nie widzą usterek, które powstają dopiero przy pakowaniu:
# wykluczony moduł, niedołączony zasób, magazyn CA, którego `certifi` nie
# odnajduje w paczce. Pierwsza kompilacja tego projektu zakończyła się kodem 0
# i dała plik, który nie uruchamiał się wcale — dlatego `tools/verify_exe.py`
# startuje zbudowaną aplikację i sprawdza, czy naprawdę ostemplowała plik.
#
#   .\build.ps1                → testy + kompilacja + weryfikacja
#   .\build.ps1 -SkipTests     → sama kompilacja + weryfikacja
#   .\build.ps1 -SkipVerify    → bez uruchamiania gotowej aplikacji (bez sieci)
#   .\build.ps1 -Python <sciezka\python.exe>
#                              → inne srodowisko niz .venv (np. probne, gdy
#                                .venv trzyma otwarte VS Code)
#
# Paczka MSIX dla Microsoft Store powstaje osobno, z gotowego katalogu:
#   .\packaging\build_msix.ps1

param(
    [switch]$SkipTests,
    [switch]$SkipVerify,
    [string]$Python = ''
)

# UWAGA: NIE ustawiamy tu `$ErrorActionPreference = 'Stop'`. W Windows
# PowerShellu 5.1 kazda linia, ktora program natywny wypisze na stderr, staje
# sie wtedy bledem przerywajacym skrypt — a testy i PyInstaller pisza tam
# zwykle komunikaty postepu. Poprawny przebieg konczyl sie przez to
# „bledem". Jedynym wiarygodnym sygnalem jest kod wyjscia.
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot

function Stop-Build($message) {
    Write-Host "`nBLAD: $message" -ForegroundColor Red
    exit 1
}

$python = if ($Python) { $Python } else { Join-Path $PSScriptRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path $python)) {
    Stop-Build "Brak srodowiska .venv. Utworz je:`n  py -3.14 -m venv .venv`n  .venv\Scripts\python.exe -m pip install -r requirements-dev.txt"
}
# HTTPS w programie idzie przez OpenSSL z wydania CPythona. Python 3.14.0-3.14.3
# (i caly 3.12) maja OpenSSL 3.0, bez wsparcia od 2026-09-07 — taka paczka
# nie moze trafic do uzytkownikow, wiec budowanie konczy sie tu, a nie po
# wydaniu.
$pyCheck = & $python -c "import ssl, sys; v = ssl.OPENSSL_VERSION_INFO; print('ok' if sys.version_info[:2] == (3, 14) and v[:2] >= (3, 5) else f'Python {sys.version.split()[0]}, {ssl.OPENSSL_VERSION}')"
if ($pyCheck -ne 'ok') {
    Stop-Build "Srodowisko $python ma $pyCheck. Wymagany Python 3.14 z OpenSSL >= 3.5 (3.14.7 lub nowszy):`n  py install --update 3.14`n  py -3.14 -m venv .venv --clear`n  .venv\Scripts\python.exe -m pip install -r requirements-dev.txt"
}

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

if (-not $SkipTests) {
    Step 'Testy'
    $env:QT_QPA_PLATFORM = 'offscreen'
    & $python -m unittest discover -s tests
    if ($LASTEXITCODE -ne 0) { Stop-Build 'Testy nie przeszly - kompilacja przerwana.' }
    Remove-Item Env:\QT_QPA_PLATFORM -ErrorAction SilentlyContinue
}

Step 'Katalogi tlumaczen'
# Pliki .mo sa w repozytorium (tak jak w locale/ serwera), ale przebudowujemy
# je przed kazdym wydaniem: .po zmieniony bez rekompilacji daje paczke ze
# STARYM tlumaczeniem, a roznica jest niewidoczna az do uruchomienia.
& $python tools\compile_catalogs.py
if ($LASTEXITCODE -ne 0) { Stop-Build 'Nie udalo sie skompilowac katalogow tlumaczen.' }

Step 'Kompilacja'
# Dzialajaca instancja trzyma plik .exe i PyInstaller konczy sie
# „Odmowa dostepu". Przebudowa przy otwartej aplikacji jest sytuacja
# normalna, wiec zamykamy ja sami zamiast kazac to robic recznie.
# TYLKO kopie uruchomiona z dist\SigelithDesktop — to jej pliki nadpisujemy.
# Do 2026-09-27 skrypt zamykal SILA kazda kopie programu, takze zwykla kopie
# uzytkownika (np. z Pulpitu) w trakcie pracy.
$distExe = Join-Path $PSScriptRoot 'dist\SigelithDesktop\SigelithDesktop.exe'
Get-Process SigelithDesktop -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and ($_.Path -ieq $distExe) } |
    ForEach-Object {
        Write-Host "zamykam instancje z dist (PID $($_.Id))"
        Stop-Process -Id $_.Id -Force
    }
Start-Sleep -Milliseconds 400

# Pozostalosc po trybie jednoplikowym (BeatStamp 2.1). Gdyby zostala, `dist\` zawieraloby
# JEDNOCZESNIE stary plik i nowy katalog — a skrypt pakujacy MSIX albo
# czlowiek szukajacy „tego .exe" trafilby na wydanie sprzed zmiany.
$legacy = Join-Path $PSScriptRoot 'dist\BeatStamp.exe'
if (Test-Path $legacy) {
    Write-Host 'usuwam pozostalosc po trybie jednoplikowym: dist\BeatStamp.exe'
    Remove-Item $legacy -Force
}

& $python -m PyInstaller --noconfirm --clean beatstamp.spec
if ($LASTEXITCODE -ne 0) { Stop-Build 'PyInstaller zakonczyl sie bledem.' }

$appDir = Join-Path $PSScriptRoot 'dist\SigelithDesktop'
$exe = Join-Path $appDir 'SigelithDesktop.exe'
if (-not (Test-Path $exe)) { Stop-Build "PyInstaller nie zostawil pliku $exe" }

function Get-DirSizeMB($path) {
    $bytes = (Get-ChildItem $path -Recurse -File | Measure-Object -Property Length -Sum).Sum
    return [math]::Round($bytes / 1MB, 1)
}
$size = Get-DirSizeMB $appDir
$files = (Get-ChildItem $appDir -Recurse -File | Measure-Object).Count

# Kontrola zasobow PRZED uruchomieniem: brak katalogu tlumaczen albo magazynu
# CA to awaria, ktora w gotowej aplikacji objawia sie dopiero po starcie —
# raz jako interfejs uparcie angielski, raz jako kazde polaczenie HTTPS
# odrzucone. Tutaj widac ja od razu i z nazwy.
$internal = Join-Path $appDir '_internal'
$required = @(
    @{ Path = 'beatstamp.ico';                          What = 'ikona aplikacji' },
    @{ Path = 'certifi\cacert.pem';                     What = 'magazyn CA (certifi)' },
    @{ Path = 'licenses\NOTICE';                        What = 'noty licencyjne' },
    @{ Path = 'fonts\Inter-Regular.ttf';                What = 'czcionka interfejsu i certyfikatu (Inter)' },
    @{ Path = 'fonts\JetBrainsMono-Regular.ttf';        What = 'czcionka skrotow i zegara (JetBrains Mono)' },
    @{ Path = 'icons\fingerprint.svg';                  What = 'ikony interfejsu (Bootstrap Icons)' },
    @{ Path = 'licenses\LGPL-3.0.txt';                  What = 'tekst LGPL v3 (wymog par. 4(c))' },
    @{ Path = 'licenses\GPL-3.0.txt';                   What = 'tekst GPL v3 (LGPL odwoluje sie do niego)' }
)
# Katalog tlumaczen dla KAZDEGO jezyka z `i18n.SUPPORTED` (poza zrodlowym
# angielskim) — lista z kodu, zeby nowy jezyk nie mogl wypasc z paczki po cichu.
$languages = & $python -c "from beatstamp import i18n; print(' '.join(c for c in i18n.SUPPORTED if c != i18n.SOURCE_LANGUAGE))"
if ($LASTEXITCODE -ne 0 -or -not $languages) { Stop-Build 'nie udalo sie odczytac listy jezykow z beatstamp/i18n.py' }
foreach ($code in ($languages -split ' ')) {
    $required += @{ Path = "locale\$code\LC_MESSAGES\beatstamp.mo"; What = "katalog tlumaczen: $code" }
}
foreach ($item in $required) {
    if (-not (Test-Path (Join-Path $internal $item.Path))) {
        Stop-Build "w paczce brakuje zasobu: $($item.What) (_internal\$($item.Path))"
    }
}
Write-Host "zasoby w _internal\: ikona, magazyn CA, tlumaczenia ($languages), licencje" -ForegroundColor DarkGray

Write-Host "Zbudowano: $appDir ($size MB, $files plikow)" -ForegroundColor Green

Step 'Noty licencyjne'
# Noty sa GENEROWANE z gotowej paczki (`tools/licenses.py` -> `NOTICE`), wiec
# kazda zmiana zaleznosci je uniewaznia. Plik not, ktory nie zgadza sie z tym,
# co naprawde lezy w paczce, klamie CICHO: nic sie nie psuje, testy jednostkowe
# sa zielone, a wydanie zawiera skladnik, o ktorym nie napisano ani slowa.
# Dlatego sprawdzamy to tutaj, a nie „przy okazji".
#
# Niezgodnosc naprawia sie w dwoch krokach, w tej kolejnosci:
#   .venv\Scripts\python.exe tools\make_notice.py    (nowe noty)
#   .\build.ps1                                      (paczka z nowymi notami)
& $python tools\make_notice.py --check
if ($LASTEXITCODE -ne 0) {
    Stop-Build "NOTICE rozjechal sie z paczka. Uruchom:`n  .venv\Scripts\python.exe tools\make_notice.py`n  .\build.ps1"
}

if (-not $SkipVerify) {
    Step 'Weryfikacja zbudowanej aplikacji (wymaga internetu)'
    & $python tools\verify_exe.py $exe
    if ($LASTEXITCODE -ne 0) { Stop-Build 'Zbudowana aplikacja NIE PRZESZLA weryfikacji.' }
}

Step 'Gotowe'
Write-Host "dist\SigelithDesktop\ — $size MB w $files plikach" -ForegroundColor Green
Write-Host "Paczka dla Sklepu: .\packaging\build_msix.ps1" -ForegroundColor DarkGray
