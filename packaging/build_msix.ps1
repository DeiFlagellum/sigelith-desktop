# Składa paczkę MSIX z gotowego katalogu `dist\SigelithDesktop\`.
#
# Kolejność jest wymuszona: najpierw `..\build.ps1` (testy → katalog programu
# → weryfikacja, że zbudowana aplikacja NAPRAWDĘ stempluje), dopiero potem ten
# skrypt. Pakowanie niczego nie sprawdza — zawija to, co dostanie.
#
#   .\packaging\build_msix.ps1                 → sama paczka (do wysłania do Sklepu)
#   .\packaging\build_msix.ps1 -SelfSign       → + podpis tymczasowy do testu lokalnego
#   .\packaging\build_msix.ps1 -SelfSign -Install  → + instalacja na tej maszynie
#
# Paczka wysyłana do Sklepu jest NIEPODPISANA: podpisuje ją Microsoft przy
# publikacji, własnym certyfikatem. Podpis tymczasowy (`-SelfSign`) służy
# wyłącznie do sprawdzenia paczki u siebie przed wysłaniem — Windows nie
# zainstaluje pakietu bez podpisu, więc bez tego kroku nie da się zobaczyć,
# czy aplikacja w ogóle wstaje z paczki.

param(
    [string]$Version,
    [switch]$SelfSign,
    [switch]$Install,
    [string]$CertPassword = 'sigelith-test'
)

# Patrz komentarz w ..\build.ps1: w Windows PowerShellu 5.1 `Stop` zamienia
# kazda linie na stderr programu natywnego w blad przerywajacy skrypt.
$ErrorActionPreference = 'Continue'

$Packaging = $PSScriptRoot
$Desktop = Split-Path $Packaging -Parent
Set-Location $Desktop

function Stop-Build($message) {
    Write-Host "`nBLAD: $message" -ForegroundColor Red
    exit 1
}
function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function Note($text) { Write-Host "  $text" -ForegroundColor DarkGray }

# --- Tozsamosc paczki (PRZED czymkolwiek innym) --------------------------
#
# Program nazywa sie od 3.0.0 Sigelith Desktop i ma w Partner Center WLASNY
# produkt (9P1ZQVR2MPST). Paczka z tozsamoscia BeatStampa (AdamKoch.BeatStamp)
# nalezy do innego produktu: Sklep by jej nie przyjal, a zainstalowana lokalnie
# udawalaby stary program. Wczesniej placeholder w <Identity> dal paczke, ktora
# budowala sie bez bledu i byla bezuzyteczna — dlatego tu jest TWARDY STOP,
# a nie ostrzezenie, i dzieje sie przed kasowaniem dist\msix i przed makeappx.
# Logika jest w osobnym pliku, zeby test (tests/test_rebrand.py) mogl ja
# sprawdzic bez budowania czegokolwiek.
& (Join-Path $Packaging 'check_identity.ps1') -Manifest (Join-Path $Packaging 'AppxManifest.xml')
if ($LASTEXITCODE -ne 0) {
    Stop-Build 'Tozsamosc w packaging\AppxManifest.xml nie jest tozsamoscia Sigelith Desktop (szczegoly wyzej). Paczka NIE zostala zbudowana.'
}

# --- Narzedzia -------------------------------------------------------------

function Find-SdkTool($name) {
    # Najnowsza wersja Windows SDK, jaka jest na maszynie. Kolejnosc wersji
    # sortujemy jako TEKST po znormalizowanym numerze — „10.0.9” i „10.0.26100”
    # posortowane naiwnie ustawily by sie w zlej kolejnosci.
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    ) | Where-Object { Test-Path $_ }
    $found = @()
    foreach ($root in $roots) {
        $found += Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^10\.' } |
            ForEach-Object { Join-Path $_.FullName "x64\$name" } |
            Where-Object { Test-Path $_ }
    }
    if (-not $found) {
        $inPath = Get-Command $name -ErrorAction SilentlyContinue
        if ($inPath) { return $inPath.Source }
        return $null
    }
    # Numer wersji SDK to katalog DZIADEK: <bin>\10.0.26100.0\x64\narzedzie.exe.
    return ($found | Sort-Object { [version](Split-Path (Split-Path (Split-Path $_ -Parent) -Parent) -Leaf) } |
            Select-Object -Last 1)
}

Step 'Narzedzia'
$makeappx = Find-SdkTool 'makeappx.exe'
if (-not $makeappx) {
    Stop-Build @"
Nie znaleziono makeappx.exe (Windows SDK).

Zainstaluj „Windows SDK" — wystarczy skladnik „MSIX Packaging Tools" /
„Windows SDK Signing Tools for Desktop Apps":
  winget install --id Microsoft.WindowsSDK.10.0.26100 --accept-package-agreements
albo instalator ze strony:
  https://developer.microsoft.com/windows/downloads/windows-sdk/

Narzedzie trafia do:
  C:\Program Files (x86)\Windows Kits\10\bin\<wersja>\x64\makeappx.exe
"@
}
Note "makeappx: $makeappx"

$makepri = Find-SdkTool 'makepri.exe'
if ($makepri) { Note "makepri:  $makepri" } else { Note 'makepri:  BRAK (krok pominiety)' }

$signtool = Find-SdkTool 'signtool.exe'
if ($signtool) { Note "signtool: $signtool" } else { Note 'signtool: BRAK' }

# --- Wersja ----------------------------------------------------------------

Step 'Wersja'
if (-not $Version) {
    # Zrodlem prawdy jest `__version__` w kodzie. Wersja przepisana recznie do
    # manifestu rozjezdza sie z ta w oknie „O programie" przy pierwszym
    # wydaniu, o ktorym ktos zapomni — a w Sklepie wersja jest identyfikatorem
    # wydania i nie da sie jej poprawic po wyslaniu.
    $init = Get-Content (Join-Path $Desktop 'beatstamp\__init__.py') -Raw
    if ($init -notmatch "__version__\s*=\s*'([^']+)'") {
        Stop-Build 'Nie udalo sie odczytac __version__ z beatstamp\__init__.py'
    }
    $Version = $Matches[1]
}
# Czwarty segment MUSI byc zerem — Sklep rezerwuje go dla siebie i odrzuca
# paczke z inna wartoscia.
$parts = $Version.Split('.')
while ($parts.Count -lt 3) { $parts += '0' }
$packageVersion = "$($parts[0]).$($parts[1]).$($parts[2]).0"
Note "wersja aplikacji: $Version  →  wersja paczki: $packageVersion"

# --- Zawartosc -------------------------------------------------------------

Step 'Zawartosc paczki'
$appDir = Join-Path $Desktop 'dist\SigelithDesktop'
if (-not (Test-Path (Join-Path $appDir 'SigelithDesktop.exe'))) {
    Stop-Build "Brak zbudowanej aplikacji w $appDir. Uruchom najpierw:`n  .\build.ps1"
}

$python = Join-Path $Desktop '.venv\Scripts\python.exe'
if (Test-Path $python) {
    & $python (Join-Path $Packaging 'make_logos.py')
    if ($LASTEXITCODE -ne 0) { Stop-Build 'Nie udalo sie wygenerowac logo.' }
} elseif (-not (Test-Path (Join-Path $Packaging 'Assets\StoreLogo.png'))) {
    Stop-Build 'Brak srodowiska .venv i brak gotowych logo w packaging\Assets.'
}

$layout = Join-Path $Desktop 'dist\msix'
if (Test-Path $layout) { Remove-Item $layout -Recurse -Force }
New-Item -ItemType Directory -Path $layout | Out-Null

Copy-Item (Join-Path $appDir '*') $layout -Recurse -Force
Copy-Item (Join-Path $Packaging 'Assets') $layout -Recurse -Force

# Manifest kopiujemy z podmieniona wersja — szablon w repozytorium zostaje
# nietkniety.
$manifestSource = Join-Path $Packaging 'AppxManifest.xml'
$manifest = Get-Content $manifestSource -Raw -Encoding UTF8
$manifest = [regex]::Replace($manifest, '(<Identity[\s\S]*?Version=")[^"]*(")',
                             "`${1}$packageVersion`${2}")
$manifestTarget = Join-Path $layout 'AppxManifest.xml'
[System.IO.File]::WriteAllText($manifestTarget, $manifest, (New-Object System.Text.UTF8Encoding $false))

$identityName = if ($manifest -match '<Identity[\s\S]*?Name="([^"]*)"') { $Matches[1] } else { '' }
$publisher = if ($manifest -match '<Identity[\s\S]*?Publisher="([^"]*)"') { $Matches[1] } else { '' }
Note "Identity Name: $identityName"
Note "Publisher:     $publisher"

$placeholder = ($identityName -like '*PLACEHOLDER*') -or ($publisher -like '*PLACEHOLDER*')
if ($placeholder) {
    Write-Host @"

  UWAGA: manifest wciaz ma PLACEHOLDERY tozsamosci.
  Paczka zbuduje sie i da zainstalowac lokalnie (z podpisem tymczasowym),
  ale Sklep JEJ NIE PRZYJMIE. Wartosci sa w Partner Center:
    aplikacja → Product management → Product identity
  i trzeba je przepisac do packaging\AppxManifest.xml co do znaku.
"@ -ForegroundColor Yellow
}

$files = (Get-ChildItem $layout -Recurse -File | Measure-Object).Count
$sizeMB = [math]::Round((Get-ChildItem $layout -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
Note "uklad paczki: $files plikow, $sizeMB MB"

# --- Zasoby (PRI) ----------------------------------------------------------

if ($makepri) {
    Step 'Indeks zasobow (resources.pri)'
    # Logo maja w nazwach kwalifikatory skali (`.scale-200`) i rozmiaru
    # docelowego (`.targetsize-32`). Windows wybiera miedzy nimi PRZEZ indeks
    # zasobow — bez `resources.pri` widzi tylko warianty bez kwalifikatora
    # i kazdy kafelek dostaje obrazek w skali 100%, przeskalowany przez system.
    $priConfig = Join-Path $layout 'priconfig.xml'
    & $makepri createconfig /cf $priConfig /dq 'en-US_pl-PL_de-DE_es-ES_fr-FR_ru-RU_tr-TR_ja-JP_ko-KR_zh-CN_ar-SA' /o | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Build 'makepri createconfig zakonczylo sie bledem.' }
    # Jeden resources.pri ze WSZYSTKIMI skalami i tylko z katalogu Assets.
    # Domyslna konfiguracja ma sekcje <packaging>, ktora rozdziela warianty
    # skali do resources.scale-*.pri — to uklad dla pakietow zasobow
    # w bundlach; w pojedynczej paczce .msix system moze ich nie dolaczyc
    # i kafelki przy 200% dostawaly obrazek 100%. Indeks zostaje od korzenia
    # paczki: `startIndexAt="Assets"` gubil prefiks — zasoby nazywaly sie
    # Files/X.png, a manifest odwoluje sie do Assets\X.png (sprawdzone
    # `makepri dump`, 2026-09-27).
    [xml]$pri = Get-Content -Path $priConfig -Raw
    $packaging = $pri.SelectSingleNode('/resources/packaging')
    if ($packaging) { [void]$pri.DocumentElement.RemoveChild($packaging) }
    $pri.Save($priConfig)
    & $makepri new /pr $layout /cf $priConfig /of (Join-Path $layout 'resources.pri') /o | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Build 'makepri new zakonczylo sie bledem.' }
    Remove-Item $priConfig -Force
    $split = Get-ChildItem $layout -Filter 'resources.*.pri' -File
    if ($split) { Stop-Build "makepri rozdzielil zasoby: $($split.Name -join ', ')" }
    Note 'resources.pri zbudowany'
} else {
    Write-Host '  makepri nie znaleziony — paczka bez resources.pri.' -ForegroundColor Yellow
    Write-Host '  Zainstaluje sie i zadziala, ale kafelki uzyja logo w skali 100%.' -ForegroundColor Yellow
}

# --- Pakowanie -------------------------------------------------------------

Step 'Pakowanie'
$msix = Join-Path $Desktop "dist\SigelithDesktop-$packageVersion-x64.msix"
if (Test-Path $msix) { Remove-Item $msix -Force }
& $makeappx pack /d $layout /p $msix /o
if ($LASTEXITCODE -ne 0) { Stop-Build 'makeappx pack zakonczylo sie bledem.' }
$msixMB = [math]::Round((Get-Item $msix).Length / 1MB, 1)
Write-Host "Zbudowano: $msix ($msixMB MB)" -ForegroundColor Green

# --- Podpis tymczasowy -----------------------------------------------------

if ($SelfSign) {
    Step 'Podpis tymczasowy (TYLKO do testu lokalnego)'
    if (-not $signtool) {
        Stop-Build @"
Nie znaleziono signtool.exe. To ten sam Windows SDK co makeappx — skladnik
„Windows SDK Signing Tools for Desktop Apps".
"@
    }
    # Certyfikat MUSI miec `Subject` identyczny z `Publisher` z manifestu.
    # Windows porownuje te dwa napisy ZNAK PO ZNAKU i przy najmniejszej
    # roznicy odmawia instalacji komunikatem o „niezgodnosci wydawcy",
    # ktory nie mowi, ktora strona jest zla.
    $local = Join-Path $Packaging '_local'
    New-Item -ItemType Directory -Path $local -Force | Out-Null
    $pfx = Join-Path $local 'SigelithDesktop-test.pfx'
    $cer = Join-Path $local 'SigelithDesktop-test.cer'

    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $publisher -and $_.FriendlyName -eq 'Sigelith Desktop test (self-signed)' } |
        Select-Object -First 1
    if (-not $existing) {
        Note "tworze certyfikat testowy dla Subject: $publisher"
        $existing = New-SelfSignedCertificate `
            -Type Custom -Subject $publisher `
            -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
            -FriendlyName 'Sigelith Desktop test (self-signed)' `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}Subject Type:End Entity')
    } else {
        Note 'uzywam istniejacego certyfikatu testowego'
    }
    $secure = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
    Export-PfxCertificate -Cert $existing -FilePath $pfx -Password $secure | Out-Null
    Export-Certificate -Cert $existing -FilePath $cer | Out-Null

    & $signtool sign /fd SHA256 /a /f $pfx /p $CertPassword $msix
    if ($LASTEXITCODE -ne 0) { Stop-Build 'signtool zakonczyl sie bledem.' }
    Write-Host "Podpisano paczke certyfikatem TESTOWYM." -ForegroundColor Green
    Write-Host @"

  Certyfikat testowy: $cer
  Zeby Windows przyjal paczke, ten certyfikat musi byc zaufany NA TEJ MASZYNIE.
  W oknie PowerShell URUCHOMIONYM JAKO ADMINISTRATOR:

    Import-Certificate -FilePath "$cer" -CertStoreLocation Cert:\LocalMachine\TrustedPeople

  Potem (juz bez administratora):

    Add-AppxPackage "$msix"

  Odinstalowanie:

    Get-AppxPackage *SigelithDesktop* | Remove-AppxPackage

  UWAGA: certyfikat testowy NIE MA nic wspolnego z paczka wysylana do Sklepu.
  Do Sklepu idzie plik NIEPODPISANY — Microsoft podpisuje go sam. Przed
  wyslaniem zbuduj paczke jeszcze raz BEZ `-SelfSign`.
"@ -ForegroundColor DarkGray

    if ($Install) {
        Step 'Instalacja'
        $trusted = Get-ChildItem Cert:\LocalMachine\TrustedPeople -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $existing.Thumbprint }
        if (-not $trusted) {
            Write-Host '  Certyfikat nie jest jeszcze zaufany — zaimportuj go jako administrator (komenda wyzej).' -ForegroundColor Yellow
        }
        Add-AppxPackage -Path $msix
        if (-not $?) { Stop-Build 'Add-AppxPackage nie powiodlo sie.' }
        Write-Host 'Zainstalowano. Aplikacja jest w menu Start jako „Sigelith Desktop".' -ForegroundColor Green
    }
}

Step 'Gotowe'
Write-Host $msix -ForegroundColor Green
if ($placeholder) {
    Write-Host 'Do Sklepu: NIE — manifest ma placeholdery tozsamosci.' -ForegroundColor Yellow
}
