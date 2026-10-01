# Straznik tozsamosci paczki MSIX - wywolywany przez build_msix.ps1 PRZED
# czymkolwiek innym (i przez tests/test_rebrand.py, bez budowania).
#
#   .\packaging\check_identity.ps1 -Manifest packaging\AppxManifest.xml
#
# Kod wyjscia: 0 = tozsamosc Sigelith Desktop, 1 = ODMOWA (tozsamosc albo
# nazwa BeatStampa), 2 = manifestu nie da sie odczytac.
#
# Po co osobny straznik. Od 3.0.0 program nazywa sie Sigelith Desktop i ma
# w Partner Center wlasny produkt (9P1ZQVR2MPST, Package/Identity/Name
# `AdamKoch.SigelithDesktop`). Paczka z tozsamoscia BeatStampa
# (`AdamKoch.BeatStamp`, stara rezerwacja z 2026-09-26) nalezy do innego
# produktu: Sklep jej nie przyjmie, a zainstalowana lokalnie udawalaby stary
# program. Juz raz placeholder w <Identity> dal paczke, ktora zbudowala sie
# bez bledu i byla bezuzyteczna - dlatego to jest twardy stop, a nie
# ostrzezenie. Plik jest czystym ASCII: Windows PowerShell 5.1 czyta skrypty
# bez BOM w stronie kodowej systemu.

param(
    [Parameter(Mandatory = $true)]
    [string]$Manifest
)

$ErrorActionPreference = 'Stop'

try {
    [xml]$doc = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8
} catch {
    Write-Host "BLAD: nie da sie odczytac manifestu ${Manifest}: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

$identity = $doc.Package.Identity
$name = [string]$identity.Name
$publisher = [string]$identity.Publisher
$displayName = [string]$doc.Package.Properties.DisplayName
$tileName = ''
$application = $doc.Package.Applications.Application | Select-Object -First 1
if ($application -and $application.VisualElements) {
    $tileName = [string]$application.VisualElements.DisplayName
}

$problems = @()
if (-not $name) {
    $problems += 'brak Package/Identity/Name'
}
# `-like` jest w PowerShellu niewrazliwe na wielkosc liter.
if ($name -like '*BeatStamp*') {
    $problems += "Package/Identity/Name = '$name' to tozsamosc BeatStampa (AdamKoch.BeatStamp), nie Sigelith Desktop"
}
if ($displayName -like '*BeatStamp*') {
    $problems += "Properties/DisplayName = '$displayName' to nazwa BeatStampa"
}
if ($tileName -like '*BeatStamp*') {
    $problems += "VisualElements/@DisplayName = '$tileName' to nazwa BeatStampa"
}

if ($problems.Count -gt 0) {
    Write-Host ''
    Write-Host 'ODMOWA: manifest MSIX wciaz nalezy do BeatStampa.' -ForegroundColor Red
    foreach ($problem in $problems) {
        Write-Host "  - $problem" -ForegroundColor Red
    }
    Write-Host @"

  Sigelith Desktop to osobny produkt w Partner Center (9P1ZQVR2MPST).
  Wartosci z: aplikacja -> Product management -> Product identity
  trzeba przepisac do packaging\AppxManifest.xml co do znaku:
    Package/Identity/Name                    = AdamKoch.SigelithDesktop
    Package/Identity/Publisher               = CN=322BC472-4859-4579-991B-25EE879D3796
    Package/Properties/PublisherDisplayName  = Adam Koch
  oraz DisplayName i VisualElements/@DisplayName = Sigelith Desktop.
"@ -ForegroundColor Yellow
    exit 1
}

Write-Host "  tozsamosc paczki: $name ($publisher), nazwa: $displayName" -ForegroundColor DarkGray
exit 0
