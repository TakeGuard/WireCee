param(
    [switch]$SkipBuild,
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "build\out\windows"
$stage = Join-Path $root "dist\windows\WireCee"

function Find-MSBuild {
    $onPath = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
                            -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($found) { return $found }
    }
    $guess = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio" -Recurse -Filter MSBuild.exe `
             -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*Current\Bin\MSBuild.exe" } |
             Select-Object -First 1
    if ($guess) { return $guess.FullName }
    throw "MSBuild was not found. Install the Visual Studio Build Tools with the C++ workload."
}

$version = ([regex]::Match((Get-Content (Join-Path $root "src\core\version.h") -Raw), '"([^"]+)"')).Groups[1].Value
Write-Host "WireCee $version" -ForegroundColor Cyan

$running = Get-Process WireCee, WireCeeUI -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "  stopping the running engine" -ForegroundColor Yellow
    & (Join-Path $out "WireCee.exe") --stop *> $null
    Start-Sleep -Seconds 3
    Get-Process WireCee, WireCeeUI -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

if (-not $SkipBuild) {
    $msbuild = Find-MSBuild
    Write-Host "  building" -ForegroundColor Cyan
    & $msbuild (Join-Path $root "build\windows\WireCee.sln") /p:Configuration=$Configuration /p:Platform=x64 /m /v:m /nologo
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
}
if (-not (Test-Path (Join-Path $out "WireCee.exe"))) { throw "no build output in $out" }

Write-Host "  staging" -ForegroundColor Cyan
Remove-Item -Recurse -Force (Join-Path $root "dist\windows") -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null

$skip = @(".pdb", ".ilk", ".exp", ".lib", ".log")
Get-ChildItem $out -Force | Where-Object {
    $_.Name -notin @("DawnCache", "GPUCache") -and $skip -notcontains $_.Extension
} | ForEach-Object {
    Copy-Item $_.FullName -Destination $stage -Recurse -Force
}
Copy-Item (Join-Path $root "README.md") $stage
Copy-Item (Join-Path $root "LICENSE") $stage

$zip = Join-Path $root "dist\WireCee-$version-windows-x64.zip"
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Write-Host "  compressing" -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $root "dist\windows\WireCee") -DestinationPath $zip -CompressionLevel Optimal

$files = (Get-ChildItem $stage -Recurse -File).Count
$mb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host "`n$zip" -ForegroundColor Green
Write-Host "$files files, $mb MB compressed" -ForegroundColor Green
