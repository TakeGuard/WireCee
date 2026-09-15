param(
    [int]$Port = 30850,
    [string]$Probe = "1.1.1.1",
    [switch]$Keep
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "build\out\windows\WireCee.exe"

$script:Pass = 0; $script:Fail = 0; $script:Skip = 0

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Check($name, $ok, $detail) {
    if ($ok) { Write-Host "  PASS  $name" -ForegroundColor Green; $script:Pass++ }
    else {
        Write-Host "  FAIL  $name" -ForegroundColor Red
        if ($detail) { Write-Host "        $detail" -ForegroundColor DarkGray }
        $script:Fail++
    }
}
function Skip($name, $why) { Write-Host "  SKIP  $name ($why)" -ForegroundColor Yellow; $script:Skip++ }
function Api($path) {
    $r = Invoke-RestMethod "http://127.0.0.1:$Port$path" -TimeoutSec 5 -ErrorAction Stop
    if ($r -is [System.Array]) { foreach ($item in $r) { $item } }
    elseif ($null -ne $r) { $r }
}

if (-not (Test-Path $exe)) { throw "Not built: $exe" }

& $exe --stop *> $null
Get-Process WireCee, WireCeeUI -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$env:WIRECEE_DATA_DIR = Join-Path $env:TEMP "wirecee-cli-test"
New-Item -ItemType Directory -Force $env:WIRECEE_DATA_DIR | Out-Null
foreach ($inst in @((Join-Path $env:WIRECEE_DATA_DIR "instance.port"),
                    (Join-Path $env:ProgramData "TakeGuard\WireCee\instance.port"))) {
    if (Test-Path $inst) { [System.IO.File]::Delete($inst) }
}
Start-Sleep -Milliseconds 700

$client = New-Object System.Net.Sockets.TcpClient
$online = $false
try { $client.Connect($Probe, 443); $online = $client.Connected } catch { }
$me = (Get-Process -Id $PID).ProcessName + ".exe"

Section "Start the engine (headless)"
Get-ChildItem $env:WIRECEE_DATA_DIR -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
$proc = Start-Process -FilePath $exe -ArgumentList "--headless", "--port", "$Port", "--no-elevate" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3
Check "engine process is alive" (-not $proc.HasExited) "exited immediately"
$status = Api "/api/status"
Check "GET /api/status answers" ($status.engine -eq "online") "engine=$($status.engine)"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin) {
    Check "reports enforcement as active (elevated)" ($status.enforcement -eq "active") "enforcement=$($status.enforcement)"
} else {
    Check "reports enforcement as unavailable (not elevated)" ($status.enforcement -eq "unavailable") "enforcement=$($status.enforcement)"
}

Section "1. Live connections  (wirecee connections)"
$connText = & $exe connections
$connText | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
Check "text listing has a header" (($connText -join "`n") -cmatch "PROCESS") ""
$conns = @(Api "/api/connections")
Check "JSON listing parses" ($null -ne $conns) ""

if ($online) {
    $mine = @($conns | Where-Object { $_.pid -eq $PID -and $_.remoteIp -eq $Probe -and $_.remotePort -eq 443 })
    Check "sees this test's own connection to ${Probe}:443" ($mine.Count -ge 1) "not in $($conns.Count) rows"
    if ($mine.Count) {
        Check "attributes it to $me" ($mine[0].process -ieq $me) "process=$($mine[0].process)"
        Check "reports the real TCP state" ($mine[0].state -eq "ESTABLISHED") "state=$($mine[0].state)"
        Check "carries byte counters" ($null -ne $mine[0].rx -and $null -ne $mine[0].tx) "rx=$($mine[0].rx)"
    }
} else {
    Skip "own-connection checks" "no outbound connection to ${Probe}:443"
}

$os = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0$|::$)' })
$engineKeys = @{}
foreach ($c in $conns) { if ($c.state -eq "ESTABLISHED") { $engineKeys["$($c.pid)|$($c.remotePort)"] = 1 } }
$matched = @($os | Where-Object { $engineKeys.ContainsKey("$($_.OwningProcess)|$($_.RemotePort)") }).Count
if ($os.Count -gt 0) {
    $ratio = $matched / $os.Count
    Check ("agrees with Get-NetTCPConnection ({0}/{1} established)" -f $matched, $os.Count) ($ratio -ge 0.8) `
          "connections open and close between the two reads; 80% is the bar"
} else {
    Skip "Get-NetTCPConnection cross-check" "no established connections"
}

Section "2. Applications  (wirecee apps)"
& $exe apps | Select-Object -First 12 | ForEach-Object { Write-Host "  $_" }
$appsBefore = @(Api "/api/apps")
$target = if ($online) { $me } else { ($appsBefore | Sort-Object connections -Descending | Select-Object -First 1).name }
Check "has a program to test with ($target)" ([bool]$target) "no applications at all"
Check "blocked list starts empty" (@(Api "/api/apps?policy=block").Count -eq 0) ""

Section "3. Block a program  (wirecee block $target)"
& $exe block $target | ForEach-Object { Write-Host "  $_" }
Check "block command exits 0" ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"

Section "4. Applications again, and the blocked list"
& $exe apps --blocked | ForEach-Object { Write-Host "  $_" }
$appsAfter = @(Api "/api/apps")
$blocked = @(Api "/api/apps?policy=block")
Check "$target is recorded as blocked" ((@($appsAfter | Where-Object { $_.name -ieq $target })[0]).policy -eq "block") ""
Check "blocked list is exactly $target" ($blocked.Count -eq 1 -and $blocked[0].name -ieq $target) "count=$($blocked.Count)"
Check "no other program changed" (@($appsAfter | Where-Object { $_.policy -eq "block" }).Count -eq 1) ""

Section "5. Blocking is recorded, not faked"
$metrics = Api "/api/metrics"
Check "metrics report enforcement $(if ($admin) { 'on' } else { 'off' })" ($metrics.enforcement -eq $admin) "enforcement=$($metrics.enforcement)"
if ($online) {
    Start-Sleep -Seconds 2
    $still = @((Api "/api/connections") | Where-Object { $_.pid -eq $PID -and $_.remoteIp -eq $Probe -and $_.state -eq "ESTABLISHED" })
    if ($admin) {
        Check "own connection was cut by the block" ($still.Count -eq 0) "the connection is still established"
    } else {
        Check "own connection is still open" ($still.Count -ge 1) `
              "a policy must not be shown as enforced when nothing enforces it"
    }
}

Section "6. New application detection"
if ($online -and (Test-Path "$env:SystemRoot\System32\curl.exe")) {
    $curl = Start-Process -FilePath "$env:SystemRoot\System32\curl.exe" `
            -ArgumentList "-s", "-m", "6", "telnet://${Probe}:443" -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 4
    $logs = @(Api "/api/logs?since=0")
    $announced = @($logs | Where-Object { $_.message -like "New application on the network: curl.exe*" })
    Check "curl.exe started after the engine is announced as new" ($announced.Count -ge 1) ""
    Check "programs already running are not announced" `
          (@($logs | Where-Object { $_.message -like "New application on the network: $me*" }).Count -eq 0) ""
    if (-not $curl.HasExited) { $curl.Kill() }
} else {
    Skip "new-application detection" "needs outbound internet and curl.exe"
}

Section "7. CLI and GUI agree"
$cliText = (& $exe apps --blocked) -join "`n"
Check "CLI text names $target" ($cliText -match [regex]::Escape($target)) ""
Check "GUI JSON names $target" ((@(Api "/api/apps?policy=block"))[0].name -ieq $target) ""
$r1 = Invoke-WebRequest "http://127.0.0.1:$Port/api/settings" -UseBasicParsing -TimeoutSec 5
try {
    $r2 = Invoke-WebRequest "http://127.0.0.1:$Port/api/settings" -UseBasicParsing `
          -Headers @{ "If-None-Match" = $r1.Headers.ETag } -TimeoutSec 5
    $code = $r2.StatusCode
} catch { $code = $_.Exception.Response.StatusCode.value__ }
Check "unchanged settings revalidate to 304" ($code -eq 304) "got $code"

Section "8. Unblock and error handling"
& $exe allow $target | ForEach-Object { Write-Host "  $_" }
Check "blocked list is empty again" (@(Api "/api/apps?policy=block").Count -eq 0) ""
& $exe block "definitely-not-a-real-program.exe" *> $null
Check "unknown program exits non-zero" ($LASTEXITCODE -ne 0) "exit=$LASTEXITCODE"

$settings = Api "/api/settings"
Check "notifyOnBlock defaults off" ($settings.notifyOnBlock -eq $false) ""
Check "DNS filtering defaults off" ($settings.dnsFilter -eq $false) ""
Check "settings expose the data plan" ($settings.dataResetDay -ge 1 -and $null -ne $settings.dataLimitMb) ""

Section "9. Usage, devices, alerts and DNS"
$usage = Api "/api/usage?days=7"
Check "usage reports one entry per day" ($usage.days.Count -eq 7) "days=$($usage.days.Count)"
Check "usage reports a billing period" ($null -ne $usage.period.start) ""
$devices = @(Api "/api/devices")
Check "device list answers" ($null -ne $devices) ""
$alerts = @(Api "/api/alerts")
Check "alert list answers" ($null -ne $alerts) ""
$dnsState = Api "/api/dns"
Check "DNS reports itself as off" ($dnsState.active -eq $false -and $dnsState.enabled -eq $false) "active=$($dnsState.active)"

& $exe dns block wirecee-test.example *> $null
Check "dns block exits 0" ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
$dnsState = Api "/api/dns"
Check "the domain is on the blocklist" ($dnsState.blocklist -contains "wirecee-test.example") "count=$($dnsState.blocklistCount)"
& $exe dns unblock wirecee-test.example *> $null
$dnsState = Api "/api/dns"
Check "the domain is removed again" (-not ($dnsState.blocklist -contains "wirecee-test.example")) ""

$textUsage = (& $exe usage --days 3) -join "`n"
Check "usage renders a text table for the CLI" ($textUsage -cmatch "DOWNLOAD") ""

$client.Close()
if (-not $Keep) {
    Section "Teardown"
    & $exe --stop *> $null
    Start-Sleep -Seconds 2
    Check "engine stopped cleanly" (@(Get-Process WireCee -ErrorAction SilentlyContinue).Count -eq 0) ""
}

Write-Host ""
Write-Host ("{0} passed, {1} failed, {2} skipped" -f $script:Pass, $script:Fail, $script:Skip) `
    -ForegroundColor $(if ($script:Fail) { "Red" } else { "Green" })
exit $(if ($script:Fail) { 1 } else { 0 })
