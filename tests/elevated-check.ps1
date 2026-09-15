param(
    [int]$Port = 30862,
    [switch]$Keep
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "build\out\windows\WireCee.exe"

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
    $r = Invoke-RestMethod "http://127.0.0.1:$Port/api$path" -TimeoutSec 10 -ErrorAction Stop
    if ($r -is [System.Array]) { foreach ($i in $r) { $i } } elseif ($null -ne $r) { $r }
}
function Save($json) {
    Invoke-RestMethod "http://127.0.0.1:$Port/api/settings" -Method Patch -TimeoutSec 30 `
        -ContentType "application/json" -Body $json
}
function Alerts($kind) { @(Api "/alerts" | Where-Object { $_.kind -eq $kind }) }
function WaitFor([scriptblock]$cond, [int]$seconds) {
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) {
        if (& $cond) { return $true }
        Start-Sleep -Milliseconds 900
    }
    return $false
}
function Reaches($url, $extra = @()) {
    $code = & curl.exe @extra -s -o NUL -w "%{http_code}" -m 6 $url 2>$null
    return "$code" -ne "000"
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host "This suite needs administrator rights. Start PowerShell with Run as administrator." -ForegroundColor Red
    exit 2
}
if (-not (Test-Path $exe)) { throw "Not built: $exe" }

$data = Join-Path $env:TEMP "wirecee-elevated-test"
Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $data | Out-Null
$env:WIRECEE_DATA_DIR = $data

& $exe --stop *> $null
Get-Process WireCee -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Section "Engine"
Start-Process -FilePath $exe -ArgumentList "--headless", "--port", "$Port" -WindowStyle Hidden | Out-Null
$up = WaitFor { try { $null = Api "/status"; $true } catch { $false } } 30
Check "engine answers on port $Port" $up ""
if (-not $up) { throw "engine did not start" }
$status = Api "/status"
Check "runs elevated" ($status.elevated -eq $true) "elevated=$($status.elevated)"
Check "enforcement is active" ($status.enforcement -eq "active") "reason=$($status.enforcementReason)"

Section "1. Byte counts and UDP flows"
$dl = Start-Process curl.exe -ArgumentList "-s","-o","NUL","--limit-rate","200k","-m","30",
      "https://speed.cloudflare.com/__down?bytes=20000000" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 6
$conns = @(Api "/connections")
Check "connections carry byte counts" (@($conns | Where-Object { $_.rx -gt 0 }).Count -gt 0) "none of $($conns.Count) rows"
Check "the download is attributed to curl" (@($conns | Where-Object { $_.pid -eq $dl.Id -and $_.rx -gt 100000 }).Count -ge 1) ""
Check "UDP flows are visible" (@($conns | Where-Object { $_.proto -like "UDP*" }).Count -gt 0) "no UDP rows"
Check "metrics report byte counts as available" ((Api "/metrics").bytesPerApp -eq $true) ""

Section "2. Blocking"
Check "baseline: curl reaches 1.1.1.1" (Reaches "https://1.1.1.1/" @("-4")) ""
& $exe block curl.exe *> $null
Start-Sleep -Seconds 2
Check "a blocked application is refused" (-not (Reaches "https://1.1.1.1/" @("-4"))) "curl still connected"
Check "it is refused over IPv6 too" (-not (Reaches "https://one.one.one.one/" @("-6"))) ""
& $exe allow curl.exe *> $null
Start-Sleep -Seconds 2
Check "allowing it again restores access" (Reaches "https://1.1.1.1/" @("-4")) ""

Section "3. Rules"
$rule = Invoke-RestMethod "http://127.0.0.1:$Port/api/rules" -Method Post -TimeoutSec 30 -ContentType "application/json" `
        -Body '{"name":"Elevated test block","action":"block","direction":"out","remote":"1.1.1.1","port":"any","proto":"any"}'
Start-Sleep -Seconds 2
$row = @(Api "/rules" | Where-Object { $_.name -eq "Elevated test block" })[0]
Check "the rule is created" ($null -ne $row) ""
Check "the rule blocks its address" (-not (Reaches "https://1.1.1.1/" @("-4"))) ""
Check "other addresses still work" (Reaches "https://1.0.0.1/" @("-4")) ""
Start-Sleep -Seconds 3
$hits = @(Api "/rules" | Where-Object { $_.id -eq $row.id })[0].hits
Check "the rule counts what it refused" ($hits -gt 0) "hits=$hits"
Invoke-RestMethod "http://127.0.0.1:$Port/api/rules/$($row.id)" -Method Patch -TimeoutSec 30 `
    -ContentType "application/json" -Body '{"enabled":false}' | Out-Null
Start-Sleep -Seconds 2
Check "disabling the rule stops the blocking" (Reaches "https://1.1.1.1/" @("-4")) ""
Invoke-RestMethod "http://127.0.0.1:$Port/api/rules/$($row.id)" -Method Delete -TimeoutSec 30 | Out-Null

Section "4. DNS filtering"
& $exe dns block wirecee-blocked-test.example *> $null
Save '{"dnsFilter":true}' | Out-Null
$active = WaitFor { (Api "/dns").active -eq $true } 25
Check "DNS filtering starts" $active "reason=$((Api '/dns').reason)"
if ($active) {
    $dns = Api "/dns"
    Check "it picked usable upstream servers" ($dns.upstreams.Count -ge 1) "upstreams=$($dns.upstreams -join ',')"
    Check "no site local placeholder is used as an upstream" `
          (@($dns.upstreams | Where-Object { $_ -like "fec0:*" -or $_ -like "fe80:*" }).Count -eq 0) `
          "upstreams=$($dns.upstreams -join ',')"

    $resolved = (Resolve-DnsName example.com -Server 127.0.0.1 -Type A -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
    Check "an ordinary name resolves through WireCee" ([bool]$resolved) "no answer from 127.0.0.1"

    $blocked = Resolve-DnsName wirecee-blocked-test.example -Server 127.0.0.1 -Type A -ErrorAction SilentlyContinue
    Check "a blocked domain is refused" (-not $blocked) "it answered anyway"

    $system = (Resolve-DnsName github.com -Type A -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
    Check "the system resolver still works while filtering" ([bool]$system) "system resolution broke"

    $guard = WaitFor { (Api "/dns").queries -gt 0 } 15
    Check "queries are counted" $guard ""
}
Save '{"dnsFilter":false}' | Out-Null
Start-Sleep -Seconds 3
Check "turning it off restores name resolution" `
      ([bool]((Resolve-DnsName cloudflare.com -Type A -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress)) ""
$loopback = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -contains "127.0.0.1" })
Check "no adapter is left pointing at WireCee" ($loopback.Count -eq 0) "$($loopback.InterfaceAlias -join ', ')"
& $exe dns unblock wirecee-blocked-test.example *> $null

Section "5. DNS server change alert"
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and -not $_.Virtual } | Select-Object -First 1
if (-not $adapter) {
    Skip "DNS server change alert" "no physical adapter is up"
} else {
    $original = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
    Start-Sleep -Seconds 9
    $before = @(Alerts "dns").Count
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "9.9.9.9"
    $fired = WaitFor { @(Alerts "dns").Count -gt $before } 25
    Check "changing a DNS server raises an alert" $fired "no alert within 25s"
    if ($original) { Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $original }
    else { Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses }
    $now = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
    Check "the DNS servers are put back" (("$now" -eq "$original")) "now=$now was=$original"
}

Section "6. Start with Windows"
$was = (Api "/settings").startWithWindows
Save '{"startWithWindows":true}' | Out-Null
Start-Sleep -Seconds 3
$task = Get-ScheduledTask -TaskPath "\TakeGuard\" -TaskName "WireCee" -ErrorAction SilentlyContinue
Check "the task is created" ($null -ne $task) ""
if ($task) { Check "it runs with highest privileges" ($task.Principal.RunLevel -eq "Highest") "runLevel=$($task.Principal.RunLevel)" }
Check "the setting reports it" ((Api "/settings").startWithWindows -eq $true) ""
if (-not $was) {
    Save '{"startWithWindows":false}' | Out-Null
    Start-Sleep -Seconds 3
    Check "turning it off removes the task" ($null -eq (Get-ScheduledTask -TaskPath "\TakeGuard\" -TaskName "WireCee" -ErrorAction SilentlyContinue)) ""
}

Section "7. Terminate a connection"
if (-not $dl.HasExited) {
    $row = @(Api "/connections" | Where-Object { $_.pid -eq $dl.Id -and $_.proto -eq "TCP" })[0]
    if ($row) {
        Invoke-RestMethod "http://127.0.0.1:$Port/api/connections/$($row.id)" -Method Delete -TimeoutSec 15 | Out-Null
        Start-Sleep -Seconds 3
        Check "the connection is closed" ($dl.HasExited) "curl is still running"
    } else {
        Skip "terminate a connection" "the download connection was gone already"
    }
} else {
    Skip "terminate a connection" "the download finished first"
}
if (-not $dl.HasExited) { $dl.Kill() }

Skip "remote access alert" "needs an incoming Remote Desktop session from another machine"

if (-not $Keep) {
    Section "Teardown"
    & $exe --stop *> $null
    Start-Sleep -Seconds 3
    Check "engine stopped and filters removed" (@(Get-Process WireCee -ErrorAction SilentlyContinue).Count -eq 0) ""
    Check "the network still works afterwards" (Reaches "https://1.1.1.1/" @("-4")) ""
    Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
}
Remove-Item Env:\WIRECEE_DATA_DIR -ErrorAction SilentlyContinue

Write-Host "`n$script:Pass passed, $script:Fail failed, $script:Skip skipped" -ForegroundColor Cyan
exit ($(if ($script:Fail) { 1 } else { 0 }))
