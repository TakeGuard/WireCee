param(
    [int]$Port = 30851,
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
    $r = Invoke-RestMethod "http://127.0.0.1:$Port/api$path" -TimeoutSec 8 -ErrorAction Stop
    if ($r -is [System.Array]) { foreach ($i in $r) { $i } } elseif ($null -ne $r) { $r }
}
function Save($json) {
    Invoke-RestMethod "http://127.0.0.1:$Port/api/settings" -Method Patch -TimeoutSec 20 `
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

if (-not (Test-Path $exe)) { throw "Not built: $exe" }

$data = Join-Path $env:TEMP "wirecee-settings-test"
Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $data | Out-Null
$hosts = Join-Path $data "hosts"
"# scratch hosts file for the WireCee settings test" | Set-Content $hosts -Encoding ASCII

$env:WIRECEE_DATA_DIR = $data
$env:WIRECEE_HOSTS_FILE = $hosts

& $exe --stop *> $null
Get-Process WireCee -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

function StartEngine {
    $p = Start-Process -FilePath $exe -ArgumentList "--headless", "--port", "$Port", "--no-elevate" `
                       -PassThru -WindowStyle Hidden
    $up = WaitFor { try { $null = Api "/status"; $true } catch { $false } } 25
    return @{ Process = $p; Up = $up }
}

Section "Engine"
$engine = StartEngine
Check "engine answers on port $Port" $engine.Up ""
if (-not $engine.Up) { throw "engine did not start" }
$status = Api "/status"
Check "reports itself as unelevated" ($status.elevated -eq $false) "elevated=$($status.elevated)"

Section "1. Settings round trip and persistence"
$wanted = @{
    notifyOnNewApp = $false; notifyOnBlock = $true; notifyOnNewDevice = $false; quietMode = $true
    alertHostsFile = $true; alertDnsChange = $false; alertProxyChange = $true
    alertRemoteAccess = $false; alertAppChange = $true; alertNotify = $false
    defaultOutbound = "ask"; defaultInbound = "block"; dnsUpstream = "quad9"
    blockEncryptedDns = $true; logRetentionDays = 9; dataLimitMb = 4096; dataResetDay = 12
}
$saved = Save ($wanted | ConvertTo-Json -Compress)
$mismatch = @($wanted.Keys | Where-Object { $saved.$_ -ne $wanted[$_] })
Check "all 17 values are accepted" ($mismatch.Count -eq 0) "differs: $($mismatch -join ', ')"

& $exe --stop *> $null
Start-Sleep -Seconds 2
$engine = StartEngine
Check "engine restarts" $engine.Up ""
$after = Api "/settings"
$lost = @($wanted.Keys | Where-Object { $after.$_ -ne $wanted[$_] })
Check "all values survive a restart" ($lost.Count -eq 0) "lost: $($lost -join ', ')"

Save '{"notifyOnNewApp":true,"quietMode":false,"defaultOutbound":"allow","defaultInbound":"allow","blockEncryptedDns":false,"dataLimitMb":0,"dnsUpstream":"system"}' | Out-Null

Section "2. Security monitoring: hosts file"
Start-Sleep -Seconds 9
$before = @(Alerts "hosts").Count
Add-Content $hosts "`n# changed by the settings test at $(Get-Date -Format o)"
$fired = WaitFor { @(Alerts "hosts").Count -gt $before } 20
Check "editing the hosts file raises an alert" $fired "no hosts alert within 20s"
if ($fired) {
    $alert = @(Alerts "hosts")[0]
    Check "the alert names the file" ($alert.detail -like "*hosts*") "detail=$($alert.detail)"
    Check "the alert is unread" ($alert.unread -eq $true) ""
}

Save '{"alertHostsFile":false}' | Out-Null
$before = @(Alerts "hosts").Count
Add-Content $hosts "`n# second change, alerting is off"
$again = WaitFor { @(Alerts "hosts").Count -gt $before } 14
Check "turning the setting off stops the alert" (-not $again) "an alert appeared with the setting off"
Save '{"alertHostsFile":true}' | Out-Null

Section "3. Security monitoring: proxy"
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$proxyServer = (Get-ItemProperty -Path $key -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
$proxyEnable = (Get-ItemProperty -Path $key -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
if ($proxyServer) {
    Skip "proxy change alert" "a proxy is configured on this account, leaving it alone"
} else {
    $before = @(Alerts "proxy").Count
    Set-ItemProperty -Path $key -Name ProxyEnable -Value 1 -Type DWord
    $fired = WaitFor { @(Alerts "proxy").Count -gt $before } 20
    Check "changing the proxy configuration raises an alert" $fired "no proxy alert within 20s"
    if ($null -ne $proxyEnable) { Set-ItemProperty -Path $key -Name ProxyEnable -Value $proxyEnable -Type DWord }
    else { Remove-ItemProperty -Path $key -Name ProxyEnable -ErrorAction SilentlyContinue }
    $restored = (Get-ItemProperty -Path $key -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
    Check "the proxy setting is put back" (("$restored" -eq "$proxyEnable") -or ($null -eq $restored)) "now=$restored was=$proxyEnable"
}

Section "3b. Windows notifications for alerts"
function Notices { @(Api "/logs?since=0" | Where-Object { $_.message -like "Notification*" }).Count }

Save '{"alertNotify":false}' | Out-Null
$alertsBefore = @(Alerts "hosts").Count
$noticesBefore = Notices
Add-Content $hosts "`n# change with notifications off"
$fired = WaitFor { @(Alerts "hosts").Count -gt $alertsBefore } 20
Check "the alert is still recorded with notifications off" $fired ""
Check "no notification is raised" ((Notices) -eq $noticesBefore) "a notification was raised anyway"

Save '{"alertNotify":true}' | Out-Null
$alertsBefore = @(Alerts "hosts").Count
$noticesBefore = Notices
Add-Content $hosts "`n# change with notifications on"
$fired = WaitFor { @(Alerts "hosts").Count -gt $alertsBefore } 20
Check "the alert is recorded with notifications on" $fired ""
$shown = WaitFor { (Notices) -gt $noticesBefore } 12
Check "a notification is handed to Windows" $shown "nothing was handed to the shell"
if ($shown) {
    $line = @(Api "/logs?since=0" | Where-Object { $_.message -like "Notification*" })[-1].message
    $systemOn = (Api "/status").notifications
    Check "the log tells the truth about whether it can be seen" `
          (($systemOn -and $line -like "Notification shown*") -or (-not $systemOn -and $line -like "*suppressed*")) `
          "notifications=$systemOn but the log says: $line"
}

Section "4. Security monitoring: application changes"
$probe = Join-Path $data "wirecee-probe.exe"
Copy-Item "$env:SystemRoot\System32\curl.exe" $probe -Force
$held = Start-Process $probe -ArgumentList "-s", "-m", "8", "telnet://1.1.1.1:443" -PassThru -WindowStyle Hidden
$known = WaitFor { @(Api "/apps" | Where-Object { $_.name -ieq "wirecee-probe.exe" }).Count -ge 1 } 20
if (-not $held.HasExited) { $held.Kill() }
Check "the probe program is seen on the network" $known "not listed in /api/apps"
if ($known) {
    Start-Sleep -Seconds 35
    $before = @(Alerts "app").Count
    Add-Content $probe ([byte[]](0x00)) -Encoding Byte
    $fired = WaitFor { @(Alerts "app").Count -gt $before } 75
    Check "modifying the executable raises an alert" $fired "no application alert within 45s"
    if ($fired) {
        Check "the alert names the program" (@(Alerts "app")[0].detail -like "*wirecee-probe.exe*") ""
    }
}

Section "5. Data usage limit"
$before = @(Alerts "data").Count
Save '{"dataLimitMb":1,"dataResetDay":1}' | Out-Null
& curl.exe -s -o NUL -m 25 "https://speed.cloudflare.com/__down?bytes=4000000" 2>$null
$fired = WaitFor { @(Alerts "data").Count -gt $before } 45
Check "passing the monthly limit raises an alert" $fired "no data alert within 30s"
if ($fired) {
    Check "the alert reports the amount used" (@(Alerts "data")[0].detail -match "\d") ""
}
$usage = Api "/usage?days=1"
Check "usage records the traffic" ($usage.rx + $usage.tx -gt 0) "rx=$($usage.rx) tx=$($usage.tx)"
Check "the billing period follows the reset day" ($usage.period.start -like "*-01") "start=$($usage.period.start)"
Save '{"dataLimitMb":0}' | Out-Null

Section "6. Log retention"
$old = Join-Path $data "logs\2020-01-01.log"
New-Item -ItemType Directory -Force (Split-Path $old) | Out-Null
"old line" | Set-Content $old
(Get-Item $old).LastWriteTime = (Get-Date).AddDays(-30)
Save '{"logRetentionDays":7}' | Out-Null
Start-Sleep -Seconds 2
Check "a log older than the retention window is deleted" (-not (Test-Path $old)) "still present"
Check "today's log is kept" ((Get-ChildItem "$data\logs\*.log").Count -ge 1) ""

Section "7. Start with Windows"
$saved = Save '{"startWithWindows":true}'
Start-Sleep -Seconds 2
$readback = Api "/settings"
Check "an unelevated engine cannot create the task and says so" ($readback.startWithWindows -eq $false) `
      "reported $($readback.startWithWindows) without administrator rights"
$logs = @(Api "/logs?since=0")
Check "the refusal is written to the log" (@($logs | Where-Object { $_.message -like "*startup entry*" }).Count -ge 1) ""

Section "8. DNS filtering"
Save '{"dnsFilter":true}' | Out-Null
Start-Sleep -Seconds 3
$dns = Api "/dns"
Check "DNS filtering refuses to claim it is active" ($dns.active -eq $false) "active=$($dns.active)"
Check "it explains why" ($dns.reason -like "*administrator*") "reason=$($dns.reason)"
Save '{"dnsFilter":false}' | Out-Null
Skip "DNS blocking end to end" "needs administrator rights"
Skip "DNS server change alert" "changing DNS servers needs administrator rights"
Skip "remote access alert" "needs an incoming Remote Desktop session"

Section "9. Blocklist and device names"
& $exe dns block settings-test.example *> $null
$device = @(Api "/devices")[0]
if ($device) {
    Invoke-RestMethod ("http://127.0.0.1:$Port/api/devices?mac=" + [uri]::EscapeDataString($device.mac) + "&name=Test%20Name") -Method Post -TimeoutSec 10 | Out-Null
}
& $exe --stop *> $null
Start-Sleep -Seconds 2
$engine = StartEngine
Check "engine restarts again" $engine.Up ""
$dns = Api "/dns"
Check "the blocked domain survives a restart" ($dns.blocklist -contains "settings-test.example") "count=$($dns.blocklistCount)"
if ($device) {
    $renamed = @(Api "/devices" | Where-Object { $_.mac -eq $device.mac })
    Check "a device name survives a restart" ($renamed.Count -eq 1 -and $renamed[0].name -eq "Test Name") "name=$($renamed[0].name)"
}
& $exe dns unblock settings-test.example *> $null

Section "10. Alerts"
Start-Sleep -Seconds 9
Add-Content $hosts "`n# change for the alert list test"
$raised = WaitFor { @(Alerts "hosts").Count -ge 1 } 20
Check "an alert is raised on demand" $raised "no alert within 20s"
Invoke-RestMethod "http://127.0.0.1:$Port/api/alerts/read" -Method Post -TimeoutSec 10 | Out-Null
Check "marking as read clears the unread flag" (@(Api "/alerts" | Where-Object { $_.unread }).Count -eq 0) ""
Check "metrics agree there is nothing unread" ((Api "/metrics").alertsUnread -eq 0) ""
Invoke-RestMethod "http://127.0.0.1:$Port/api/alerts" -Method Delete -TimeoutSec 10 | Out-Null
Check "clearing empties the list" (@(Api "/alerts").Count -eq 0) ""

if (-not $Keep) {
    Section "Teardown"
    & $exe --stop *> $null
    Start-Sleep -Seconds 2
    Check "engine stopped" (@(Get-Process WireCee -ErrorAction SilentlyContinue).Count -eq 0) ""
    Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
}
Remove-Item Env:\WIRECEE_HOSTS_FILE -ErrorAction SilentlyContinue
Remove-Item Env:\WIRECEE_DATA_DIR -ErrorAction SilentlyContinue

Write-Host "`n$script:Pass passed, $script:Fail failed, $script:Skip skipped" -ForegroundColor Cyan
exit ($(if ($script:Fail) { 1 } else { 0 }))
