# ==========================================================================
#  LogBok.AppLogs.psm1 - تحلیلِ لاگِ اپلیکیشن: Apache و DHCP
#  (IIS و SQL از قبل در Detectors هستند.) این‌ها لاگِ فایل‌محور را می‌خوانند و
#  خطا/حملهٔ احتمالی را به‌صورت یافته برمی‌گردانند. روی سروری اجرا می‌شوند که
#  لاگ را دارد یا مسیرِ UNC در دسترس است.
# ==========================================================================

# --- Apache access/error log ---------------------------------------------
#  حملهٔ وب: سیلِ خطای 4xx از یک IP در access log (combined/common format)
function Invoke-DetectApache {
    param($Config,[datetime]$Start)
    $f = @()
    if (-not $Config.ApacheServers) { return $f }
    $th = if ($Config.Thresholds.IISErrorPerWindow) { [int]$Config.Thresholds.IISErrorPerWindow } else { 50 }
    foreach ($srv in @($Config.ApacheServers)) {
        $base = $Config.ApacheLogPath
        if (-not $base) { continue }
        if ($srv -ne 'localhost' -and $srv -ne $env:COMPUTERNAME) { $base = "\\$srv\" + ($base -replace ':','$') }
        if (-not (Test-Path $base)) { continue }
        $logs = Get-ChildItem -Path $base -Recurse -Include '*access*.log','*access_log' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Start.AddHours(-1) }
        $byIp=@{}
        foreach ($lf in $logs) {
            try { $lines = Get-Content $lf.FullName -Tail 4000 -ErrorAction Stop } catch { continue }
            foreach ($ln in $lines) {
                # فرمتِ combined:  IP - - [10/Oct/2026:13:55:36 +0330] "GET /x" 404 123 ...
                if ($ln -match '^(\S+) \S+ \S+ \[([^\]]+)\] "[^"]*" (\d{3})') {
                    $ip=$Matches[1]; $ts=$Matches[2]; $st=[int]$Matches[3]
                    # فقط خطوطِ داخلِ بازهٔ زمانی (قبلاً ۴۰۰۰ خطِ آخر بدونِ توجه به زمان شمرده می‌شد)
                    $tsn = $ts -replace '([+-]\d{2})(\d{2})$','$1:$2'
                    $dto = [DateTimeOffset]::MinValue
                    if ([DateTimeOffset]::TryParseExact($tsn, 'dd/MMM/yyyy:HH:mm:ss zzz', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$dto)) {
                        if ($dto.LocalDateTime -lt $Start) { continue }
                    }
                    if ($st -ge 400 -and $st -lt 500) { if(-not $byIp.ContainsKey($ip)){$byIp[$ip]=0}; $byIp[$ip]++ }
                }
            }
        }
        foreach ($ip in $byIp.Keys) { if ($byIp[$ip] -ge $th) {
            $f += [pscustomobject]@{ Category='AppLog'; Severity='Critical'; Machine=$srv; Time=(Get-Date)
                Title=("حملهٔ احتمالی به Apache — {0} خطای 4xx از {1} | possible Apache attack — {0} 4xx errors from {1}" -f $byIp[$ip],$ip)
                Details=("سرور: {0} | مبدأ: {1} | خطای 4xx در بازه: {2}" -f $srv,$ip,$byIp[$ip]); Key=("APACHE|{0}|{1}" -f $srv,$ip) }
        } }
    }
    return $f
}

# --- DHCP server log (Windows DHCP: C:\Windows\System32\dhcp\*.log) -------
#  رویدادهای مهم: کمبودِ آدرس (14), رد شدن (15/16), و خطاها.
function Invoke-DetectDhcp {
    param($Config,[datetime]$Start)
    $f = @()
    if (-not $Config.DhcpServers) { return $f }
    foreach ($srv in @($Config.DhcpServers)) {
        $base = if ($Config.DhcpLogPath) { $Config.DhcpLogPath } else { 'C:\Windows\System32\dhcp' }
        if ($srv -ne 'localhost' -and $srv -ne $env:COMPUTERNAME) { $base = "\\$srv\" + ($base -replace ':','$') }
        if (-not (Test-Path $base)) { continue }
        $today = 'DhcpSrvLog-' + (Get-Date).DayOfWeek.ToString().Substring(0,3)
        $lf = Join-Path $base "$today.log"
        if (-not (Test-Path $lf)) { continue }
        try { $lines = Get-Content $lf -Tail 3000 -ErrorAction Stop } catch { continue }
        $full=0
        foreach ($ln in $lines) {
            $c = $ln -split ','
            if ($c.Count -lt 3) { continue }
            # ستون‌ها: ID,Date(MM/dd/yy),Time(HH:mm:ss),... — فقط داخلِ بازه
            $t = [datetime]::MinValue
            if ([datetime]::TryParseExact(("{0} {1}" -f $c[1],$c[2]), 'MM/dd/yy HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$t)) {
                if ($t -lt $Start) { continue }
            } else { continue }
            if ($c[0] -eq '14') { $full++ }     # 14 = تمام‌شدنِ آدرس‌های Scope | scope exhausted
        }
        if ($full -ge 1) {
            $f += [pscustomobject]@{ Category='AppLog'; Severity='Warning'; Machine=$srv; Time=(Get-Date)
                Title=("کمبودِ آدرسِ DHCP — {0} رویداد | DHCP scope exhaustion — {0} events" -f $full)
                Details=("سرور DHCP: {0} | رویدادهای کمبود/پاکسازی: {1}" -f $srv,$full); Key=("DHCP|FULL|{0}" -f $srv) }
        }
    }
    return $f
}

function Invoke-DetectAppLogs {
    param($Config,[datetime]$Start)
    @(Invoke-DetectApache -Config $Config -Start $Start) + @(Invoke-DetectDhcp -Config $Config -Start $Start)
}

Export-ModuleMember -Function *
