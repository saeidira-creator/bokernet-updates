# ==========================================================================
#  LogBok.Intel.psm1 - شهرت و موقعیتِ جغرافیاییِ IP (Threat intel enrichment)
#  برای IPهای مهاجم، نوعِ آدرس (خصوصی/عمومی)، کشور و امتیازِ شهرت را می‌دهد.
#  - تشخیصِ خصوصی/رزرو آفلاین و بدونِ شبکه انجام می‌شود.
#  - غنی‌سازیِ جغرافیا/شهرت فقط اگر در config فعال و کلید/سرویس در دسترس باشد
#    (ip-api.com یا AbuseIPDB). اگر شبکه مجاز نبود، بی‌صدا رد می‌شود.
#  نتیجه‌ها برای کاهشِ فراخوانی در state کش می‌شوند.
# ==========================================================================

function Test-LBPrivateIp {
    param([string]$Ip)
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $true }  # غیرِ IPv4 → محلی فرض
    $o = $Ip.Split('.') | ForEach-Object { [int]$_ }
    if ($o[0] -eq 10) { return $true }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
    if ($o[0] -eq 127 -or $o[0] -eq 0 -or ($o[0] -eq 169 -and $o[1] -eq 254)) { return $true }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $true }   # CGNAT
    if ($o[0] -ge 224) { return $true }                                         # multicast/reserved
    return $false
}

function Get-LBIntelCachePath { param($Config) Join-Path $Config.Paths.State 'ipintel.json' }
function Get-LBIntelCache { param($Config)
    $f=Get-LBIntelCachePath -Config $Config; $h=@{}
    if (Test-Path $f) { try { (Get-Content $f -Raw|ConvertFrom-Json).PSObject.Properties|ForEach-Object{ $h[$_.Name]=$_.Value } } catch {} }
    return $h
}
function Save-LBIntelCache { param($Config,$Cache)
    # حذفِ موارد قدیمی‌تر از ۷ روز تا کش بی‌نهایت بزرگ نشود
    $o=[ordered]@{}
    foreach($k in $Cache.Keys){
        $v = $Cache[$k]; $ts = $null
        try { $ts = [datetime]::Parse([string]$v.ts, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } catch {}
        if ($k -eq '__offline_until' -or ($ts -and $ts -gt (Get-Date).AddDays(-7))) { $o[$k]=$v }
    }
    $o | ConvertTo-Json -Depth 4 | Set-Content -Path (Get-LBIntelCachePath -Config $Config) -Encoding UTF8
}

# اطلاعاتِ یک IP | lookup one IP (cached)
function Get-LBIpInfo {
    param($Config,[string]$Ip)
    if (-not $Ip) { return $null }
    if (Test-LBPrivateIp -Ip $Ip) { return [pscustomobject]@{ Ip=$Ip; Scope='private'; Country='-'; Abuse=$null; Note='محلی/خصوصی' } }
    $cache = Get-LBIntelCache -Config $Config
    if ($cache.ContainsKey($Ip)) {
        $c=$cache[$Ip]
        try { if ((Get-Date) -lt ([datetime]::Parse([string]$c.ts, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)).AddDays(7)) { return [pscustomobject]@{ Ip=$Ip; Scope='public'; Country=$c.country; Abuse=$c.abuse; Note='از کش' } } } catch {}
    }
    $country='?'; $abuse=$null
    # اگر اخیراً اینترنت در دسترس نبوده، یک ساعت تلاش نکن (بدونِ کندکردنِ موتور)
    $offline = $false
    if ($cache.ContainsKey('__offline_until')) {
        try { $offline = (Get-Date) -lt [datetime]::Parse([string]$cache['__offline_until'].ts, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } catch {}
    }
    if ($Config.Intel -and $Config.Intel.Enabled -and -not $offline) {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
        # AbuseIPDB (اگر کلید داده شده)
        if ($Config.Intel.AbuseIpDbKey) {
            try {
                $r = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$Ip" -Headers @{ Key=$Config.Intel.AbuseIpDbKey; Accept='application/json' } -TimeoutSec 6 -ErrorAction Stop
                $abuse=[int]$r.data.abuseConfidenceScore; $country=[string]$r.data.countryCode
            } catch {}
        }
        # ip-api.com (رایگان، بدون کلید) اگر کشور هنوز نامشخص است
        if ($country -eq '?' ) {
            try { $r2 = Invoke-RestMethod -Uri "http://ip-api.com/json/$Ip`?fields=status,countryCode" -TimeoutSec 6 -ErrorAction Stop
                  if ($r2.status -eq 'success') { $country=[string]$r2.countryCode } }
            catch { $cache['__offline_until'] = @{ ts=(Get-Date).AddHours(1).ToString('o',[Globalization.CultureInfo]::InvariantCulture) } }
        }
    }
    # نتیجهٔ ناموفق ('?') کش نمی‌شود تا دفعهٔ بعد دوباره امتحان شود
    if ($country -ne '?' -or $null -ne $abuse) {
        $cache[$Ip]=@{ country=$country; abuse=$abuse; ts=(Get-Date).ToString('o',[Globalization.CultureInfo]::InvariantCulture) }
    }
    try { Save-LBIntelCache -Config $Config -Cache $cache } catch {}
    return [pscustomobject]@{ Ip=$Ip; Scope='public'; Country=$country; Abuse=$abuse; Note='' }
}

# استخراجِ IP از متنِ یافته و افزودنِ خطِ غنی‌سازی | enrich a finding's details
function Add-LBIntel {
    param($Config,$Finding)
    if (-not $Config.Intel -or -not $Config.Intel.Enabled) { return $Finding }
    $ip=$null
    if ($Finding.Details -match '(\d{1,3}(\.\d{1,3}){3})') { $ip=$Matches[1] }
    if ($ip) {
        $info = Get-LBIpInfo -Config $Config -Ip $ip
        if ($info -and $info.Scope -eq 'public') {
            $ab = if ($null -ne $info.Abuse) { " | شهرت(Abuse): $($info.Abuse)%" } else { '' }
            $Finding.Details = "$($Finding.Details)`nمبدأ $ip → کشور: $($info.Country)$ab"
        }
    }
    return $Finding
}

Export-ModuleMember -Function *
