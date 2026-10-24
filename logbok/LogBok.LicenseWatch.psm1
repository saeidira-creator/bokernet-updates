# ==========================================================================
#  LogBok.LicenseWatch.psm1 - پایشِ انقضای همهٔ لایسنس‌ها
#
#  از «WarnDays» روز قبل از انقضا (پیش‌فرض ۳۰)، هر «IntervalDays» روز یک‌بار
#  (پیش‌فرض ۷ = هفته‌ای یک‌بار) یک ایمیلِ خلاصه به مدیران می‌فرستد که چه
#  لایسنس‌هایی رو به اتمام‌اند و باید تمدید شوند. بعد از انقضا هم تا تمدید،
#  هفته‌ای یک‌بار یادآوری می‌کند.
#
#  منابع | sources:
#   1) لایسنسِ خودِ لاگ‌بوک (license.key)
#   2) گواهی‌های SSL/TLS ماشین (LocalMachine\My) - مثل گواهیِ IIS
#   3) فعال‌سازیِ ویندوز با مهلت (نسخهٔ Evaluation / KMS منقضی‌شونده)
#   4) هر سرویسِ لایسنس‌دارِ دیگر که در config → LicenseWatch.Items ثبت شود
#      (آنتی‌ویروس، SQL، فایروال، دامنه، نرم‌افزار حسابداری و…)
# ==========================================================================

$script:Inv = [Globalization.CultureInfo]::InvariantCulture

function ConvertTo-LWDate {
    param($v)
    if ($null -eq $v -or "$v" -eq '') { return $null }
    if ($v -is [datetime]) { return $v.Date }
    $d = [datetime]::MinValue
    # تاریخِ شمسی هم پذیرفته می‌شود (سالِ کمتر از 1700 = شمسی)، مثلاً '1406/01/15'
    # ارقامِ فارسی/عربی → لاتین (بدونِ replace با scriptblock که در PS 5.1 نیست)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in ([string]$v).Trim().ToCharArray()) {
        if ([char]::IsDigit($ch)) { [void]$sb.Append([int][char]::GetNumericValue($ch)) } else { [void]$sb.Append($ch) }
    }
    $t = $sb.ToString()
    if ($t -match '^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$' -and [int]$Matches[1] -lt 1700) {
        try { return ([Globalization.PersianCalendar]::new()).ToDateTime([int]$Matches[1],[int]$Matches[2],[int]$Matches[3],0,0,0,0).Date } catch { return $null }
    }
    foreach ($f in 'yyyy-MM-dd','yyyy/MM/dd','yyyy-M-d','yyyy/M/d','yyyy-MM-ddTHH:mm:ss','o') {
        if ([datetime]::TryParseExact($t, $f, $script:Inv, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d.Date }
    }
    if ([datetime]::TryParse([string]$v, $script:Inv, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d.Date }
    return $null
}

function Get-LWSettings {
    param($Config)
    $lw = if ($Config.LicenseWatch) { $Config.LicenseWatch } else { @{} }
    [pscustomobject]@{
        WarnDays            = $(if ($lw.WarnDays)     { [int]$lw.WarnDays }     else { 30 })
        IntervalDays        = $(if ($lw.IntervalDays) { [int]$lw.IntervalDays } else { 7 })
        IncludeCertificates = ($lw.IncludeCertificates -ne $false)
        IncludeWindows      = ($lw.IncludeWindows -ne $false)
        RemindAfterExpiry   = ($lw.RemindAfterExpiry -ne $false)
        ExtraTo             = @($lw.ExtraTo | Where-Object { $_ })
        Items               = @($lw.Items | Where-Object { $_ })
    }
}

function New-LWItem {
    param([string]$Key,[string]$Name,[string]$Type,$Expiry,[string]$Detail,[int]$WarnDays)
    $exp = ConvertTo-LWDate $Expiry
    $days = if ($exp) { [int]($exp - (Get-Date).Date).TotalDays } else { $null }
    $status = if ($null -eq $days) { 'Unknown' } elseif ($days -lt 0) { 'Expired' } elseif ($days -le $WarnDays) { 'Warning' } else { 'OK' }
    [pscustomobject]@{
        Key      = $Key
        Name     = $Name
        Type     = $Type
        Expiry   = $(if ($exp) { $exp.ToString('yyyy-MM-dd', $script:Inv) } else { '' })
        DaysLeft = $days
        Status   = $status
        Detail   = $Detail
    }
}

# فهرستِ همهٔ لایسنس‌های قابل‌پایش | all watched licenses
function Get-LBLicenseItems {
    param($Config, [string]$Root)
    if (-not $Root) { $Root = Split-Path -Parent $PSCommandPath }
    $s = Get-LWSettings $Config
    $out = New-Object System.Collections.ArrayList

    # 1) لایسنسِ لاگ‌بوک
    try {
        if (-not (Get-Command Test-LogBokLicense -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $Root 'LogBok.License.psm1') -DisableNameChecking -ErrorAction Stop }
        $lic = Test-LogBokLicense -Config $Config -Path (Get-LBLicenseFile -Root $Root) -NoClockUpdate
        if ($lic.Permanent -and $lic.Valid) {
            # لایسنسِ دائمی: همیشه سالم، بدونِ هشدارِ انقضا | permanent license
            $it = New-LWItem -Key 'logbok' -Name 'LogBok (لاگ‌بوک)' -Type 'LogBok' -Expiry $null -Detail ("{0} — دائمی | permanent" -f $lic.Company) -WarnDays $s.WarnDays
            $it.Status = 'OK'; $it.Expiry = 'never'
            [void]$out.Add($it)
        } elseif ($lic.Expiry -and $lic.Reason -in 'Valid','Expired') {
            [void]$out.Add((New-LWItem -Key 'logbok' -Name 'LogBok (لاگ‌بوک)' -Type 'LogBok' -Expiry $lic.Expiry -Detail ("{0} — {1}" -f $lic.Company, $lic.Reason) -WarnDays $s.WarnDays))
        } elseif ($lic.Reason -ne 'Valid' -and $lic.Reason -ne 'DeviceUnknown') {
            $it = New-LWItem -Key 'logbok' -Name 'LogBok (لاگ‌بوک)' -Type 'LogBok' -Expiry $null -Detail (Get-LogBokLicenseReasonText -License $lic -Lang 'both') -WarnDays $s.WarnDays
            $it.Status = 'Invalid'
            [void]$out.Add($it)
        }
    } catch { }

    # 2) گواهی‌های SSL/TLS
    if ($s.IncludeCertificates) {
        try {
            $certs = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.HasPrivateKey })
            # گواهیِ قدیمیِ جایگزین‌شده نباید هر هفته هشدار دهد: از هر Subject فقط جدیدترین
            $certs = @($certs | Group-Object Subject | ForEach-Object { $_.Group | Sort-Object NotAfter -Descending | Select-Object -First 1 })
            $ignore = @($Config.LicenseWatch.IgnoreThumbprints | Where-Object { $_ })
            foreach ($c in $certs) {
                if ($ignore -contains $c.Thumbprint) { continue }
                # گواهی‌های خودامضای داخلیِ ویندوز (مثل WinRM/RDP خودکار) نادیده گرفته می‌شوند
                if ($c.Subject -eq $c.Issuer -and $c.Subject -match 'CN=(WMSvc|localhost|' + [regex]::Escape($env:COMPUTERNAME) + ')') { continue }
                # گواهی‌ای که بیش از ۹۰ روز پیش منقضی شده و تمدید نشده، دیگر پیگیری نمی‌شود
                if ($c.NotAfter -lt (Get-Date).AddDays(-90)) { continue }
                $cn = if ($c.FriendlyName) { $c.FriendlyName } else { ($c.Subject -replace '^CN=','' -split ',')[0] }
                [void]$out.Add((New-LWItem -Key "cert:$($c.Thumbprint)" -Name "SSL: $cn" -Type 'Certificate' -Expiry $c.NotAfter -Detail ("Issuer: {0} · Thumbprint: {1}" -f $c.Issuer, $c.Thumbprint) -WarnDays $s.WarnDays))
            }
        } catch { }
    }

    # 3) فعال‌سازیِ ویندوز با مهلت
    if ($s.IncludeWindows) {
        try {
            $p = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f'" -ErrorAction Stop |
                 Where-Object { $_.GracePeriodRemaining -gt 0 } | Select-Object -First 1
            if ($p) {
                $exp = (Get-Date).AddMinutes([double]$p.GracePeriodRemaining)
                [void]$out.Add((New-LWItem -Key 'windows' -Name "Windows: $($p.Name)" -Type 'Windows' -Expiry $exp -Detail "$($p.Description)" -WarnDays $s.WarnDays))
            }
        } catch { }
    }

    # 4) لایسنس‌های ثبت‌شده در config
    foreach ($i in $s.Items) {
        $n = [string]$i.Name
        if (-not $n) { continue }
        $warn = if ($i.WarnDays) { [int]$i.WarnDays } else { $s.WarnDays }
        $det = (@($i.Vendor, $i.Owner, $i.Note) | Where-Object { $_ }) -join ' · '
        $it = New-LWItem -Key "item:$n" -Name $n -Type 'Manual' -Expiry $i.Expiry -Detail $det -WarnDays $warn
        # تاریخِ نامعتبر بی‌صدا نادیده گرفته نمی‌شود
        if ($it.Status -eq 'Unknown') { $it.Status = 'Invalid'; $it.Detail = "تاریخِ انقضا نامعتبر است | invalid expiry date: '$($i.Expiry)' — config.psd1 → LicenseWatch.Items" }
        [void]$out.Add($it)
    }
    return $out.ToArray()
}

function Get-LWStateFile { param($Config) Join-Path $Config.Paths.State 'licensewatch.json' }
function Get-LWState {
    param($Config)
    $f = Get-LWStateFile $Config
    $h = @{}
    if (Test-Path $f) {
        try { $o = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } } catch {}
    }
    return $h
}
function Save-LWState {
    param($Config, $State)
    $d = $Config.Paths.State
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $State | ConvertTo-Json | Set-Content -Path (Get-LWStateFile $Config) -Encoding UTF8
}

# ساختِ HTMLِ ایمیل | mail body
function New-LWMailHtml {
    param($Config, $Items)
    $isEn = ($Config.Language -eq 'en')
    function _LW($fa,$en){ if ($isEn) { $en } elseif ($Config.Language -eq 'fa') { $fa } else { "$fa / $en" } }
    function _E($t){ [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $dir = if ($isEn) { 'ltr' } else { 'rtl' }
    $al  = if ($isEn) { 'left' } else { 'right' }
    $brand = if ($Config.Brand) { $Config.Brand } else { @{ NameEn='LogBok'; Brass='#C9A24B'; InkTeal='#0E2529' } }
    $ink = if ($brand.InkTeal) { $brand.InkTeal } else { '#0E2529' }
    $rows = ''
    foreach ($i in ($Items | Sort-Object DaysLeft)) {
        $c = if ($i.Status -in 'Expired','Invalid') { '#C53030' } elseif ($i.DaysLeft -le 7) { '#C05621' } else { '#B7791F' }
        $when = if ($i.Status -eq 'Invalid') { _LW 'نامعتبر' 'Invalid' }
                elseif ($i.DaysLeft -lt 0) { _LW ("{0} روز پیش منقضی شده" -f (-$i.DaysLeft)) ("expired {0} days ago" -f (-$i.DaysLeft)) }
                elseif ($i.DaysLeft -eq 0) { _LW 'امروز منقضی می‌شود' 'expires today' }
                else { _LW ("{0} روز مانده" -f $i.DaysLeft) ("{0} days left" -f $i.DaysLeft) }
        $rows += "<tr><td style='padding:8px;border-bottom:1px solid #e6eaec;font-weight:600'>$(_E $i.Name)</td><td style='padding:8px;border-bottom:1px solid #e6eaec;color:#667'>$(_E $i.Type)</td><td style='padding:8px;border-bottom:1px solid #e6eaec;white-space:nowrap'>$(_E $i.Expiry)</td><td style='padding:8px;border-bottom:1px solid #e6eaec;color:$c;font-weight:700;white-space:nowrap'>$when</td><td style='padding:8px;border-bottom:1px solid #e6eaec;color:#667;font-size:12px'>$(_E $i.Detail)</td></tr>"
    }
    $intro = _LW 'لایسنس‌های زیر رو به اتمام هستند یا منقضی شده‌اند. لطفاً برای تمدید اقدام کنید تا سرویس‌ها متوقف نشوند.' 'The licenses below are about to expire or have expired. Please renew them so services are not interrupted.'
    return @"
<!DOCTYPE html><html dir="$dir"><head><meta charset="utf-8"></head>
<body style="font-family:Vazirmatn,'Segoe UI',Tahoma,sans-serif;background:#f4f6f8;margin:0;padding:20px;direction:$dir;text-align:$al">
<div style="max-width:760px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e3e8ea">
 <div style="background:$ink;color:#fff;padding:16px 22px;font-size:17px;font-weight:700">$(_LW 'هشدارِ انقضای لایسنس' 'License expiry notice') — $(_E $brand.NameEn)</div>
 <div style="padding:18px 22px">
  <p style="margin:0 0 12px;line-height:1.9">$intro</p>
  <table style="width:100%;border-collapse:collapse;font-size:13px;text-align:$al">
   <tr style="background:#f6f8fa"><th style="padding:8px">$(_LW 'سرویس' 'Service')</th><th style="padding:8px">$(_LW 'نوع' 'Type')</th><th style="padding:8px">$(_LW 'انقضا' 'Expiry')</th><th style="padding:8px">$(_LW 'وضعیت' 'Status')</th><th style="padding:8px">$(_LW 'جزئیات' 'Details')</th></tr>
   $rows
  </table>
  <p style="color:#889;font-size:12px;margin-top:16px">$(_LW 'این یادآوری تا زمانِ تمدید، هفته‌ای یک‌بار ارسال می‌شود.' 'This reminder repeats weekly until renewed.') · $(_E $env:COMPUTERNAME)</p>
 </div>
</div></body></html>
"@
}

# اجرای پایش | run the watch
#  -Force : بدون توجه به بازهٔ هفتگی همین الان ایمیل بفرست (اگر موردی هست)
function Invoke-LBLicenseWatch {
    param($Config, [string]$Root, [switch]$Force, [switch]$NoMail)
    $s = Get-LWSettings $Config
    $items = @(Get-LBLicenseItems -Config $Config -Root $Root)
    $alert = @($items | Where-Object { $_.Status -in 'Warning','Invalid' -or ($_.Status -eq 'Expired' -and $s.RemindAfterExpiry) })
    $state = Get-LWState $Config
    $due = $false
    foreach ($i in $alert) {
        $last = ConvertTo-LWDate $state[$i.Key]
        if ($Force -or -not $last -or ((Get-Date).Date - $last).TotalDays -ge $s.IntervalDays) { $due = $true }
    }
    $sent = $false
    if ($due -and -not $NoMail -and $alert.Count -gt 0) {
        $html = New-LWMailHtml -Config $Config -Items $alert
        $soon = ($alert | Sort-Object DaysLeft | Select-Object -First 1)
        $subj = if ($Config.Language -eq 'en') { "License expiry: $($alert.Count) item(s) need renewal (nearest: $($soon.Name))" }
                else { "انقضای لایسنس: $($alert.Count) مورد نیاز به تمدید (نزدیک‌ترین: $($soon.Name))" }
        $to = @(@($Config.Mail.To) + $s.ExtraTo | Where-Object { $_ } | Select-Object -Unique)
        $sent = [bool](Send-LogBokMail -Subject $subj -Body $html -Html -To $to -Config $Config)
        if ($sent) {
            $today = (Get-Date).ToString('yyyy-MM-dd', $script:Inv)
            foreach ($i in $alert) { $state[$i.Key] = $today }
        }
    }
    # کلیدِ موردی که تمدید شده (دیده شد و دیگر هشدار نیست) پاک می‌شود؛ اگر منبعش این‌بار
    # خوانده نشد (خطای موقتِ WMI/Cert) نگه داشته می‌شود تا ایمیلِ زودهنگام نرود
    foreach ($k in @($state.Keys)) {
        $seen = @($items | Where-Object Key -eq $k).Count -gt 0
        $al   = @($alert | Where-Object Key -eq $k).Count -gt 0
        $old  = ConvertTo-LWDate $state[$k]
        if (($seen -and -not $al) -or (-not $seen -and $old -and $old -lt (Get-Date).AddDays(-60))) { $state.Remove($k) }
    }
    Save-LWState -Config $Config -State $state
    return [pscustomobject]@{ Items=$items; Alerting=$alert; Sent=$sent; Due=$due }
}

Export-ModuleMember -Function Get-LBLicenseItems, Invoke-LBLicenseWatch, New-LWMailHtml, ConvertTo-LWDate
