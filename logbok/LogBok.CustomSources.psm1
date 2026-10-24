# ==========================================================================
#  LogBok.CustomSources.psm1 — لاگ‌های سفارشی (افزودنِ لاگ از رابط)
#  Custom log sources added from the console / web console:
#   • EventLog : هر کانالِ رویدادِ ویندوز روی هر سیستم؛ رویدادها در انبار ذخیره و
#                با EventIDها/کلیدواژه‌ها به یافته (و هشدار) تبدیل می‌شوند.
#   • File     : فایلِ متنیِ لاگِ برنامه (محلی یا \\سیستم\C$\…)؛ خط‌های تازه دنبال،
#                در انبار ذخیره و با کلیدواژه‌ها به یافته تبدیل می‌شوند.
# ==========================================================================
$script:Inv = [Globalization.CultureInfo]::InvariantCulture

function Get-LBCustomList { param($Config) return @($Config.CustomSources | Where-Object { $_ }) }

function New-LBCustomFinding {
    param($Src, [string]$HostName, [datetime]$Time, [string]$Msg, [string]$KeyTail)
    $nm = [string]$Src.Name
    $short = (($Msg -split "`r?`n")[0]); if ($short.Length -gt 140) { $short = $short.Substring(0, 140) + '…' }
    [pscustomobject]@{
        Category = 'Custom'; Severity = $(if ($Src.Severity) { [string]$Src.Severity } else { 'Warning' })
        Machine = $HostName; Time = $Time
        Title = ("لاگِ سفارشی «{0}»: {1} | Custom log '{0}': {1}" -f $nm, $short)
        Details = ("منبع | Source: {0}`nمسیر/کانال | Log: {1}{2}`nپیام | Message: {3}" -f $nm, $Src.Log, $Src.Path, $Msg)
        Key = ("CUST|{0}|{1}|{2}" -f $Src.Id, $HostName, $KeyTail)
    }
}

function Test-LBKeywordHit {
    param([string]$Text, [string[]]$Keywords)
    $kws = @($Keywords | Where-Object { $_ })
    if (-not $kws.Count) { return $true }
    foreach ($k in $kws) { if ($Text -like "*$k*") { return $true } }
    return $false
}

# --- کانال‌های رویدادِ سفارشی → یافته (بدونِ state؛ مثلِ بقیهٔ آشکارسازها) ------
function Invoke-DetectCustom {
    param($Config, [datetime]$Start)
    $f = @()
    foreach ($s in (Get-LBCustomList -Config $Config)) {
        if ([string]$s.Type -ne 'EventLog' -or $s.Alert -eq $false) { continue }
        $ids = @($s.Ids | Where-Object { $_ } | ForEach-Object { [int]$_ })
        if (-not $ids.Count -and -not @($s.Keywords | Where-Object { $_ }).Count) { continue }   # بدونِ قاعده فقط بایگانی می‌شود
        $p = @{ LogName = [string]$s.Log; StartTime = $Start; ComputerName = [string]$s.Host; Config = $Config; MaxEvents = 2000 }
        if ($ids.Count) { $p.Id = $ids }
        foreach ($e in (Get-LogBokEvents @p)) {
            $msg = ''; try { $msg = [string]$e.Message } catch { }
            if (-not $msg) { $msg = "EventID $($e.Id) ($($e.ProviderName))" }
            if (-not (Test-LBKeywordHit -Text $msg -Keywords @($s.Keywords))) { continue }
            $f += New-LBCustomFinding -Src $s -HostName ([string]$e.MachineName) -Time $e.TimeCreated -Msg ("[{0}] {1}" -f $e.Id, $msg) -KeyTail ([string]$e.RecordId)
        }
    }
    return $f
}

# --- فایل‌های لاگِ سفارشی: دنبال‌کردنِ خط‌های تازه (فقط از اجرای بلادرنگ) --------
function Get-LBCustomFilePath {
    param($Src)
    $p = [string]$Src.Path
    $h = [string]$Src.Host
    if ($h -and $h -ne 'localhost' -and $h -ne $env:COMPUTERNAME -and $p -match '^[A-Za-z]:\\') { return "\\$h\" + ($p -replace ':', '$') }
    return $p
}
function Invoke-LBCustomFiles {
    param($Config)
    $findings = @()
    $list = @(Get-LBCustomList -Config $Config | Where-Object { [string]$_.Type -eq 'File' })
    if (-not $list.Count) { return $findings }
    $sd = if ($Config.Paths.State -and (Test-Path $Config.Paths.State)) { $Config.Paths.State } else { Join-Path (Split-Path -Parent $PSCommandPath) 'state' }
    $stF = Join-Path $sd 'custom-files.json'
    $st = @{}; if (Test-Path $stF) { try { $st = ConvertTo-LBHashtable ((Get-Content $stF -Raw) | ConvertFrom-Json) } catch { $st = @{} } }
    if (-not ($st -is [hashtable])) { $st = @{} }
    $archLines = New-Object System.Collections.Generic.List[string]
    foreach ($s in $list) {
        $path = Get-LBCustomFilePath -Src $s
        $sk = "{0}|{1}" -f $s.Id, $path
        try {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $fi = Get-Item -LiteralPath $path
            $off = 0L; if ($st.ContainsKey($sk)) { $off = [long]$st[$sk] }
            if ($off -eq 0 -and -not $st.ContainsKey($sk)) { $off = [math]::Max(0, $fi.Length - 65536) }   # بارِ اول: فقط ۶۴KB آخر
            if ($fi.Length -lt $off) { $off = 0 }                                                          # چرخشِ فایل | rotated
            if ($fi.Length -eq $off) { $st[$sk] = $off; continue }
            $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try {
                [void]$fs.Seek($off, [IO.SeekOrigin]::Begin)
                $max = [math]::Min([long]4MB, $fi.Length - $off)
                $buf = New-Object byte[] $max
                $read = $fs.Read($buf, 0, $buf.Length)
            } finally { $fs.Dispose() }
            $text = [Text.Encoding]::UTF8.GetString($buf, 0, $read)
            $lastNl = $text.LastIndexOf("`n")
            if ($lastNl -lt 0) { continue }                                  # هنوز خطِ کاملی نیست
            $consumed = [Text.Encoding]::UTF8.GetByteCount($text.Substring(0, $lastNl + 1))
            $st[$sk] = $off + $consumed
            $hostN = if ($s.Host) { [string]$s.Host } else { $env:COMPUTERNAME }
            $now = Get-Date
            $ln = 0
            foreach ($line in ($text.Substring(0, $lastNl) -split "`r?`n")) {
                $ln++
                if (-not $line.Trim()) { continue }
                $l2 = if ($line.Length -gt 2000) { $line.Substring(0, 2000) } else { $line }
                $rec = [ordered]@{ t=$now.ToString('o', $script:Inv); host=$hostN; log=("file:{0}" -f $s.Name); id=0; lvl=''; prov='LogBok-File'; user=''; ip=''; rec=($off + $ln); msg=$l2 }
                $archLines.Add((ConvertTo-Json -InputObject $rec -Compress))
                if ($s.Alert -ne $false -and @($s.Keywords | Where-Object { $_ }).Count -and (Test-LBKeywordHit -Text $l2 -Keywords @($s.Keywords))) {
                    $findings += New-LBCustomFinding -Src $s -HostName $hostN -Time $now -Msg $l2 -KeyTail ([string]($off + $ln))
                }
            }
        } catch { }
    }
    if ($archLines.Count) {
        try {
            Import-Module (Join-Path (Split-Path -Parent $PSCommandPath) 'LogBok.Archive.psm1') -DisableNameChecking -ErrorAction Stop
            $dir = Get-LBArchiveDir -Config $Config
            Add-LBArchiveLines -File (Join-Path $dir ("events-{0}.ndjson" -f (Get-Date).ToString('yyyy-MM-dd', $script:Inv))) -Lines $archLines.ToArray()
        } catch { }
    }
    try { [IO.File]::WriteAllText($stF, (ConvertTo-Json -InputObject $st -Compress), (New-Object Text.UTF8Encoding($false))) } catch { }
    return $findings
}

Export-ModuleMember -Function Invoke-DetectCustom, Invoke-LBCustomFiles, Test-LBKeywordHit, Get-LBCustomFilePath
