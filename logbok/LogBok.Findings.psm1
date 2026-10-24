# ==========================================================================
#  LogBok.Findings.psm1 — تاریخچهٔ یافته‌ها با شناسه (برای باز کردنِ جزئیات)
#  Findings history with stable IDs, so every event shown in the UI can be
#  opened, searched and acted on later. Stored as state\findings\YYYY-MM-DD.ndjson.
# ==========================================================================
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
if (-not (Get-Module LogBok.Core)) { Import-Module (Join-Path (Split-Path -Parent $PSCommandPath) 'LogBok.Core.psm1') -DisableNameChecking -ErrorAction SilentlyContinue }

function Get-LBFindingsDir {
    param($Config)
    $sd = if ($Config -and $Config.Paths -and $Config.Paths.State -and (Test-Path $Config.Paths.State)) { $Config.Paths.State } else { Join-Path (Split-Path -Parent $PSCommandPath) 'state' }
    $d = Join-Path $sd 'findings'
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}
function Get-LBFindingId {
    param($Finding)
    $t = if ($Finding.Time -is [datetime]) { $Finding.Time.ToUniversalTime().ToString('yyyyMMddHHmmss', $script:Inv) } else { [string]$Finding.Time }
    $s = "{0}|{1}|{2}|{3}" -f $Finding.Key, $t, $Finding.Machine, $Finding.Title
    $sha = [Security.Cryptography.SHA1]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s)) } finally { $sha.Dispose() }
    return (-join ($h[0..7] | ForEach-Object { $_.ToString('x2') }))
}

# ذخیرهٔ یافته‌های تازه (تکراری‌ها نادیده) | persist new findings (dedupe by id)
function Save-LBFindings {
    param($Config, [object[]]$Findings)
    if (-not $Findings -or -not @($Findings).Count) { return 0 }
    $dir = Get-LBFindingsDir -Config $Config
    $seenF = Join-Path $dir 'seen.json'
    $seen = @{}
    if (Test-Path $seenF) { try { foreach ($x in @((Get-Content $seenF -Raw | ConvertFrom-Json))) { $seen[[string]$x] = $true } } catch { } }
    $byDay = @{}; $n = 0
    foreach ($f in $Findings) {
        if (-not $f) { continue }
        $id = Get-LBFindingId $f
        if ($seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $tm = if ($f.Time -is [datetime]) { $f.Time } else { try { [datetime]::Parse([string]$f.Time, $script:Inv) } catch { Get-Date } }
        $o = [ordered]@{ id=$id; t=$tm.ToString('o', $script:Inv); cat=[string]$f.Category; sev=[string]$f.Severity; host=[string]$f.Machine
                         title=[string]$f.Title; det=[string]$f.Details; key=[string]$f.Key; mitre=[string]$f.Mitre }
        foreach ($p in $f.PSObject.Properties) {
            if ($p.Name -match '^(Guard|Intel|Ip|User|Corr)' -and $null -ne $p.Value) { $o["x_$($p.Name)"] = [string]$p.Value }
        }
        $day = $tm.ToString('yyyy-MM-dd', $script:Inv)
        if (-not $byDay.ContainsKey($day)) { $byDay[$day] = New-Object System.Collections.Generic.List[string] }
        $byDay[$day].Add((ConvertTo-Json -InputObject $o -Compress -Depth 4))
        $n++
    }
    foreach ($d in $byDay.Keys) {
        $file = Join-Path $dir "$d.ndjson"
        $ok = $false
        for ($i = 0; $i -lt 5 -and -not $ok; $i++) {
            try { [IO.File]::AppendAllLines($file, [string[]]$byDay[$d].ToArray(), (New-Object Text.UTF8Encoding($false))); $ok = $true } catch { Start-Sleep -Milliseconds 200 }
        }
    }
    # فقط ۲۰٬۰۰۰ شناسهٔ اخیر نگه داشته می‌شود | keep the last 20k ids
    $ids = @($seen.Keys); if ($ids.Count -gt 20000) { $ids = $ids[($ids.Count - 20000)..($ids.Count - 1)] }
    try { [IO.File]::WriteAllText($seenF, (ConvertTo-Json -InputObject @($ids) -Compress), (New-Object Text.UTF8Encoding($false))) } catch { }
    # نگه‌داری ۱۸۰ روز | retention
    Get-ChildItem $dir -Filter '*.ndjson' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-180) } | Remove-Item -Force -ErrorAction SilentlyContinue
    return $n
}

function ConvertFrom-LBFindingLine {
    param([string]$Line)
    try { return ($Line | ConvertFrom-Json) } catch { return $null }
}

# جست‌وجو در تاریخچه | query history (newest first)
function Get-LBFindings {
    param($Config, [datetime]$From = (Get-Date).AddDays(-1), [datetime]$To = (Get-Date),
          [string[]]$Category, [string]$Severity, [string]$HostName, [string]$Text, [int]$Skip = 0, [int]$Max = 100)
    $dir = Get-LBFindingsDir -Config $Config
    $items = New-Object System.Collections.Generic.List[object]
    $total = 0
    $sevRank = @{ Critical=3; Warning=2; Info=1 }
    $minRank = if ($Severity -and $sevRank.ContainsKey($Severity)) { $sevRank[$Severity] } else { 0 }
    $exact = ($Severity -and $Severity -like '=*')
    $day = $To.Date
    $txt = if ($Text) { $Text.ToLowerInvariant() } else { $null }
    while ($day -ge $From.Date) {
        $file = Join-Path $dir ($day.ToString('yyyy-MM-dd', $script:Inv) + '.ndjson')
        if (Test-Path $file) {
            $lines = @(); try { $lines = [IO.File]::ReadAllLines($file, [Text.Encoding]::UTF8) } catch { }
            for ($i = $lines.Count - 1; $i -ge 0; $i--) {
                $ln = $lines[$i]; if (-not $ln) { continue }
                if ($txt -and $ln.ToLowerInvariant().IndexOf($txt) -lt 0) { continue }
                $r = ConvertFrom-LBFindingLine $ln; if (-not $r) { continue }
                $t = ConvertTo-LBLocal $r.t
                if (-not $t -or $t -lt $From -or $t -gt $To) { continue }
                if ($Category -and $Category.Count -and $Category -notcontains [string]$r.cat) { continue }
                if ($Severity) { $rk = $sevRank[[string]$r.sev]; if ($exact) { if ([string]$r.sev -ne $Severity.TrimStart('=')) { continue } } elseif ($rk -lt $minRank) { continue } }
                if ($HostName -and ([string]$r.host) -notlike "*$HostName*") { continue }
                $total++
                if ($total -gt $Skip -and $items.Count -lt $Max) { $items.Add($r) }
            }
        }
        $day = $day.AddDays(-1)
    }
    return [pscustomobject]@{ Total = $total; Items = $items.ToArray() }
}

# یک یافته با شناسه | one finding by id (searches the last 180 days, newest first)
function Get-LBFinding {
    param($Config, [Parameter(Mandatory)][string]$Id)
    if ($Id -notmatch '^[0-9a-f]{16}$') { return $null }
    $dir = Get-LBFindingsDir -Config $Config
    foreach ($f in (Get-ChildItem $dir -Filter '*.ndjson' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
        foreach ($ln in [IO.File]::ReadAllLines($f.FullName, [Text.Encoding]::UTF8)) {
            if ($ln.IndexOf($Id) -lt 0) { continue }
            $r = ConvertFrom-LBFindingLine $ln
            if ($r -and $r.id -eq $Id) { return $r }
        }
    }
    return $null
}

# آمارِ بازه برای نمای کلی | counts per severity/category
function Get-LBFindingStats {
    param($Config, [datetime]$From = (Get-Date).AddDays(-1), [datetime]$To = (Get-Date))
    $all = (Get-LBFindings -Config $Config -From $From -To $To -Max 100000).Items
    $bySev = @{ Critical=0; Warning=0; Info=0 }; $byCat = @{}; $byHost = @{}
    # خطِ زمانیِ ۲۴ بازه برای نوارِ دیده‌بانی | 24-bucket timeline for the overview watch strip
    $nb = 24; $tc = New-Object int[] $nb; $tw = New-Object int[] $nb; $ti = New-Object int[] $nb
    $t0 = $From.Ticks; $span = [double]($To.Ticks - $t0); if ($span -le 0) { $span = 1 }
    foreach ($r in $all) {
        $s = [string]$r.sev; if ($bySev.ContainsKey($s)) { $bySev[$s]++ }
        try {
            $bi = [int][math]::Floor((([datetime]::Parse([string]$r.t, $script:Inv)).Ticks - $t0) / $span * $nb)
            if ($bi -ge $nb) { $bi = $nb - 1 }
            if ($bi -ge 0) { if ($s -eq 'Critical') { $tc[$bi]++ } elseif ($s -eq 'Warning') { $tw[$bi]++ } else { $ti[$bi]++ } }
        } catch { }
        $c = [string]$r.cat; if (-not $byCat.ContainsKey($c)) { $byCat[$c] = @{ n=0; crit=0 } }; $byCat[$c].n++; if ($s -eq 'Critical') { $byCat[$c].crit++ }
        $h = [string]$r.host; if (-not $byHost.ContainsKey($h)) { $byHost[$h] = 0 }; $byHost[$h]++
    }
    $tl = @(for ($k = 0; $k -lt $nb; $k++) { [ordered]@{ c=$tc[$k]; w=$tw[$k]; i=$ti[$k] } })
    return [pscustomobject]@{ Total=@($all).Count; BySeverity=$bySev; ByCategory=$byCat; ByHost=$byHost; Timeline=$tl; Latest=@($all | Where-Object { $_.sev -eq 'Critical' } | Select-Object -First 8) }
}

Export-ModuleMember -Function Get-LBFindingsDir, Get-LBFindingId, Save-LBFindings, Get-LBFindings, Get-LBFinding, Get-LBFindingStats
