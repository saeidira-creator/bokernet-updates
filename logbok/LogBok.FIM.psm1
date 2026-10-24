# ==========================================================================
#  LogBok.FIM.psm1 - File Integrity Monitoring
#  Builds a SHA256 hash baseline of critical files and, each cycle, detects added/
#  changed/removed files. Runs on the agent (client/server); logs event
#  9014, which is forwarded to the Collector. No external dependency.
# ==========================================================================

function Write-LBFimEvent { param([string]$Message)
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch {}
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9014 -EntryType Warning -Message $Message } catch {}
}

function Get-LBFimBaselinePath { param([string]$StateDir) Join-Path $StateDir 'fim-baseline.json' }

# enumerate monitored files
function Get-LBFimFiles {
    param([string[]]$Paths,[string[]]$Include)
    # when $null was passed the default was not applied, so no files were monitored
    if (-not $Include -or $Include.Count -eq 0) { $Include = @('*.exe','*.dll','*.sys','*.conf','*.config','*.ps1','*.bat','*.cmd') }
    $files = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Paths) {
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        if (Test-Path -LiteralPath $p -PathType Leaf) { $files.Add((Resolve-Path -LiteralPath $p).Path); continue }
        foreach ($inc in $Include) {
            Get-ChildItem -Path $p -Recurse -File -Filter $inc -ErrorAction SilentlyContinue |
                ForEach-Object { $files.Add($_.FullName) }
        }
    }
    return ($files | Select-Object -Unique)
}

function Get-LBFimSnapshot {
    param([string[]]$Paths,[string[]]$Include,$Previous)
    $snap = @{}
    foreach ($f in (Get-LBFimFiles -Paths $Paths -Include $Include)) {
        try { $h=(Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop).Hash; $snap[$f]=$h }
        catch {
            # a locked/unreadable file is not treated as deleted; its previous hash is kept
            if ($Previous -and $Previous.ContainsKey($f)) { $snap[$f] = $Previous[$f] } else { $snap[$f] = 'UNREADABLE' }
        }
    }
    return $snap
}

# (re)build baseline
function Set-LBFimBaseline {
    param([string]$StateDir,[string[]]$Paths,[string[]]$Include=$null)
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $snap = if ($Include) { Get-LBFimSnapshot -Paths $Paths -Include $Include } else { Get-LBFimSnapshot -Paths $Paths }
    $o=[ordered]@{}; foreach($k in ($snap.Keys|Sort-Object)){ $o[$k]=$snap[$k] }
    $o | ConvertTo-Json -Depth 3 | Set-Content -Path (Get-LBFimBaselinePath $StateDir) -Encoding UTF8
    return $snap.Count
}

# check against baseline -> changes + event
function Invoke-LBFimCheck {
    param([string]$StateDir,[string[]]$Paths,[string[]]$Include=$null,[switch]$UpdateBaseline)
    $bf = Get-LBFimBaselinePath $StateDir
    if (-not (Test-Path $bf)) { Set-LBFimBaseline -StateDir $StateDir -Paths $Paths -Include $Include | Out-Null; return @() }
    $base=@{}; try { (Get-Content $bf -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $base[$_.Name]=$_.Value } } catch {}
    $now = Get-LBFimSnapshot -Paths $Paths -Include $Include -Previous $base
    $changes=@()
    foreach ($k in $now.Keys) {
        if (-not $base.ContainsKey($k)) { $changes += [pscustomobject]@{Path=$k;Change='added'} }
        elseif ($base[$k] -ne $now[$k] -and $now[$k] -ne 'UNREADABLE' -and $base[$k] -ne 'UNREADABLE') { $changes += [pscustomobject]@{Path=$k;Change='modified'} }
    }
    foreach ($k in $base.Keys) { if (-not $now.ContainsKey($k)) { $changes += [pscustomobject]@{Path=$k;Change='deleted'} } }
    if ($changes.Count -gt 0) {
        $sample = ($changes | Select-Object -First 10 | ForEach-Object { "$($_.Change): $($_.Path)" }) -join "`n"
        Write-LBFimEvent -Message ("FIM change on {0} ({1} items):`n{2}" -f $env:COMPUTERNAME,$changes.Count,$sample)
        # the baseline is updated to this snapshot so a change alerts only once
        if ($UpdateBaseline) {
            $o=[ordered]@{}; foreach($k in ($now.Keys|Sort-Object)){ $o[$k]=$now[$k] }
            $o | ConvertTo-Json -Depth 3 | Set-Content -Path $bf -Encoding UTF8
        }
    }
    return $changes
}

Export-ModuleMember -Function *
