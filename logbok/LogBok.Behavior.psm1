# ==========================================================================
#  LogBok.Behavior.psm1 - user/system behavior analysis (UEBA) + suspicious-file scan
#  Instead of a "magic AI model", we use the real method of UEBA products:
#  a behavioral baseline is built per user/system, and a significant deviation from
#  it (with robust stats: median + MAD and a z-score) is reported as anomalous behavior.
#  This method is adaptive, explainable, and needs no AI server.
#  Real UEBA: per-entity behavioral baseline + robust anomaly scoring
#  (median + MAD modified z-score). Learns over time, explainable, offline.
#  Depends on LogBok.Core.psm1
# ==========================================================================

# --- robust stats helpers ---
function Get-Median { param([double[]]$x)
    if (-not $x -or $x.Count -eq 0) { return 0 }
    $s = $x | Sort-Object; $n = $s.Count
    if ($n % 2) { return $s[[int](($n-1)/2)] }
    return (($s[$n/2-1] + $s[$n/2]) / 2)
}
function Get-MAD { param([double[]]$x,[double]$median)
    if (-not $x -or $x.Count -eq 0) { return 0 }
    $dev = $x | ForEach-Object { [math]::Abs($_ - $median) }
    return (Get-Median $dev)
}

# absolute floor per metric (to avoid alerts on small numbers) ----------
$script:MetricFloor = @{ FailedLogons=8; FileDeletes=20; ServiceStops=2; SqlFailures=8 }

# --- collect current-window metrics from forwarded logs ----------------
function Get-LogBokWindowMetrics {
    param($Config,[datetime]$Start)
    $m = @{}
    function Add($k){ if ($m.ContainsKey($k)){ $m[$k]++ } else { $m[$k]=1 } }
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 4625 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $u = Get-LogBokEventField -Event $e -Name 'TargetUserName'; if ($u) { Add "user|$u|FailedLogons" }
        }
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 4663 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $u = Get-LogBokEventField -Event $e -Name 'SubjectUserName'
            if (-not $u -or $u -eq 'SYSTEM' -or $u -like '*$') { continue }
            $mk = 0; try { $mk = [Convert]::ToInt32(([string](Get-LogBokEventField -Event $e -Name 'AccessMask')).Trim(),16) } catch { continue }
            if ($mk -band 0x10000) { Add "user|$u|FileDeletes" }   # deletes only (DELETE bit)
        }
        # 7036 is in the System log (not Security); service events live in System
        $sysLog = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'System' }
        foreach ($e in (Get-LogBokEvents -LogName $sysLog -Id 7036 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            if ($e.Id -ne 7036) { continue }
            if ([string]$e.Message -match 'stopped|متوقف') { Add "host|$($e.MachineName)|ServiceStops" }
        }
    }
    foreach ($srv in $Config.SqlServers) {
        foreach ($e in (Get-LogBokEvents -LogName 'Application' -Id 18456 -StartTime $Start -ComputerName $srv -Config $Config)) {
            Add "host|$srv|SqlFailures"
        }
    }
    return $m
}

# --- anomaly detection + (optional) baseline update --------------------
function Get-LogBokAnomalies {
    param($Config,[datetime]$Start,[switch]$UpdateBaseline)
    $dir = $Config.Paths.State
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $bfile = Join-Path $dir 'baseline.json'
    $base = @{}
    if (Test-Path $bfile) { try { ((Get-Content $bfile -Raw) | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $base[$_.Name] = @([double[]]$_.Value) } } catch {} }

    $cur = Get-LogBokWindowMetrics -Config $Config -Start $Start
    $findings = @()
    foreach ($k in $cur.Keys) {
        $val = [double]$cur[$k]
        $arr = @(); if ($base.ContainsKey($k)) { $arr = @([double[]]$base[$k]) }
        $metric = ($k -split '\|')[2]
        $floor = if ($script:MetricFloor.ContainsKey($metric)) { $script:MetricFloor[$metric] } else { 5 }
        if ($arr.Count -ge 8) {
            $med = Get-Median $arr
            $mad = Get-MAD $arr $med; if ($mad -eq 0) { $mad = 1 }
            $z = 0.6745 * ($val - $med) / $mad
            if ($z -ge 3.5 -and $val -ge $floor -and $val -gt $med) {
                $parts = $k -split '\|'
                $sev = if ($z -ge 6) { 'Critical' } else { 'Warning' }
                $findings += [pscustomobject]@{
                    Category='Behavior'; Severity=$sev; Machine=$parts[1]; Time=(Get-Date)
                    Title=("رفتار غیرعادی ({0}) | Behavioral anomaly: {0}" -f $metric)
                    Details=("{0}: {1}`nمقدار فعلی/current: {2}  |  میانهٔ معمول/usual median: {3}  |  امتیاز z: {4:N1}`nمتریک: {5}" -f ($parts[0]),$parts[1],$val,$med,$z,$metric)
                    Key=("BEH|{0}|{1}" -f $k,(Get-Date).ToString('yyyyMMddHH',[Globalization.CultureInfo]::InvariantCulture))
                }
            }
        }
        if ($UpdateBaseline) {
            $arr += $val; if ($arr.Count -gt 30) { $arr = $arr[($arr.Count-30)..($arr.Count-1)] }
            $base[$k] = $arr
        }
    }
    # known keys missing in this window are recorded as zero (otherwise the median would inflate)
    if ($UpdateBaseline) {
        foreach ($k in @($base.Keys)) {
            if (-not $cur.ContainsKey($k)) {
                $arr = @([double[]]$base[$k]) + 0
                if ($arr.Count -gt 30) { $arr = $arr[($arr.Count-30)..($arr.Count-1)] }
                $base[$k] = $arr
            }
        }
    }
    if ($UpdateBaseline) {
        $obj = [ordered]@{}
        foreach ($k in $base.Keys) { $obj[$k] = $base[$k] }
        $obj | ConvertTo-Json -Depth 4 | Set-Content -Path $bfile -Encoding UTF8
    }
    return $findings
}

# ===================== suspicious-file scan =============================
# heuristic scoring (no antivirus engine needed). Optional: VirusTotal.
function Get-LogBokFileSuspicion {
    param([Parameter(Mandatory)][string]$Path,$Config)
    $score = 0; $reasons = @()
    $name = Split-Path $Path -Leaf
    if ($name -match '\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|js|vbs|bat|cmd|ps1|pif|com)$') { $score+=45; $reasons+='double-extension' }
    if ($name -match '\.(scr|pif|hta|wsf|vbs|js|jse|bat|cmd)$') { $score+=20; $reasons+='risky-extension' }
    if ($Path -match '\\(Downloads|Temp|AppData|Users\\Public|\$Recycle)') { $score+=15; $reasons+='risky-location' }
    if ($name -match '\.(exe|dll|scr)$') {
        try { $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
              if ($sig.Status -ne 'Valid') { $score+=25; $reasons+='unsigned/invalid-sig' } } catch { $score+=10; $reasons+='sig-unknown' }
    }
    try { $it = Get-Item $Path -Force -ErrorAction Stop
          if ($it.Attributes -band [IO.FileAttributes]::Hidden) { $score+=10; $reasons+='hidden' } } catch {}

    # optional: VirusTotal if a key is configured and network is allowed
    if ($Config -and $Config.VirusTotalApiKey) {
        try {
            $h = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
            $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$h" -Headers @{ 'x-apikey'=$Config.VirusTotalApiKey } -TimeoutSec 15 -ErrorAction Stop
            $mal = [int]$r.data.attributes.last_analysis_stats.malicious
            if ($mal -gt 0) { $score+=100; $reasons+=("VirusTotal:$mal engines") }
        } catch {}
    }
    return [pscustomobject]@{ Path=$Path; Score=$score; Reasons=($reasons -join ',') }
}

# scan recently created files in folders
function Invoke-LogBokFileScan {
    param([string[]]$Folders,[int]$RecentMinutes=120,$Config,[int]$Threshold=40)
    $hits = @()
    $cut = (Get-Date).AddMinutes(-$RecentMinutes)
    foreach ($folder in $Folders) {
        if (-not (Test-Path $folder)) { continue }
        Get-ChildItem -Path $folder -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cut } | ForEach-Object {
                $r = Get-LogBokFileSuspicion -Path $_.FullName -Config $Config
                if ($r.Score -ge $Threshold) { $hits += $r }
            }
    }
    return $hits
}

Export-ModuleMember -Function *
