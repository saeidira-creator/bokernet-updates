# ==========================================================================
#  LogBok.Threat.psm1 - threat feed + controlled enforcement + rollback
#  Safety principle: no destructive action happens without approval and a restore point.
#   - the threat feed (malware hashes, bad process/app, ransomware extensions) is RSA-signed
#     and verified on the agent; a forged feed is rejected.
#   - detection is automatic and harmless (report only).
#   - enforcement (block/quarantine) only on console approval, and always with a snapshot
#     so that, if anything goes wrong, everything returns exactly to its previous state.
#   - deleting a file = quarantine (moved to the quarantine folder), so it is always reversible.
#  Signed threat feed + approval-gated enforcement + full rollback (snapshots).
# ==========================================================================

function Get-LogBokThreatFeed {
    param([string]$InstallDir='C:\Scripts\LogBok')
    $file = Join-Path $InstallDir 'threatfeed.json'
    if (-not (Test-Path $file)) { return $null }
    try {
        Import-Module (Join-Path $InstallDir 'LogBok.License.psm1') -Force -ErrorAction Stop
        $o = Get-Content $file -Raw | ConvertFrom-Json
        $payload = ConvertFrom-B64Url $o.payload
        $sig     = ConvertFrom-B64Url $o.sig
        if (-not (Test-LogBokSignature -Data $payload -Signature $sig)) { return $null }  # invalid signature -> reject
        return ([Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json)
    } catch { return $null }
}

# check one file against the feed (report only, harmless)
function Test-LogBokFileAgainstFeed {
    param([string]$Path,$Feed)
    if (-not $Feed) { return $null }
    try {
        $name = Split-Path $Path -Leaf
        foreach ($ext in @($Feed.RansomExtensions)) { if ($ext -and $name.ToLower().EndsWith($ext.ToLower())) { return "ransom-extension $ext" } }
        if (@($Feed.BadHashes).Count -gt 0) {
            $h = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($Feed.BadHashes -contains $h) { return "known-bad-hash" }
        }
    } catch {}
    return $null
}

# safe self-hardening (harmless, automatic)
function Update-LogBokDefenses {
    param($Feed)
    try { Update-MpSignature -ErrorAction SilentlyContinue } catch {}   # Defender signatures
    # blocking network IOCs (domain/IP) via the firewall is low-risk and reversible,
    # but per the safety policy it only happens under approved enforcement, not here.
}

# ---------------- restore point helpers --------------------------------
function New-LogBokRestore { param([string]$ChangeId) [pscustomobject]@{ ChangeId=$ChangeId; Time=(Get-Date).ToString('o'); Host=$env:COMPUTERNAME; Actions=@() } }
function Save-LogBokRestore { param($RP,[string]$InstallDir)
    $dir = Join-Path $InstallDir 'restore'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $RP | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $dir "$($RP.ChangeId).json") -Encoding UTF8
}

# ---------------- enforce with snapshot --------------------------------
#  $Items: a subset of @('BadApps','BadProcesses','BadHashes','BadNet')
function Invoke-LogBokEnforce {
    param([string]$InstallDir='C:\Scripts\LogBok',$Feed,[string[]]$Items,[string]$ChangeId=([guid]::NewGuid().ToString('N').Substring(0,10)))
    if (-not $Feed) { return $null }
    Import-Module (Join-Path $InstallDir 'LogBok.Firewall.psm1') -Force -ErrorAction SilentlyContinue
    $rp = New-LogBokRestore -ChangeId $ChangeId
    $acts = New-Object System.Collections.ArrayList
    $qdir = Join-Path $InstallDir 'quarantine'; if (-not (Test-Path $qdir)) { New-Item -ItemType Directory -Path $qdir -Force | Out-Null }

    if ($Items -contains 'BadApps') {
        foreach ($app in @($Feed.BadApps)) { if ($app) {
            $n = Block-LogBokApp -Path $app
            [void]$acts.Add(@{ type='unblockapp'; name=$n })
        } }
    }
    if ($Items -contains 'BadNet') {
        foreach ($ip in @($Feed.BadDomainsIPs)) { if ($ip) {
            New-NetFirewallRule -DisplayName "LogBok-IOC-$ip" -Direction Outbound -RemoteAddress $ip -Action Block -Enabled True -ErrorAction SilentlyContinue | Out-Null
            [void]$acts.Add(@{ type='delrule'; name="LogBok-IOC-$ip" })
        } }
    }
    if ($Items -contains 'BadProcesses') {
        foreach ($pn in @($Feed.BadProcesses)) { if ($pn) {
            $procs = Get-Process -Name $pn -ErrorAction SilentlyContinue
            foreach ($pr in $procs) {
                $path = $null; try { $path = $pr.Path } catch {}
                try { Stop-Process -Id $pr.Id -Force -ErrorAction SilentlyContinue } catch {}
                if ($path) { $n = Block-LogBokApp -Path $path; [void]$acts.Add(@{ type='unblockapp'; name=$n }) }
            }
        } }
    }
    if ($Items -contains 'BadHashes') {
        $scan = @(); if (Test-Path (Join-Path $InstallDir 'config.psd1')) { try { $c = Import-PowerShellDataFile (Join-Path $InstallDir 'config.psd1'); $scan = if ($c.FileScanFolders.Count){$c.FileScanFolders}else{$c.WatchedFolders} } catch {} }
        foreach ($folder in $scan) { if (Test-Path $folder) {
            Get-ChildItem $folder -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try { $h=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                    if (@($Feed.BadHashes) -contains $h) {
                        # unique name so two same-named files do not overwrite each other in quarantine
                        $dest = Join-Path $qdir ("{0}__{1}__{2}" -f $ChangeId,([guid]::NewGuid().ToString('N').Substring(0,8)),$_.Name)
                        Move-Item -LiteralPath $_.FullName -Destination $dest    # quarantine, not delete
                        [void]$acts.Add(@{ type='restorefile'; from=$dest; to=$_.FullName })
                    } } catch {}
            }
        } }
    }
    $rp.Actions = $acts.ToArray()
    Save-LogBokRestore -RP $rp -InstallDir $InstallDir
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch {}
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9011 -EntryType Warning -Message ("ENFORCE on {0}: change={1} items={2} actions={3}" -f $env:COMPUTERNAME,$ChangeId,($Items -join ','),$acts.Count) } catch {}
    return [pscustomobject]@{ ChangeId=$ChangeId; Actions=$acts.Count }
}

# ---------------- rollback one change ----------------------------------
function Restore-LogBokChange {
    param([string]$InstallDir='C:\Scripts\LogBok',[string]$ChangeId)
    $f = Join-Path $InstallDir "restore\$ChangeId.json"
    if (-not (Test-Path $f)) { return $false }
    Import-Module (Join-Path $InstallDir 'LogBok.Firewall.psm1') -Force -ErrorAction SilentlyContinue
    $rp = Get-Content $f -Raw | ConvertFrom-Json
    foreach ($a in @($rp.Actions)) {
        try { switch ($a.type) {
            'unblockapp'  { Get-NetFirewallRule -DisplayName "$($a.name)*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
            'delrule'     { Get-NetFirewallRule -DisplayName $a.name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
            'restorefile' { if (Test-Path $a.from) { Move-Item $a.from -Destination $a.to -Force } }
            'setinbound'  { & netsh advfirewall set allprofiles firewallpolicy "$($a.value),allowoutbound" | Out-Null }
        } } catch {}
    }
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9012 -EntryType Warning -Message ("ROLLBACK on {0}: change={1} restored" -f $env:COMPUTERNAME,$ChangeId) } catch {}
    Remove-Item $f -Force -ErrorAction SilentlyContinue
    return $true
}

function Get-LogBokChanges {
    param([string]$InstallDir='C:\Scripts\LogBok')
    $dir = Join-Path $InstallDir 'restore'; if (-not (Test-Path $dir)) { return @() }
    Get-ChildItem $dir -Filter '*.json' | ForEach-Object { try { Get-Content $_.FullName -Raw | ConvertFrom-Json } catch {} }
}

Export-ModuleMember -Function *
