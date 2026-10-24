# ==========================================================================
#  LogBok.AntiRansomware.psm1 - anti-ransomware
#  Three layers:
#   1) enable Windows Defender Controlled Folder Access (native Windows shield)
#   2) canary files in important folders; tampering with them = a ransomware sign
#   3) response: instant email + (optional) automatic system isolation
#  (mass file delete/change detection is also done in LogBok.Detectors.)
#  Anti-ransomware: Defender Controlled Folder Access + canary files +
#  response (instant email + optional auto-isolation).
# ==========================================================================

# 1) Defender Controlled Folder Access
function Enable-LogBokCFA {
    param([string[]]$ProtectedFolders)
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
        foreach ($p in $ProtectedFolders) { if ($p -and (Test-Path $p)) { Add-MpPreference -ControlledFolderAccessProtectedFolders $p -ErrorAction SilentlyContinue } }
        return $true
    } catch { return $false }
}

# 2) deploy canary files
function Deploy-LogBokCanary {
    param([Parameter(Mandatory)][string[]]$Folders,[string]$StateDir=(Join-Path $env:ProgramData 'Agent\state'))
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $canaries = @()
    foreach ($folder in $Folders) {
        if (-not (Test-Path $folder)) { continue }
        # names that sort alphabetically first so ransomware hits them first
        $name = Join-Path $folder '0000_LOGBOK_DO_NOT_DELETE.docx'
        $content = "LogBok canary file. Do not modify or delete. | فایل طعمهٔ لاگ‌بوک؛ تغییر یا حذف نکنید."
        try {
            Set-Content -Path $name -Value $content -Encoding UTF8 -ErrorAction Stop
            (Get-Item $name).Attributes = 'Hidden'
            $hash = (Get-FileHash -Path $name -Algorithm SHA256).Hash
            $canaries += [pscustomobject]@{ Path=$name; Hash=$hash }
        } catch {}
    }
    $canaries | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $StateDir 'canary.json') -Encoding UTF8
    return $canaries
}

# 3) check canaries - returns the tripped list
function Test-LogBokCanary {
    param([string]$StateDir=(Join-Path $env:ProgramData 'Agent\state'))
    $file = Join-Path $StateDir 'canary.json'
    if (-not (Test-Path $file)) { return @() }
    $raw = Get-Content $file -Raw
    if (-not $raw -or -not $raw.Trim()) { return @() }
    $canaries = @($raw | ConvertFrom-Json | ForEach-Object { $_ })
    $tripped = @()
    foreach ($c in $canaries) {
        if (-not $c -or -not $c.Path) { continue }
        if (-not (Test-Path -LiteralPath $c.Path)) { $tripped += [pscustomobject]@{ Path=$c.Path; Reason='deleted' }; continue }
        # a locked file (Word, indexer, antivirus) is not counted as changed - retry a few times
        $now = $null
        for ($i = 0; $i -lt 3 -and -not $now; $i++) {
            try { $now = (Get-FileHash -LiteralPath $c.Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { Start-Sleep -Milliseconds 300 }
        }
        if (-not $now) { continue }
        if ($now -ne $c.Hash) { $tripped += [pscustomobject]@{ Path=$c.Path; Reason='modified' } }
    }
    return $tripped
}

Export-ModuleMember -Function *
