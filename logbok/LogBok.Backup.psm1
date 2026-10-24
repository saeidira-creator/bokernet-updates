# ==========================================================================
#  LogBok.Backup.psm1 — پشتیبان/بازگردانیِ هویتِ ایجنت‌ها و پیکربندیِ استقرار
#  Backup / restore of agent identities + deployment configuration (server migration)
#
#  چرا: رازِ هر ایجنت، توکنِ ثبت‌نام و حساب‌های ذخیره‌شده با DPAPIِ همین سرور قفل‌اند و روی سرورِ دیگر
#  خوانده نمی‌شوند. این ماژول آن‌ها را باز می‌کند، با یک عبارتِ عبور (AES-256 + HMAC) می‌بندد و روی سرورِ
#  تازه دوباره با DPAPIِ همان سرور قفل می‌کند. پس از بازگردانی، ایجنت‌ها بدونِ نصبِ دوباره وصل می‌شوند.
#  Why: per-agent secrets, the enrollment token and saved accounts are DPAPI-locked to THIS server.
#  The bundle unlocks them, seals them with a passphrase (PBKDF2 -> AES-256-CBC + HMAC-SHA256) and
#  the new server re-locks them with its own DPAPI. Agents then continue without a reinstall.
# ==========================================================================
Set-StrictMode -Off
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:Magic = 'LBKB1'
$script:StateFiles = @('agent-enroll.json','agent-keys.json','agent-policies.json','ad-domains.json','workgroups.json','targets.json','settings.json','endpoint-policies.json','inventory.json','agent-actions.json','report-schedules.json')

function Get-LBBackupKeys {
    param([string]$Passphrase, [byte[]]$Salt)
    $k = New-Object Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $Salt, 120000)
    try { return @{ Enc = $k.GetBytes(32); Mac = $k.GetBytes(32) } } finally { $k.Dispose() }
}
# بستهٔ پشتیبان (بایت‌ها) | build the sealed bundle
function New-LBAgentBackup {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$Passphrase, [string]$ServerName = $env:COMPUTERNAME)
    if ($Passphrase.Length -lt 8) { throw 'عبارتِ عبور دست‌کم ۸ نویسه | passphrase must be at least 8 characters' }
    $b = [ordered]@{ v = 1; created = (Get-Date).ToString('o', $script:Inv); server = $ServerName; files = [ordered]@{}; keys = [ordered]@{}; creds = [ordered]@{}; agents = [ordered]@{} }
    foreach ($f in $script:StateFiles) { $p = Join-Path $StateDir $f; if (Test-Path $p) { $b.files[$f] = (Get-Content $p -Raw -Encoding UTF8) } }
    # رازهای ایجنت‌ها: بازشده | agent secrets, unlocked
    $keys = @{}; try { $keys = Get-LBAgentKeys -StateDir $StateDir } catch { }
    foreach ($h in @($keys.Keys)) {
        $r = $keys[$h]; $sec = ''; try { $sec = [string](Get-LBAgentSecret $r) } catch { }
        $pend = ''; if ($r.PendingSecret) { try { $pend = Unprotect-LBMachine ([string]$r.PendingSecret) } catch { } }
        $b.keys[$h] = @{ secret = $sec; pending = $pend }
    }
    # حساب‌های ذخیره‌شده: بازشده | saved credentials, unlocked
    $cd = Join-Path $StateDir 'creds'
    if (Test-Path $cd) { foreach ($cf in (Get-ChildItem -Path $cd -Filter '*.sec' -File)) { $c = Read-LBCredFile -File $cf.FullName; if ($c) { $b.creds[$cf.BaseName] = @{ user = $c.UserName; pass = $c.GetNetworkCredential().Password } } } }
    # وضعیتِ ایجنت‌ها | agent status files
    $ad = Join-Path $StateDir 'agents'
    if (Test-Path $ad) { foreach ($af in (Get-ChildItem -Path $ad -Filter '*.json' -File)) { $b.agents[$af.Name] = (Get-Content $af.FullName -Raw -Encoding UTF8) } }
    $json = ConvertTo-Json -InputObject $b -Depth 12 -Compress
    $ms = New-Object IO.MemoryStream; $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress); $jb = [Text.Encoding]::UTF8.GetBytes($json); $gz.Write($jb, 0, $jb.Length); $gz.Close(); $plain = $ms.ToArray()
    $salt = New-Object byte[] 16; $iv = New-Object byte[] 16; $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider; $rng.GetBytes($salt); $rng.GetBytes($iv)
    $k = Get-LBBackupKeys -Passphrase $Passphrase -Salt $salt
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $k.Enc; $aes.IV = $iv
    $ct = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length); $aes.Dispose()
    $head = [Text.Encoding]::ASCII.GetBytes($script:Magic)
    $body = New-Object byte[] ($head.Length + 32 + $ct.Length); [Array]::Copy($head, 0, $body, 0, $head.Length); [Array]::Copy($salt, 0, $body, $head.Length, 16); [Array]::Copy($iv, 0, $body, $head.Length + 16, 16); [Array]::Copy($ct, 0, $body, $head.Length + 32, $ct.Length)
    $mac = (New-Object Security.Cryptography.HMACSHA256(, $k.Mac)).ComputeHash($body)
    $out = New-Object byte[] ($body.Length + 32); [Array]::Copy($body, 0, $out, 0, $body.Length); [Array]::Copy($mac, 0, $out, $body.Length, 32)
    return [pscustomobject]@{ Bytes = $out; Agents = $b.keys.Count; Creds = $b.creds.Count; Files = $b.files.Count }
}
# بازکردنِ بسته | open a bundle (verifies HMAC, then decrypts)
function Open-LBAgentBackup {
    param([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][string]$Passphrase)
    $hl = $script:Magic.Length
    if ($Bytes.Length -lt $hl + 64 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, $hl) -ne $script:Magic) { throw 'این فایل پشتیبانِ لاگ‌بوک نیست | not a LogBok backup file' }
    $salt = New-Object byte[] 16; [Array]::Copy($Bytes, $hl, $salt, 0, 16)
    $iv = New-Object byte[] 16; [Array]::Copy($Bytes, $hl + 16, $iv, 0, 16)
    $k = Get-LBBackupKeys -Passphrase $Passphrase -Salt $salt
    $bodyLen = $Bytes.Length - 32
    $mac = (New-Object Security.Cryptography.HMACSHA256(, $k.Mac)).ComputeHash($Bytes, 0, $bodyLen)
    $d = 0; for ($i = 0; $i -lt 32; $i++) { $d = $d -bor ($mac[$i] -bxor $Bytes[$bodyLen + $i]) }
    if ($d -ne 0) { throw 'عبارتِ عبور نادرست است یا فایل دست‌کاری شده | wrong passphrase or the file was modified' }
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $k.Enc; $aes.IV = $iv
    $plain = $aes.CreateDecryptor().TransformFinalBlock($Bytes, $hl + 32, $bodyLen - $hl - 32); $aes.Dispose()
    $gz = New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(, $plain)), [IO.Compression.CompressionMode]::Decompress); $sr = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)
    try { return ($sr.ReadToEnd() | ConvertFrom-Json) } finally { $sr.Dispose() }
}
# بازگردانی روی این سرور (قفلِ دوباره با DPAPIِ همین سرور) | restore onto THIS server (re-lock with local DPAPI)
#   Merge: رکوردهای موجود با همان نام جایگزین می‌شوند؛ بقیه می‌مانند | existing entries with the same name are replaced, others kept
function Restore-LBAgentBackup {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][string]$Passphrase, [switch]$Replace)
    $b = Open-LBAgentBackup -Bytes $Bytes -Passphrase $Passphrase
    if ([int]$b.v -ne 1) { throw "unsupported backup version $($b.v)" }
    $n = [ordered]@{ agents = 0; creds = 0; files = 0; from = [string]$b.server; created = [string]$b.created }
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    # ۱) فایل‌های ساده | plain state files (agent-keys handled separately)
    foreach ($p in $b.files.PSObject.Properties) {
        if ($p.Name -eq 'agent-keys.json') { continue }
        if ($p.Name -eq 'settings.json' -and -not $Replace -and (Test-Path (Join-Path $StateDir 'settings.json'))) { continue }   # تنظیماتِ سرورِ تازه نگه داشته می‌شود | keep the new server's own settings unless Replace
        [IO.File]::WriteAllText((Join-Path $StateDir $p.Name), [string]$p.Value, (New-Object Text.UTF8Encoding($false))); $n.files++
    }
    try { $ef = Join-Path $StateDir 'agent-enroll.json'; if (Test-Path $ef) { & icacls.exe $ef /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null } } catch { }
    # ۲) کلیدهای ایجنت‌ها: راز → DPAPIِ این سرور | agent keys: secret -> local DPAPI
    $keys = @{}; if (-not $Replace) { try { $keys = Get-LBAgentKeys -StateDir $StateDir } catch { } }
    $src = @{}; if ($b.files.'agent-keys.json') { try { $src = ConvertTo-LBHashtable ([string]$b.files.'agent-keys.json' | ConvertFrom-Json) } catch { $src = @{} } }
    foreach ($p in $b.keys.PSObject.Properties) {
        $h = $p.Name; $rec = $src[$h]; if (-not $rec) { $rec = @{} }
        if ($p.Value.secret) { $rec.Secret = Protect-LBMachine ([string]$p.Value.secret) } else { $rec.Remove('Secret') }
        if ($p.Value.pending) { $rec.PendingSecret = Protect-LBMachine ([string]$p.Value.pending) } else { $rec.Remove('PendingSecret') }
        $rec.LastTs = ''   # ضدِ تکرار از نو | replay guard restarts on the new server
        $keys[$h] = $rec; $n.agents++
    }
    Save-LBAgentKeys -StateDir $StateDir -Keys $keys
    # ۳) حساب‌ها | credentials
    foreach ($p in $b.creds.PSObject.Properties) {
        $sec = New-Object Security.SecureString; foreach ($ch in ([string]$p.Value.pass).ToCharArray()) { $sec.AppendChar($ch) }
        [void](Set-LBTargetCredential -Name $p.Name -Credential (New-Object Management.Automation.PSCredential([string]$p.Value.user, $sec)) -StateDir $StateDir); $n.creds++
    }
    # ۴) وضعیتِ ایجنت‌ها | agent status files
    $ad = Join-Path $StateDir 'agents'; if (-not (Test-Path $ad)) { New-Item -ItemType Directory -Path $ad -Force | Out-Null }
    foreach ($p in $b.agents.PSObject.Properties) { if ($p.Name -match '^[A-Za-z0-9_.\-]{1,100}\.json$') { [IO.File]::WriteAllText((Join-Path $ad $p.Name), [string]$p.Value, (New-Object Text.UTF8Encoding($false))) } }
    return $n
}
# پشتیبانِ خودکارِ روزانه (از جابِ Connect) | daily automatic backup to a folder/UNC, if configured
function Invoke-LBAutoBackup {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$InstallDir)
    $o = Get-LBSettingsOverlay -StateDir $StateDir
    $bk = $o['Backup']; if (-not ($bk -is [hashtable]) -or -not $bk['PassEnc']) { return $null }
    if (-not $bk['Path'] -and $bk['Email'] -ne $true) { return $null }
    $last = $null; try { if ($bk['LastRun']) { $last = [datetime]::Parse([string]$bk['LastRun'], $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind) } } catch { }
    if ($last -and $last -gt (Get-Date).AddHours(-23)) { return $null }
    $pass = ''; try { $pass = Unprotect-LBMachine ([string]$bk['PassEnc']) } catch { return 'backup: passphrase unreadable' }
    $dir = [string]$bk['Path']; if (-not $dir) { $dir = Join-Path $StateDir 'backups' }   # فقط ایمیل: نسخهٔ محلی در state\backups | email-only: local copy under state\backups
    try {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $r = New-LBAgentBackup -StateDir $StateDir -Passphrase $pass
        $f = Join-Path $dir ("LogBok-Agents-{0}.lbk" -f (Get-Date).ToString('yyyyMMdd-HHmm', $script:Inv))
        [IO.File]::WriteAllBytes($f, $r.Bytes)
        # نگه‌داشتنِ ۱۴ نسخهٔ آخر | keep the last 14
        Get-ChildItem -Path $dir -Filter 'LogBok-Agents-*.lbk' -File | Sort-Object LastWriteTime -Descending | Select-Object -Skip 14 | Remove-Item -Force -ErrorAction SilentlyContinue
        [void](Set-LBSetting -Path 'Backup.LastRun' -Value (Get-Date).ToString('o', $script:Inv) -StateDir $StateDir)
        [void](Set-LBSetting -Path 'Backup.LastFile' -Value $f -StateDir $StateDir); [void](Set-LBSetting -Path 'Backup.LastError' -Value '' -StateDir $StateDir)
        $mailNote = ''
        if ($bk['Email'] -eq $true) {
            # ارسال به ایمیلِ مدیران (پیوستِ رمزگذاری‌شده؛ عبارتِ عبور هرگز در ایمیل نیست) | mail to admins; the file is encrypted, the passphrase is never mailed
            try {
                $cfgM = Get-LogBokConfig -Path (Join-Path $InstallDir 'config.psd1')
                $to = @(@($bk['EmailTo']) | Where-Object { $_ } | ForEach-Object { [string]$_ }); if (-not $to.Count) { $to = @($cfgM.Mail.To) }
                $sub = ("LogBok agent backup - {0} - {1}" -f $env:COMPUTERNAME, (Get-Date).ToString('yyyy-MM-dd HH:mm', $script:Inv))
                $bodyM = ("<p>LogBok daily agent-identity backup from <b>{0}</b>.</p><p>Agents: {1} &middot; Saved accounts: {2} &middot; File: {3}</p><p>The attachment is encrypted; it opens only with the backup passphrase set in the console. Keep it with your other server backups.</p><p dir='rtl'>پشتیبانِ روزانهٔ هویتِ ایجنت‌های لاگ‌بوک از سرورِ {0}. فایل رمزگذاری‌شده است و فقط با عبارتِ عبورِ تنظیم‌شده در کنسول باز می‌شود.</p>" -f $env:COMPUTERNAME, $r.Agents, $r.Creds, [IO.Path]::GetFileName($f))
                Send-LogBokMail -Subject $sub -Body $bodyM -Html -Attachments @($f) -To $to -Config $cfgM
                [void](Set-LBSetting -Path 'Backup.LastMail' -Value (Get-Date).ToString('o', $script:Inv) -StateDir $StateDir); [void](Set-LBSetting -Path 'Backup.LastMailError' -Value '' -StateDir $StateDir)
                $mailNote = (", mailed to {0}" -f ($to -join ', '))
            } catch { [void](Set-LBSetting -Path 'Backup.LastMailError' -Value $_.Exception.Message -StateDir $StateDir); $mailNote = (", mail failed: {0}" -f $_.Exception.Message) }
        }
        return ("backup: {0} ({1} agents){2}" -f $f, $r.Agents, $mailNote)
    } catch { [void](Set-LBSetting -Path 'Backup.LastError' -Value $_.Exception.Message -StateDir $StateDir); return ("backup failed: {0}" -f $_.Exception.Message) }
}
Export-ModuleMember -Function New-LBAgentBackup, Open-LBAgentBackup, Restore-LBAgentBackup, Invoke-LBAutoBackup
