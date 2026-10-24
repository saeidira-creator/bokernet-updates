# ==========================================================================
#  LogBok.WebAuth.psm1 — ورود به کنسول (کاربر/رمزِ داخلی + حساب‌های ویندوز)
#  Console login: console-managed users (PBKDF2) AND Windows accounts, with
#  cookie sessions, failed-login lockout, and roles (admin / viewer).
#
#  Everything is file-backed under state\ and cached in the shared worker
#  hashtable, so it survives a web-job restart and works across all workers.
# ==========================================================================

# --- paths ------------------------------------------------------------------
function Get-LBAuthDir {
    param([string]$StateDir)
    $d = Join-Path $StateDir 'auth'
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}
function Get-LBUsersPath    { param([string]$StateDir) Join-Path (Get-LBAuthDir $StateDir) 'users.json' }
function Get-LBSessionsPath { param([string]$StateDir) Join-Path (Get-LBAuthDir $StateDir) 'sessions.json' }
function Get-LBLockPath     { param([string]$StateDir) Join-Path (Get-LBAuthDir $StateDir) 'lockout.json' }

function Get-LBAuthConfig {
    param($Config)
    $w = $null; try { $w = $Config.Web } catch { }
    $lg = $null; try { $lg = $w.Login } catch { }
    return [ordered]@{
        Enabled      = $(if ($lg -and $lg.Enabled -eq $false) { $false } else { $true })
        Mode         = $(if ($lg -and [string]$lg.Mode) { [string]$lg.Mode } else { 'both' })   # console | windows | both
        SessionHours = $(if ($lg -and [int]$lg.SessionHours -gt 0) { [int]$lg.SessionHours } else { 12 })
        MaxFails     = $(if ($lg -and [int]$lg.MaxFails -gt 0) { [int]$lg.MaxFails } else { 5 })
        LockMinutes  = $(if ($lg -and [int]$lg.LockMinutes -gt 0) { [int]$lg.LockMinutes } else { 15 })
    }
}

# --- small JSON helpers (atomic write) --------------------------------------
function Read-LBJsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}
function Write-LBJsonFile {
    param([string]$Path, $Obj)
    $json = $Obj | ConvertTo-Json -Depth 8
    $tmp = "$Path.tmp"
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

# --- password hashing (PBKDF2-SHA256) ---------------------------------------
function New-LBPwHash {
    param([string]$Password, [int]$Iterations = 120000)
    $salt = New-Object byte[] 16; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt)
    $k = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, $Iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
    try { $hash = $k.GetBytes(32) } finally { $k.Dispose() }
    return ('pbkdf2${0}${1}${2}' -f $Iterations, [Convert]::ToBase64String($salt), [Convert]::ToBase64String($hash))
}
function Test-LBPwHash {
    param([string]$Password, [string]$Stored)
    try {
        $p = $Stored -split '\$'
        if ($p.Count -ne 4 -or $p[0] -ne 'pbkdf2') { return $false }
        $iter = [int]$p[1]; $salt = [Convert]::FromBase64String($p[2]); $want = [Convert]::FromBase64String($p[3])
        $k = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, $iter, [Security.Cryptography.HashAlgorithmName]::SHA256)
        try { $got = $k.GetBytes($want.Length) } finally { $k.Dispose() }
        # constant-time compare
        if ($got.Length -ne $want.Length) { return $false }
        $diff = 0; for ($i = 0; $i -lt $want.Length; $i++) { $diff = $diff -bor ($got[$i] -bxor $want[$i]) }
        return ($diff -eq 0)
    } catch { return $false }
}

# --- user store -------------------------------------------------------------
function Read-LBWebUsers {
    param([string]$StateDir)
    $o = Read-LBJsonFile (Get-LBUsersPath $StateDir)
    $list = @()
    if ($o -and $o.users) { $list = @($o.users) }
    return $list
}
function Save-LBWebUsers {
    param([string]$StateDir, $Users)
    Write-LBJsonFile (Get-LBUsersPath $StateDir) ([ordered]@{ users = @($Users) })
}
function Get-LBWebUser {
    param([string]$StateDir, [string]$Name)
    $n = ([string]$Name).Trim().ToLowerInvariant()
    foreach ($u in (Read-LBWebUsers $StateDir)) { if (([string]$u.name).ToLowerInvariant() -eq $n) { return $u } }
    return $null
}
function Test-LBNeedsSetup {
    param([string]$StateDir)
    return (@(Read-LBWebUsers $StateDir).Count -eq 0)
}
function Add-LBWebUser {
    param([string]$StateDir, [string]$Name, [string]$Password, [string]$Role = 'admin')
    $n = ([string]$Name).Trim()
    if ($n -notmatch '^[A-Za-z0-9._\-\\@ ]{2,64}$') { throw 'نامِ کاربری نامعتبر است | invalid username' }
    if (([string]$Password).Length -lt 6) { throw 'رمز حداقل ۶ نویسه | password must be at least 6 characters' }
    if ($Role -ne 'admin' -and $Role -ne 'viewer') { $Role = 'viewer' }
    $users = @(Read-LBWebUsers $StateDir)
    if ($users | Where-Object { ([string]$_.name).ToLowerInvariant() -eq $n.ToLowerInvariant() }) { throw 'این کاربر از قبل هست | user already exists' }
    $users += [ordered]@{ name = $n; hash = (New-LBPwHash $Password); role = $Role; disabled = $false; created = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    Save-LBWebUsers $StateDir $users
    return $true
}
function Set-LBWebUserPassword {
    param([string]$StateDir, [string]$Name, [string]$Password)
    if (([string]$Password).Length -lt 6) { throw 'رمز حداقل ۶ نویسه | password must be at least 6 characters' }
    $users = @(Read-LBWebUsers $StateDir); $found = $false
    foreach ($u in $users) { if (([string]$u.name).ToLowerInvariant() -eq ([string]$Name).ToLowerInvariant()) { $u.hash = (New-LBPwHash $Password); $found = $true } }
    if (-not $found) { throw 'کاربر یافت نشد | user not found' }
    Save-LBWebUsers $StateDir $users; return $true
}
function Set-LBWebUserState {
    param([string]$StateDir, [string]$Name, [string]$Role, [Nullable[bool]]$Disabled)
    $users = @(Read-LBWebUsers $StateDir); $found = $false
    foreach ($u in $users) {
        if (([string]$u.name).ToLowerInvariant() -eq ([string]$Name).ToLowerInvariant()) {
            if ($Role -and ($Role -eq 'admin' -or $Role -eq 'viewer')) { $u.role = $Role }
            if ($null -ne $Disabled) { $u.disabled = [bool]$Disabled }
            $found = $true
        }
    }
    if (-not $found) { throw 'کاربر یافت نشد | user not found' }
    # never leave zero enabled admins
    if (-not (@($users | Where-Object { [string]$_.role -eq 'admin' -and -not $_.disabled }).Count)) { throw 'حداقل یک مدیرِ فعال لازم است | at least one active admin is required' }
    Save-LBWebUsers $StateDir $users; return $true
}
function Remove-LBWebUser {
    param([string]$StateDir, [string]$Name)
    $users = @(Read-LBWebUsers $StateDir | Where-Object { ([string]$_.name).ToLowerInvariant() -ne ([string]$Name).ToLowerInvariant() })
    if (-not (@($users | Where-Object { [string]$_.role -eq 'admin' -and -not $_.disabled }).Count)) { throw 'آخرین مدیر را نمی‌توان حذف کرد | cannot remove the last admin' }
    Save-LBWebUsers $StateDir $users; return $true
}
function Get-LBWebUserList {
    param([string]$StateDir)
    return @(Read-LBWebUsers $StateDir | ForEach-Object { [ordered]@{ name = [string]$_.name; role = [string]$_.role; disabled = [bool]$_.disabled; created = [string]$_.created; email = [string]$_.email; totpEnabled = [bool]$_.totpEnabled; emailEnabled = [bool]$_.emailEnabled; twofa = ([bool]$_.totpEnabled -or [bool]$_.emailEnabled) } })
}

# --- Windows account validation ---------------------------------------------
#  Validates a username/password against the local machine and (if joined) the
#  domain, then authorizes only local Administrators or configured AllowedUsers.
function Test-LBWindowsLogin {
    param([string]$User, [string]$Password, $Config)
    $res = [ordered]@{ ok = $false; name = $User; role = 'admin' }
    if (-not $User -or -not $Password) { return $res }
    try { Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop } catch { return $res }
    $valid = $false; $resolved = $User
    # strip DOMAIN\ or machine\ prefix for the machine check
    $bare = $User; if ($User -match '\\') { $bare = ($User -split '\\')[-1] }
    foreach ($ctxKind in @('Machine', 'Domain')) {
        try {
            if ($ctxKind -eq 'Domain') {
                $joined = $false; try { $joined = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain } catch { }
                if (-not $joined) { continue }
            }
            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$ctxKind)
            try {
                $u = if ($ctxKind -eq 'Machine') { $bare } else { $User }
                if ($ctx.ValidateCredentials($u, $Password)) { $valid = $true; $resolved = $u; break }
            } finally { $ctx.Dispose() }
        } catch { }
    }
    if (-not $valid) { return $res }
    # authorization: local Administrators membership OR AllowedUsers in config
    $authorized = $false
    try {
        $members = @()
        try { $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch {
            try { $g = [ADSI]"WinNT://./Administrators,group"; $members = @($g.psbase.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) }) } catch { }
        }
        $short = ($resolved -split '\\')[-1]
        foreach ($m in $members) { $ms = ($m -split '\\')[-1]; if ($ms -and ($ms -eq $short)) { $authorized = $true; break } }
    } catch { }
    if (-not $authorized) {
        try {
            $au = @(); if ($Config.Web -and $Config.Web.AllowedUsers) { $au = @($Config.Web.AllowedUsers | ForEach-Object { ([string]$_ -split '\\')[-1] }) }
            $short = ($resolved -split '\\')[-1]
            if ($au -contains $short) { $authorized = $true }
        } catch { }
    }
    if (-not $authorized) { $res.role = 'denied'; return $res }
    $res.ok = $true; $res.name = $resolved; $res.role = 'admin'
    return $res
}

# --- lockout (per user+ip) --------------------------------------------------
function Test-LBLoginLock {
    param([string]$StateDir, [string]$Key, $Config)
    $ac = Get-LBAuthConfig $Config
    $o = Read-LBJsonFile (Get-LBLockPath $StateDir); if (-not $o) { return @{ locked = $false; wait = 0 } }
    $e = $o.$Key; if (-not $e) { return @{ locked = $false; wait = 0 } }
    if ([int]$e.fails -lt $ac.MaxFails) { return @{ locked = $false; wait = 0 } }
    $until = ConvertTo-LBDate ([string]$e.until)
    if ($until -and $until -gt (Get-Date)) { return @{ locked = $true; wait = [int]([math]::Ceiling(($until - (Get-Date)).TotalSeconds)) } }
    return @{ locked = $false; wait = 0 }
}
function Add-LBLoginFail {
    param([string]$StateDir, [string]$Key, $Config)
    $ac = Get-LBAuthConfig $Config
    $o = Read-LBJsonFile (Get-LBLockPath $StateDir); if (-not $o) { $o = [pscustomobject]@{} }
    $h = @{}; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value }
    $cur = $h[$Key]; $fails = 1
    if ($cur) { $fails = [int]$cur.fails + 1 }
    $until = ''; if ($fails -ge $ac.MaxFails) { $until = (Get-Date).AddMinutes($ac.LockMinutes).ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    $h[$Key] = [ordered]@{ fails = $fails; until = $until }
    Write-LBJsonFile (Get-LBLockPath $StateDir) ([pscustomobject]$h)
}
function Clear-LBLoginFail {
    param([string]$StateDir, [string]$Key)
    $o = Read-LBJsonFile (Get-LBLockPath $StateDir); if (-not $o) { return }
    $h = @{}; foreach ($p in $o.PSObject.Properties) { if ($p.Name -ne $Key) { $h[$p.Name] = $p.Value } }
    Write-LBJsonFile (Get-LBLockPath $StateDir) ([pscustomobject]$h)
}

# --- sessions (cookie) ------------------------------------------------------
function Read-LBSessions  { param([string]$StateDir) $o = Read-LBJsonFile (Get-LBSessionsPath $StateDir); if (-not $o) { return @{} }; $h = @{}; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value }; return $h }
function Save-LBSessions  { param([string]$StateDir, $H) Write-LBJsonFile (Get-LBSessionsPath $StateDir) ([pscustomobject]$H) }
function New-LBWebSession {
    param([string]$StateDir, [string]$User, [string]$Role, [string]$Via, $Config, [string]$Ip, [int]$Days = 0)
    $ac = Get-LBAuthConfig $Config
    $b = New-Object byte[] 32; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
    $id = -join ($b | ForEach-Object { $_.ToString('x2') })
    $h = Read-LBSessions $StateDir
    # prune expired
    $now = Get-Date
    foreach ($k in @($h.Keys)) { $ex = ConvertTo-LBDate ([string]$h[$k].expires); if (-not $ex -or $ex -lt $now) { $h.Remove($k) } }
    # «مرا به‌خاطر بسپار»: پس از یک احرازِ کامل، نشست تا N روز معتبر می‌ماند (۱۸۰/۳۶۰ روز هم پذیرفته می‌شود)
    $exp = if ($Days -gt 0) { $now.AddDays([math]::Min(730, $Days)) } else { $now.AddHours($ac.SessionHours) }
    $h[$id] = [ordered]@{ user = $User; role = $Role; via = $Via; ip = $Ip; created = $now.ToString('o', [Globalization.CultureInfo]::InvariantCulture); expires = $exp.ToString('o', [Globalization.CultureInfo]::InvariantCulture); days = $Days }
    Save-LBSessions $StateDir $h
    return $id
}
function Get-LBWebSession {
    param([string]$StateDir, [string]$Id, $Config, [switch]$Slide)
    if (-not $Id -or $Id -notmatch '^[0-9a-f]{64}$') { return $null }
    $h = Read-LBSessions $StateDir; $e = $h[$Id]; if (-not $e) { return $null }
    $ex = ConvertTo-LBDate ([string]$e.expires); if (-not $ex -or $ex -lt (Get-Date)) { $h.Remove($Id); Save-LBSessions $StateDir $h; return $null }
    if ($Slide) {
        $ac = Get-LBAuthConfig $Config
        $e.expires = (Get-Date).AddHours($ac.SessionHours).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $h[$Id] = $e; try { Save-LBSessions $StateDir $h } catch { }
    }
    return $e
}
function Remove-LBWebSession {
    param([string]$StateDir, [string]$Id)
    $h = Read-LBSessions $StateDir; if ($h.ContainsKey($Id)) { $h.Remove($Id); Save-LBSessions $StateDir $h }
}

# ============================ احراز هویتِ دومرحله‌ای | 2FA =============================
#  TOTP (Google Authenticator) کاملاً آفلاین کار می‌کند — بدونِ اینترنت.
#  کدِ ایمیلی، جایگزینِ آنلاین است و با SMTP محصول فرستاده می‌شود.
function Update-LBWebUserField {
    param([string]$StateDir, [string]$Name, [hashtable]$Fields)
    $users = @(Read-LBWebUsers $StateDir); $found = $false
    foreach ($u in $users) {
        if (([string]$u.name).ToLowerInvariant() -eq ([string]$Name).ToLowerInvariant()) {
            foreach ($k in $Fields.Keys) { $u | Add-Member -NotePropertyName $k -NotePropertyValue $Fields[$k] -Force }
            $found = $true
        }
    }
    if (-not $found) { throw 'کاربر یافت نشد | user not found' }
    Save-LBWebUsers $StateDir $users
}
# ---- base32 (RFC4648) ----
$script:LBB32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function New-LBBase32Secret {
    param([int]$Bytes = 20)
    $b = New-Object byte[] $Bytes; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
    $bits = ''; foreach ($x in $b) { $bits += [Convert]::ToString($x, 2).PadLeft(8, '0') }
    $out = ''; for ($i = 0; $i + 5 -le $bits.Length; $i += 5) { $out += $script:LBB32[[Convert]::ToInt32($bits.Substring($i, 5), 2)] }
    return $out
}
function ConvertFrom-LBBase32 {
    param([string]$S)
    $s = ($S -replace '=', '').ToUpperInvariant() -replace '[^A-Z2-7]', ''
    $bits = ''; foreach ($c in $s.ToCharArray()) { $v = $script:LBB32.IndexOf($c); if ($v -lt 0) { continue }; $bits += [Convert]::ToString($v, 2).PadLeft(5, '0') }
    $bytes = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i + 8 -le $bits.Length; $i += 8) { [void]$bytes.Add([Convert]::ToByte($bits.Substring($i, 8), 2)) }
    return , $bytes.ToArray()
}
# ---- TOTP (RFC6238, SHA1, 6 رقم، هر ۳۰ ثانیه) ----
function Get-LBTotpCode {
    param([string]$Base32Secret, [long]$Counter)
    $key = ConvertFrom-LBBase32 $Base32Secret
    $msg = [BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder([long]$Counter))
    $hmac = New-Object Security.Cryptography.HMACSHA1; $hmac.Key = $key
    $hash = $hmac.ComputeHash($msg)
    $off = $hash[$hash.Length - 1] -band 0x0f
    $bin = ((([int]$hash[$off]) -band 0x7f) -shl 24) -bor ((([int]$hash[$off + 1]) -band 0xff) -shl 16) -bor ((([int]$hash[$off + 2]) -band 0xff) -shl 8) -bor (([int]$hash[$off + 3]) -band 0xff)
    return ('{0:D6}' -f ($bin % 1000000))
}
function Test-LBTotp {
    param([string]$Secret, [string]$Code, [int]$Window = 1)
    $c = ($Code -replace '\D', ''); if ($c.Length -ne 6) { return $false }
    $step = [long][math]::Floor(((Get-Date).ToUniversalTime() - (Get-Date '1970-01-01Z').ToUniversalTime()).TotalSeconds / 30)
    for ($i = -$Window; $i -le $Window; $i++) { if ((Get-LBTotpCode -Base32Secret $Secret -Counter ($step + $i)) -eq $c) { return $true } }
    return $false
}
function Get-LBTotpUri {
    param([string]$User, [string]$Secret, [string]$Issuer = 'LogBok')
    $label = [Uri]::EscapeDataString(($Issuer + ':' + $User))
    return ('otpauth://totp/{0}?secret={1}&issuer={2}&digits=6&period=30' -f $label, $Secret, [Uri]::EscapeDataString($Issuer))
}
# ---- ثبت و مدیریت | enroll / manage ----
function Start-LBUserTotp {
    param([string]$StateDir, [string]$Name)
    $u = Get-LBWebUser -StateDir $StateDir -Name $Name; if (-not $u) { throw 'کاربر یافت نشد | user not found' }
    $secret = New-LBBase32Secret 20
    Update-LBWebUserField -StateDir $StateDir -Name $Name -Fields @{ totpSecretPending = $secret }
    return [ordered]@{ secret = $secret; uri = (Get-LBTotpUri -User $Name -Secret $secret) }
}
function Confirm-LBUserTotp {
    param([string]$StateDir, [string]$Name, [string]$Code)
    $u = Get-LBWebUser -StateDir $StateDir -Name $Name; if (-not $u) { throw 'کاربر یافت نشد | user not found' }
    $sec = [string]$u.totpSecretPending; if (-not $sec) { throw 'ابتدا کدِ مخفی را بساز | start TOTP setup first' }
    if (-not (Test-LBTotp -Secret $sec -Code $Code)) { throw 'کدِ واردشده درست نیست | the code is not valid' }
    Update-LBWebUserField -StateDir $StateDir -Name $Name -Fields @{ totpSecret = $sec; totpEnabled = $true; totpSecretPending = '' }
    return $true
}
function Set-LBUserEmail2FA {
    param([string]$StateDir, [string]$Name, [string]$Email, [bool]$Enable)
    $u = Get-LBWebUser -StateDir $StateDir -Name $Name; if (-not $u) { throw 'کاربر یافت نشد | user not found' }
    if ($Enable -and $Email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw 'آدرسِ ایمیل نامعتبر | invalid email address' }
    $f = @{ emailEnabled = [bool]$Enable }; if ($Email) { $f['email'] = $Email }
    Update-LBWebUserField -StateDir $StateDir -Name $Name -Fields $f
    return $true
}
function Disable-LBUser2FA {
    param([string]$StateDir, [string]$Name, [string]$Which = 'all')
    $f = @{}
    if ($Which -eq 'all' -or $Which -eq 'totp') { $f['totpEnabled'] = $false; $f['totpSecret'] = ''; $f['totpSecretPending'] = '' }
    if ($Which -eq 'all' -or $Which -eq 'email') { $f['emailEnabled'] = $false }
    Update-LBWebUserField -StateDir $StateDir -Name $Name -Fields $f
    return $true
}
function Get-LBUser2FA {
    param([string]$StateDir, [string]$Name)
    $u = Get-LBWebUser -StateDir $StateDir -Name $Name
    if (-not $u) { return [ordered]@{ totp = $false; email = $false; emailAddr = ''; on = $false } }
    return [ordered]@{ totp = [bool]$u.totpEnabled; email = [bool]$u.emailEnabled; emailAddr = [string]$u.email; on = ([bool]$u.totpEnabled -or [bool]$u.emailEnabled) }
}
# ---- بلیتِ کوتاه‌عمرِ مرحلهٔ دوم | short-lived 2FA login ticket ----
function Get-LBTicketsPath { param([string]$StateDir) Join-Path (Get-LBAuthDir $StateDir) 'twofa-tickets.json' }
function New-LB2FATicket {
    param([string]$StateDir, [string]$User, [string]$Role, [int]$TtlMin = 5)
    $b = New-Object byte[] 24; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
    $id = -join ($b | ForEach-Object { $_.ToString('x2') })
    $o = Read-LBJsonFile (Get-LBTicketsPath $StateDir); $h = @{}; if ($o) { foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $now = Get-Date
    foreach ($k in @($h.Keys)) { $ex = ConvertTo-LBDate ([string]$h[$k].expires); if (-not $ex -or $ex -lt $now) { $h.Remove($k) } }
    $h[$id] = [ordered]@{ user = $User; role = $Role; expires = $now.AddMinutes($TtlMin).ToString('o', [Globalization.CultureInfo]::InvariantCulture); emailHash = ''; emailExp = '' }
    Write-LBJsonFile (Get-LBTicketsPath $StateDir) ([pscustomobject]$h)
    return $id
}
function Get-LB2FATicket {
    param([string]$StateDir, [string]$Id)
    if (-not $Id -or $Id -notmatch '^[0-9a-f]{48}$') { return $null }
    $o = Read-LBJsonFile (Get-LBTicketsPath $StateDir); if (-not $o) { return $null }
    $e = $o.$Id; if (-not $e) { return $null }
    $ex = ConvertTo-LBDate ([string]$e.expires); if (-not $ex -or $ex -lt (Get-Date)) { return $null }
    return $e
}
function Set-LB2FATicketEmail {
    param([string]$StateDir, [string]$Id, [string]$CodeHash, [datetime]$Expires)
    $o = Read-LBJsonFile (Get-LBTicketsPath $StateDir); if (-not $o) { return }
    $h = @{}; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value }
    if (-not $h.ContainsKey($Id)) { return }
    $e = $h[$Id]; $e.emailHash = $CodeHash; $e.emailExp = $Expires.ToString('o', [Globalization.CultureInfo]::InvariantCulture); $h[$Id] = $e
    Write-LBJsonFile (Get-LBTicketsPath $StateDir) ([pscustomobject]$h)
}
function Remove-LB2FATicket {
    param([string]$StateDir, [string]$Id)
    $o = Read-LBJsonFile (Get-LBTicketsPath $StateDir); if (-not $o) { return }
    $h = @{}; foreach ($p in $o.PSObject.Properties) { if ($p.Name -ne $Id) { $h[$p.Name] = $p.Value } }
    Write-LBJsonFile (Get-LBTicketsPath $StateDir) ([pscustomobject]$h)
}
function Send-LBEmailOtp {
    param([string]$StateDir, [string]$Id, [string]$Email, $Config)
    $code = ('{0:D6}' -f (Get-Random -Minimum 0 -Maximum 1000000))
    Set-LB2FATicketEmail -StateDir $StateDir -Id $Id -CodeHash (New-LBPwHash $code) -Expires (Get-Date).AddMinutes(5)
    $body = "کدِ ورودِ یک‌بارمصرفِ LogBok: $code`r`n`r`nLogBok one-time sign-in code: $code`r`n(۵ دقیقه معتبر | valid for 5 minutes)"
    try { Send-LogBokMail -Subject 'کدِ ورود | sign-in code' -Body $body -To @($Email) -Config $Config | Out-Null; return $true } catch { return $false }
}
function Test-LB2FACode {
    param([string]$StateDir, $Ticket, [string]$Code, [string]$Method)
    $user = [string]$Ticket.user
    if ($Method -eq 'email') {
        $hash = [string]$Ticket.emailHash; $exp = ConvertTo-LBDate ([string]$Ticket.emailExp)
        if (-not $hash -or -not $exp -or $exp -lt (Get-Date)) { return $false }
        return (Test-LBPwHash ($Code -replace '\D', '') $hash)
    }
    $u = Get-LBWebUser -StateDir $StateDir -Name $user; if (-not $u -or -not $u.totpEnabled) { return $false }
    return (Test-LBTotp -Secret ([string]$u.totpSecret) -Code $Code)
}

# parse the lbsid cookie out of the Cookie header
function Get-LBCookie {
    param($Request, [string]$Name)
    try {
        $c = $Request.Headers['Cookie']; if (-not $c) { return '' }
        foreach ($part in ($c -split ';')) { $kv = $part.Trim(); $i = $kv.IndexOf('='); if ($i -gt 0 -and $kv.Substring(0, $i) -eq $Name) { return $kv.Substring($i + 1) } }
    } catch { }
    return ''
}

Export-ModuleMember -Function *
