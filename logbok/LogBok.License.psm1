# ==========================================================================
#  LogBok.License.psm1 - license & activation (client side)
#
#  The v2 scheme (same activation method as BokerNet products, with no dependency on them):
#   1) a "device code" is read from this server's hardware (MachineGuid + BIOS
#      serial + system UUID -> SHA256 -> XXXXX-XXXXX-XXXXX-XXXXX). The CPU id is
#      not used because it changes on a VM when the host moves.
#   2) the vendor, via the issuing panel (Tools\LogBok-LicensePanel.ps1), builds a
#      license for that code, company, expiry (permanent/days/date) and per-role seats, and signs it
#      with the RSA-2048 private key.
#   3) the license text is pasted into the activation window -> license.key.
#  The license is locked to that one server and will not work on another. Rolling the
#  system clock back to bypass expiry is detected.
#
#  Old v1 licenses (base64.base64 token, no device lock) issued previously
#  stay valid until their own expiry (Format='legacy') so an upgrade does not
#  break the customer server; all new licenses are v2.
#
#  The public key is embedded below; licenses can't be forged without the
#  vendor private key. v2 licenses are bound to the engine server's device code.
# ==========================================================================

# >>> PUBLIC-KEY-BEGIN  (auto-filled)
$script:PublicKeyXml = @'
<RSAKeyValue><Modulus>1A02iEiVxN6W6NzLWNaWa8D6tbnIVih4ysT/wYt7UC4kLJfyY3oasV8k9DQmG+RXexs7WoSINUVHmm5KMo/o6y0yoGEqESG/EJonF0wqsJ7EK2PEr/2FkiioA9pMVhjydJYa6XzOR08J9slj2r2uwk7HtRnAluL6r5DvqWqkKuTNf1ywYH4MNs3hl0yUfgnh89nVISAwhoFymn1RBIwtWiQArnqqTR+kTHVczcpiRmkY9MjwGuTU2knMCCCe0sT5XlioEzCuyS72fL56cpaRJ3DbY7zlGihTn2caGBZ9CBkdKQ+JrYzepnLXMeSvBrm4lMC5wB+uQRcJf2H1BmQUzQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
'@
# >>> PUBLIC-KEY-END

$script:Header   = 'LOGBOK-LICENSE-2'
$script:Inv      = [Globalization.CultureInfo]::InvariantCulture
$script:DevCache = $null
$script:DeviceCodeOverride = $null   # tests only
$script:SeatRoles = @('Clients','FileServers','IIS','SQL','DomainControllers')

function ConvertFrom-B64Url { param([string]$s)
    $s = $s.Replace('-','+').Replace('_','/'); switch ($s.Length % 4){2{$s+='=='}3{$s+='='}}
    return [Convert]::FromBase64String($s)
}

# ---------------------------------------------------------------------------
#  device code
# ---------------------------------------------------------------------------
function Get-LBMachineGuid {
    try {
        $b = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $k = $b.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
        if ($k) { $v = $k.GetValue('MachineGuid'); $k.Close(); $b.Close(); if ($v) { return [string]$v } }
    } catch { }
    return $null
}
# a WMI value like "v1;v2;"; $null means a read error (not "no value")
function Get-LBWmiValue {
    param([string]$Class, [string]$Prop)
    $objs = $null; $ok = $false
    try { $objs = @(Get-CimInstance -ClassName $Class -ErrorAction Stop); $ok = $true } catch { }
    if (-not $ok -and (Get-Command Get-WmiObject -ErrorAction SilentlyContinue)) {
        try { $objs = @(Get-WmiObject -Class $Class -ErrorAction Stop); $ok = $true } catch { }
    }
    if (-not $ok) { return $null }
    $sb = New-Object System.Text.StringBuilder
    foreach ($o in $objs) { $v = $o.$Prop; if ($null -ne $v) { [void]$sb.Append(([string]$v).Trim()).Append(';') } }
    return $sb.ToString()
}
# device code of this system; $null if the hardware could not be read momentarily
function Get-LogBokDeviceCode {
    if ($script:DeviceCodeOverride) { return $script:DeviceCodeOverride }
    if ($script:DevCache) { return $script:DevCache }
    $guid = Get-LBMachineGuid
    $bios = Get-LBWmiValue -Class 'Win32_BIOS' -Prop 'SerialNumber'
    $uuid = Get-LBWmiValue -Class 'Win32_ComputerSystemProduct' -Prop 'UUID'
    if (-not $guid -or $null -eq $bios -or $null -eq $uuid) { return $null }
    $raw = 'LogBok|' + $guid.Trim().ToLowerInvariant() + '|' + $bios.Trim().ToUpperInvariant() + '|' + $uuid.Trim().ToUpperInvariant()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($raw)) } finally { $sha.Dispose() }
    $hex = (($h[0..9] | ForEach-Object { $_.ToString('X2') }) -join '')
    $script:DevCache = '{0}-{1}-{2}-{3}' -f $hex.Substring(0,5), $hex.Substring(5,5), $hex.Substring(10,5), $hex.Substring(15,5)
    return $script:DevCache
}
function Test-LogBokDeviceCodeFormat { param([string]$Code) return ([string]$Code).Trim().ToUpperInvariant() -match '^[0-9A-F]{5}(-[0-9A-F]{5}){3}$' }

# ---------------------------------------------------------------------------
#  v2 format
# ---------------------------------------------------------------------------
# canonical seats text (sorted keys) - both issuer and validator sign exactly this
function ConvertTo-LBLimitsText {
    param($Limits)
    if (-not $Limits) { return '' }
    $keys = @($Limits.Keys | ForEach-Object { [string]$_ } | Sort-Object)
    return (($keys | ForEach-Object { '{0}={1}' -f $_, [int]$Limits[$_] }) -join ';')
}
function ConvertFrom-LBLimitsText {
    param([string]$Text)
    $h = @{}
    foreach ($p in ([string]$Text -split ';')) {
        if ($p -match '^\s*([A-Za-z]+)\s*=\s*(-?\d+)\s*$') { $h[$Matches[1]] = [int]$Matches[2] }
    }
    return $h
}
# identical normalization for issuer and validator
function ConvertTo-LBCleanLicenseText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return (([string]$Text).TrimStart([char]0xFEFF) -replace '[\u200B\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]', '' -replace '\u00A0', ' ')
}
function Get-LBLicensePayload {
    param([string]$Company, [string]$Device, [string]$Issued, [string]$Expires, [string]$LimitsText, [string]$LicenseId)
    return ('LB2|{0}|{1}|{2}|{3}|{4}|{5}' -f $Company, $Device, $Issued, $Expires, $LimitsText, $LicenseId)
}

# parse the license text (pasted from email/messenger; extra lines ignored)
function ConvertFrom-LBLicenseText {
    param([string]$Text)
    if (-not $Text) { return $null }
    # invisible direction/zero-width marks that Persian messengers add are stripped
    #  (the Persian ZWNJ U+200C is left intact; a non-breaking space becomes a normal space - same as the issuer does)
    $t = ConvertTo-LBCleanLicenseText $Text
    $lines = @($t -split "`r?`n" | ForEach-Object { $_.Trim() })
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -eq $script:Header) { $start = $i; break } }
    if ($start -lt 0) { return $null }
    $o = [ordered]@{ Company=$null; Device=$null; Issued=$null; Expires=$null; Limits=''; LicenseId=''; Sig=$null }
    for ($i = $start + 1; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        $eq = $ln.IndexOf('=')
        if ($eq -lt 1) { continue }
        $k = $ln.Substring(0, $eq).Trim(); $v = $ln.Substring($eq + 1).Trim()
        if ($o.Contains($k) -and -not $o[$k]) { $o[$k] = $v }   # the first value wins
        if ($k -eq 'Sig') {
            # a signature broken across lines (plain-text email ~76 chars) is rejoined
            #  (an RSA-2048 signature is always 344 chars; nothing beyond that is appended, e.g. "Regards")
            for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                if ($o['Sig'].Length -ge 344 -or $o['Sig'].EndsWith('=')) { break }
                if ($lines[$j] -match '^[A-Za-z0-9+/=]+$') { $o['Sig'] += $lines[$j] } else { break }
            }
            break
        }
    }
    if (-not $o.Company -or -not $o.Device -or -not $o.Issued -or -not $o.Expires -or -not $o.Sig) { return $null }
    return [pscustomobject]$o
}

# ---------------------------------------------------------------------------
#  clock roll-back guard (file + registry; the max of both)
# ---------------------------------------------------------------------------
$script:RegKey = 'HKLM:\SOFTWARE\BokerNet\LogBok'
function Get-LBLastSeen {
    param([string]$StateDir)
    $best = [datetime]::MinValue
    $cands = @()
    try { $f = Join-Path $StateDir 'ls.dat'; if (Test-Path $f) { $cands += ([IO.File]::ReadAllText($f)).Trim() } } catch { }
    try { $r = (Get-ItemProperty -Path $script:RegKey -Name 'LastSeen' -ErrorAction Stop).LastSeen; if ($r) { $cands += [string]$r } } catch { }
    foreach ($c in $cands) {
        $d = [datetime]::MinValue
        if ([datetime]::TryParse($c, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) {
            $d = $d.ToUniversalTime(); if ($d -gt $best) { $best = $d }
        }
    }
    return $best
}
function Set-LBLastSeen {
    param([string]$StateDir, [datetime]$Utc)
    $s = $Utc.ToString('o', $script:Inv)
    try { if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }; [IO.File]::WriteAllText((Join-Path $StateDir 'ls.dat'), $s) } catch { }
    try { if (-not (Test-Path $script:RegKey)) { New-Item -Path $script:RegKey -Force | Out-Null }; New-ItemProperty -Path $script:RegKey -Name 'LastSeen' -Value $s -PropertyType String -Force | Out-Null } catch { }
}

# ---------------------------------------------------------------------------
#  full validation
# ---------------------------------------------------------------------------
function Get-LBLicenseFile {
    param([string]$Root)
    foreach ($n in 'license.key','license.lic') { $p = Join-Path $Root $n; if (Test-Path $p) { return $p } }
    return (Join-Path $Root 'license.key')
}

function Test-LogBokLicense {
    param($Config, [string]$Path, [string]$Text, [switch]$NoClockUpdate, [switch]$AllowClockReset)
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $Path -and -not $Text) { $Path = Get-LBLicenseFile -Root $root }
    $stateDir = if ($Config -and $Config.Paths -and $Config.Paths.State) { $Config.Paths.State }
                elseif ($Path) { Join-Path (Split-Path -Parent $Path) 'state' } else { Join-Path $root 'state' }
    $res = [pscustomobject]@{ Valid=$false; Reason='Missing'; Company=$null; Expiry=$null; Issued=$null; LicenseId=$null
                              Limits=@{}; Format=$null; Device=$null; DeviceCode=$null; Permanent=$false; Legacy=$false
                              ExpiryDate=$null; DaysLeft=$null; Path=$Path }
    $res.DeviceCode = Get-LogBokDeviceCode
    if (-not $Text) {
        if (-not $Path -or -not (Test-Path $Path)) { $res.Reason = 'Missing'; return $res }
        try { $Text = [IO.File]::ReadAllText($Path) } catch { $res.Reason = "Error: $($_.Exception.Message)"; return $res }
    }
    try {
        $t = $Text.TrimStart([char]0xFEFF).Trim()
        $exp = $null
        if ($t.Contains($script:Header)) {
            # ---------------- v2 (device-locked) ----------------
            $res.Format = 'v2'
            $L = ConvertFrom-LBLicenseText -Text $t
            if (-not $L) { $res.Reason = 'Malformed'; return $res }
            $payload = Get-LBLicensePayload -Company $L.Company -Device $L.Device -Issued $L.Issued -Expires $L.Expires -LimitsText $L.Limits -LicenseId $L.LicenseId
            $sig = $null; try { $sig = [Convert]::FromBase64String($L.Sig) } catch { $res.Reason = 'Malformed'; return $res }
            if (-not (Test-LogBokSignature -Data ([Text.Encoding]::UTF8.GetBytes($payload)) -Signature $sig)) { $res.Reason = 'BadSignature'; return $res }
            $res.Company = $L.Company; $res.Issued = $L.Issued; $res.LicenseId = $L.LicenseId
            $res.Limits = ConvertFrom-LBLimitsText -Text $L.Limits
            $res.Device = $L.Device.ToUpperInvariant()
            $me = $res.DeviceCode
            if (-not $me) { $res.Reason = 'DeviceUnknown'; return $res }
            if ($me -ne $res.Device) { $res.Reason = 'WrongDevice'; return $res }
            if ($L.Expires -ieq 'never') {
                $res.Permanent = $true; $res.Expiry = 'never'
            } else {
                $d = [datetime]::MinValue
                if (-not [datetime]::TryParseExact($L.Expires, 'yyyy-MM-dd', $script:Inv, [Globalization.DateTimeStyles]::None, [ref]$d)) { $res.Reason = 'Malformed'; return $res }
                $exp = $d
            }
        } else {
            # ---------------- v1 (legacy, no device lock) ----------------
            $res.Format = 'legacy'; $res.Legacy = $true
            $parts = $t.Split('.')
            if ($parts.Count -ne 2) { $res.Reason = 'Malformed'; return $res }
            $payloadBytes = ConvertFrom-B64Url $parts[0]
            $sigBytes     = ConvertFrom-B64Url $parts[1]
            if (-not (Test-LogBokSignature -Data $payloadBytes -Signature $sigBytes)) { $res.Reason = 'BadSignature'; return $res }
            $payload = [Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
            $res.Company = $payload.Company; $res.Issued = $payload.Issued; $res.LicenseId = $payload.LicenseId
            $lim = @{}; foreach ($p in $payload.Limits.PSObject.Properties) { $lim[$p.Name] = [int]$p.Value }
            $res.Limits = $lim
            $e = $payload.Expiry
            if ($e -is [datetime]) { $exp = $e } else {
                $d = [datetime]::MinValue
                if (-not [datetime]::TryParseExact([string]$e, 'yyyy-MM-dd', $script:Inv, [Globalization.DateTimeStyles]::None, [ref]$d)) { $res.Reason = 'Malformed'; return $res }
                $exp = $d
            }
        }

        if ($exp) {
            $res.Expiry = $exp.ToString('yyyy-MM-dd', $script:Inv)
            $res.ExpiryDate = $exp.Date
            $res.DaysLeft = [int]($exp.Date - (Get-Date).Date).TotalDays
            # clock roll-back guard (dated licenses only)
            $nowUtc = (Get-Date).ToUniversalTime()
            $last = Get-LBLastSeen -StateDir $stateDir
            if ($last -ne [datetime]::MinValue -and $nowUtc -lt $last.AddDays(-2)) {
                # a freshly issued license (vendor issue time ~ current clock) means the clock is correct and
                # the "last seen time" is a leftover from a wrong forward clock jump -> reset (activation only)
                $iss = [datetime]::MinValue
                $fresh = $AllowClockReset -and [datetime]::TryParseExact([string]$res.Issued, 'yyyy-MM-dd', $script:Inv, [Globalization.DateTimeStyles]::None, [ref]$iss) -and
                         ([math]::Abs(($nowUtc.Date - $iss.Date).TotalDays) -le 2)
                if (-not $fresh) { $res.Reason = 'ClockRollback'; return $res }
                Set-LBLastSeen -StateDir $stateDir -Utc $nowUtc
                $last = $nowUtc
            }
            if ($exp.Date -lt (Get-Date).Date) { $res.Reason = 'Expired'; return $res }
            if (-not $NoClockUpdate -and ($last -eq [datetime]::MinValue -or $nowUtc -gt $last.AddHours(1))) { Set-LBLastSeen -StateDir $stateDir -Utc $nowUtc }
        }
        $res.Valid = $true; $res.Reason = 'Valid'
        return $res
    } catch { $res.Reason = "Error: $($_.Exception.Message)"; return $res }
}

# install the license text (activation): validate then write license.key
function Install-LogBokLicense {
    param([Parameter(Mandatory)][string]$Text, [string]$Root, $Config)
    if (-not $Root) { $Root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path } }
    # if a file path was given, read its contents
    $txt = $Text
    try { if ($Text.Length -lt 400 -and -not $Text.Contains("`n") -and (Test-Path -LiteralPath $Text -PathType Leaf)) { $txt = [IO.File]::ReadAllText($Text) } } catch { }
    $r = Test-LogBokLicense -Config $Config -Text $txt -NoClockUpdate -AllowClockReset
    if (-not $r.Valid) { return $r }
    # only the license part is stored (extra email text removed)
    $clean = $txt.Trim()
    if ($r.Format -eq 'v2') {
        $L = ConvertFrom-LBLicenseText -Text $txt
        $clean = ($script:Header, "Company=$($L.Company)", "Device=$($L.Device)", "Issued=$($L.Issued)", "Expires=$($L.Expires)", "Limits=$($L.Limits)", "LicenseId=$($L.LicenseId)", "Sig=$($L.Sig)") -join "`r`n"
    }
    $dst = Join-Path $Root 'license.key'
    if (Test-Path $dst) { try { Copy-Item $dst "$dst.bak" -Force } catch { } }
    $tmp = "$dst.tmp"
    [IO.File]::WriteAllText($tmp, $clean + "`r`n", (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $dst -Force
    $old = Join-Path $Root 'license.lic'; if (Test-Path $old) { Remove-Item $old -Force -ErrorAction SilentlyContinue }
    $r.Path = $dst
    return $r
}

# human-readable reason for invalidity (fa / en)
function Get-LogBokLicenseReasonText {
    param($License, [string]$Lang = 'both')
    $code = if ($License.DeviceCode) { $License.DeviceCode } else { '?' }
    $fa = $null; $en = $null
    switch -Wildcard ([string]$License.Reason) {
        'Valid'         { $fa = 'لایسنس معتبر است'; $en = 'License valid' }
        'Missing'       { $fa = "لایسنس نصب نشده است. کد دستگاهِ این سرور: $code"; $en = "No license installed. This server's device code: $code" }
        'Malformed'     { $fa = 'متنِ لایسنس ناقص یا خراب است'; $en = 'License text is incomplete or damaged' }
        'BadSignature'  { $fa = 'امضای لایسنس نامعتبر است (دستکاری‌شده یا از محصولِ دیگر)'; $en = 'Invalid license signature (tampered or from another product)' }
        'WrongDevice'   { $fa = "این لایسنس برای سیستمِ دیگری صادر شده است. کد دستگاهِ این سرور: $code"; $en = "This license belongs to another machine. This server's device code: $code" }
        'DeviceUnknown' { $fa = 'سخت‌افزارِ این سیستم موقتاً خوانده نشد؛ دوباره تلاش می‌شود'; $en = 'Hardware ID temporarily unavailable; will retry' }
        'Expired'       { $fa = "لایسنس در $($License.Expiry) منقضی شده است"; $en = "License expired on $($License.Expiry)" }
        'ClockRollback' { $fa = 'ساعتِ سیستم به عقب برگردانده شده است؛ ساعت را درست کنید'; $en = 'System clock was set back; please correct the clock' }
        default         { $fa = "خطای لایسنس: $($License.Reason)"; $en = "License error: $($License.Reason)" }
    }
    switch ($Lang) { 'fa' { return $fa } 'en' { return $en } default { return "$fa | $en" } }
}

# check one category's seat usage
function Test-LogBokSeat {
    param($License,[string]$Category,[int]$Used)
    if (-not $License.Limits.ContainsKey($Category)) { return $true }  # unlimited if not defined
    return ($Used -le $License.Limits[$Category])
}

# verify a data signature with this product's public key (for the threat feed, etc.)
# verify arbitrary data signed with the vendor private key
function Test-LogBokSignature {
    param([byte[]]$Data,[byte[]]$Signature)
    try {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.PersistKeyInCsp = $false
        $rsa.FromXmlString($script:PublicKeyXml)
        return $rsa.VerifyData($Data,'SHA256',$Signature)
    } catch { return $false }
}

Export-ModuleMember -Function Test-LogBokLicense, Install-LogBokLicense, Get-LogBokDeviceCode, Test-LogBokDeviceCodeFormat, `
    Get-LogBokLicenseReasonText, Test-LogBokSeat, ConvertFrom-B64Url, Test-LogBokSignature, `
    ConvertFrom-LBLicenseText, ConvertTo-LBLimitsText, ConvertFrom-LBLimitsText, Get-LBLicensePayload, Get-LBLicenseFile, ConvertTo-LBCleanLicenseText
