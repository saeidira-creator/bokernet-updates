# ==========================================================================
#  LogBok.Remote.psm1 — دسترسیِ راه‌دور به کنسول (LAN / اینترنت با NAT)
#  Remote access to the console: Local-only, LAN, or Internet (UPnP NAT).
#
#  امنیت: ورود + احراز دومرحله‌ای همیشه روشن می‌ماند و قفلِ تلاشِ ناموفق فعال
#  است. چون ترافیک HTTP است، برای اینترنت توصیه می‌شود ۲FA روشن باشد و در صورت
#  امکان فهرستِ IPهای مجاز تنظیم شود.
# ==========================================================================

function Get-LBLocalIPv4 {
    try {
        $c = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
        if ($c -and $c.IPv4Address) { return [string]$c.IPv4Address.IPAddress }
    } catch { }
    try {
        $a = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1
        if ($a) { return [string]$a.IPAddress }
    } catch { }
    return ''
}

function Get-LBPublicIP {
    foreach ($u in @('https://api.ipify.org', 'https://ifconfig.me/ip', 'https://ipv4.icanhazip.com')) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $ip = (Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 8).Content.Trim()
            if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { return $ip }
        } catch { }
    }
    return ''
}

# --- UPnP NAT (port-forward روی روتر) ---
function Get-LBNatCollection {
    try { $nat = New-Object -ComObject HNetCfg.NATUPnP; return $nat.StaticPortMappingCollection } catch { return $null }
}
function Get-LBNatMapping {
    param([int]$ExternalPort)
    $col = Get-LBNatCollection; if ($null -eq $col) { return $null }
    try { foreach ($m in $col) { if ([int]$m.ExternalPort -eq $ExternalPort -and [string]$m.Protocol -eq 'TCP') { return [ordered]@{ external = [int]$m.ExternalPort; internal = [int]$m.InternalPort; client = [string]$m.InternalClient; enabled = [bool]$m.Enabled } } } } catch { }
    return $null
}
function Add-LBNatMapping {
    param([int]$ExternalPort, [int]$InternalPort, [string]$LocalIp, [string]$Desc = 'LogBok Console')
    $col = Get-LBNatCollection
    if ($null -eq $col) { return [ordered]@{ ok = $false; reason = 'router UPnP not available / روتر از UPnP پشتیبانی نمی‌کند یا خاموش است' } }
    try { $col.Remove($ExternalPort, 'TCP') } catch { }
    try { $col.Add($ExternalPort, 'TCP', $InternalPort, $LocalIp, $true, $Desc); return [ordered]@{ ok = $true } }
    catch { return [ordered]@{ ok = $false; reason = [string]$_.Exception.Message } }
}
function Remove-LBNatMapping {
    param([int]$ExternalPort)
    $col = Get-LBNatCollection; if ($null -eq $col) { return $false }
    try { $col.Remove($ExternalPort, 'TCP'); return $true } catch { return $false }
}

# --- فایروالِ ویندوز برای پورتِ کنسول ---
function Set-LBWebFirewall {
    param([int]$Port, [bool]$Enable, [string[]]$AllowedIps)
    $name = 'LogBok Console'
    try { Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch { }
    if ($Enable) {
        $p = @{ DisplayName = $name; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = $Port; Profile = 'Any' }
        $ips = @($AllowedIps | Where-Object { $_ })
        if ($ips.Count) { $p['RemoteAddress'] = $ips }
        try { New-NetFirewallRule @p | Out-Null } catch { return $false }
    }
    return $true
}
function Test-LBWebFirewall {
    try { return [bool](Get-NetFirewallRule -DisplayName 'LogBok Console' -ErrorAction SilentlyContinue) } catch { return $false }
}

# --- وضعیت و اعمال ---
function Get-LBRemoteStatus {
    param($Config)
    $port = 8686; try { if ($Config.Web -and $Config.Web.Port) { $port = [int]$Config.Web.Port } } catch { }
    $listen = 'local'; try { if ([string]$Config.Web.Listen -eq 'lan') { $listen = 'lan' } } catch { }
    $rm = $null; try { $rm = $Config.Web.Remote } catch { }
    $mode = 'local'; try { if ($rm -and [string]$rm.Mode) { $mode = [string]$rm.Mode } elseif ($listen -eq 'lan') { $mode = 'lan' } } catch { }
    $ext = $port; try { if ($rm -and [int]$rm.ExternalPort -gt 0) { $ext = [int]$rm.ExternalPort } } catch { }
    $ips = @(); try { if ($rm -and $rm.AllowedIps) { $ips = @($rm.AllowedIps) } } catch { }
    $localIp = Get-LBLocalIPv4
    $nat = $null; if ($mode -eq 'internet') { $nat = Get-LBNatMapping -ExternalPort $ext }
    $pub = ''; if ($mode -eq 'internet') { $pub = Get-LBPublicIP }
    $url = ''
    if ($mode -eq 'internet' -and $pub) { $url = ('http://{0}:{1}/' -f $pub, $ext) }
    elseif ($mode -eq 'lan' -and $localIp) { $url = ('http://{0}:{1}/' -f $localIp, $port) }
    else { $url = ('http://localhost:{0}/' -f $port) }
    return [ordered]@{
        mode = $mode; port = $port; externalPort = $ext; listen = $listen
        localIp = $localIp; publicIp = $pub
        firewall = (Test-LBWebFirewall)
        nat = $(if ($nat) { $nat } else { $false })
        allowedIps = @($ips)
        url = $url
    }
}

function Set-LBRemoteAccess {
    param($Config, [string]$StateDir, [ValidateSet('local', 'lan', 'internet')][string]$Mode, [int]$ExternalPort = 0, [string[]]$AllowedIps, [int]$Port = 8686)
    if ($Port -le 0) { $Port = 8686 }
    if ($ExternalPort -le 0) { $ExternalPort = $Port }
    $ips = @($AllowedIps | Where-Object { $_ })
    $restartNeeded = $false
    # listen mode: local => localhost only; lan/internet => bind to the network
    $wantListen = $(if ($Mode -eq 'local') { 'local' } else { 'lan' })
    $curListen = 'local'; try { if ([string]$Config.Web.Listen -eq 'lan') { $curListen = 'lan' } } catch { }
    if ($wantListen -ne $curListen) { $restartNeeded = $true }
    Set-LBSetting -Path 'Web.Listen' -Value $wantListen -StateDir $StateDir | Out-Null
    Set-LBSetting -Path 'Web.Remote.Mode' -Value $Mode -StateDir $StateDir | Out-Null
    Set-LBSetting -Path 'Web.Remote.ExternalPort' -Value $ExternalPort -StateDir $StateDir | Out-Null
    Set-LBSetting -Path 'Web.Remote.AllowedIps' -Value $ips -StateDir $StateDir | Out-Null

    $notes = @()
    if ($Mode -eq 'local') {
        Set-LBWebFirewall -Port $Port -Enable $false | Out-Null
        Remove-LBNatMapping -ExternalPort $ExternalPort | Out-Null
    }
    else {
        Set-LBWebFirewall -Port $Port -Enable $true -AllowedIps $ips | Out-Null
        if ($Mode -eq 'internet') {
            $localIp = Get-LBLocalIPv4
            if (-not $localIp) { $notes += 'local IP not found / IP محلی پیدا نشد' }
            else {
                $nr = Add-LBNatMapping -ExternalPort $ExternalPort -InternalPort $Port -LocalIp $localIp
                if (-not $nr.ok) { $notes += ('NAT: ' + [string]$nr.reason) }
            }
        }
        else { Remove-LBNatMapping -ExternalPort $ExternalPort | Out-Null }
    }
    $st = Get-LBRemoteStatus -Config (Get-LogBokConfig)
    $st.restartNeeded = $restartNeeded
    $st.notes = $notes
    return $st
}

Export-ModuleMember -Function Get-LBLocalIPv4, Get-LBPublicIP, Get-LBNatMapping, Add-LBNatMapping, Remove-LBNatMapping, Set-LBWebFirewall, Test-LBWebFirewall, Get-LBRemoteStatus, Set-LBRemoteAccess
