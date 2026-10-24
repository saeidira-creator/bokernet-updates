# ==========================================================================
#  LogBok.Sessions.psm1 - live sessions (console/RDP) and actions on them
#  Live sessions (console/RDP) via the Windows Terminal Services API, plus logoff / message / disconnect.
#  runs on the agent and on the LogBok server itself
# ==========================================================================
Set-StrictMode -Off
$script:WtsSrc = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class LBWtsSession {
    public int Id; public string Station; public string State; public string User; public string Domain;
    public string ClientName; public string ClientIp; public long LogonTime; public long ConnectTime; public long DisconnectTime; public long LastInputTime; public long CurrentTime;
}
public static class LBWts {
    [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSEnumerateSessions(IntPtr h, int r, int v, out IntPtr p, out int c);
    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool WTSQuerySessionInformationW(IntPtr h, int id, int cls, out IntPtr buf, out int bytes);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
    [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSLogoffSession(IntPtr h, int id, bool wait);
    [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSDisconnectSession(IntPtr h, int id, bool wait);
    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool WTSSendMessageW(IntPtr h, int id, string title, int titleLen, string msg, int msgLen, int style, int timeout, out int resp, bool wait);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct SI { public int Id; public IntPtr Station; public int State; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct INFO {
        public int State; public int SessionId; public int InB; public int OutB; public int InF; public int OutF; public int InC; public int OutC;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string Station;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string Domain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string User;
        public long ConnectTime; public long DisconnectTime; public long LastInputTime; public long LogonTime; public long CurrentTime;
    }
    static readonly string[] States = { "Active", "Connected", "ConnectQuery", "Shadow", "Disconnected", "Idle", "Listen", "Reset", "Down", "Init" };
    static string Str(int id, int cls) {
        IntPtr b; int n; if (!WTSQuerySessionInformationW(IntPtr.Zero, id, cls, out b, out n)) return "";
        try { return Marshal.PtrToStringUni(b) ?? ""; } finally { WTSFreeMemory(b); }
    }
    static string Ip(int id) {
        IntPtr b; int n; if (!WTSQuerySessionInformationW(IntPtr.Zero, id, 14, out b, out n)) return "";
        try {
            int fam = Marshal.ReadInt32(b); byte[] a = new byte[20]; Marshal.Copy(new IntPtr(b.ToInt64() + 4), a, 0, 20);
            if (fam == 2) return a[2] + "." + a[3] + "." + a[4] + "." + a[5];
            return "";
        } finally { WTSFreeMemory(b); }
    }
    public static List<LBWtsSession> Get() {
        var list = new List<LBWtsSession>(); IntPtr p; int c;
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out p, out c)) return list;
        try {
            int sz = Marshal.SizeOf(typeof(SI));
            for (int i = 0; i < c; i++) {
                SI s = (SI)Marshal.PtrToStructure(new IntPtr(p.ToInt64() + i * sz), typeof(SI));
                var o = new LBWtsSession { Id = s.Id, Station = Marshal.PtrToStringUni(s.Station) ?? "", State = (s.State >= 0 && s.State < States.Length) ? States[s.State] : s.State.ToString() };
                o.User = Str(s.Id, 5); o.Domain = Str(s.Id, 7);
                if (String.IsNullOrEmpty(o.User)) continue;   // listeners / services
                o.ClientName = Str(s.Id, 10); o.ClientIp = Ip(s.Id);
                IntPtr b; int n;
                if (WTSQuerySessionInformationW(IntPtr.Zero, s.Id, 24, out b, out n)) {
                    try { INFO f = (INFO)Marshal.PtrToStructure(b, typeof(INFO)); o.LogonTime = f.LogonTime; o.ConnectTime = f.ConnectTime; o.DisconnectTime = f.DisconnectTime; o.LastInputTime = f.LastInputTime; o.CurrentTime = f.CurrentTime; }
                    finally { WTSFreeMemory(b); }
                }
                list.Add(o);
            }
        } finally { WTSFreeMemory(p); }
        return list;
    }
    public static bool Logoff(int id) { return WTSLogoffSession(IntPtr.Zero, id, false); }
    public static bool Disconnect(int id) { return WTSDisconnectSession(IntPtr.Zero, id, false); }
    public static bool Message(int id, string title, string text) { int r; return WTSSendMessageW(IntPtr.Zero, id, title, title.Length * 2, text, text.Length * 2, 0x40, 120, out r, false); }
}
'@
function Initialize-LBWts {
    if ('LBWts' -as [type]) { return $true }
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { return $false }
    try { Add-Type -TypeDefinition $script:WtsSrc -Language CSharp -ErrorAction Stop; return $true } catch { return $false }
}
function ConvertFrom-LBFileTime { param([long]$v) if ($v -le 0) { return $null }; try { return [datetime]::FromFileTime($v) } catch { return $null } }

# live sessions on this computer
#  compact output for sending: u (user), s (station), st (state), cn/ip (device and source IP), lt/ct/dt (times), idle (seconds)
function Get-LBLiveSessions {
    if (-not (Initialize-LBWts)) { return @() }
    $out = @()
    foreach ($s in [LBWts]::Get()) {
        $lt = ConvertFrom-LBFileTime $s.LogonTime; $ct = ConvertFrom-LBFileTime $s.ConnectTime; $dt = ConvertFrom-LBFileTime $s.DisconnectTime
        $idle = $null; if ($s.LastInputTime -gt 0 -and $s.CurrentTime -gt $s.LastInputTime) { $idle = [int](($s.CurrentTime - $s.LastInputTime) / 10000000) }
        $kind = if ($s.Station -match '^RDP-') { 'rdp' } elseif ($s.Station -eq 'Console') { 'console' } elseif ($s.State -eq 'Disconnected') { $(if ($s.ClientIp -or $s.ClientName) { 'rdp' } else { 'console' }) } else { 'other' }
        $out += [ordered]@{ id = [int]$s.Id; u = $(if ($s.Domain) { "{0}\{1}" -f $s.Domain, $s.User } else { [string]$s.User }); s = [string]$s.Station; st = [string]$s.State; k = $kind
                            cn = [string]$s.ClientName; ip = [string]$s.ClientIp
                            lt = $(if ($lt) { $lt.ToString('o') } else { '' }); ct = $(if ($ct) { $ct.ToString('o') } else { '' }); dt = $(if ($dt -and $s.State -eq 'Disconnected') { $dt.ToString('o') } else { '' }); idle = $idle }
    }
    return $out
}
# act on a session: logoff / disconnect / message
function Invoke-LBSessionAction {
    param([Parameter(Mandatory)][int]$Id, [ValidateSet('logoff','disconnect','message')][string]$Action, [string]$Text, [string]$Title = 'IT')
    if (-not (Initialize-LBWts)) { throw 'session API not available on this system' }
    if ($Id -le 0) { throw 'session 0 (services) cannot be touched' }
    $exists = @([LBWts]::Get() | Where-Object { $_.Id -eq $Id }).Count
    if (-not $exists) { throw "session $Id not found (already ended?)" }
    switch ($Action) {
        'logoff'     { if (-not [LBWts]::Logoff($Id)) { throw ("logoff failed ({0})" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }; return "session $Id logged off" }
        'disconnect' { if (-not [LBWts]::Disconnect($Id)) { throw ("disconnect failed ({0})" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }; return "session $Id disconnected" }
        'message'    { $t = ([string]$Text).Trim(); if (-not $t) { throw 'empty message' }; if ($t.Length -gt 500) { $t = $t.Substring(0, 500) }; [void][LBWts]::Message($Id, $Title, $t); return "message shown in session $Id" }
    }
}
Export-ModuleMember -Function Get-LBLiveSessions, Invoke-LBSessionAction, Initialize-LBWts
