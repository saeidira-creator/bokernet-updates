# ==========================================================================
#  LogBok.Correlation.psm1 - موتور همبستگیِ چندمرحله‌ای (Multi-stage)
#  چند یافتهٔ منفرد را که با هم یک الگوی حمله می‌سازند، در یک «یافتهٔ همبسته»
#  با شدتِ بالاتر ترکیب می‌کند. مثلاً «بروت‌فورس + تغییرِ حسابِ AD» = احتمالِ
#  نفوذ به حساب. روی سرور اجرا می‌شود؛ ورودی = یافته‌های بازهٔ جاری.
#  وابسته به LogBok.Mitre (برای برچسب).
# ==========================================================================

# قواعدِ همبستگی | correlation rules: وقتی همهٔ دسته‌های All برای یک سیستم در
# بازه دیده شوند، یک یافتهٔ همبسته تولید می‌شود.
$script:CorrRules = @(
    @{ Name='AccountCompromise'; Title='احتمالِ نفوذ به حساب: حملهٔ ورود + تغییرِ حساب | Account compromise: login attack + account change';
       All=@('BruteForce','ActiveDirectory'); Mitre='T1110, T1098' }
    @{ Name='DestructiveIntrusion'; Title='نفوذِ مخرب: حملهٔ ورود + حذفِ انبوهِ فایل | Destructive intrusion: login attack + mass file delete';
       All=@('BruteForce','MassFile'); Mitre='T1110, T1485' }
    @{ Name='RansomwareChain'; Title='زنجیرهٔ باج‌افزار: تغییرِ انبوه + فایلِ طعمه | Ransomware chain: mass change + canary tripped';
       All=@('MassFile','Ransomware'); Mitre='T1486' }
    @{ Name='DefenseEvasionAttack'; Title='دورزدنِ دفاع + حمله: دستکاری/خاموشیِ محافظ + حمله | Defense evasion + attack';
       All=@('Tamper','BruteForce'); Mitre='T1562, T1110' }
    @{ Name='PrivEscChain'; Title='زنجیرهٔ ارتقای دسترسی: آسیب‌پذیری + تغییرِ حسابِ حساس | Priv-esc chain: vulnerability + sensitive account change';
       All=@('Vulnerability','ActiveDirectory'); Mitre='T1068, T1098' }
    @{ Name='AVOffThenMalware'; Title='آنتی‌ویروس خاموش + بدافزار/باج‌افزار | AV disabled then malware';
       All=@('Defender','Ransomware'); Mitre='T1562.001, T1486' }
)

function New-CorrFinding {
    param($Machine,$Title,$Mitre,$Parts,$Time)
    [pscustomobject]@{
        Category='Correlation'; Severity='Critical'; Machine=$Machine; Time=$Time
        Title=$Title
        Details=("الگوی همبسته روی {0}`nمولفه‌ها: {1}`nMITRE: {2}" -f $Machine,($Parts -join ' + '),$Mitre)
        Key=("CORR|{0}|{1}" -f $Machine,($Parts -join '|'))
        Mitre=$Mitre
    }
}

# اجرای همبستگی روی یافته‌ها | run correlation over findings
function Invoke-LBCorrelation {
    param($Findings)
    $out = @()
    if (-not $Findings) { return $out }
    # گروه‌بندی بر اساس سیستم | group by machine
    $byHost = @{}
    foreach ($f in $Findings) {
        # یافته‌های Info (مثل تغییرِ عادیِ صفتِ AD) در همبستگی شرکت نمی‌کنند
        if ($f.Severity -eq 'Info') { continue }
        $m = [string]$f.Machine; if (-not $m) { $m='(unknown)' }
        if (-not $byHost.ContainsKey($m)) { $byHost[$m] = [System.Collections.Generic.List[object]]::new() }
        $byHost[$m].Add($f)
    }
    foreach ($m in $byHost.Keys) {
        $cats = @($byHost[$m] | ForEach-Object { $_.Category } | Select-Object -Unique)
        foreach ($rule in $script:CorrRules) {
            $match = $true
            foreach ($need in $rule.All) { if ($cats -notcontains $need) { $match=$false; break } }
            if ($match) {
                $t = ($byHost[$m] | Where-Object { $_.Category -in $rule.All } | Sort-Object Time -Descending | Select-Object -First 1).Time
                if (-not $t) { $t = Get-Date }
                $out += New-CorrFinding -Machine $m -Title $rule.Title -Mitre $rule.Mitre -Parts $rule.All -Time $t
            }
        }
    }
    return $out
}

Export-ModuleMember -Function *
