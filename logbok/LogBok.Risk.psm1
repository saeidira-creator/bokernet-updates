# ==========================================================================
#  LogBok.Risk.psm1 - امتیازِ ریسکِ کاربر/سیستم (UEBA risk scoring)
#  به هر یافته وزنی می‌دهد و امتیازِ ریسکِ تجمعیِ هر کاربر/سیستم را نگه می‌دارد
#  (با فراموشیِ تدریجی/decay). خروجی: فهرستِ «پرخطرترین‌ها» برای داشبورد.
#  risk.json در state ذخیره می‌شود. روی سرور اجرا می‌شود.
# ==========================================================================

# وزنِ هر دسته | per-category weight
$script:RiskWeight = @{
    Correlation=40; Ransomware=35; Tamper=30; BruteForce=20; SqlLogin=18; FtpAttack=15
    ActiveDirectory=15; MassFile=20; Defender=15; Firewall=10; IISAttack=12; ServiceState=8
    Behavior=15; FileSuspicion=12; Vulnerability=10; Policy=6; FwGovernance=8; FIM=15
    ADAttack=40; GPO=15; FileACL=8; MemberServer=12; Network=12; AppLog=10; Guard=5; Custom=8; Connectivity=3; EndpointHealth=6; AppControl=10
}
$script:SevMult = @{ Critical=1.0; Warning=0.5; Info=0.15 }

function Get-LBRiskPath { param($Config) Join-Path $Config.Paths.State 'risk.json' }

function Get-LBRisk {
    param($Config)
    $f = Get-LBRiskPath -Config $Config
    $h = @{}
    if (Test-Path $f) { try { (Get-Content $f -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $h[$_.Name] = [double]$_.Value } } catch {} }
    return $h
}
function Save-LBRisk { param($Config,$Risk)
    $o=[ordered]@{}; foreach($k in ($Risk.Keys | Sort-Object)){ $o[$k]=[math]::Round([double]$Risk[$k],1) }
    $o | ConvertTo-Json | Set-Content -Path (Get-LBRiskPath -Config $Config) -Encoding UTF8
}

# به‌روزرسانیِ ریسک با یافته‌های تازه + فراموشیِ تدریجی | update with decay
function Update-LBRisk {
    param($Config,$Findings,[double]$DecayPerRun=0.92)
    $risk = Get-LBRisk -Config $Config
    # فراموشیِ تدریجی (هر اجرا کمی کم می‌شود تا ریسکِ قدیمی محو شود)
    foreach ($k in @($risk.Keys)) { $risk[$k] = [double]$risk[$k] * $DecayPerRun; if ($risk[$k] -lt 1) { $risk.Remove($k) } }
    foreach ($f in $Findings) {
        if (-not $f) { continue }
        # دسته/شدت ممکن است خالی باشد (یافته‌ای بدونِ این فیلدها)؛ ContainsKey با کلیدِ null خطا می‌داد
        $cat = [string]$f.Category; $sev = [string]$f.Severity
        $w = if ($cat -and $script:RiskWeight.ContainsKey($cat)) { $script:RiskWeight[$cat] } else { 8 }
        $mult = if ($sev -and $script:SevMult.ContainsKey($sev)) { $script:SevMult[$sev] } else { 0.3 }
        $pts = $w * $mult
        # موجودیت: کاربر (در صورت وجود در Details) یا سیستم
        $ent = "host:$($f.Machine)"
        if ($f.Category -eq 'Guard') {
            # سپرِ ورود: ریسک به IPِ مهاجم نسبت داده می‌شود، نه به نامِ کاربرهایی که امتحان کرده
            if ($f.PSObject.Properties.Name -contains 'GuardAction' -and $f.GuardAction -ne 'block') { continue }
            if ($f.PSObject.Properties.Name -contains 'GuardIp' -and $f.GuardIp) { $ent = "ip:$($f.GuardIp)" }
        } elseif ($f.Details -match 'کاربر[^:]*:\s*([^\s|]+)' -or $f.Details -match '[Uu]ser[^:]*:\s*([^\s|]+)') {
            $u = $Matches[1]; if ($u -and $u -ne 'SYSTEM' -and $u -notlike '*$') { $ent = "user:$u" }
        }
        if (-not $risk.ContainsKey($ent)) { $risk[$ent]=0.0 }
        $risk[$ent] = [double]$risk[$ent] + $pts
    }
    Save-LBRisk -Config $Config -Risk $risk
    return $risk
}

# پرخطرترین موجودیت‌ها | top-risk entities
function Get-LBTopRisk {
    param($Config,[int]$Top=8)
    $risk = Get-LBRisk -Config $Config
    $risk.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top |
        ForEach-Object { [pscustomobject]@{ Entity=$_.Key; Score=[int]$_.Value;
            Level=if($_.Value -ge 60){'بالا | High'}elseif($_.Value -ge 25){'متوسط | Medium'}else{'کم | Low'} } }
}

Export-ModuleMember -Function *
