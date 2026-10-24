# ==========================================================================
#  LogBok.Update.psm1 - به‌روزرسانی خودکارِ سبک (سمت ایجنت)
#  ابتدا فقط یک مانیفست کوچک (version.json) از Collector خوانده می‌شود؛ اگر
#  نسخه عوض نشده باشد، هیچ فایلی دانلود نمی‌شود (بار شبکه ≈ صفر). فقط وقتی
#  نسخه فرق کند، آن هم فقط فایل‌هایی که هَش‌شان تغییر کرده از شبکهٔ محلی کپی
#  می‌شوند. اجرای تسک‌ها چون اسکریپت‌اند، دفعهٔ بعد خودکار کد جدید را می‌خوانند.
#  Lightweight agent self-update: manifest-first, hash-diff, LAN copy, jittered.
# ==========================================================================

function Get-LogBokUpdateSource {
    param($Config)
    if ($Config.Update -and $Config.Update.Source) { return $Config.Update.Source }
    # اشتراکِ فقط‌خواندنیِ LogBokDist$ که نصّابِ سرور می‌سازد (حسابِ کامپیوترِ
    # ایجنت‌ها به C$ دسترسی ندارد؛ قبلاً به‌روزرسانی هرگز اعمال نمی‌شد)
    if ($Config.CollectorFqdn) { return "\\$($Config.CollectorFqdn)\LogBokDist`$" }
    return $null
}

# تأییدِ امضای مانیفست با کلیدِ عمومیِ محصول | verify manifest signature
#  version.json + version.sig (امضای RSA-SHA256 روی بایت‌های دقیقِ version.json)
function Test-LogBokManifest {
    param([string]$Src, [string]$InstallDir)
    $mf = Join-Path $Src 'version.json'; $sg = Join-Path $Src 'version.sig'
    if (-not (Test-Path $mf) -or -not (Test-Path $sg)) { return $null }
    try {
        Import-Module (Join-Path $InstallDir 'LogBok.License.psm1') -DisableNameChecking -ErrorAction Stop
        $bytes = [IO.File]::ReadAllBytes($mf)
        $sig = [Convert]::FromBase64String(([IO.File]::ReadAllText($sg)).Trim())
        if (-not (Test-LogBokSignature -Data $bytes -Signature $sig)) { return $null }
        $txt = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
        return ($txt | ConvertFrom-Json)
    } catch { return $null }
}

function Write-LBUpdateEvent {
    param([int]$Id, [string]$Type, [string]$Msg)
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch {}
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId $Id -EntryType $Type -Message $Msg } catch {}
}

function Invoke-LogBokSelfUpdate {
    param([string]$InstallDir,$Config)
    if (-not $Config.Update -or $Config.Update.Enabled -eq $false) { return $null }
    $src = Get-LogBokUpdateSource -Config $Config
    if (-not $src -or -not (Test-Path $src)) { return $null }
    if (-not (Test-Path (Join-Path $src 'version.json'))) { return $null }

    $verFile = Join-Path $InstallDir 'state\version.txt'
    $localVer = if (Test-Path $verFile) { (Get-Content $verFile -Raw).Trim() } else { '' }

    # مسیرِ کم‌هزینه: نسخه را بدونِ تأییدِ امضا مقایسه می‌کنیم؛ اگر عوض نشده، خروج
    try { $peek = Get-Content (Join-Path $src 'version.json') -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    if ([string]$peek.Version -eq $localVer) { return $null }

    # نسخهٔ جدید → فقط با امضای معتبرِ سازنده پذیرفته می‌شود
    #  (بدونِ امضا، هر کسی با دسترسیِ نوشتن به dist می‌توانست کد را روی همهٔ
    #   ایجنت‌ها با SYSTEM اجرا کند یا ماژولِ لایسنس را عوض کند)
    $remote = Test-LogBokManifest -Src $src -InstallDir $InstallDir
    if (-not $remote) {
        Write-LBUpdateEvent 9001 Warning "LogBok update rejected on ${env:COMPUTERNAME}: version.json signature missing/invalid at $src"
        return $null
    }

    $changed = @(); $failed = 0
    $root = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\') + '\'
    foreach ($p in $remote.Files.PSObject.Properties) {
        $name = [string]$p.Name; $hash = [string]$p.Value
        # جلوگیری از پیمایشِ مسیر | path traversal guard
        if (-not $name -or [IO.Path]::IsPathRooted($name) -or $name -match '\.\.|[:*?"<>|]' -or $name -notmatch '\.(psm1|ps1|psd1|svg|json)$') { $failed++; continue }
        $dst = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
        if (-not $dst.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { $failed++; continue }
        $localHash = if (Test-Path -LiteralPath $dst) { (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash } else { '' }
        if ($localHash -eq $hash) { continue }
        $tmp = "$dst.new"
        try {
            Copy-Item -LiteralPath (Join-Path $src $name) -Destination $tmp -Force -ErrorAction Stop
            if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash -ne $hash) { throw "hash mismatch" }
            Move-Item -LiteralPath $tmp -Destination $dst -Force -ErrorAction Stop
            $changed += $name
        } catch {
            $failed++
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
    # فید تهدیدِ امضاشده (امضایش جداگانه هنگامِ اعمال بررسی می‌شود)
    $feedSrc = Join-Path $src 'threatfeed.json'
    if (Test-Path $feedSrc) {
        $feedDst = Join-Path $InstallDir 'threatfeed.json'
        $sh = if (Test-Path $feedDst) { (Get-FileHash $feedDst -Algorithm SHA256).Hash } else { '' }
        $rh = (Get-FileHash $feedSrc -Algorithm SHA256).Hash
        if ($sh -ne $rh) { try { Copy-Item $feedSrc -Destination $feedDst -Force; $changed += 'threatfeed.json' } catch {} }
    }
    # نسخه فقط وقتی ثبت می‌شود که همهٔ فایل‌ها موفق بوده‌اند (وگرنه دفعهٔ بعد دوباره تلاش)
    if ($failed -eq 0) { Set-Content -Path $verFile -Value $remote.Version -Encoding ASCII }
    if ($changed.Count -gt 0) {
        Write-LBUpdateEvent 9010 Information ("Agent updated to v{0} on {1}: {2}{3}" -f $remote.Version,$env:COMPUTERNAME,($changed -join ','),$(if($failed){" (failed: $failed, will retry)"}))
    }
    return $changed
}

# ==========================================================================
#  به‌روزرسانیِ خودکارِ «سرورِ شرکت» از فیدِ سازنده (HTTPS یا پوشهٔ اشتراکی)
#  Server self-update: pulls the vendor's SIGNED server package, verifies it,
#  backs up, applies atomically, HEALTH-CHECKS the result, and ROLLS BACK on
#  any problem — so a bad push can never break a client server. Then it mirrors
#  the code-only package into the local dist share so this server's own agents
#  update as usual. config/policies/license are never touched.
# ==========================================================================

# یک فایل را از فید بگیر (HTTPS یا مسیر/اشتراک) و در مقصد بنویس
function Get-LBFeedToFile {
    param([string]$Feed, [string]$Rel, [string]$OutFile)
    try {
        if ($Feed -match '^https?://') {
            $url = ($Feed.TrimEnd('/')) + '/' + ($Rel -replace '\\', '/')
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
            Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 120 -OutFile $OutFile -ErrorAction Stop
            return (Test-Path -LiteralPath $OutFile)
        }
        else {
            $p = Join-Path $Feed ($Rel -replace '/', '\')
            if (-not (Test-Path -LiteralPath $p)) { return $false }
            Copy-Item -LiteralPath $p -Destination $OutFile -Force -ErrorAction Stop
            return $true
        }
    }
    catch { return $false }
}

# پس از اعمال، بستهٔ «فقط کد» را در dist محلی آینه کن تا ایجنت‌های همین سرور آپدیت شوند
function Publish-LBAgentMirror {
    param([string]$InstallDir, [string]$Feed)
    $dist = Join-Path $InstallDir 'dist'
    if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist -Force | Out-Null }
    $vj = Join-Path $dist 'version.json'; $vs = Join-Path $dist 'version.sig'
    if (-not (Get-LBFeedToFile -Feed $Feed -Rel 'version.json' -OutFile $vj)) { return }
    if (-not (Get-LBFeedToFile -Feed $Feed -Rel 'version.sig' -OutFile $vs)) { return }
    try {
        $m = Get-Content $vj -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $m.Files.PSObject.Properties) {
            $n = [string]$p.Name; $src = Join-Path $InstallDir $n
            if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination (Join-Path $dist $n) -Force -ErrorAction SilentlyContinue }
        }
    } catch { }
}

function Invoke-LBServerUpdate {
    param([string]$InstallDir, $Config)
    $feed = ''; try { $feed = [string]$Config.Update.ServerFeed } catch { }
    if (-not $feed) { return $null }
    if ($Config.Update -and $Config.Update.Enabled -eq $false) { return $null }

    $sd = Join-Path $InstallDir 'state'
    $work = Join-Path $sd 'update-work'
    if (-not (Test-Path $work)) { New-Item -ItemType Directory -Path $work -Force | Out-Null }
    $mfFile = Join-Path $work 'server.json'; $sgFile = Join-Path $work 'server.sig'
    if (-not (Get-LBFeedToFile -Feed $feed -Rel 'server.json' -OutFile $mfFile)) { return $null }
    if (-not (Get-LBFeedToFile -Feed $feed -Rel 'server.sig' -OutFile $sgFile)) { return $null }

    # مسیرِ کم‌هزینه: مقایسهٔ نسخه قبل از تأییدِ امضا
    $verFile = Join-Path $sd 'server-version.txt'
    $localVer = if (Test-Path $verFile) { (Get-Content $verFile -Raw).Trim() } else { '' }
    $peek = $null; try { $peek = Get-Content $mfFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    if ([string]$peek.Version -eq $localVer) { return $null }

    # تأییدِ امضا با کلیدِ عمومیِ سازنده (هیچ آپدیتِ بدونِ امضای معتبر اعمال نمی‌شود)
    try { if (-not (Get-Command Test-LogBokSignature -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $InstallDir 'LogBok.License.psm1') -DisableNameChecking -Global -ErrorAction Stop } } catch { return $null }
    $bytes = [IO.File]::ReadAllBytes($mfFile)
    $sig = $null; try { $sig = [Convert]::FromBase64String((Get-Content $sgFile -Raw).Trim()) } catch { return $null }
    if (-not (Test-LogBokSignature -Data $bytes -Signature $sig)) {
        Write-LBUpdateEvent 9021 Warning "LogBok server update REJECTED on ${env:COMPUTERNAME}: bad/missing signature from $feed"
        return $null
    }
    $remote = ([Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json)

    # فقط فایل‌های مجاز (کد + رابطِ وب)؛ هر چیزِ دیگری نادیده گرفته می‌شود
    $allow = '^(LogBok\.[\w.]+\.psm1|Run-[\w-]+\.ps1|Search-Logs\.ps1|compliance-templates\.psd1|Web\\(app\.js|app\.css|index\.html|logo\.svg))$'
    $root = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\') + '\'
    $staged = @(); $failed = 0
    foreach ($p in $remote.Files.PSObject.Properties) {
        $name = [string]$p.Name; $hash = [string]$p.Value
        if ($name -notmatch $allow) { continue }
        $dst = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
        if (-not $dst.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { $failed++; continue }
        $localHash = if (Test-Path -LiteralPath $dst) { (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash } else { '' }
        if ($localHash -eq $hash) { continue }
        $tmp = "$dst.new"
        $pdir = Split-Path $dst -Parent; if (-not (Test-Path $pdir)) { New-Item -ItemType Directory -Path $pdir -Force | Out-Null }
        if (-not (Get-LBFeedToFile -Feed $feed -Rel $name -OutFile $tmp)) { $failed++; continue }
        if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash -ne $hash) { $failed++; Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; continue }
        $staged += [pscustomobject]@{ name = $name; dst = $dst; tmp = $tmp }
    }
    # هر فایلِ ناموفق → کلِ آپدیت لغو (همه-یا-هیچ) تا نیمه‌کاره اعمال نشود
    if ($failed -gt 0) {
        foreach ($s in $staged) { Remove-Item -LiteralPath $s.tmp -Force -ErrorAction SilentlyContinue }
        Write-LBUpdateEvent 9022 Warning "LogBok server update aborted on ${env:COMPUTERNAME}: $failed file(s) failed to fetch/verify (will retry)"
        return $null
    }
    if (-not $staged.Count) { Set-Content -Path $verFile -Value $remote.Version -Encoding ASCII; return @() }

    # پشتیبان قبل از اعمال | backup
    $bdir = Join-Path $InstallDir ('_Backups\pre-update-{0}-{1}' -f ($remote.Version -replace '[^0-9A-Za-z._\-]', '_'), (Get-Date).ToString('yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $bdir -Force | Out-Null
    foreach ($s in $staged) {
        if (Test-Path -LiteralPath $s.dst) {
            $bd = Split-Path (Join-Path $bdir $s.name) -Parent; if (-not (Test-Path $bd)) { New-Item -ItemType Directory -Path $bd -Force | Out-Null }
            Copy-Item -LiteralPath $s.dst -Destination (Join-Path $bdir $s.name) -Force -ErrorAction SilentlyContinue
        }
    }
    # اعمال (جابه‌جایی همه) | apply
    $applied = @()
    foreach ($s in $staged) { try { Move-Item -LiteralPath $s.tmp -Destination $s.dst -Force -ErrorAction Stop; $applied += $s } catch { break } }

    # بررسیِ سلامت: ماژول‌های حیاتی باید بدونِ خطا تجزیه شوند | health check
    $healthy = $true; $badmsg = ''
    foreach ($crit in @('LogBok.Core.psm1', 'LogBok.Web.psm1', 'LogBok.Detectors.psm1', 'LogBok.License.psm1', 'LogBok.Findings.psm1')) {
        $cf = Join-Path $InstallDir $crit; if (-not (Test-Path $cf)) { continue }
        $te = $null; $tt = $null
        try { [void][System.Management.Automation.Language.Parser]::ParseFile($cf, [ref]$tt, [ref]$te) } catch { $healthy = $false; $badmsg = "$crit parse crash"; break }
        if ($te -and $te.Count) { $healthy = $false; $badmsg = ("{0}: {1}" -f $crit, $te[0].Message); break }
    }
    if ($applied.Count -ne $staged.Count -or -not $healthy) {
        foreach ($s in $applied) { $bk = Join-Path $bdir $s.name; if (Test-Path -LiteralPath $bk) { Copy-Item -LiteralPath $bk -Destination $s.dst -Force -ErrorAction SilentlyContinue } }
        foreach ($s in $staged) { Remove-Item -LiteralPath $s.tmp -Force -ErrorAction SilentlyContinue }
        Write-LBUpdateEvent 9023 Error ("LogBok server update v{0} ROLLED BACK on {1}: {2}" -f $remote.Version, $env:COMPUTERNAME, $(if ($badmsg) { $badmsg } else { 'apply incomplete' }))
        return $null
    }
    Set-Content -Path $verFile -Value $remote.Version -Encoding ASCII
    # آینهٔ بستهٔ ایجنت در dist محلی | mirror the agent (code-only) package for this server's agents
    try { Publish-LBAgentMirror -InstallDir $InstallDir -Feed $feed } catch { }
    Write-LBUpdateEvent 9024 Information ("LogBok server updated to v{0} on {1}: {2} file(s)" -f $remote.Version, $env:COMPUTERNAME, ($staged | ForEach-Object { $_.name }) -join ',')
    return @($staged | ForEach-Object { $_.name })
}

Export-ModuleMember -Function Get-LogBokUpdateSource, Test-LogBokManifest, Invoke-LogBokSelfUpdate, Invoke-LBServerUpdate, Get-LBFeedToFile, Publish-LBAgentMirror
