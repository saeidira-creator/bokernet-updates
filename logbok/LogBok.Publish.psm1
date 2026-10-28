# ==========================================================================
#  LogBok.Publish.psm1 — انتشارِ آپدیت از کنسولِ سازنده (vendor side)
#  یک دکمه در کنسول: کدِ جدید را هَش و امضا می‌کند و بسته‌ای امضاشده می‌سازد
#  که هر سرورِ شرکت آن را امن می‌گیرد و اعمال می‌کند، و ایجنت‌ها هم از سرورِ
#  خودشان آن را می‌گیرند. دو مانیفست ساخته می‌شود:
#     version.json  (فقط کد)          → ایجنت‌ها (مثلِ قبل، دست‌نخورده)
#     server.json   (کد + رابطِ وب)   → سرورِ شرکت‌ها (کنسول هم آپدیت می‌شود)
#  هر دو با کلیدِ خصوصیِ سازنده (Tools\privatekey.xml) امضا می‌شوند؛ هیچ طرفی
#  آپدیتِ بدونِ امضای معتبر را نمی‌پذیرد. config/policies/license هرگز منتشر
#  نمی‌شوند؛ تنظیماتِ محلیِ هر شرکت دست‌نخورده می‌ماند.
# ==========================================================================

function Get-LBPublishKeyPath { param([string]$InstallDir) Join-Path $InstallDir 'Tools\privatekey.xml' }
function Test-LBIsVendor      { param([string]$InstallDir) return (Test-Path (Get-LBPublishKeyPath $InstallDir)) }

# فایل‌های کدِ قابلِ انتشار (نه config/policies/license که محلیِ هر شرکت‌اند)
function Get-LBPublishCodeFiles {
    param([string]$InstallDir)
    return @(Get-ChildItem -Path $InstallDir -File | Where-Object {
            ($_.Name -like 'LogBok.*.psm1' -or $_.Name -like 'Run-*.ps1' -or $_.Name -eq 'Search-Logs.ps1' -or $_.Name -eq 'compliance-templates.psd1') -and
            $_.Name -ne 'LogBok.FireBok.psm1'
        } | Select-Object -ExpandProperty Name | Sort-Object)
}
# فایل‌های رابطِ وب که فقط سرورها می‌گیرند (ایجنت‌ها نه) | Web UI files (servers only)
function Get-LBPublishWebFiles {
    param([string]$InstallDir)
    $out = @()
    foreach ($n in @('app.js', 'app.css', 'index.html', 'logo.svg')) { if (Test-Path (Join-Path $InstallDir (Join-Path 'Web' $n))) { $out += ('Web\' + $n) } }
    return $out
}

function Sign-LBBytes {
    param([byte[]]$Bytes, [string]$KeyFile)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.PersistKeyInCsp = $false
    $rsa.FromXmlString((Get-Content $KeyFile -Raw))
    return $rsa.SignData($Bytes, 'SHA256')
}

function Write-LBManifest {
    param([string]$Dist, [string]$Name, $Manifest, [string]$KeyFile)
    $json = $Manifest | ConvertTo-Json -Depth 6
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
    [IO.File]::WriteAllBytes((Join-Path $Dist ($Name + '.json')), $bytes)
    $sig = Sign-LBBytes -Bytes $bytes -KeyFile $KeyFile
    [IO.File]::WriteAllText((Join-Path $Dist ($Name + '.sig')), [Convert]::ToBase64String($sig))
}

# انتشار: ساختِ بسته + امضا + zip + کپیِ اختیاری به مقصد
function Invoke-LBPublishUpdate {
    param(
        [Parameter(Mandatory)][string]$InstallDir,
        [string]$Version = '',
        [string]$Notes = '',
        [string]$CopyTo = '',
        [string]$By = ''
    )
    $key = Get-LBPublishKeyPath $InstallDir
    if (-not (Test-Path $key)) { throw 'این سرور، سرورِ سازنده نیست (privatekey.xml نیست) — انتشار فقط از سرورِ سازنده ممکن است | not a vendor server (no privatekey.xml)' }
    # automatic version = product series + build number (2.1.1, 2.1.2, ...), not a date/time stamp.
    # clients only compare for equality, so the format change is safe.
    if (-not $Version) {
        $bnFile = Join-Path $InstallDir 'dist\build-number.txt'
        $bn = 0; try { if (Test-Path $bnFile) { $bn = [int]((Get-Content $bnFile -Raw).Trim()) } } catch { $bn = 0 }
        $bn++
        $Version = '2.1.' + $bn
        try { if (-not (Test-Path (Split-Path $bnFile -Parent))) { New-Item -ItemType Directory -Path (Split-Path $bnFile -Parent) -Force | Out-Null }; Set-Content -Path $bnFile -Value $bn -Encoding ASCII } catch { }
    }
    if ($Version -notmatch '^[0-9A-Za-z._\-]{1,40}$') { throw 'شمارهٔ نسخه نامعتبر | invalid version string' }

    $dist = Join-Path $InstallDir 'dist'
    if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist -Force | Out-Null }
    if (-not (Test-Path (Join-Path $dist 'Web'))) { New-Item -ItemType Directory -Path (Join-Path $dist 'Web') -Force | Out-Null }

    $code = Get-LBPublishCodeFiles $InstallDir
    $web = Get-LBPublishWebFiles $InstallDir
    if (-not $code.Count) { throw 'هیچ فایلِ کدی برای انتشار پیدا نشد | no code files found' }

    $published = (Get-Date).ToString('s', [Globalization.CultureInfo]::InvariantCulture)
    # --- مانیفستِ ایجنت‌ها: فقط کد (دست‌نخورده نسبت به قبل) ---
    $mAgent = [ordered]@{ Version = $Version; Published = $published; Notes = $Notes; Files = [ordered]@{} }
    foreach ($f in $code) {
        Copy-Item (Join-Path $InstallDir $f) -Destination (Join-Path $dist $f) -Force
        $mAgent.Files[$f] = (Get-FileHash -Path (Join-Path $dist $f) -Algorithm SHA256).Hash
    }
    Write-LBManifest -Dist $dist -Name 'version' -Manifest $mAgent -KeyFile $key

    # --- مانیفستِ سرورها: کد + رابطِ وب ---
    $mServer = [ordered]@{ Version = $Version; Published = $published; Notes = $Notes; Files = [ordered]@{} }
    foreach ($f in $code) { $mServer.Files[$f] = $mAgent.Files[$f] }
    foreach ($f in $web) {
        Copy-Item (Join-Path $InstallDir $f) -Destination (Join-Path $dist $f) -Force
        $mServer.Files[$f] = (Get-FileHash -Path (Join-Path $dist $f) -Algorithm SHA256).Hash
    }
    Write-LBManifest -Dist $dist -Name 'server' -Manifest $mServer -KeyFile $key

    # --- تاریخچهٔ انتشار | publish history ---
    $histPath = Join-Path $dist 'published.json'
    $hist = @(); if (Test-Path $histPath) { try { $hist = @((Get-Content $histPath -Raw -Encoding UTF8 | ConvertFrom-Json)) } catch { } }
    $hist = @([ordered]@{ version = $Version; published = $published; notes = $Notes; files = ($code.Count + $web.Count); by = $By }) + $hist
    if ($hist.Count -gt 50) { $hist = $hist[0..49] }
    [IO.File]::WriteAllText($histPath, ($hist | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))

    # --- به‌روزرسانِ آفلاینِ خوداجرا را هم کنارِ بسته بگذار | bundle the offline updater ---
    #  so the manual mode is simply: copy the folder/zip to a server and run it.
    $applySrc = Join-Path $InstallDir 'Tools\Apply-LogBokUpdate.ps1'
    $cmdText = "@echo off`r`nchcp 65001 >nul`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"%~dp0Apply-LogBokUpdate.ps1`"`r`n"
    if (Test-Path $applySrc) { Copy-Item $applySrc -Destination (Join-Path $dist 'Apply-LogBokUpdate.ps1') -Force }
    [IO.File]::WriteAllText((Join-Path $dist 'Update-LogBok.cmd'), $cmdText, (New-Object Text.ASCIIEncoding))

    # --- بستهٔ zip برای آپلودِ آسان به میزبانِ HTTPS یا کپی به مقصد ---
    $zip = Join-Path $dist ('LogBok-Update-{0}.zip' -f $Version)
    try {
        if (Test-Path $zip) { Remove-Item $zip -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        # zip فقط فایل‌های بسته (نه zipهای قدیمی) | zip only the package files
        $tmpStage = Join-Path ([IO.Path]::GetTempPath()) ('lbpub-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmpStage -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $tmpStage 'Web') -Force | Out-Null
        foreach ($f in $code) { Copy-Item (Join-Path $dist $f) -Destination (Join-Path $tmpStage $f) -Force }
        foreach ($f in $web) { Copy-Item (Join-Path $dist $f) -Destination (Join-Path $tmpStage $f) -Force }
        foreach ($m in @('version.json', 'version.sig', 'server.json', 'server.sig')) { Copy-Item (Join-Path $dist $m) -Destination (Join-Path $tmpStage $m) -Force }
        if (Test-Path $applySrc) { Copy-Item $applySrc -Destination (Join-Path $tmpStage 'Apply-LogBokUpdate.ps1') -Force }
        [IO.File]::WriteAllText((Join-Path $tmpStage 'Update-LogBok.cmd'), $cmdText, (New-Object Text.ASCIIEncoding))
        [IO.Compression.ZipFile]::CreateFromDirectory($tmpStage, $zip)
        Remove-Item $tmpStage -Recurse -Force -ErrorAction SilentlyContinue
    } catch { $zip = '' }

    # --- کپیِ اختیاری به مقصد (پوشه/اشتراکِ شبکه) ---
    $copied = ''
    if ($CopyTo) {
        try {
            if (-not (Test-Path $CopyTo)) { New-Item -ItemType Directory -Path $CopyTo -Force | Out-Null }
            if (-not (Test-Path (Join-Path $CopyTo 'Web'))) { New-Item -ItemType Directory -Path (Join-Path $CopyTo 'Web') -Force | Out-Null }
            foreach ($f in $code) { Copy-Item (Join-Path $dist $f) -Destination (Join-Path $CopyTo $f) -Force }
            foreach ($f in $web) { Copy-Item (Join-Path $dist $f) -Destination (Join-Path $CopyTo $f) -Force }
            foreach ($m in @('version.json', 'version.sig', 'server.json', 'server.sig')) { Copy-Item (Join-Path $dist $m) -Destination (Join-Path $CopyTo $m) -Force }
            $copied = $CopyTo
        } catch { throw ("کپی به مقصد ناموفق بود: {0} | copy to target failed: {0}" -f $_.Exception.Message) }
    }

    try { if (-not [Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' }; Write-EventLog -LogName Application -Source 'LogBok' -EventId 9020 -EntryType Information -Message ("LogBok update published v{0} by {1}: {2} code + {3} UI files" -f $Version, $By, $code.Count, $web.Count) } catch { }

    return [ordered]@{
        ok = $true; version = $Version; published = $published
        codeFiles = $code.Count; webFiles = $web.Count
        dist = $dist; zip = $zip; copiedTo = $copied
    }
}

# وضعیتِ انتشار برای کنسول | publish status for the console
function Get-LBPublishStatus {
    param([string]$InstallDir)
    $dist = Join-Path $InstallDir 'dist'
    $cur = ''; $pub = ''
    $mf = Join-Path $dist 'server.json'
    if (Test-Path $mf) { try { $j = Get-Content $mf -Raw -Encoding UTF8 | ConvertFrom-Json; $cur = [string]$j.Version; $pub = [string]$j.Published } catch { } }
    $hist = @(); $hp = Join-Path $dist 'published.json'
    if (Test-Path $hp) { try { $hist = @((Get-Content $hp -Raw -Encoding UTF8 | ConvertFrom-Json)) } catch { } }
    return [ordered]@{
        isVendor = (Test-LBIsVendor $InstallDir)
        publishedVersion = $cur; publishedAt = $pub
        dist = $dist
        history = @($hist | Select-Object -First 20)
    }
}

Export-ModuleMember -Function Invoke-LBPublishUpdate, Get-LBPublishStatus, Test-LBIsVendor, Get-LBPublishCodeFiles, Get-LBPublishWebFiles
