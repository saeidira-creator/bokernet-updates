# ==========================================================================
#  LogBok.ADReports.psm1 - گزارشِ وضعیتِ اکتیودایرکتوری (State reports)
#  برخلافِ آشکارسازها که «رویدادمحور»اند، این‌ها «وضعیتِ فعلیِ AD» را کوئری
#  می‌کنند: حساب‌های راکد/غیرفعال/قفل، وضعیتِ رمز، و اعضای گروه‌های ممتاز.
#  نیازمندِ ماژولِ ActiveDirectory (RSAT) روی سرور/DC؛ اگر نبود، پیغامِ شفاف.
# ==========================================================================

function Test-LBADModule {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try { Import-Module ActiveDirectory -ErrorAction Stop; return $true } catch { return $false }
    }
    return $false
}

# حساب‌های راکد (بدونِ ورود در N روز) | stale accounts
function Get-LBStaleAccounts {
    param([int]$Days=90)
    if (-not (Test-LBADModule)) { return $null }
    $cut = (Get-Date).AddDays(-$Days)
    Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate,whenCreated |
        Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cut } |
        Select-Object SamAccountName,Name,LastLogonDate,whenCreated |
        Sort-Object LastLogonDate
}

# حساب‌های غیرفعال/قفل | disabled & locked
function Get-LBDisabledLocked {
    if (-not (Test-LBADModule)) { return $null }
    $dis = Get-ADUser -Filter {Enabled -eq $false} -Properties whenChanged | Select-Object SamAccountName,Name,@{n='State';e={'Disabled'}},whenChanged
    $lok = Search-ADAccount -LockedOut | Select-Object SamAccountName,Name,@{n='State';e={'LockedOut'}},@{n='whenChanged';e={$null}}
    @($dis) + @($lok)
}

# وضعیتِ رمز: منقضی/بی‌انقضا | password status
function Get-LBPasswordReport {
    if (-not (Test-LBADModule)) { return $null }
    Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordLastSet,PasswordNeverExpires,PasswordExpired |
        Select-Object SamAccountName,Name,PasswordLastSet,PasswordNeverExpires,PasswordExpired |
        Sort-Object PasswordNeverExpires -Descending
}

# اعضای گروه‌های ممتاز | privileged group membership
function Get-LBPrivilegedMembers {
    param([string[]]$Groups=@('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators'))
    if (-not (Test-LBADModule)) { return $null }
    $out=@()
    foreach ($g in $Groups) {
        try { Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop |
            ForEach-Object { $out += [pscustomobject]@{ Group=$g; Member=$_.SamAccountName; Name=$_.Name; Class=$_.objectClass } } } catch {}
    }
    return $out
}

Export-ModuleMember -Function *
