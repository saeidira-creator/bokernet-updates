# ==========================================================================
#  compliance-templates.psd1 - نگاشتِ دسته‌های LogBok به کنترل‌های چارچوب‌ها
#  هر چارچوب فهرستی از کنترل است؛ هر کنترل به چند «دستهٔ» LogBok نگاشت شده.
#  گزارش‌گیرِ انطباق با این، پوششِ هر کنترل را از یافته‌ها/انبار محاسبه می‌کند.
#  چارچوب‌ها نمونه و قابلِ‌گسترش‌اند (ویرایش همین فایل کافی است).
# ==========================================================================
@{
    'ISO27001' = @{
        Title = 'ISO/IEC 27001 — نمونه'
        Controls = @(
            @{ id='A.9.2';  name='مدیریت دسترسی کاربران | User access management'; cats=@('ActiveDirectory') }
            @{ id='A.9.4';  name='کنترل دسترسی به سیستم | System access control';   cats=@('BruteForce','SqlLogin','FtpAttack') }
            @{ id='A.12.2'; name='حفاظت در برابر بدافزار | Protection from malware'; cats=@('Defender','Ransomware','FileSuspicion') }
            @{ id='A.12.4'; name='ثبت وقایع و پایش | Logging and monitoring';       cats=@('Behavior','Policy','Tamper') }
            @{ id='A.12.6'; name='مدیریت آسیب‌پذیری فنی | Technical vuln mgmt';      cats=@('Vulnerability') }
            @{ id='A.13.1'; name='امنیت شبکه | Network security';                   cats=@('Firewall','FwGovernance','IISAttack') }
        )
    }
    'PCI-DSS' = @{
        Title = 'PCI-DSS — نمونه'
        Controls = @(
            @{ id='Req.1';  name='فایروال و کنترل ترافیک | Firewall & traffic';     cats=@('Firewall','FwGovernance') }
            @{ id='Req.5';  name='ضدِبدافزار | Anti-malware';                        cats=@('Defender','Ransomware','FileSuspicion') }
            @{ id='Req.8';  name='شناسایی و احراز هویت | Identify & authenticate';   cats=@('ActiveDirectory','BruteForce','SqlLogin') }
            @{ id='Req.10'; name='ثبت و پایش دسترسی | Track & monitor access';       cats=@('Behavior','Policy','Tamper','MassFile') }
            @{ id='Req.11'; name='آزمون امنیت سامانه | Test security of systems';    cats=@('Vulnerability') }
        )
    }
    'HIPAA' = @{
        Title = 'HIPAA Security Rule — نمونه'
        Controls = @(
            @{ id='164.308(a)(1)'; name='مدیریت ریسک امنیتی | Security management'; cats=@('Vulnerability','Policy') }
            @{ id='164.308(a)(5)'; name='پایشِ ورود و بدافزار | Login & malware monitoring'; cats=@('BruteForce','Defender','Ransomware') }
            @{ id='164.312(a)';    name='کنترلِ دسترسی | Access control'; cats=@('ActiveDirectory','ADAttack','GPO') }
            @{ id='164.312(b)';    name='کنترلِ حسابرسی | Audit controls'; cats=@('Behavior','Tamper','FIM') }
            @{ id='164.312(c)';    name='یکپارچگی | Integrity'; cats=@('FIM','MassFile','FileACL') }
        )
    }
    'GDPR' = @{
        Title = 'GDPR — نمونه'
        Controls = @(
            @{ id='Art.32(1)';  name='امنیتِ پردازش | Security of processing'; cats=@('Defender','Ransomware','Firewall') }
            @{ id='Art.32(2)';  name='دسترسی و احراز هویت | Access & auth'; cats=@('ActiveDirectory','BruteForce','ADAttack') }
            @{ id='Art.33';     name='کشفِ نقض و واکنش | Breach detection'; cats=@('Correlation','Behavior','MassFile') }
            @{ id='Art.5(1)(f)';name='یکپارچگی و محرمانگی | Integrity & confidentiality'; cats=@('FIM','FileACL') }
        )
    }
    'SOX' = @{
        Title = 'SOX (IT General Controls) — نمونه'
        Controls = @(
            @{ id='ITGC-Access';  name='کنترلِ دسترسی و تفکیکِ وظایف | Access & SoD'; cats=@('ActiveDirectory','ADAttack','GPO') }
            @{ id='ITGC-Change';  name='مدیریتِ تغییر | Change management'; cats=@('FIM','FileACL','MemberServer') }
            @{ id='ITGC-Ops';     name='عملیاتِ رایانه‌ای | Computer operations'; cats=@('ServiceState','Vulnerability','Policy') }
            @{ id='ITGC-Monitor'; name='پایش و ثبت | Monitoring & logging'; cats=@('Behavior','Tamper','Correlation') }
        )
    }
    'Local' = @{
        Title = 'چارچوبِ بومی سازمان | Organization baseline'
        Controls = @(
            @{ id='L-1'; name='حساب‌های کاربری و گروه‌های حساس';   cats=@('ActiveDirectory') }
            @{ id='L-2'; name='حملات ورود (ویندوز/SQL/IIS/FTP)';   cats=@('BruteForce','SqlLogin','IISAttack','FtpAttack') }
            @{ id='L-3'; name='باج‌افزار و فایل';                  cats=@('Ransomware','MassFile','FileSuspicion') }
            @{ id='L-4'; name='فایروال و آنتی‌ویروس';             cats=@('Firewall','Defender','FwGovernance') }
            @{ id='L-5'; name='سلامت سرویس و آسیب‌پذیری';          cats=@('ServiceState','Vulnerability','Policy') }
        )
    }
}
