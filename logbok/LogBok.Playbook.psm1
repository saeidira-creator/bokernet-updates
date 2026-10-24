# ==========================================================================
#  LogBok.Playbook.psm1 — توضیحِ ساده و «چه کنیم» برای هر نوع هشدار
#  Plain-language explanation + what-to-do for every alert category/title
#  در ایمیل، کشوی رخداد و کشوی رویداد استفاده می‌شود | used by mail, incident drawer and event drawer
# ==========================================================================
Set-StrictMode -Off

# هر مدخل: What (چه شد)، Why (چرا مهم است)، Do (چه کنیم؛ گام‌ها)، Normal (اگر طبیعی است)، Urgency (now/today/week)
$script:PB = @{
    'Connectivity' = @{
        fa = @{ What='لاگ‌بوک نتوانست به یکی از سیستم‌هایی که زیرِ نظر دارد وصل شود (نام/آدرسِ سیستم و کانالِ قطع‌شده در جزئیات آمده).'
                Why='تا وقتی ارتباط قطع است، لاگِ آن سیستم جمع نمی‌شود و حمله روی آن دیده نمی‌شود.'
                Do=@('اگر «dns» است: نامِ سیستم از روی سرورِ لاگ‌بوک پیدا نمی‌شود؛ DNSِ سرور را به DNSِ دامنه بدهید، یا در «سیستم‌ها» آدرسِ IP را برای آن سیستم ثبت کنید.','اگر «ping/rpc/winrm» است: سیستم خاموش است یا فایروالش بسته؛ روشن بودن و فایروال (WinRM 5985، RPC 135) را بررسی کنید.','اگر سیستم دیگر وجود ندارد یا آزمایشی بود: در «سیستم‌ها» آن را حذف یا غیرفعال کنید تا هشدار قطع شود.','اگر سیستم ایجنت دارد، این هشدار معنی ندارد: نوعِ پایش را روی «ایجنت» بگذارید.')
                Normal='سیستم‌هایی که شب‌ها خاموش می‌شوند این هشدار را می‌دهند؛ برای آن‌ها پایش را «ایجنت» کنید یا در ساعتِ کاری محدود کنید.'; Urgency='today' }
        en = @{ What='LogBok could not reach one of the monitored computers (name/address and the failed channel are in the details).'
                Why='While the connection is down, no logs are collected from that computer and attacks on it go unseen.'
                Do=@('If it says "dns": the name does not resolve from the LogBok server; point the server DNS to the domain DNS or set an IP address for the computer under Computers.','If "ping/rpc/winrm": the computer is off or its firewall blocks it; check it is on and that WinRM (5985) / RPC (135) are allowed.','If the computer no longer exists or was a test: remove or disable it under Computers.','If the computer runs the agent, set its monitoring type to "agent".')
                Normal='Computers switched off at night produce this; monitor them via agent or limit to business hours.'; Urgency='today' }
    }
    'Defender' = @{
        fa = @{ What='آنتی‌ویروسِ ویندوز (Defender) روی این سیستم چیزی گزارش کرده: یافتنِ بدافزار، خاموش‌شدنِ حفاظت یا تغییرِ تنظیمات.'
                Why='اگر بدافزار پیدا شده یا حفاظت خاموش شده، سیستم در خطرِ مستقیم است. تغییرِ تنظیمات معمولاً از به‌روزرسانی خودِ Defender است، مگر کسی عمداً آن را ضعیف کرده باشد.'
                Do=@('اگر «بدافزار شناسایی شد»: ببینید قرنطینه شده یا نه؛ اگر نه، سیستم را از شبکه جدا کنید (در لاگ‌بوک: ایزوله) و اسکنِ کامل بزنید.','اگر «حفاظتِ بلادرنگ غیرفعال شد»: از همین کنسول «سیستم‌ها → (سیستم) → امنیت → اصلاح» را بزنید تا دوباره روشن شود، و بپرسید چه کسی و چرا خاموش کرده.','اگر «پیکربندی تغییر کرد» و هم‌زمان چیزِ دیگری نیست: معمولاً به‌روزرسانیِ عادی است؛ کاری لازم نیست.')
                Normal='«پیکربندی تغییر کرد» بعد از به‌روزرسانیِ امضاها طبیعی است.'; Urgency='now' }
        en = @{ What='Windows Defender on this computer reported something: malware found, protection turned off, or a configuration change.'
                Why='Malware or disabled protection means direct risk. A configuration change is usually Defender updating itself, unless someone weakened it on purpose.'
                Do=@('"Malware detected": check it was quarantined; if not, isolate the computer (LogBok: Isolate) and run a full scan.','"Real-time protection disabled": use Computers -> (computer) -> Security -> Fix in the console to re-enable it, and find out who disabled it and why.','"Configuration changed" with nothing else: normally a routine update; no action.')
                Normal='"Configuration changed" right after a signature update is normal.'; Urgency='now' }
    }
    'ServiceState' = @{
        fa = @{ What='یک سرویسِ حیاتی (مثلاً آنتی‌ویروس، فایروال، لاگ‌گیری) روی این سیستم متوقف شد.'; Why='خاموش‌شدنِ این سرویس‌ها اولین کارِ بسیاری از بدافزارها و مهاجم‌ها است؛ یا نشانهٔ خرابیِ سیستم است.'
                Do=@('سرویس را دوباره روشن کنید (services.msc) و ببینید چرا متوقف شده: به‌روزرسانی، ری‌استارت، یا دستِ کسی؟','اگر چند بار تکرار شد یا کسی عمداً آن را خاموش کرده، سیستم را بررسیِ کامل کنید.'); Normal='هنگامِ ری‌استارت یا به‌روزرسانیِ ویندوز یکی‌دوبار طبیعی است.'; Urgency='now' }
        en = @{ What='A critical service (antivirus, firewall, logging) stopped on this computer.'; Why='Stopping these is the first move of much malware and many attackers, or a sign the system is failing.'
                Do=@('Start the service again (services.msc) and find out why it stopped: update, reboot, or a person?','If it repeats or someone stopped it on purpose, investigate the computer fully.'); Normal='Once or twice during a reboot or Windows update is normal.'; Urgency='now' }
    }
    'EndpointHealth' = @{
        fa = @{ What='بررسیِ روزانهٔ سلامتِ سیستم‌ها چیزی پیدا کرده: ایجنتی تماس نگرفته، آپدیتِ امنیتیِ نصب‌نشده، آنتی‌ویروسِ قدیمی یا تنظیمِ ضعیف.'; Why='این‌ها حمله نیستند، اما درهای نیمه‌باز هستند؛ اگر بمانند، حمله آسان می‌شود.'
                Do=@('«ایجنت تماس نگرفته»: سیستم خاموش است یا ایجنت از کار افتاده؛ اگر سیستم حذف شده، در «سیستم‌ها» آن را فراموش کنید.','«به‌روزرسانیِ امنیتی نصب نشده»: از «حفاظت → آپدیت» نصب را بزنید یا سیاستِ آپدیتِ خودکار بسازید.','«تنظیمِ ضعیف»: از «سیستم‌ها → (سیستم) → امنیت → اصلاح» یک‌کلیک درست کنید.'); Normal='یک‌بار در روز می‌آید؛ تا درست نشود هر روز تکرار می‌شود.'; Urgency='week' }
        en = @{ What='The daily health check found something: an agent not reporting, missing security updates, old antivirus signatures or a weak setting.'; Why='Not attacks, but half-open doors; left alone they make an attack easy.'
                Do=@('"Agent has not reported": the computer is off or the agent died; if the computer was removed, Forget it under Computers.','"Security updates not installed": install from Protection -> Updates or create an automatic update policy.','"Weak setting": use Computers -> (computer) -> Security -> Fix.'); Normal='Arrives once a day and repeats daily until fixed.'; Urgency='week' }
    }
    'BruteForce' = @{
        fa = @{ What='کسی پشتِ سرِ هم رمزِ اشتباه زده (حملهٔ حدسِ رمز) روی این سیستم؛ کاربر و IPِ مهاجم در جزئیات است.'; Why='اگر رمز ضعیف باشد، دیر یا زود وارد می‌شود.'
                Do=@('اگر IP بیرونی است: سپرِ ورودِ لاگ‌بوک معمولاً خودش بلاک می‌کند؛ مطمئن شوید RDP روی اینترنت باز نیست (VPN بگذارید).','اگر IP داخلی است: احتمالاً سرویس/برنامه‌ای با رمزِ قدیمی تلاش می‌کند یا کاربر رمزش را فراموش کرده؛ آن سیستم را بررسی کنید.','رمزِ آن حساب را قوی کنید و قفلِ حساب (Lockout) را فعال نگه دارید.'); Normal='چند تلاشِ اشتباهِ یک کاربر در دقیقه طبیعی است؛ ده‌ها تلاش از یک IP نه.'; Urgency='now' }
        en = @{ What='Repeated wrong passwords (password-guessing) against this computer; the account and attacker IP are in the details.'; Why='With a weak password they eventually get in.'
                Do=@('External IP: the LogBok login guard normally blocks it; make sure RDP is not exposed to the internet (use a VPN).','Internal IP: usually a service/app with an old saved password or a user who forgot theirs; check that computer.','Strengthen that account password and keep account lockout enabled.'); Normal='A few mistakes by one user are normal; dozens from one IP are not.'; Urgency='now' }
    }
    'Guard' = @{
        fa = @{ What='سپرِ ورودِ لاگ‌بوک یک IP را به‌خاطرِ تلاش‌های ناموفقِ زیاد مسدود کرد (یا آزاد کرد).'; Why='خودکار انجام شده؛ خطر فعلاً دفع شده است.'
                Do=@('اگر IP آشناست (کاربر یا سرورِ داخلی): از «سپرِ ورود» آزادش کنید و به لیستِ سفید بیفزایید؛ رمزِ آن کاربر/سرویس را درست کنید.','اگر ناشناس است: کاری لازم نیست؛ اگر از یک کشور/رنج تکرار می‌شود، آن رنج را دائمی بلاک کنید.'); Normal='بلاک‌شدنِ IPهای اینترنتی روی سرورِ RDP/SQL هر روز طبیعی است.'; Urgency='today' }
        en = @{ What='The LogBok login guard blocked (or unblocked) an IP after too many failed attempts.'; Why='Handled automatically; the threat is contained for now.'
                Do=@('Known IP (a user or internal server): unblock it under Login guard, whitelist it, fix that user/service password.','Unknown IP: nothing to do; if the same range repeats, block it permanently.'); Normal='Internet IPs getting blocked on an RDP/SQL server daily is normal.'; Urgency='today' }
    }
    'ActiveDirectory' = @{
        fa = @{ What='تغییری در اکتیودایرکتوری رخ داده: ساخت/حذفِ کاربر یا گروه، ریستِ رمز، قفل‌شدنِ حساب، یا عضویت در گروهِ مدیریتی.'; Why='تغییرِ گروه‌های مدیریتی و ساختِ کاربرِ ناخواسته راهِ معمولِ ماندگارشدنِ مهاجم است.'
                Do=@('ببینید «چه کسی» (Subject) این تغییر را داده؛ اگر مدیرِ شناخته‌شده و برنامه‌ریزی‌شده بود، تأیید کنید.','عضویتِ تازه در Domain Admins/Administrators را که برنامه‌ریزی نشده، فوراً برگردانید و رمزِ آن حساب‌ها را عوض کنید.','قفل‌شدنِ حساب: کاربر رمز را اشتباه زده یا دستگاهی با رمزِ قدیمی تلاش می‌کند؛ از «کاربر ۳۶۰» منبعِ قفل را ببینید.'); Normal='ریستِ رمز و ساختِ کاربر در ساعتِ کاری توسطِ ادمین طبیعی است.'; Urgency='today' }
        en = @{ What='An Active Directory change: user/group created or deleted, password reset, account lockout, or a privileged-group membership change.'; Why='Privileged-group changes and unexpected accounts are the usual way attackers persist.'
                Do=@('See WHO (Subject) made the change; if a known admin did it as planned, confirm it.','Unplanned membership in Domain Admins/Administrators: revert immediately and change those account passwords.','Lockout: the user mistyped or a device holds an old password; use User 360 to find the source.'); Normal='Password resets and user creation by admins in business hours are normal.'; Urgency='today' }
    }
    'ADAttack' = @{
        fa = @{ What='نشانهٔ حملهٔ شناخته‌شده به اکتیودایرکتوری (DCSync، Kerberoasting، Golden Ticket، Pass-the-Hash…).'; Why='این‌ها حملاتِ واقعیِ مرحلهٔ پیشرفته‌اند؛ مهاجم احتمالاً از قبل واردِ شبکه شده.'
                Do=@('فوراً: سیستمِ منبع (IP/نامِ سیستم در جزئیات) را ایزوله کنید.','رمزِ حساب‌های درگیر و krbtgt را (دو بار، با فاصله) تغییر دهید.','لاگِ همان بازه را در «لاگ‌ها» برای همان IP/کاربر بررسی کنید و اگر لازم شد، تیمِ امنیت را خبر کنید.'); Normal='خیلی کم؛ ابزارهای ممیزی (مثلاً اسکنرِ AD) ممکن است شبیه‌سازی کنند.'; Urgency='now' }
        en = @{ What='A known Active Directory attack pattern (DCSync, Kerberoasting, Golden Ticket, Pass-the-Hash...).'; Why='These are real late-stage attacks; the attacker is probably already inside.'
                Do=@('Immediately isolate the source computer (IP/name in the details).','Reset the involved accounts and krbtgt (twice, with a gap).','Review the logs for that IP/user in the same window; involve your security team if needed.'); Normal='Rare; audit tools (AD scanners) may mimic it.'; Urgency='now' }
    }
    'Tamper' = @{
        fa = @{ What='کسی لاگ را پاک کرده، حسابرسی را خاموش کرده یا سعی کرده ایجنتِ لاگ‌بوک را متوقف/حذف کند.'; Why='پاک‌کردنِ رد پا کارِ مهاجم است، نه کاربرِ عادی.'
                Do=@('ببینید چه کسی (کاربر در جزئیات) و کِی؛ اگر ادمینِ شناخته‌شده نبود، سیستم را ایزوله و بررسی کنید.','اگر ایجنت از کار افتاده، از کنسول دوباره نصب کنید (ایجنت‌ها → نصب).'); Normal='فقط وقتی خودِ شما ایجنت را حذف می‌کنید.'; Urgency='now' }
        en = @{ What='Someone cleared a log, disabled auditing, or tried to stop/remove the LogBok agent.'; Why='Covering tracks is attacker behaviour, not normal use.'
                Do=@('See who (user in details) and when; if not a known admin, isolate and investigate.','If the agent is down, reinstall it from the console (Computers -> Add computers).'); Normal='Only when you remove the agent yourself.'; Urgency='now' }
    }
    'Ransomware' = @{
        fa = @{ What='نشانهٔ باج‌افزار: تغییرِ انبوهِ فایل‌ها، پسوندهای عجیب، یا فایلِ «طعمه» دست‌کاری شده.'; Why='هر دقیقه تأخیر یعنی فایل‌های بیشترِ رمزشده.'
                Do=@('همین حالا سیستم را ایزوله کنید (لاگ‌بوک: ایزوله) و آن را خاموش نکنید (برای تحلیل).','اشتراک‌های شبکه‌ای که این کاربر دسترسی داشته را قطع و بک‌آپ‌ها را بررسی کنید.','کاربر/حسابِ درگیر را غیرفعال کنید.'); Normal='کپی/جابه‌جاییِ انبوهِ فایل توسطِ ادمین ممکن است شبیه باشد؛ اول ایزوله کنید، بعد بپرسید.'; Urgency='now' }
        en = @{ What='Ransomware indicators: mass file changes, strange extensions, or a canary file touched.'; Why='Every minute means more encrypted files.'
                Do=@('Isolate the computer now (LogBok: Isolate); do not power it off (forensics).','Cut the network shares that user could reach and verify backups.','Disable the involved user/account.'); Normal='Admin bulk copy/move can look similar; isolate first, ask later.'; Urgency='now' }
    }
    'MassFile' = 'Ransomware'
    'FIM' = @{
        fa = @{ What='فایل یا پوشهٔ حساسی که زیرِ نظر است تغییر کرده یا مجوزش عوض شده.'; Why='تغییرِ فایل‌های سیستمی/پیکربندی بدونِ برنامه می‌تواند نشانهٔ نفوذ یا خرابیِ ناخواسته باشد.'
                Do=@('بررسی کنید چه کسی و کِی تغییر داده (جزئیات)؛ اگر نصب/به‌روزرسانیِ برنامه‌ریزی‌شده بود، تأیید کنید.','اگر ناشناس است، فایل را با نسخهٔ سالم مقایسه و سیستم را بررسی کنید.'); Normal='هنگامِ به‌روزرسانیِ ویندوز یا نصبِ برنامه طبیعی است.'; Urgency='today' }
        en = @{ What='A monitored sensitive file/folder changed or its permissions changed.'; Why='Unplanned changes to system/config files can mean intrusion or accidental damage.'
                Do=@('Check who changed it and when (details); confirm if it was a planned install/update.','If unknown, compare with a known-good copy and investigate the computer.'); Normal='Normal during Windows updates or software installs.'; Urgency='today' }
    }
    'FileACL' = 'FIM'; 'FileSuspicion' = 'FIM'
    'MemberServer' = @{
        fa = @{ What='روی سرور چیزی تازه نصب یا اجرا شده: سرویسِ جدید، Scheduled Task، یا دستورِ PowerShellِ مشکوک.'; Why='نصبِ سرویس/تسکِ جدید راهِ کلاسیکِ ماندگارشدنِ مهاجم است.'
                Do=@('نام و مسیرِ سرویس/تسک را در جزئیات ببینید؛ اگر خودتان یا نصب‌کنندهٔ شناخته‌شده‌ای (آپدیت، نرم‌افزارِ شرکت) بوده، تأیید کنید.','نامِ ناآشنا یا مسیرِ Temp/AppData: سرویس را متوقف، فایل را اسکن و سیستم را بررسی کنید.'); Normal='نصبِ نرم‌افزار و به‌روزرسانی‌ها این را می‌دهند.'; Urgency='today' }
        en = @{ What='Something new was installed or run on a server: a new service, scheduled task, or suspicious PowerShell.'; Why='New services/tasks are the classic way attackers persist.'
                Do=@('Check the name and path in the details; confirm if it was you or a known installer (updates, company software).','Unknown name or a Temp/AppData path: stop the service, scan the file, investigate.'); Normal='Software installs and updates produce this.'; Urgency='today' }
    }
    'Behavior' = 'MemberServer'
    'GPO' = @{
        fa = @{ What='یک Group Policy یا تنظیمِ فایروال تغییر کرده.'; Why='GPO روی همهٔ سیستم‌ها اثر دارد؛ تغییرِ ناخواسته می‌تواند امنیت را یک‌جا پایین بیاورد.'
                Do=@('ببینید چه کسی تغییر داده؛ اگر برنامه‌ریزی‌شده نبود، در GPMC تاریخچه را ببینید و برگردانید.'); Normal='تغییراتِ خودِ شما (مثلاً استقرارِ ایجنت با GPO) طبیعی است.'; Urgency='today' }
        en = @{ What='A Group Policy or firewall setting changed.'; Why='GPO affects every computer; an unplanned change can lower security everywhere at once.'
                Do=@('See who changed it; if unplanned, review the history in GPMC and revert.'); Normal='Your own changes (e.g. agent deployment via GPO) are normal.'; Urgency='today' }
    }
    'Firewall' = 'GPO'; 'FwGovernance' = @{
        fa = @{ What='روی این سیستم یک رولِ فایروال به‌صورتِ دستی اضافه/تغییر شده که با سیاستِ لاگ‌بوک نمی‌خواند.'; Why='رولِ دستی می‌تواند درِ پشتی باز کند (مثلاً RDP به همه).'
                Do=@('رول را در جزئیات ببینید؛ اگر لازم است، در سیاستِ لاگ‌بوک ثبتش کنید؛ وگرنه حذف کنید.'); Normal='نصبِ برخی برنامه‌ها رول اضافه می‌کند.'; Urgency='today' }
        en = @{ What='A firewall rule was added/changed by hand on this computer, outside the LogBok policy.'; Why='A manual rule can open a back door (e.g. RDP to everyone).'
                Do=@('Check the rule in the details; if needed, record it in the LogBok policy; otherwise remove it.'); Normal='Some installers add rules.'; Urgency='today' }
    }
    'Vulnerability' = @{
        fa = @{ What='اسکنِ روزانه یک ضعفِ شناخته‌شده پیدا کرده: نرم‌افزارِ قدیمی/پرخطر، SMBv1، پروتکلِ ضعیف یا پیکربندیِ ناامن.'; Why='حمله نیست، ولی مهاجم دقیقاً دنبالِ همین‌ها می‌گردد.'
                Do=@('موردِ جزئیات را به‌روز یا غیرفعال کنید (برای تنظیمات: «سیستم‌ها → (سیستم) → امنیت → اصلاح»).','اگر عمداً لازم است (نرم‌افزارِ قدیمیِ ضروری)، در «رخدادها» با یادداشت ببندید تا دوباره باز نشود.'); Normal='یک‌بار در روز تا رفعِ مشکل.'; Urgency='week' }
        en = @{ What='The daily scan found a known weakness: outdated/risky software, SMBv1, a weak protocol or an insecure setting.'; Why='Not an attack, but exactly what attackers look for.'
                Do=@('Update or disable the item in the details (for settings: Computers -> (computer) -> Security -> Fix).','If it is needed on purpose (legacy software), close the incident with a note so it does not reopen.'); Normal='Once a day until fixed.'; Urgency='week' }
    }
    'Policy' = 'Vulnerability'
    'AppControl' = @{
        fa = @{ What='کاربری سعی کرده برنامه‌ای را اجرا کند که در سیاستِ «کنترلِ اجرا» ممنوع است (نامِ برنامه و کاربر در جزئیات).'; Why='سیاست کارش را کرده؛ این فقط اطلاع است.'
                Do=@('اگر این برنامه برای این کاربر لازم است، در سیاستِ کنترلِ اجرا او را مستثنا کنید.','اگر تکرارِ زیاد از یک کاربر است، با او صحبت کنید.'); Normal='بله، همین است که می‌خواستید.'; Urgency='week' }
        en = @{ What='A user tried to run a program forbidden by the App-launch policy (program and user in the details).'; Why='The policy did its job; this is informational.'
                Do=@('If the user needs this program, add an exception in the App-launch policy.','If one user repeats it a lot, talk to them.'); Normal='Yes, this is what you asked for.'; Urgency='week' }
    }
    'SqlLogin' = @{
        fa = @{ What='ورودهای ناموفق به SQL Server (یا IIS/FTP) از یک IP.'; Why='حدسِ رمزِ sa یا حسابِ برنامه؛ اگر موفق شود، به دیتابیس می‌رسد.'
                Do=@('IP بیرونی: پورتِ SQL (1433) را از اینترنت ببندید؛ سپرِ ورود بلاک می‌کند.','IP داخلی: برنامه‌ای با رمزِ غلطِ ذخیره‌شده؛ همان سیستم را درست کنید.','حسابِ sa را غیرفعال/تغییرِ نام دهید و رمزِ قوی بگذارید.'); Normal='بعد از تغییرِ رمزِ یک حسابِ برنامه، چند ساعت تکرار می‌شود تا برنامه‌ها اصلاح شوند.'; Urgency='today' }
        en = @{ What='Failed logins to SQL Server (or IIS/FTP) from one IP.'; Why='Guessing sa or an app account; success means database access.'
                Do=@('External IP: close SQL (1433) from the internet; the login guard blocks it.','Internal IP: an app with a wrong saved password; fix that system.','Disable/rename sa and use strong passwords.'); Normal='Repeats for a few hours after changing an app account password.'; Urgency='today' }
    }
    'IISAttack' = 'SqlLogin'; 'FtpAttack' = 'SqlLogin'; 'FtpSuspicion' = 'SqlLogin'; 'AppLog' = 'SqlLogin'
    'Network' = @{
        fa = @{ What='تجهیزِ شبکه (سوییچ/روتر/فایروال) از راهِ syslog خبری فرستاده: تغییرِ پیکربندی، لینکِ قطع‌شده، ورودِ ناموفق.'; Why='تغییرِ پیکربندیِ بدونِ برنامه یا ورودِ ناموفقِ زیاد روی تجهیز، نشانهٔ دست‌کاری است.'
                Do=@('پیام را در جزئیات بخوانید؛ اگر تغییر برنامه‌ریزی‌شده نبود، با مدیرِ شبکه هماهنگ کنید و پیکربندی را مقایسه کنید.'); Normal='لینک‌های قطع/وصل در ساعتِ کاری طبیعی است.'; Urgency='today' }
        en = @{ What='A network device (switch/router/firewall) reported via syslog: config change, link down, failed login.'; Why='Unplanned config changes or many failed logins on a device suggest tampering.'
                Do=@('Read the message in the details; if unplanned, coordinate with the network admin and diff the config.'); Normal='Link flaps in business hours are normal.'; Urgency='today' }
    }
    'Correlation' = @{
        fa = @{ What='لاگ‌بوک چند رویدادِ جدا را کنارِ هم گذاشته و یک زنجیرهٔ حمله تشخیص داده (مثلاً ورودِ ناموفقِ زیاد و بعد ورودِ موفق).'; Why='تک‌تکِ این رویدادها بی‌خطر به‌نظر می‌رسند؛ کنارِ هم یعنی حملهٔ موفق.'
                Do=@('حساب و سیستمِ درگیر را فوراً بررسی کنید؛ نشستِ آن کاربر را قطع و رمزش را تغییر دهید.','سیستمِ منبع را ایزوله کنید اگر IP ناشناس است.'); Normal='کم‌تکرار؛ جدی بگیرید.'; Urgency='now' }
        en = @{ What='LogBok linked several separate events into an attack chain (e.g. many failed logons then a success).'; Why='Each event alone looks harmless; together they mean a successful attack.'
                Do=@('Check the account and computer right away; end that user session and reset the password.','Isolate the source if the IP is unknown.'); Normal='Rare; take it seriously.'; Urgency='now' }
    }
    'Custom' = @{
        fa = @{ What='یکی از قواعدِ لاگِ سفارشیِ شما جور شده.'; Why='این قاعده را خودتان تعریف کرده‌اید؛ معنایش را شما بهتر می‌دانید.'; Do=@('متنِ لاگ را در جزئیات ببینید و طبقِ روالِ خودتان اقدام کنید.'); Normal='—'; Urgency='today' }
        en = @{ What='One of your custom log rules matched.'; Why='You defined this rule; you know its meaning best.'; Do=@('Read the log text in the details and act per your own procedure.'); Normal='—'; Urgency='today' }
    }
}
$script:Generic = @{
    fa = @{ What='لاگ‌بوک رویدادی را گزارش کرده که در جزئیات آمده.'; Why='بسته به نوعِ رویداد می‌تواند عادی یا نشانهٔ مشکل باشد.'; Do=@('جزئیات را بخوانید؛ اگر عادی است، رخداد را ببندید؛ اگر نه، سیستم و کاربرِ درگیر را بررسی کنید.'); Normal='—'; Urgency='today' }
    en = @{ What='LogBok reported an event; see the details.'; Why='Depending on the event it may be normal or a sign of trouble.'; Do=@('Read the details; if normal, close the incident; otherwise check the involved computer and user.'); Normal='—'; Urgency='today' }
}
# راهنمای خاص برای چند عنوان | title-specific overrides (regex on the title)
$script:ByTitle = @(
    @{ Re = 'Defender configuration changed'; fa = @{ What='تنظیماتِ آنتی‌ویروسِ ویندوز روی این سیستم تغییر کرد. در بیشترِ موارد خودِ Defender بعد از به‌روزرسانیِ امضاها این را می‌نویسد.'; Why='فقط وقتی مهم است که هم‌زمان حفاظت خاموش شده یا کسی عمداً تنظیمات را ضعیف کرده باشد.'; Do=@('اگر هشدارِ «حفاظتِ بلادرنگ غیرفعال شد» یا «بدافزار» کنارش نیست: کاری لازم نیست.','برای اطمینان، در «وضعیتِ امنیتی» همان سیستم ببینید آنتی‌ویروس روشن و امضا تازه است.'); Normal='بله، معمولاً عادی است و دیگر برایش ایمیلِ فوری نمی‌آید.'; Urgency='week' }
                                              en = @{ What='Windows Defender settings changed on this computer. Usually Defender itself writes this after a signature update.'; Why='Only matters if protection was also disabled or someone weakened the settings on purpose.'; Do=@('If there is no "real-time protection disabled" or "malware" alert alongside: nothing to do.','To be sure, check Security posture for that computer: antivirus on and signatures fresh.'); Normal='Yes, usually normal; it no longer triggers an instant e-mail.'; Urgency='week' } }
    @{ Re = 'Agent has not reported'; fa = @{ What='ایجنتِ لاگ‌بوک روی این سیستم بیش از یک روز با سرور تماس نگرفته.'; Why='تا تماس برقرار نشود، لاگ و سیاست‌های آن سیستم اعمال نمی‌شود.'; Do=@('اگر سیستم خاموش/تعطیل است: کاری لازم نیست؛ وقتی روشن شود خودش وصل می‌شود.','اگر روشن است: فایروالِ بین آن و سرور (پورتِ 8687) و سرویسِ Task Scheduler را بررسی کنید؛ یا از «سیستم‌ها» دوباره نصب کنید.','اگر سیستم حذف شده یا آزمایشی بود: در «سیستم‌ها» دکمهٔ «فراموش کردن» را بزنید تا هشدار تمام شود.'); Normal='برای سیستم‌های آزمایشی یا حذف‌شده: فراموش کنید.'; Urgency='week' }
                                        en = @{ What='The LogBok agent on this computer has not contacted the server for more than a day.'; Why='Until it does, no logs or policies apply to that computer.'; Do=@('If the computer is off: nothing to do; it reconnects when switched on.','If it is on: check the firewall between it and the server (port 8687) and the Task Scheduler service; or reinstall from Computers -> Add computers.','If the computer was removed or was a test: press Forget under Computers to stop the alert.'); Normal='For test or removed computers: Forget it.'; Urgency='week' } }
)
function Get-LBPlaybook {
    param([string]$Category, [string]$Title, [string]$Lang = 'fa')
    $l = if ($Lang -eq 'en') { 'en' } else { 'fa' }
    foreach ($bt in $script:ByTitle) { if ($Title -and $Title -match $bt.Re) { return $bt[$l] } }
    $e = $script:PB[[string]$Category]
    if ($e -is [string]) { $e = $script:PB[$e] }
    if (-not $e) { return $script:Generic[$l] }
    return $e[$l]
}
Export-ModuleMember -Function Get-LBPlaybook
