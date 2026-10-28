/* LogBok web console — single-page app (vanilla JS, no external dependencies).
   Security: every value coming from logs/events is attacker-controlled, so all
   rendering goes through el()/text nodes — never innerHTML with data. */
(function () {
  'use strict';

  var S = { meta: null, lang: 'fa', token: '', cats: [], view: '', ev: { hours: 24, sev: '', cat: '', host: '', q: '', skip: 0 }, logs: { hours: 24, q: '', host: '', user: '', id: '', source: 'all' } };

  // ------------------------------------------------------------------ i18n
  var D = {
    fa: {
      overview: 'نمای کلی', events: 'رویدادها', logs: 'جست‌وجوی لاگ', incidents: 'میزِ رخداد', alerts: 'هشدار و ایمیل', sources: 'منابعِ لاگ',
      guard: 'سپرِ ورود', connections: 'ارتباط‌ها', jobs: 'جاب‌ها', settings: 'تنظیمات', grpMonitor: 'پایش', grpConfig: 'پیکربندی', grpSystem: 'سامانه',
      updated: 'به‌روز', refresh: 'تازه‌سازی', light: 'روشن', dark: 'تاریک', loading: 'در حالِ بارگذاری…', none: '—', save: 'ذخیره', cancel: 'انصراف', add: 'افزودن', remove: 'حذف',
      edit: 'ویرایش', test: 'آزمون', testNow: 'آزمونِ فوری', close: 'بستن', apply: 'اعمال', yes: 'بله', no: 'خیر', search: 'جست‌وجو', all: 'همه', saved: 'ذخیره شد',
      crit: 'بحرانی', warn: 'هشدار', info: 'اطلاع', time: 'زمان', host: 'سیستم', sev: 'سطح', cat: 'دسته', title: 'رویداد', details: 'جزئیات', status: 'وضعیت', owner: 'مسئول',
      count: 'تعداد', name: 'نام', address: 'آدرس (IP یا نام)', kind: 'نوع', roles: 'نقش‌ها', ports: 'پورت‌ها', user: 'کاربر', password: 'گذرواژه', notes: 'یادداشت',
      lastHours: 'ساعتِ اخیر', h1: '۱ ساعت', h6: '۶ ساعت', h24: '۲۴ ساعت', d7: '۷ روز', d30: '۳۰ روز', anySev: 'همهٔ سطح‌ها', minWarn: 'هشدار و بالاتر', onlyCrit: 'فقط بحرانی', anyCat: 'همهٔ دسته‌ها',
      hostFilter: 'سیستم…', textFilter: 'متن…', prev: 'قبلی', next: 'بعدی', of: 'از',
      ovLead: 'وضعیتِ امنیتیِ همهٔ منابع. روی هر عدد، دسته یا رویداد کلیک کنید تا جزئیاتش باز شود.',
      latestCrit: 'آخرین رویدادهای بحرانی', topHosts: 'پرحادثه‌ترین سیستم‌ها', health: 'سلامتِ سامانه', license: 'لایسنس', valid: 'معتبر', permanent: 'دائمی', invalid: 'نامعتبر',
      blockedIps: 'IPِ بلاک‌شده', openInc: 'رخدادِ باز', srcCount: 'منبعِ لاگ', connDown: 'منبعِ قطع', jobsOn: 'جابِ فعال', categories: 'دسته‌ها',
      evLead: 'همهٔ یافته‌های امنیتی. روی هر ردیف کلیک کنید تا جزئیات، لاگ‌های خامِ مرتبط و اقدام‌ها (بلاکِ IP، غیرفعال‌کردنِ کاربر، ایزوله…) باز شود.',
      noEvents: 'رویدادی در این بازه نیست', related: 'لاگ‌های خامِ مرتبط (±۱۵ دقیقه، همان سیستم)', actions: 'اقدام', mitre: 'MITRE ATT&CK',
      blockIp1h: 'بلاکِ IP (۱ ساعت)', blockIpPerm: 'بلاکِ دائمی', unblockIp: 'آزادکردنِ IP', whitelistIp: 'لیستِ سفید', disableUser: 'غیرفعال‌کردنِ کاربر', disableAdUser: 'غیرفعال در AD',
      enableUser: 'فعال‌کردنِ کاربر', unlockUser: 'رفعِ قفلِ کاربر', isolate: 'ایزوله‌کردنِ سیستم', restore: 'برداشتنِ ایزوله', openIncident: 'ثبتِ رخداد', viewIncident: 'مشاهدهٔ رخداد',
      searchAround: 'جست‌وجوی لاگ در همین بازه', copyLink: 'کپیِ پیوند', copied: 'کپی شد', confirmIsolate: 'این سیستم از شبکه جدا می‌شود (جز مسیرِ مدیریت). ادامه؟',
      confirmDisable: 'حسابِ کاربر غیرفعال شود؟', isBlocked: 'بلاک است', notBlocked: 'بلاک نیست',
      logsLead: 'جست‌وجو در کلِ لاگ‌های ذخیره‌شده (ویندوز، syslog، لاگ‌های سفارشی). عبارتِ پیشرفته: AND / OR / NOT، "عبارت"، و * — مثال:', logsEx: 'admin AND (fail* OR denied) NOT 10.0.0.5',
      query: 'عبارت', eventId: 'EventID', source: 'منبع', srcAll: 'همه', srcWin: 'ویندوز', srcSys: 'Syslog', results: 'نتیجه', rawRecord: 'رکوردِ خام', log: 'لاگ', message: 'پیام', ip: 'IP',
      incLead: 'رویدادهای هم‌جنس روی هر سیستم در یک رخداد جمع می‌شوند. وضعیت، مسئول و یادداشت را از این‌جا تغییر دهید.', showOpen: 'باز', showAll: 'همه', stOpen: 'باز', stInv: 'در حالِ بررسی', stClosed: 'بسته',
      first: 'اولین', last: 'آخرین', note: 'یادداشت', relatedEvents: 'رویدادهای این رخداد',
      alLead: 'هر پروفایل مشخص می‌کند کدام رویدادها (دسته، حداقلِ شدت، سیستم، کلیدواژه، ساعتِ کاری) به کدام ایمیل‌ها فرستاده شوند. اگر هیچ پروفایلی جور نشود، رویدادهای بحرانی به گیرنده‌های پیش‌فرضِ ایمیل می‌روند.',
      profiles: 'پروفایل‌های هشدار', newProfile: 'پروفایلِ تازه', recipients: 'گیرنده‌ها', minSev: 'حداقلِ شدت', throttle: 'ضدِسیل (دقیقه)', bh: 'ساعتِ کاری', bhAny: 'همیشه', bhIn: 'فقط ساعتِ کاری', bhOut: 'فقط بیرونِ ساعتِ کاری',
      enabled: 'فعال', hosts: 'سیستم‌ها (با * )', keywords: 'کلیدواژه‌ها', catsAllHint: 'هیچ‌کدام = همهٔ دسته‌ها', commaHint: 'با کاما جدا کنید', smtp: 'سرورِ ایمیل (SMTP)', smtpServer: 'سرور', port: 'پورت', useSsl: 'STARTTLS/SSL',
      from: 'فرستنده', to: 'گیرنده‌های پیش‌فرض', smtpUser: 'نام‌کاربریِ SMTP', smtpPass: 'گذرواژهٔ SMTP', passKeep: 'خالی = بدونِ تغییر', hasPass: 'گذرواژه ذخیره شده است', subjTag: 'پیشوندِ عنوان',
      sendTest: 'ارسالِ ایمیلِ آزمایشی', testSent: 'ایمیلِ آزمایشی فرستاده شد', options: 'گزینه‌ها', defaultMail: 'رویدادِ بحرانیِ بدونِ پروفایل → گیرنده‌های پیش‌فرض', bhDays: 'روزهای کاری', bhStart: 'شروع', bhEnd: 'پایان',
      history: 'هشدارهای ارسال‌شده', profile: 'پروفایل', sent: 'ارسال', failed: 'ناموفق', delProfile: 'این پروفایل حذف شود؟',
      srcLead: 'هر سیستم، دامنهٔ اکتیودایرکتوری، دستگاهِ شبکه، سرویس یا لاگِ سفارشی که لاگ‌بوک باید پایش کند. بعد از افزودن، ارتباط فوراً آزموده می‌شود و اگر برقرار نشد، دلیل و راهِ‌حل نشان داده می‌شود.',
      tabList: 'همهٔ منابع', tabWin: 'سیستمِ ویندوزی', tabAd: 'اکتیودایرکتوری', tabNet: 'دستگاهِ شبکه', tabSvc: 'سرویس / برنامه', tabCustom: 'لاگِ سفارشی', tabCred: 'اعتبارنامه‌ها',
      thisServer: 'این سرور', testAll: 'آزمونِ همه', cred: 'اعتبارنامه', setCred: 'تنظیمِ اعتبارنامه', clearCred: 'پاک‌کردنِ اعتبارنامه', disable: 'غیرفعال', enable: 'فعال', confirmRemove: 'این منبع حذف شود؟',
      monitor: 'روشِ جمع‌آوری', monRemote: 'خواندن از راه دور (بدونِ نصب)', monAgent: 'ایجنت (ارسالِ خودکارِ رویداد)', monNone: 'فقط آزمونِ ارتباط', detectRoles: 'تشخیصِ خودکارِ نقش (SQL/IIS/FTP/DC)',
      credOptional: 'اعتبارنامه (اختیاری؛ برای workgroup یا حسابِ جدا)', added: 'افزوده شد', testResult: 'نتیجهٔ آزمونِ ارتباط', channel: 'کانال', reason: 'دلیل', fix: 'راهِ‌حل',
      adLead: 'به دامنه وصل شوید، کامپیوترها را پیدا و به‌عنوانِ منبع اضافه کنید. روی سرورِ عضوِ دامنه نیازی به اعتبارنامه نیست؛ در غیرِ این صورت آدرسِ DC و حسابِ دامنه را وارد کنید.',
      adTest: 'آزمونِ اتصال به دامنه', dcAddr: 'آدرسِ DC (اختیاری)', adUser: 'حسابِ دامنه (DOMAIN\\user)', discover: 'یافتنِ کامپیوترها', compType: 'نوع', tAll: 'همه', tServers: 'سرورها', tWks: 'ایستگاه‌ها', tDcs: 'کنترل‌کننده‌های دامنه',
      ou: 'واحدِ سازمانی (OU)', loadOus: 'بارگذاریِ OUها', anyOu: 'کلِ دامنه', nameLike: 'فیلترِ نام (مثلاً SRV*)', inclDisabled: 'شاملِ غیرفعال‌ها', importSel: 'افزودنِ انتخاب‌شده‌ها', selectAll: 'انتخابِ همه',
      saveDefault: 'این حساب را اعتبارنامهٔ پیش‌فرض کن', os: 'سیستم‌عامل', lastLogon: 'آخرین ورود', isDc: 'DC', already: 'موجود', imported: 'افزوده شد',
      netLead: 'سوییچ، روتر، فایروال، NVR و… لاگشان را با syslog (UDP 514) به این سرور می‌فرستند. بعد از افزودن، دستورِ تنظیمِ دستگاه نشان داده می‌شود و دریافتِ لاگ آزموده می‌شود.',
      devType: 'نوعِ دستگاه', extraPorts: 'پورت‌های مدیریتی برای آزمون (اختیاری)', syslogHint: 'روی دستگاه این را تنظیم کنید', svcLead: 'هر سرویس یا برنامهٔ دیگر (وب‌اپ، پایگاه‌داده، سرورِ لینوکسی…) با پورت‌هایش. پورت‌ها مرتب آزموده و قطعی گزارش می‌شود.',
      svcKind: 'نوع', kService: 'سرویس / برنامه', kLinux: 'سرورِ لینوکسی (SSH)',
      customLead: 'هر کانالِ رویدادِ ویندوز (مثل TerminalServices، PowerShell، برنامه‌ها) یا فایلِ متنیِ لاگِ برنامه را اضافه کنید. لاگ در انبار ذخیره و قابلِ جست‌وجو می‌شود؛ با EventID یا کلیدواژه هشدار می‌دهد.',
      onSource: 'روی منبع', cType: 'نوعِ لاگ', cEvent: 'کانالِ رویدادِ ویندوز', cFile: 'فایلِ متنی', channelName: 'نامِ کانال', loadChannels: 'فهرستِ کانال‌ها', ids: 'EventIDها (اختیاری)', path: 'مسیرِ فایل (مثلاً D:\\App\\logs\\app.log)',
      alertOn: 'هشدار بدهد', existingCustom: 'لاگ‌های سفارشیِ تعریف‌شده', credLead: 'اعتبارنامه‌ها با DPAPIِ ماشین رمزگذاری می‌شوند و فقط SYSTEM و مدیران می‌توانند بخوانند. «پیش‌فرض» برای منابعی است که اعتبارنامهٔ خودشان را ندارند.',
      defCred: 'اعتبارنامهٔ پیش‌فرض', hasCred: 'تنظیم شده', noCred: 'تنظیم نشده (حسابِ کامپیوتر)',
      guardLead: 'IPهایی که پشتِ سرِ هم رمزِ اشتباه می‌زنند خودکار در فایروال بلاک می‌شوند. این‌جا می‌توانید دستی بلاک/آزاد کنید و لیستِ سفید/سیاه را مدیریت کنید.',
      blockedNow: 'هم‌اکنون بلاک', watching: 'زیرِ نظر', rules: 'رولِ فایروال', manualBlock: 'بلاکِ دستی', minutes: 'دقیقه (خالی = دائمی)', block: 'بلاک', unblock: 'آزاد', whitelist: 'لیستِ سفید', blacklist: 'لیستِ سیاه',
      since: 'از', until: 'تا', reasonCol: 'دلیل', usersTried: 'کاربرانِ امتحان‌شده', country: 'کشور', guardSettings: 'قاعده', editInSettings: 'تغییر در «تنظیمات»',
      connLead: 'وضعیتِ هر مسیرِ ارتباطی (DNS، پورت، WinRM، خواندنِ رویداد، syslog). مسیرِ مدیریتِ محافظت‌شده تضمین می‌کند روشن/ریست‌شدنِ فایروال ارتباطِ خودِ لاگ‌بوک را قطع نکند.',
      mgmtPath: 'مسیرِ مدیریتِ محافظت‌شده', lastTest: 'آخرین آزمون', connected: 'برقرار', down: 'قطع', warning: 'هشدار', active: 'فعال', missing: 'نیست',
      jobsLead: 'کارهای زمان‌بندی‌شدهٔ لاگ‌بوک. «اجرای فوری» همان جاب را همین حالا اجرا می‌کند.', runNow: 'اجرای فوری', state: 'وضعیت', next: 'بعدی', lastRun: 'آخرین', purpose: 'کار', started: 'اجرا شد',
      setLead: 'این تنظیمات بدونِ دست‌زدن به config.psd1 ذخیره می‌شوند (state\\settings.json) و ظرفِ چند دقیقه اعمال می‌شوند.',
      general: 'عمومی', language: 'زبان', collMode: 'حالتِ جمع‌آوری', collector: 'سرورِ Collector', throttleAll: 'ضدِسیلِ پیش‌فرض (دقیقه)', retention: 'نگه‌داریِ لاگ (روز)',
      mgmt: 'محافظت از مسیرِ مدیریت', adminIps: 'IP مدیرها', fromLan: 'اگر IPِ مدیر خالی بود، از کلِ شبکهٔ محلی', thresholds: 'آستانه‌های تشخیص', web: 'کنسولِ وب', listen: 'دسترسی',
      lLocal: 'فقط روی همین سرور', lLan: 'از شبکهٔ داخلی (با احرازِ هویتِ ویندوز)', webRestart: 'تغییرِ کنسولِ وب ظرفِ ۲ دقیقه با راه‌اندازیِ دوباره اعمال می‌شود.', jobToggles: 'روشن/خاموشِ جاب‌ها',
      gMax: 'تلاشِ ناموفق تا بلاک', gWin: 'بازه (دقیقه)', gBlock: 'مدتِ بلاکِ اول (دقیقه)', gFactor: 'ضریبِ تکرار', gPerm: 'دائمی بعد از چند بار', gWeb: 'خطای 401 وب تا بلاک', gGeo: 'بلاکِ کشوری', gAllowed: 'کشورهای مجاز', gBlocked: 'کشورهای بلاک',
      agents: 'ایجنت‌ها', agLead: 'ایجنت را روی هر سیستمِ ویندوزی یا لینوکسی نصب کنید: دستی (دانلودِ بسته) یا از راه دور از همین‌جا. بعد از نصب، سیستم در «سیستم‌ها» دیده می‌شود.',
      agWinPkg: 'ایجنتِ ویندوز — نصبِ دستی', agWinPkgLead: 'بسته را دانلود کنید، روی سیستم کپی و Extract کنید و روی Install-LogBokAgent.cmd دوبار کلیک کنید. بقیه‌اش خودکار است: هیچ کاربر، رمز، اشتراک، رول یا استثنایی لازم نیست دستی ساخته شود.',
      agNameOpt: 'نامِ سیستم (اختیاری؛ برای ثبت در منابع)', agAddrOpt: 'آدرس (IP یا نام)', agCollector: 'آدرسِ این سرور برای ایجنت', agCredWg: 'اعتبارنامهٔ مدیرِ آن سیستم (برای workgroup)',
      download: 'دانلود', agDownloaded: 'بسته دانلود شد', agReady: 'بستهٔ آماده روی همین سرور (برای کپیِ مستقیم):',
      agSteps: 'مراحل', agS1: '۱. فایلِ ZIP را روی سیستمِ مقصد کپی و Extract کنید.', agS2: '۲. روی Install-LogBokAgent.cmd دوبار کلیک کنید و در پنجرهٔ ویندوز Yes بزنید.', agS3: '۳. تمام. حداکثر ۲ دقیقه بعد، سیستم خودش در «سیستم‌ها» ظاهر می‌شود.', agS4: 'حذف: Uninstall-LogBokAgent.cmd — فقط با «کدِ حذف»ِ همان سیستم (در «سیستم‌ها» › همان سیستم)',
      agPush: 'ایجنتِ ویندوز — نصب از راه دور', agPushLead: 'لاگ‌بوک بسته را از راهِ اشتراکِ مدیریتی (C$) کپی و با WinRM نصب می‌کند. حسابِ واردشده باید مدیرِ آن سیستم باشد. اگر WinRM خاموش باشد، از راهِ WMI روشنش می‌کند.',
      agPick: 'انتخاب از منابع', agOrType: '— یا نام/آدرس را بنویسید —', agInstall: 'نصبِ ایجنت', agQueued: 'نصب شروع شد؛ وضعیت در فهرستِ پایین به‌روز می‌شود',
      agLinux: 'ایجنتِ لینوکس', agLinuxLead: 'اسکریپت را روی سرورِ لینوکسی کپی و با root اجرا کنید. rsyslog/syslog-ng را برای فرستادنِ لاگ‌های ورود (auth) و هشدارها به این سرور تنظیم می‌کند.',
      agLinuxRun: 'روی سرورِ لینوکسی اجرا کنید:', agList: 'ایجنت‌ها و وضعیتِ نصب', agMethod: 'روش', agStep: 'مرحله', agConn: 'ارتباط', agInstalled: 'نصب شد', agWaiting: 'منتظرِ نصب', agRunning: 'در حالِ نصب',
      mPush: 'از راه دور', mPackage: 'بستهٔ دستی', mLinux: 'لینوکس', mDeploy: 'نصبِ گروهی', forget: 'حذف از فهرست', cpRemove: 'حذفِ ایجنت از این سیستم', cpRemoveQ: 'ایجنت از این سیستم پاک شود؟ فایل‌ها، تسک‌ها و قواعدِ فایروال برداشته می‌شوند. (برای سیستم‌های وصل انجام می‌شود؛ خاموش‌ها در اولین ارتباط)', cpRemoveSent: 'فرمانِ حذف فرستاده شد؛ ایجنت خودش را پاک می‌کند', cpClearQueue: 'پاک‌کردنِ صفِ دستورها', cpClearQueueQ: 'همهٔ دستورهای در صفِ این سیستم پاک شوند؟ (دستورهای اجراشده در تاریخچه می‌مانند)', cpClearQueueDone: 'صفِ دستورها پاک شد', noAgents: 'هنوز ایجنتی ثبت نشده',
      quickAdd: 'افزودنِ سریع', qWin: '+ سیستمِ ویندوزی', qAd: '+ از اکتیودایرکتوری', qNet: '+ دستگاهِ شبکه', qSvc: '+ سرویس / لینوکس', qAgent: '+ نصبِ ایجنت', qCustom: '+ لاگِ سفارشی',
      agTabStatus: 'وضعیتِ ایجنت‌ها', agTabManual: 'نصبِ دستی (ویندوز/لینوکس)', agTabPush: 'نصب از راه دور', agTabAd: 'استقرار در اکتیودایرکتوری',
      agServer: 'این سرور (خودکار خوانده می‌شود)', agAuto: 'خودکار', agServerLead: 'مشخصاتِ این سرور هر بار از خودش خوانده می‌شود. اگر نام یا IP عوض شود، بسته‌های ایجنت خودکار بازسازی می‌شوند و ایجنت‌های نصب‌شده هر ۲ دقیقه نامِ سرور را دوباره پیدا می‌کنند و رولِ فایروالِ خودشان را اصلاح می‌کنند.',
      agSrvName: 'نامِ سرور', agDomain: 'دامنه', agWorkgroup: 'workgroup (بدونِ دامنه)', agUsedAddr: 'نشانیِ ثبت‌شده در ایجنت', agManualSet: '(دستی)', agAutoSet: '(خودکار از نامِ سرور)', agBuild: 'نسخهٔ بسته',
      agOverridePh: 'خالی = خودکار؛ یا نام/IPِ دلخواه', agRebuilt: 'بسته‌ها بازسازی شد', agRebuild: 'بازسازیِ بسته‌ها', agTotal: 'کلِ ایجنت‌ها', agRetry: 'تلاشِ دوباره',
      adDepLead: 'روشِ امن و پیشنهادی بالاست: یک کلیک و همهٔ سیستم‌های دامنه با Group Policy، بدونِ باز کردنِ هیچ پورت. «سیاست‌ها»ی پایین برای وقتی است که فقط بخشی از دامنه (OU یا گروهِ خاص) را می‌خواهید.',
      adAcct: 'حسابِ دامنه برای استقرار', adAcctSaved: 'حساب ذخیره شده', adAcctNone: 'حسابی ذخیره نشده', adReady: 'بررسیِ آمادگی', adAcctHint: 'حسابِ Domain Admin لازم است. با ذخیرهٔ سیاست، رمزگذاری‌شده (DPAPI) نگه داشته می‌شود؛ روی سرورِ عضوِ دامنه آدرسِ DC اختیاری است.',
      adPolicies: 'سیاست‌های استقرار', adNewPolicy: 'سیاستِ تازه', dm_both: 'هر دو: نصبِ فوری + GPO', dm_push: 'نصبِ فوری (کشف و Push)', dm_gpo: 'فقط GPO (Startup Script)',
      adGpoNot: 'ساخته نشده', adNoPolicy: 'هنوز سیاستی نیست — «سیاستِ تازه» را بزنید', adMethod: 'روش', adScope: 'محدوده', adAutoCol: 'خودکار', adCounts: 'یافت / نصب / در صف',
      adHow: 'چطور کار می‌کند', adHow1: '• نصبِ فوری (فقط اگر «نصب از راه دور» را آگاهانه روشن کرده باشید): ایجنت با WinRM/SMB/WMI روی سیستم‌های روشن نصب می‌شود. پیش‌فرض خاموش است چون این پورت‌ها امن نیستند.', adHow2: '• GPO: یک GPO با Startup Script ساخته و روی OUها لینک می‌شود؛ سیستم‌ها در راه‌اندازیِ بعدی خودشان ایجنت را نصب یا به‌روز می‌کنند (خاموش‌ها و سیستم‌های آینده هم).',
      adHow3: '• شامل/مستثنا: فقط اعضای گروه‌های «شامل» (حتی تودرتو) و هرگز اعضای گروه‌های «مستثنا» — در GPO هم با Security Filtering و Deny اعمال می‌شود.', adHow4: '• با تغییرِ نام/IPِ سرور، بستهٔ GPO خودکار به‌روز می‌شود و ایجنت‌ها خودشان را اصلاح می‌کنند.',
      adGroupPh: 'نامِ گروه…', adOuFilter: 'فیلترِ OU…', adOuLoadHint: '«بارگذاریِ OUها» را بزنید؛ هیچ انتخاب = کلِ دامنه', adPolicyPh: 'مثلاً همهٔ سرورها به‌جز DCها',
      adMethodHint: 'پیشنهاد: «هر دو» — روشن‌ها همین الان، بقیه با GPO در راه‌اندازیِ بعدی', adAuto: 'خودکار: سیستم‌های تازهٔ این محدوده هم نصب شوند', adInclude: 'فقط اعضای این گروه‌ها', adExclude: 'به‌جز اعضای این گروه‌ها',
      adParallel: 'نصبِ هم‌زمان', adReinstall: 'روی سیستم‌های دارای ایجنت هم دوباره نصب شود', adPreview: 'سیستم‌های این محدوده', adInstallSel: 'نصب روی انتخاب‌شده‌ها (همین الان)', adPushRes: 'یافت',
      agQueued2: 'در صف', adPreviewBtn: 'پیش‌نمایشِ محدوده', adSaveRun: 'ذخیره و اجرا', adGpoRemove: 'حذفِ GPO', adGpoRemoveQ: 'GPO و لینک‌هایش حذف شود؟ (ایجنت‌های نصب‌شده می‌مانند)', adDelQ: 'این سیاست حذف شود؟ GPOِ آن هم حذف می‌شود.', adLinks: 'لینک‌ها',
      alNoMail: 'سرورِ ایمیل (SMTP) هنوز تنظیم نشده؛ هشدارها ساخته می‌شوند ولی ایمیلی نمی‌رود.', alNoMailFix: 'تنظیمِ SMTP', alDefaults: 'بازگردانیِ پروفایل‌های پیش‌فرض', alBuiltin: 'پیش‌فرض', alRestored: 'پروفایل‌های پیش‌فرض اضافه شد', alRcptDefault: 'گیرنده‌های پیش‌فرض',
      notes2: 'یادداشتِ مدیر', noteEvent: 'یادداشت برای همین رویداد', noteEventPh: 'مثلاً: بررسی شد، کارِ تیمِ پشتیبان بود', noteType: 'برای همهٔ رویدادهای این نوع: عنوانِ دلخواه (اختیاری) و توضیح', noteTypePh: 'توضیحی که برای همهٔ رویدادهای این نوع نشان داده شود', clearF: 'پاک‌کردنِ فیلترها',
      agDlWin: 'دانلودِ ایجنتِ ویندوز (ZIP)', agDlLinux: 'دانلودِ اسکریپتِ لینوکس', agAutoList: 'خودکار انجام می‌شود: حسابرسی و لاگ‌ها، واچ‌داگ و سپرِ ورود، ارسالِ امضاشدهٔ رویدادها به این سرور هر ۲ دقیقه (بدونِ نیاز به رمز یا دسترسیِ راه‌دور)، استثنای Defender برای پوشهٔ قفل‌شدهٔ ایجنت، بدونِ بازکردنِ هیچ پورتِ ورودی، اجرا با اولویتِ Idle تا کاربر کندی حس نکند، و دنبال‌کردنِ سرور اگر IP آن عوض شود.',
      delivery: 'نحوهٔ ارسال', dvInstant: 'فوری (هر رویداد)', dvDigest: 'خلاصهٔ دوره‌ای (یک ایمیل)', dvMinutes: 'دقیقه (برای خلاصه)', dvDigestShort: 'خلاصه', dvInstantShort: 'فوری',
      agPerf: 'مصرفِ ایجنت در هر چرخه', perfHint: 'زمانِ CPU و حافظهٔ آخرین چرخهٔ ۲ دقیقه‌ای (با اولویتِ Idle اجرا می‌شود)', lastSeen: 'آخرین تماس',
      apPending: 'منتظرِ تأیید', apReenroll: 'ثبت‌نامِ دوباره منتظرِ تأیید', apRevoked: 'ابطال‌شده', apApprove: 'تأیید', apRevoke: 'ابطال', apRevokeQ: 'این ایجنت ابطال شود؟ رویدادهایش دیگر پذیرفته نمی‌شود.', unCode: 'کدِ حذف',
      secTitle: 'امنیتِ بستهٔ نصب', secValid: 'فعال', secInvalid: 'منقضی/ابطال', secLead: 'بسته هیچ کلیدِ دائمی ندارد؛ فقط یک «توکنِ ثبت‌نام» با تاریخِ انقضا و سقفِ تعداد دارد. هر سیستم هنگامِ نصب کلیدِ اختصاصیِ خودش را می‌سازد. اگر بسته به دستِ کسی افتاد، «توکنِ جدید» را بزنید تا همهٔ بسته‌های قبلی از کار بیفتند (ایجنت‌های نصب‌شده آسیبی نمی‌بینند).',
      secExpires: 'انقضای توکن', secUses: 'تعدادِ نصب', secSigner: 'امضای دیجیتال', secUnsigned: 'بدونِ امضا', secDays: 'اعتبار (روز)', secMax: 'حداکثرِ نصب', secApproval: 'ایجنتِ تازه فقط با تأییدِ مدیر وصل شود',
      secRotate: 'توکنِ جدید (باطل‌کردنِ بسته‌های قبلی)', secRotateQ: 'همهٔ بسته‌های دانلودشدهٔ قبلی از کار می‌افتند. ادامه؟', secRotated: 'توکنِ جدید ساخته شد و بسته‌ها دوباره ساخته شدند',
      secList: 'حفاظت‌ها: بررسیِ SHA-256 و امضای همهٔ فایل‌ها پیش از نصب • اجرای PowerShell فقط از مسیرِ سیستمی • بدونِ بازکردنِ هیچ پورتِ ورودی • رمزگذاریِ AES-256 + امضای HMAC هر ارسال • ضدِ تکرار • حذف فقط با «کدِ حذف»ِ همان سیستم • ابطالِ هر ایجنت از کنسول • قفلِ پوشه برای کاربرانِ عادی.',
      err: 'خطا', denied: 'دسترسی ندارید', reload: 'صفحه را دوباره باز کنید'
    },
    en: {
      overview: 'Overview', events: 'Events', logs: 'Log search', incidents: 'Incidents', alerts: 'Alerts & email', sources: 'Log sources',
      guard: 'Login guard', connections: 'Connections', jobs: 'Jobs', settings: 'Settings', grpMonitor: 'Monitor', grpConfig: 'Configure', grpSystem: 'System',
      updated: 'Updated', refresh: 'Refresh', light: 'Light', dark: 'Dark', loading: 'Loading…', none: '—', save: 'Save', cancel: 'Cancel', add: 'Add', remove: 'Remove',
      edit: 'Edit', test: 'Test', testNow: 'Test now', close: 'Close', apply: 'Apply', yes: 'Yes', no: 'No', search: 'Search', all: 'All', saved: 'Saved',
      crit: 'Critical', warn: 'Warning', info: 'Info', time: 'Time', host: 'Host', sev: 'Severity', cat: 'Category', title: 'Event', details: 'Details', status: 'Status', owner: 'Owner',
      count: 'Count', name: 'Name', address: 'Address (IP or name)', kind: 'Type', roles: 'Roles', ports: 'Ports', user: 'User', password: 'Password', notes: 'Notes',
      lastHours: 'Last', h1: '1 hour', h6: '6 hours', h24: '24 hours', d7: '7 days', d30: '30 days', anySev: 'All levels', minWarn: 'Warning and above', onlyCrit: 'Critical only', anyCat: 'All categories',
      hostFilter: 'Host…', textFilter: 'Text…', prev: 'Previous', next: 'Next', of: 'of',
      ovLead: 'Security status across all sources. Click any number, category or event to open its details.',
      latestCrit: 'Latest critical events', topHosts: 'Busiest hosts', health: 'System health', license: 'License', valid: 'Valid', permanent: 'permanent', invalid: 'Invalid',
      blockedIps: 'Blocked IPs', openInc: 'Open incidents', srcCount: 'Log sources', connDown: 'Sources down', jobsOn: 'Active jobs', categories: 'Categories',
      evLead: 'All security findings. Click a row to open its details, related raw logs and actions (block IP, disable user, isolate host…).',
      noEvents: 'No events in this range', related: 'Related raw logs (±15 min, same host)', actions: 'Actions', mitre: 'MITRE ATT&CK',
      blockIp1h: 'Block IP (1 hour)', blockIpPerm: 'Block permanently', unblockIp: 'Unblock IP', whitelistIp: 'Whitelist', disableUser: 'Disable user', disableAdUser: 'Disable in AD',
      enableUser: 'Enable user', unlockUser: 'Unlock user', isolate: 'Isolate host', restore: 'Lift isolation', openIncident: 'Open incident', viewIncident: 'View incident',
      searchAround: 'Search logs around this time', copyLink: 'Copy link', copied: 'Copied', confirmIsolate: 'The host will be cut off from the network (except the management path). Continue?',
      confirmDisable: 'Disable this user account?', isBlocked: 'blocked', notBlocked: 'not blocked',
      logsLead: 'Search all stored logs (Windows, syslog, custom logs). Advanced: AND / OR / NOT, "phrase", and * — example:', logsEx: 'admin AND (fail* OR denied) NOT 10.0.0.5',
      query: 'Query', eventId: 'EventID', source: 'Source', srcAll: 'All', srcWin: 'Windows', srcSys: 'Syslog', results: 'results', rawRecord: 'Raw record', log: 'Log', message: 'Message', ip: 'IP',
      incLead: 'Related events on each host are grouped into one incident. Change status, owner and notes here.', showOpen: 'Open', showAll: 'All', stOpen: 'Open', stInv: 'Investigating', stClosed: 'Closed',
      first: 'First', last: 'Last', note: 'Note', relatedEvents: 'Events of this incident',
      alLead: 'Each profile decides which events (category, minimum severity, host, keyword, business hours) are emailed to which recipients. Critical events that match no profile go to the default recipients.',
      profiles: 'Alert profiles', newProfile: 'New profile', recipients: 'Recipients', minSev: 'Minimum severity', throttle: 'Throttle (minutes)', bh: 'Business hours', bhAny: 'Always', bhIn: 'Business hours only', bhOut: 'Outside business hours only',
      enabled: 'Enabled', hosts: 'Hosts (wildcards *)', keywords: 'Keywords', catsAllHint: 'none = all categories', commaHint: 'comma-separated', smtp: 'Mail server (SMTP)', smtpServer: 'Server', port: 'Port', useSsl: 'STARTTLS/SSL',
      from: 'From', to: 'Default recipients', smtpUser: 'SMTP user', smtpPass: 'SMTP password', passKeep: 'blank = unchanged', hasPass: 'A password is stored', subjTag: 'Subject tag',
      sendTest: 'Send test email', testSent: 'Test email sent', options: 'Options', defaultMail: 'Critical events with no profile → default recipients', bhDays: 'Business days', bhStart: 'Start', bhEnd: 'End',
      history: 'Sent alerts', profile: 'Profile', sent: 'sent', failed: 'failed', delProfile: 'Delete this profile?',
      srcLead: 'Every machine, Active Directory domain, network device, service or custom log LogBok should monitor. After adding, connectivity is tested immediately; if it fails, the reason and the fix are shown.',
      tabList: 'All sources', tabWin: 'Windows computer', tabAd: 'Active Directory', tabNet: 'Network device', tabSvc: 'Service / app', tabCustom: 'Custom log', tabCred: 'Credentials',
      thisServer: 'This server', testAll: 'Test all', cred: 'Credential', setCred: 'Set credential', clearCred: 'Clear credential', disable: 'Disable', enable: 'Enable', confirmRemove: 'Remove this source?',
      monitor: 'Collection', monRemote: 'Remote read (no install)', monAgent: 'Agent (pushes its events)', monNone: 'Connectivity test only', detectRoles: 'Auto-detect roles (SQL/IIS/FTP/DC)',
      credOptional: 'Credential (optional; for workgroup or a separate account)', added: 'Added', testResult: 'Connectivity test', channel: 'Channel', reason: 'Reason', fix: 'Fix',
      adLead: 'Connect to the domain, discover computers and add them as sources. On a domain-joined server no credential is needed; otherwise enter a DC address and a domain account.',
      adTest: 'Test domain connection', dcAddr: 'DC address (optional)', adUser: 'Domain account (DOMAIN\\user)', discover: 'Discover computers', compType: 'Type', tAll: 'All', tServers: 'Servers', tWks: 'Workstations', tDcs: 'Domain controllers',
      ou: 'Organizational unit (OU)', loadOus: 'Load OUs', anyOu: 'Whole domain', nameLike: 'Name filter (e.g. SRV*)', inclDisabled: 'Include disabled', importSel: 'Add selected', selectAll: 'Select all',
      saveDefault: 'Save this account as the default credential', os: 'OS', lastLogon: 'Last logon', isDc: 'DC', already: 'added', imported: 'Imported',
      netLead: 'Switches, routers, firewalls, NVRs etc. send their logs by syslog (UDP 514) to this server. After adding, the device configuration line is shown and reception is tested.',
      devType: 'Device type', extraPorts: 'Management ports to test (optional)', syslogHint: 'Configure this on the device', svcLead: 'Any other service or application (web app, database, Linux server…) with its ports. Ports are tested regularly and outages reported.',
      svcKind: 'Type', kService: 'Service / application', kLinux: 'Linux server (SSH)',
      customLead: 'Add any Windows event channel (TerminalServices, PowerShell, applications…) or an application text log file. Logs are stored and searchable; alerts fire on EventIDs or keywords.',
      onSource: 'On source', cType: 'Log type', cEvent: 'Windows event channel', cFile: 'Text file', channelName: 'Channel name', loadChannels: 'List channels', ids: 'EventIDs (optional)', path: 'File path (e.g. D:\\App\\logs\\app.log)',
      alertOn: 'Raise alerts', existingCustom: 'Defined custom logs', credLead: 'Credentials are encrypted with machine DPAPI and readable only by SYSTEM and administrators. "Default" is used by sources without their own credential.',
      defCred: 'Default credential', hasCred: 'set', noCred: 'not set (computer account)',
      guardLead: 'IPs that keep failing to log on are blocked in the firewall automatically. Block/unblock manually and manage the white/black lists here.',
      blockedNow: 'Blocked now', watching: 'Being watched', rules: 'Firewall rules', manualBlock: 'Manual block', minutes: 'Minutes (blank = permanent)', block: 'Block', unblock: 'Unblock', whitelist: 'Whitelist', blacklist: 'Blacklist',
      since: 'Since', until: 'Until', reasonCol: 'Reason', usersTried: 'Users tried', country: 'Country', guardSettings: 'Rule', editInSettings: 'Change in Settings',
      connLead: 'Status of every connection path (DNS, ports, WinRM, event-log read, syslog). The protected management path guarantees that enabling/resetting the firewall never cuts LogBok\'s own connection.',
      mgmtPath: 'Protected management path', lastTest: 'Last test', connected: 'Connected', down: 'Down', warning: 'Warning', active: 'active', missing: 'missing',
      jobsLead: 'LogBok\'s scheduled jobs. "Run now" starts the job immediately.', runNow: 'Run now', state: 'State', next: 'Next', lastRun: 'Last', purpose: 'Purpose', started: 'Started',
      setLead: 'These settings are saved without touching config.psd1 (state\\settings.json) and apply within a few minutes.',
      general: 'General', language: 'Language', collMode: 'Collection mode', collector: 'Collector server', throttleAll: 'Default throttle (minutes)', retention: 'Log retention (days)',
      mgmt: 'Management path protection', adminIps: 'Admin IPs', fromLan: 'If no admin IP, allow the whole local subnet', thresholds: 'Detection thresholds', web: 'Web console', listen: 'Access',
      lLocal: 'This server only', lLan: 'Internal network (Windows authentication)', webRestart: 'Web console changes apply within 2 minutes after a restart.', jobToggles: 'Jobs on/off',
      gMax: 'Failed logons before block', gWin: 'Window (minutes)', gBlock: 'First block (minutes)', gFactor: 'Repeat factor', gPerm: 'Permanent after N blocks', gWeb: 'Web 401s before block', gGeo: 'Country blocking', gAllowed: 'Allowed countries', gBlocked: 'Blocked countries',
      agents: 'Agents', agLead: 'Install the agent on any Windows or Linux computer: manually (download the package) or remotely from here. After install, the computer appears under Computers.',
      agWinPkg: 'Windows agent — manual install', agWinPkgLead: 'Download the package, copy it to the computer, extract it and double-click Install-LogBokAgent.cmd. Everything else is automatic: no user, password, share, rule or exclusion has to be created by hand.',
      agNameOpt: 'Computer name (optional; registers it as a source)', agAddrOpt: 'Address (IP or name)', agCollector: 'This server\'s address for the agent', agCredWg: 'Admin credential of that computer (workgroup)',
      download: 'Download', agDownloaded: 'Package downloaded', agReady: 'Ready-made package on this server (copy directly):',
      agSteps: 'Steps', agS1: '1. Copy the ZIP to the computer and extract it.', agS2: '2. Double-click Install-LogBokAgent.cmd and answer Yes to the Windows prompt.', agS3: '3. Done. Within 2 minutes the computer appears by itself under Computers.', agS4: 'Remove: Uninstall-LogBokAgent.cmd — only with that computer\'s uninstall code (Computers › computer)',
      agPush: 'Windows agent — remote install', agPushLead: 'LogBok copies the package over the admin share (C$) and installs it with WinRM. The account must be an administrator on that computer. If WinRM is off, it is enabled via WMI.',
      agPick: 'Pick from sources', agOrType: '— or type a name/address —', agInstall: 'Install agent', agQueued: 'Install started; status updates in the list below',
      agLinux: 'Linux agent', agLinuxLead: 'Copy the script to the Linux server and run it as root. It configures rsyslog/syslog-ng to forward authentication logs and warnings to this server.',
      agLinuxRun: 'Run on the Linux server:', agList: 'Agents and install status', agMethod: 'Method', agStep: 'Step', agConn: 'Connection', agInstalled: 'Installed', agWaiting: 'Waiting for install', agRunning: 'Installing',
      mPush: 'Remote', mPackage: 'Manual package', mLinux: 'Linux', mDeploy: 'Mass deploy', forget: 'Remove from list', cpRemove: 'Remove agent from this computer', cpRemoveQ: 'Remove the agent from this computer? Files, scheduled tasks and firewall rules are removed. (Done now for connected computers; offline ones on next contact.)', cpRemoveSent: 'Uninstall sent; the agent will remove itself', cpClearQueue: 'Clear queued commands', cpClearQueueQ: 'Clear all queued commands for this computer? (Commands already run stay in history.)', cpClearQueueDone: 'Command queue cleared', noAgents: 'No agents yet',
      quickAdd: 'Quick add', qWin: '+ Windows computer', qAd: '+ From Active Directory', qNet: '+ Network device', qSvc: '+ Service / Linux', qAgent: '+ Install agent', qCustom: '+ Custom log',
      agTabStatus: 'Agent status', agTabManual: 'Manual install (Windows/Linux)', agTabPush: 'Remote install', agTabAd: 'Active Directory deployment',
      agServer: 'This server (read automatically)', agAuto: 'automatic', agServerLead: 'These details are read live from this server. If its name or IP changes, agent packages are rebuilt automatically and installed agents re-resolve the server name every 2 minutes and fix their own firewall rule.',
      agSrvName: 'Server name', agDomain: 'Domain', agWorkgroup: 'workgroup (no domain)', agUsedAddr: 'Address written into agents', agManualSet: '(manual)', agAutoSet: '(automatic, server name)', agBuild: 'Package build',
      agOverridePh: 'blank = automatic; or a custom name/IP', agRebuilt: 'Packages rebuilt', agRebuild: 'Rebuild packages', agTotal: 'Agents', agRetry: 'Retry',
      adDepLead: 'The secure, recommended way is at the top: one click and every domain computer via Group Policy, with no port to open. The policies below are for when you want only part of the domain (an OU or a group).',
      adAcct: 'Domain account for deployment', adAcctSaved: 'account saved', adAcctNone: 'no account saved', adReady: 'Check readiness', adAcctHint: 'A Domain Admin account is required. It is stored encrypted (DPAPI) when you save a policy; on a domain-joined server the DC address is optional.',
      adPolicies: 'Deployment policies', adNewPolicy: 'New policy', dm_both: 'Both: install now + GPO', dm_push: 'Install now (discover & push)', dm_gpo: 'GPO only (startup script)',
      adGpoNot: 'not created', adNoPolicy: 'No policy yet — press "New policy"', adMethod: 'Method', adScope: 'Scope', adAutoCol: 'Auto', adCounts: 'Found / installed / queued',
      adHow: 'How it works', adHow1: '• Install now (only if you deliberately turned on remote push): the agent is installed over WinRM/SMB/WMI on computers that are on. Off by default because these ports are not safe.', adHow2: '• GPO: a GPO with a startup script is created and linked to the OUs; computers install or update the agent at their next start (also those that are off and future ones).',
      adHow3: '• Include/exclude: only members of the include groups (nested too) and never members of the exclude groups — enforced in the GPO with security filtering and a Deny.', adHow4: '• When the server name/IP changes the GPO package is refreshed automatically and agents fix themselves.',
      adGroupPh: 'Group name…', adOuFilter: 'Filter OUs…', adOuLoadHint: 'Press "Load OUs"; nothing selected = whole domain', adPolicyPh: 'e.g. All servers except DCs',
      adMethodHint: 'Recommended: "Both" — online computers now, the rest via GPO at next start', adAuto: 'Automatic: also install on new computers in this scope', adInclude: 'Only members of these groups', adExclude: 'Except members of these groups',
      adParallel: 'Parallel installs', adReinstall: 'Reinstall on computers that already have the agent', adPreview: 'Computers in this scope', adInstallSel: 'Install on selected (now)', adPushRes: 'found',
      agQueued2: 'queued', adPreviewBtn: 'Preview scope', adSaveRun: 'Save & run', adGpoRemove: 'Remove GPO', adGpoRemoveQ: 'Remove the GPO and its links? (installed agents stay)', adDelQ: 'Delete this policy? Its GPO is removed too.', adLinks: 'Links',
      alNoMail: 'The mail server (SMTP) is not configured yet — alerts are generated but no email is sent.', alNoMailFix: 'Set up SMTP', alDefaults: 'Restore default profiles', alBuiltin: 'default', alRestored: 'Default profiles added', alRcptDefault: 'default recipients',
      notes2: 'Admin notes', noteEvent: 'Note for this event', noteEventPh: 'e.g. checked — it was the backup team', noteType: 'For every event of this type: custom title (optional) and description', noteTypePh: 'Description shown on every event of this type', clearF: 'Clear filters',
      agDlWin: 'Download Windows agent (ZIP)', agDlLinux: 'Download Linux script', agAutoList: 'Done automatically: audit policy and logs, watchdog and login guard, signed event push to this server every 2 minutes (no password or remote access needed), a Defender exclusion for the locked agent folder, no inbound port opened, idle priority so the user never feels it, and following the server if its IP changes.',
      delivery: 'Delivery', dvInstant: 'Instant (each event)', dvDigest: 'Periodic digest (one email)', dvMinutes: 'minutes (digest)', dvDigestShort: 'digest', dvInstantShort: 'instant',
      agPerf: 'Agent cost per cycle', perfHint: 'CPU time and memory of the last 2-minute cycle (runs at idle priority)', lastSeen: 'Last contact',
      apPending: 'awaiting approval', apReenroll: 're-enrollment awaiting approval', apRevoked: 'revoked', apApprove: 'Approve', apRevoke: 'Revoke', apRevokeQ: 'Revoke this agent? Its events will be rejected.', unCode: 'Uninstall code',
      secTitle: 'Install package security', secValid: 'active', secInvalid: 'expired/revoked', secLead: 'The package holds no permanent key — only an enrollment token with an expiry date and an install limit. Each computer creates its own key at install. If a package leaks, press "New token": every older package stops working (installed agents are not affected).',
      secExpires: 'Token expires', secUses: 'Installs', secSigner: 'Digital signature', secUnsigned: 'unsigned', secDays: 'Valid for (days)', secMax: 'Max installs', secApproval: 'New agents connect only after admin approval',
      secRotate: 'New token (invalidate older packages)', secRotateQ: 'All previously downloaded packages will stop working. Continue?', secRotated: 'New token created and packages rebuilt',
      secList: 'Protections: SHA-256 + signature check of every file before install • PowerShell only from the system path • no inbound port opened • AES-256 + HMAC on every message • replay protection • uninstall only with that computer\'s uninstall code • revoke any agent from the console • folder locked for normal users.',
      err: 'Error', denied: 'Access denied', reload: 'Reload the page'
    }
  };
  // endpoint management strings
  var D2 = {
    fa: {
      epMin: 'دقیقه', endpoints: 'سیاست‌های سیستم‌ها', software: 'نرم‌افزارها', disabled: 'غیرفعال', geoOff: 'خاموش', geoAllow: 'فقط کشورهای مجاز', geoBlock: 'بلاکِ کشورهای فهرست‌شده',
      epLead: 'برای هر سیستم یا گروهی از سیستم‌ها، تنظیمِ جداگانه بگذارید: اینترنتِ برنامه‌های دلخواه را ببندید یا سپرِ ورود را با تنظیمِ متفاوت اعمال کنید. تغییرها حداکثر ظرفِ ۲ دقیقه از کانالِ امن و رمزنگاری‌شدهٔ ایجنت روی سیستم‌ها می‌نشیند؛ هیچ پورتِ ورودی روی کلاینت‌ها باز نمی‌شود.',
      epTabApp: 'محدودیتِ اینترنتِ برنامه‌ها', epTabGuard: 'پروفایل‌های سپرِ ورود', epTabStatus: 'وضعیتِ اعمال روی سیستم‌ها',
      epAppPolicies: 'سیاست‌های اینترنتِ برنامه‌ها', epGuardPolicies: 'پروفایل‌های سپرِ ورود', epNew: 'سیاستِ تازه', epNone: 'هنوز سیاستی تعریف نشده',
      epAppLead: 'یک یا چند برنامه (مثلاً chrome.exe یا Telegram.exe) را روی سیستم‌های انتخابی از اینترنت محروم کنید؛ شبکهٔ داخلی می‌تواند باز بماند و می‌توان آن را فقط در ساعت‌های مشخص اعمال کرد.',
      epGuardLead: 'هر سیستم می‌تواند سپرِ ورودِ متفاوتی داشته باشد (آستانه، مدتِ بلاک، سرویس‌های محافظت‌شده، کشورها، ساعتِ کاری). اگر چند پروفایل به یک سیستم بخورد، پروفایلِ با اولویتِ بالاتر اعمال می‌شود.',
      epAppHow: 'ایجنت مسیرِ واقعیِ برنامه را روی هر سیستم پیدا می‌کند (Program Files، AppData کاربران و برنامه‌های در حالِ اجرا) و برایش قاعدهٔ خروجیِ فایروالِ ویندوز در گروهِ «LogBok App Control» می‌سازد. با حذفِ سیاست، قاعده‌ها خودکار برداشته می‌شوند.',
      epGuardHow: 'پروفایل روی تنظیماتِ همان سیستم می‌نشیند و تنظیماتِ دستیِ قبلیِ آن سیستم نگه داشته می‌شود تا با حذفِ پروفایل برگردد. سیستم‌هایی که پروفایل ندارند تنظیمِ پیش‌فرض را دارند.',
      epPrograms: 'برنامه‌ها', epTargets: 'سیستم‌های هدف', epApplied: 'اعمال‌شده', epSettings: 'تنظیم', epPriority: 'اولویت', epAlways: 'همیشه',
      epScope: 'محدوده', epScopeInet: 'فقط اینترنت (شبکهٔ داخلی آزاد)', epScopeAll: 'همهٔ شبکه (اینترنت و داخلی)',
      epGuardOff: 'سپر خاموش', epAllAgents: 'همهٔ سیستم‌های دارای ایجنت', epServerSelf: 'همین سرورِ لاگ‌بوک', epChooseHosts: 'انتخابِ سیستم‌ها',
      epFilterHosts: 'فیلترِ نام…', epAddHost: 'افزودنِ نام + Enter', epPatterns: 'الگوی نام', epPatternsHint: 'مثل PC-* یا ACC-?? ؛ با ویرگول جدا کنید. سیستم‌های تازه‌ای که با الگو جور باشند خودکار سیاست را می‌گیرند.',
      epNewApp: 'سیاستِ تازهٔ اینترنتِ برنامه', epNewGuard: 'پروفایلِ تازهٔ سپرِ ورود', epNameAppPh: 'مثلاً: بستنِ مرورگر برای حسابداری', epNameGuardPh: 'مثلاً: سرورهای در معرضِ اینترنت', epNotePh: 'یادداشتِ مدیر (اختیاری)',
      epProgramsHint: 'هر خط یک برنامه: نامِ فایل (chrome.exe) یا مسیرِ کامل (C:\\Program Files\\…\\app.exe یا %ProgramFiles%\\…).', epQuick: 'انتخابِ سریع',
      epSchedule: 'زمان‌بندی', epScheduleOn: 'فقط در روزها و ساعت‌های زیر اعمال شود', epDays: 'روزها', epDaysHint: 'هیچ روزی = همهٔ روزها', epFromTo: 'از ساعت – تا ساعت',
      epGuardSet: 'تنظیماتِ سپرِ ورود', epGuardOn: 'سپرِ ورود روی این سیستم‌ها روشن باشد', epPriorityHint: 'عددِ بزرگ‌تر = اولویتِ بیشتر', epWebMax: 'آستانهٔ خطای وب (401)',
      epProtect: 'محافظت از', epLan: 'IPهای شبکهٔ داخلی هرگز بلاک نشوند', epAllowedC: 'کشورهای مجاز', epBlockedC: 'کشورهای ممنوع',
      epWorkHours: 'ساعتِ کاری', epWorkHoursOn: 'بیرون از ساعتِ کاری هر تلاشِ ورودِ ریموت فوراً بلاک شود',
      epSaveApply: 'ذخیره و اعمال', epSavedHint: 'ذخیره شد؛ ظرفِ ۲ دقیقه روی سیستم‌ها اعمال می‌شود', epDelQ: 'این سیاست حذف و از روی سیستم‌ها برداشته شود؟', epAppliesTo: 'شاملِ',
      epNoAgents: 'هنوز هیچ سیستمی ایجنت ندارد؛ سیاست‌ها روی سیستم‌های دارای ایجنت اعمال می‌شوند.',
      epAppliedOk: 'اعمال شد', epPendingSync: 'در انتظارِ همگام‌سازی', epNeverSynced: 'هنوز گزارش نداده', epGuardDefault: 'پیش‌فرض', epRules: 'قاعده‌ها', epNotFound: 'روی این سیستم پیدا نشد',
      epBlocking: 'در حالِ بستن', epOutside: 'بیرونِ بازهٔ زمانی',
      day_Saturday: 'شنبه', day_Sunday: 'یکشنبه', day_Monday: 'دوشنبه', day_Tuesday: 'سه‌شنبه', day_Wednesday: 'چهارشنبه', day_Thursday: 'پنجشنبه', day_Friday: 'جمعه',
      adOverview: 'نمای کلی', adHardware: 'سخت‌افزار و شبکه', adSoftware: 'نرم‌افزارها', adPolicies: 'سیاست‌ها', adActions: 'فرمان‌ها',
      adOs: 'سیستم‌عامل', adUser: 'کاربرِ واردشده', adUptime: 'روشن از', adMemFree: 'حافظهٔ آزاد', adDiskC: 'فضای آزادِ C:', adRtOn: 'محافظتِ آنی روشن', adRtOff: 'محافظتِ آنی خاموش', adSigAge: 'عمرِ امضا', adNoAv: 'Defender در دسترس نیست',
      adFirewall: 'فایروال', adReboot: 'نیازِ ری‌استارت', adIsolated: 'ایزوله', adPolicy: 'سیاست', adAgentVer: 'نسخهٔ ایجنت', adInvAt: 'آخرین موجودی‌گیری', adNoInv: 'هنوز موجودی‌ای نرسیده (حداکثر ۲ دقیقه پس از نصب)',
      adModel: 'سازنده/مدل', adSerial: 'شمارهٔ سریال', adInstalled: 'نصب', adDisks: 'دیسک‌ها', adSize: 'حجم', adFree: 'آزاد', adNet: 'کارت‌های شبکه', adAdmins: 'مدیرانِ محلی', adHotfix: 'به‌روزرسانی‌های نصب‌شده',
      adVersion: 'نسخه', adPublisher: 'ناشر', adItems: 'مورد', adPaths: 'مسیرِ پیداشده',
      acLead: 'فرمان‌ها از کانالِ امنِ ایجنت در ضربانِ بعدی (حداکثر ۲ دقیقه) اجرا می‌شوند و نتیجه همین‌جا ثبت می‌شود. فقط فرمان‌های ازپیش‌تعریف‌شده پذیرفته می‌شوند.',
      acInventory: 'موجودی‌گیریِ فوری', acSync: 'اعمالِ دوبارهٔ سیاست', acScan: 'اسکنِ سریعِ Defender', acDefUpd: 'به‌روزرسانیِ Defender', acUpdate: 'به‌روزرسانیِ ایجنت', acKill: 'بستنِ برنامه', acBlockIp: 'بلاکِ IP',
      acUnblockIp: 'آزادکردنِ IP', acIsolate: 'ایزوله', acUnisolate: 'رفعِ ایزوله', acReboot: 'ری‌استارت (۵ دقیقه)', acKillQ: 'نامِ پردازه (مثلاً chrome):', acIpQ: 'IP:', acMinQ: 'چند دقیقه؟ (0 = دائمی)',
      acRebootQ: 'سیستم پس از ۵ دقیقه با پیامِ هشدار به کاربر ری‌استارت شود؟', acQueued: 'در صف؛ در ضربانِ بعدیِ ایجنت اجرا می‌شود', acHistory: 'سابقهٔ فرمان‌ها', acDone: 'انجام شد', acSent: 'ارسال شد', acQueuedS: 'در صف',
      swLead: 'نرم‌افزارهای نصب‌شده روی همهٔ سیستم‌های دارای ایجنت (به‌روزرسانیِ روزانه). جست‌وجو کنید تا ببینید کدام برنامه، با چه نسخه‌ای، روی کدام سیستم‌ها نصب است.',
      swSearchPh: 'نامِ برنامه یا ناشر…', swComputers: 'سیستمِ دارای موجودی', swCount: 'تعدادِ سیستم', swWhere: 'روی سیستم‌ها', swNoInv: 'هنوز موجودی‌ای از ایجنت‌ها نرسیده', agDetail: 'جزئیات'
    },
    en: {
      epMin: 'min', endpoints: 'Endpoint policies', software: 'Software inventory', disabled: 'Disabled', geoOff: 'Off', geoAllow: 'Allowed countries only', geoBlock: 'Block listed countries',
      epLead: 'Give each computer, or group of computers, its own settings: cut internet access for chosen programs or apply Login Guard with different settings. Changes reach the computers within 2 minutes over the agent\'s encrypted channel; no inbound port is opened on clients.',
      epTabApp: 'App internet control', epTabGuard: 'Login Guard profiles', epTabStatus: 'Applied status',
      epAppPolicies: 'App internet policies', epGuardPolicies: 'Login Guard profiles', epNew: 'New policy', epNone: 'No policy defined yet',
      epAppLead: 'Block internet access for one or more programs (e.g. chrome.exe or Telegram.exe) on the computers you choose; the local network can stay open, and it can apply only at set hours.',
      epGuardLead: 'Each computer can have a different Login Guard (thresholds, block time, protected services, countries, work hours). If several profiles match a computer, the highest priority wins.',
      epAppHow: 'The agent finds the program\'s real path on each computer (Program Files, users\' AppData, running processes) and creates Windows Firewall outbound rules in the group "LogBok App Control". Deleting the policy removes the rules automatically.',
      epGuardHow: 'The profile overlays that computer\'s settings; its previous local settings are kept and restored when the profile is removed. Computers without a profile keep the default.',
      epPrograms: 'Programs', epTargets: 'Target computers', epApplied: 'Applied', epSettings: 'Settings', epPriority: 'Priority', epAlways: 'always',
      epScope: 'Scope', epScopeInet: 'Internet only (LAN allowed)', epScopeAll: 'All networks (internet and LAN)',
      epGuardOff: 'Guard off', epAllAgents: 'All computers with an agent', epServerSelf: 'This LogBok server', epChooseHosts: 'Choose computers',
      epFilterHosts: 'Filter names…', epAddHost: 'Add name + Enter', epPatterns: 'Name pattern', epPatternsHint: 'e.g. PC-* or ACC-??, comma separated. New computers that match get the policy automatically.',
      epNewApp: 'New app internet policy', epNewGuard: 'New Login Guard profile', epNameAppPh: 'e.g. Block browsers for accounting', epNameGuardPh: 'e.g. Internet-facing servers', epNotePh: 'Admin note (optional)',
      epProgramsHint: 'One program per line: file name (chrome.exe) or full path (C:\\Program Files\\…\\app.exe or %ProgramFiles%\\…).', epQuick: 'Quick pick',
      epSchedule: 'Schedule', epScheduleOn: 'Apply only on the days and hours below', epDays: 'Days', epDaysHint: 'No day = every day', epFromTo: 'From – to',
      epGuardSet: 'Login Guard settings', epGuardOn: 'Login Guard is on for these computers', epPriorityHint: 'Higher number = higher priority', epWebMax: 'Web failure threshold (401)',
      epProtect: 'Protect', epLan: 'Never block local network IPs', epAllowedC: 'Allowed countries', epBlockedC: 'Blocked countries',
      epWorkHours: 'Work hours', epWorkHoursOn: 'Outside work hours, block any remote logon attempt immediately',
      epSaveApply: 'Save and apply', epSavedHint: 'Saved; applied to the computers within 2 minutes', epDelQ: 'Delete this policy and remove it from the computers?', epAppliesTo: 'Covers',
      epNoAgents: 'No computer has the agent yet; policies apply to computers with an agent.',
      epAppliedOk: 'Applied', epPendingSync: 'Waiting to sync', epNeverSynced: 'Not reported yet', epGuardDefault: 'Default', epRules: 'Rules', epNotFound: 'Not found on this computer',
      epBlocking: 'Blocking', epOutside: 'Outside schedule',
      day_Saturday: 'Sat', day_Sunday: 'Sun', day_Monday: 'Mon', day_Tuesday: 'Tue', day_Wednesday: 'Wed', day_Thursday: 'Thu', day_Friday: 'Fri',
      adOverview: 'Overview', adHardware: 'Hardware & network', adSoftware: 'Software', adPolicies: 'Policies', adActions: 'Actions',
      adOs: 'Operating system', adUser: 'Signed-in user', adUptime: 'Uptime', adMemFree: 'Free memory', adDiskC: 'Free space C:', adRtOn: 'Real-time on', adRtOff: 'Real-time off', adSigAge: 'Signature age', adNoAv: 'Defender not available',
      adFirewall: 'Firewall', adReboot: 'Reboot pending', adIsolated: 'Isolated', adPolicy: 'Policy', adAgentVer: 'Agent version', adInvAt: 'Last inventory', adNoInv: 'No inventory yet (arrives within 2 minutes of install)',
      adModel: 'Make/model', adSerial: 'Serial number', adInstalled: 'Installed', adDisks: 'Disks', adSize: 'Size', adFree: 'Free', adNet: 'Network adapters', adAdmins: 'Local administrators', adHotfix: 'Installed updates',
      adVersion: 'Version', adPublisher: 'Publisher', adItems: 'items', adPaths: 'Paths found',
      acLead: 'Actions run over the agent\'s secure channel on its next heartbeat (within 2 minutes) and the result is recorded here. Only predefined actions are accepted.',
      acInventory: 'Collect inventory now', acSync: 'Re-apply policy', acScan: 'Defender quick scan', acDefUpd: 'Update Defender', acUpdate: 'Update agent', acKill: 'Stop a program', acBlockIp: 'Block IP',
      acUnblockIp: 'Unblock IP', acIsolate: 'Isolate', acUnisolate: 'Lift isolation', acReboot: 'Restart (5 min)', acKillQ: 'Process name (e.g. chrome):', acIpQ: 'IP:', acMinQ: 'Minutes? (0 = permanent)',
      acRebootQ: 'Restart the computer in 5 minutes, warning the user first?', acQueued: 'Queued; runs on the agent\'s next heartbeat', acHistory: 'Action history', acDone: 'Done', acSent: 'Sent', acQueuedS: 'Queued',
      swLead: 'Installed software on every computer with an agent (refreshed daily). Search to see which program, which version, on which computers.',
      swSearchPh: 'Program or publisher…', swComputers: 'computers with inventory', swCount: 'Computers', swWhere: 'On computers', swNoInv: 'No inventory from agents yet', agDetail: 'Details'
    }
  };
  for (var L2 in D2) { for (var k2 in D2[L2]) { D[L2][k2] = D2[L2][k2]; } }
  var D3 = {
    fa: {
      reports: 'گزارش‌ها', users: 'کاربر ۳۶۰', d90: '۹۰ روز', rpLead: 'بیش از ۶۰ گزارشِ آماده مثلِ ADAudit Plus و EventLog Analyzer: ورود، قفل‌شدنِ حساب، تغییرِ گروه‌ها، اجرای برنامه، سرویس، فایل، سیستم‌ها و نرم‌افزارها. فیلترها بی‌درنگ اعمال می‌شوند؛ خروجیِ CSV برای Excel و ارسالِ خودکار با ایمیل.',
      rpFind: 'جست‌وجوی گزارش…', rpSchedule: 'ارسالِ زمان‌بندی‌شده', rpSchedules: 'گزارش‌های زمان‌بندی‌شده', rpNewSchedule: 'زمان‌بندیِ تازه', rpTrunc: 'فقط ۲۰۰۰ ردیفِ اول نمایش داده شد؛ همه در CSV',
      rpEmpty: 'در این بازه چیزی نیست', rpNoMail: 'ایمیل تنظیم نشده؛ گزارش‌های زمان‌بندی‌شده فرستاده نمی‌شوند.', rpNoSchedules: 'هنوز زمان‌بندی‌ای ندارید', rpWhen: 'زمانِ ارسال', rpTo: 'گیرندگان',
      fq_daily: 'روزانه', fq_weekly: 'هفتگی', fq_monthly: 'ماهانه', rpSchedNamePh: 'مثلاً: گزارشِ امنیتیِ هفتگی', rpAuto: 'خودکار (به اندازهٔ دورهٔ ارسال)', rpRangeL: 'بازهٔ داده',
      rpToHint: 'هر خط یک ایمیل', rpHostHint: 'اختیاری؛ فقط این سیستم‌ها (مثلاً SRV-*)', rpSendNow: 'ذخیره و ارسالِ همین الان', rpSent: 'فرستاده شد', rpDelQ: 'این زمان‌بندی حذف شود؟',
      uaLead: 'همهٔ فعالیت‌های یک کاربر در یک صفحه (الگو: «ردِ ممیزیِ کاربر» در ADAudit Plus): ورودها و مبدأها، ناموفق‌ها و قفل‌شدن، دسترسیِ مدیر، تغییراتی که انجام داده یا روی او انجام شده، برنامه‌ها و یافته‌های امنیتی، با امتیازِ ریسک.',
      uaPh: 'نامِ کاربر (مثلاً ali یا CORP\\ali)', uaHint: 'نامِ یک کاربر را بنویسید و Enter بزنید.', uaRisk: 'امتیازِ ریسک', uaLogons: 'ورود', uaFailed: 'ورودِ ناموفق', uaLock: 'قفل‌شدن', uaAdmin: 'ورودِ مدیر',
      uaAfter: 'ورودِ بیرون از ساعتِ کاری', uaChanges: 'تغییر در حساب‌ها/گروه‌ها', uaProc: 'برنامهٔ اجراشده', uaWhere: 'کجا وارد شده', uaFindings: 'یافته‌های امنیتیِ مرتبط', uaTimeline: 'خطِ زمانیِ فعالیت'
    },
    en: {
      reports: 'Reports', users: 'User 360', d90: '90 days', rpLead: '60+ ready reports like ADAudit Plus and EventLog Analyzer: logons, lockouts, group changes, process execution, services, files, endpoints and software. Filters apply instantly; CSV export for Excel and scheduled e-mail delivery.',
      rpFind: 'Find a report…', rpSchedule: 'Schedule by e-mail', rpSchedules: 'Scheduled reports', rpNewSchedule: 'New schedule', rpTrunc: 'only the first 2000 rows are shown; all are in the CSV',
      rpEmpty: 'Nothing in this period', rpNoMail: 'E-mail is not configured; scheduled reports cannot be sent.', rpNoSchedules: 'No schedules yet', rpWhen: 'When', rpTo: 'Recipients',
      fq_daily: 'Daily', fq_weekly: 'Weekly', fq_monthly: 'Monthly', rpSchedNamePh: 'e.g. Weekly security report', rpAuto: 'Automatic (matches the frequency)', rpRangeL: 'Data period',
      rpToHint: 'One e-mail per line', rpHostHint: 'Optional; only these computers (e.g. SRV-*)', rpSendNow: 'Save and send now', rpSent: 'Sent', rpDelQ: 'Delete this schedule?',
      uaLead: 'Everything one user did, on one page (like the ADAudit Plus user audit trail): logons and their sources, failures and lockouts, admin access, changes made by or to the user, programs run and related findings, with a risk score.',
      uaPh: 'User name (e.g. ali or CORP\\ali)', uaHint: 'Type a user name and press Enter.', uaRisk: 'Risk score', uaLogons: 'Logons', uaFailed: 'Failed logons', uaLock: 'Lockouts', uaAdmin: 'Admin logons',
      uaAfter: 'After-hours logons', uaChanges: 'Account/group changes made', uaProc: 'Programs run', uaWhere: 'Where they logged on', uaFindings: 'Related security findings', uaTimeline: 'Activity timeline'
    }
  };
  for (var L3 in D3) { for (var k3 in D3[L3]) { D[L3][k3] = D3[L3][k3]; } }
  var D4 = {
    fa: {
      epTabFleet: 'امنیت و به‌روزرسانیِ سیستم‌ها', epTabHarden: 'سخت‌سازیِ اجباری', epTabPatch: 'نصبِ خودکارِ به‌روزرسانی', ptAll: 'همهٔ به‌روزرسانی‌ها', ptSec: 'فقط امنیتی و حیاتی', epEveryDay: 'هر روز',
      ptRebootAuto: 'اگر لازم بود، ری‌استارت با ۱۵ دقیقه هشدار به کاربر', ptRebootNever: 'بدونِ ری‌استارتِ خودکار',
      hdPolicies: 'سیاست‌های سخت‌سازی', hdLead: 'تنظیماتِ امنیتیِ انتخاب‌شده روی سیستم‌های هدف همیشه درست نگه داشته می‌شوند؛ اگر کسی یا برنامه‌ای عوضشان کند، ایجنت در بررسیِ بعدی (حداکثر روزی یک‌بار یا با فرمان) دوباره اصلاحشان می‌کند.',
      hdHow: 'هر مورد یک تنظیمِ مستندِ ویندوز است (رجیستری، فایروال، Defender، سیاستِ حساب). موردی که ری‌استارت لازم دارد پس از ری‌استارتِ بعدی اثر می‌کند.', hdNew: 'سیاستِ سخت‌سازیِ تازه', hdNamePh: 'مثلاً: خط‌مبنای امنیتیِ کلاینت‌ها',
      ptPolicies: 'سیاست‌های نصبِ به‌روزرسانی', ptLead: 'به‌روزرسانی‌های ویندوز در پنجرهٔ زمانیِ تعیین‌شده خودکار دانلود و نصب می‌شوند (الگو: Automated Patch Deployment در Endpoint Central).',
      ptHow: 'نصب در پس‌زمینه با اولویتِ پایین انجام می‌شود تا کاربر کندی حس نکند. نتیجه و فهرستِ به‌روزرسانی‌های باقی‌مانده در «حفاظت» دیده می‌شود.', ptNew: 'سیاستِ نصبِ تازه', ptNamePh: 'مثلاً: وصله‌های امنیتیِ پنجشنبه',
      sv_high: 'بالا', sv_medium: 'متوسط', sv_low: 'کم', hdChecks: 'تنظیماتی که باید همیشه برقرار بمانند', hdNote: 'پیشنهاد: اول روی چند سیستمِ آزمایشی اعمال کنید.',
      ptWindow: 'پنجرهٔ نصب', ptScope: 'کدام به‌روزرسانی‌ها', ptHour: 'ساعتِ شروع', ptHourHint: 'نصب تا ۳ ساعت پس از این ساعت شروع می‌شود', ptReboot: 'ری‌استارت', ptNote: 'هر روز فقط یک‌بار اجرا می‌شود.',
      flAvg: 'میانگینِ امتیازِ امنیت', flWeak: 'سیستمِ ضعیف (زیرِ ۶۰)', flMissing: 'به‌روزرسانیِ نصب‌نشده', flScanAll: 'بررسیِ دوبارهٔ همه', flInstallAll: 'نصبِ به‌روزرسانی‌های امنیتی روی همه',
      flNothing: 'به‌روزرسانیِ امنیتیِ نصب‌نشده‌ای نیست', flInstallQ: 'به‌روزرسانی‌های امنیتی روی {n} سیستم نصب شود؟ (بدونِ ری‌استارتِ خودکار)',
      flLead: 'امتیازِ پیکربندیِ امنیتی (الگو: CIS) و به‌روزرسانی‌های نصب‌نشدهٔ هر سیستم. روی هر سیستم کلیک کنید تا جزئیات و دکمه‌های رفعِ مشکل را ببینید.',
      flSec: 'امنیتی', flNoData: 'هنوز گزارشی از ایجنت‌ها نرسیده', flScore: 'امتیاز', flFailed: 'موارد ناموفق', flUpdates: 'به‌روزرسانی‌ها',
      psNone: 'هنوز بررسیِ امنیتی‌ای نرسیده.', psScan: 'بررسیِ دوباره', psFixAll: 'رفعِ همهٔ موارد', psFixQ: 'همهٔ موارد قابلِ رفع، روی این سیستم اصلاح شوند؟', psEnforced: 'اصلاحِ خودکار طبقِ سیاست',
      psCheck: 'بررسی', psSev: 'اهمیت', psValue: 'وضعیتِ فعلی', psFix: 'رفع', upInstallQ: 'به‌روزرسانی‌ها روی این سیستم نصب شوند؟', upScan: 'بررسیِ به‌روزرسانی', upInstallSec: 'نصبِ امنیتی‌ها', upInstallAll: 'نصبِ همه',
      upNone: 'هنوز نتیجهٔ بررسیِ به‌روزرسانی نرسیده (بررسی در پس‌زمینه چند دقیقه طول می‌کشد).', upLast: 'آخرین نصب', upMissing: 'به‌روزرسانیِ نصب‌نشده', upAllGood: 'همهٔ به‌روزرسانی‌ها نصب است', upTitle: 'به‌روزرسانی', upDate: 'انتشار',
      adSecurity: 'امنیت', adUpdates: 'به‌روزرسانی‌ها'
    },
    en: {
      epTabFleet: 'Security & updates', epTabHarden: 'Enforced hardening', epTabPatch: 'Automatic updates', ptAll: 'All updates', ptSec: 'Security and critical only', epEveryDay: 'every day',
      ptRebootAuto: 'Restart if needed, with a 15-minute warning to the user', ptRebootNever: 'No automatic restart',
      hdPolicies: 'Hardening policies', hdLead: 'The chosen security settings are kept in place on the target computers; if a person or program changes them, the agent fixes them again on its next check (at most daily, or on demand).',
      hdHow: 'Each item is a documented Windows setting (registry, firewall, Defender, account policy). Items that need a restart take effect after the next restart.', hdNew: 'New hardening policy', hdNamePh: 'e.g. Client security baseline',
      ptPolicies: 'Update installation policies', ptLead: 'Windows updates are downloaded and installed automatically in the chosen window (like Automated Patch Deployment in Endpoint Central).',
      ptHow: 'Installation runs in the background at low priority so users feel no slowdown. Results and remaining updates appear under Security & updates.', ptNew: 'New update policy', ptNamePh: 'e.g. Thursday security patches',
      sv_high: 'High', sv_medium: 'Medium', sv_low: 'Low', hdChecks: 'Settings that must always stay in place', hdNote: 'Tip: apply to a few test computers first.',
      ptWindow: 'Installation window', ptScope: 'Which updates', ptHour: 'Start hour', ptHourHint: 'Installation starts within 3 hours after this hour', ptReboot: 'Restart', ptNote: 'Runs at most once a day.',
      flAvg: 'Average security score', flWeak: 'Weak computers (below 60)', flMissing: 'Missing updates', flScanAll: 'Re-check all', flInstallAll: 'Install security updates on all',
      flNothing: 'No missing security updates', flInstallQ: 'Install security updates on {n} computer(s)? (no automatic restart)',
      flLead: 'Security configuration score (CIS-style) and missing updates per computer. Click a computer for details and fix buttons.',
      flSec: 'security', flNoData: 'No reports from agents yet', flScore: 'Score', flFailed: 'Failed checks', flUpdates: 'Updates',
      psNone: 'No security check received yet.', psScan: 'Check again', psFixAll: 'Fix all', psFixQ: 'Fix every fixable item on this computer?', psEnforced: 'Fixed automatically by policy',
      psCheck: 'Check', psSev: 'Severity', psValue: 'Current', psFix: 'Fix', upInstallQ: 'Install updates on this computer?', upScan: 'Check for updates', upInstallSec: 'Install security', upInstallAll: 'Install all',
      upNone: 'No update scan received yet (the background scan takes a few minutes).', upLast: 'Last installation', upMissing: 'missing update(s)', upAllGood: 'All updates are installed', upTitle: 'Update', upDate: 'Released',
      adSecurity: 'Security', adUpdates: 'Updates'
    }
  };
  for (var L4 in D4) { for (var k4 in D4[L4]) { D[L4][k4] = D4[L4][k4]; } }
  var D5 = {
    fa: {
      epTabLaunch: 'جلوگیری از اجرای برنامه‌ها', al_block: 'جلوگیری', al_warn: 'هشدار', al_audit: 'فقط ثبت',
      alPolicies: 'سیاست‌های کنترلِ اجرای برنامه', alBlockList: 'فهرستِ ممنوع', alAllowOnly: 'فقط‌مجاز',
      alLead: 'جلوی اجرای برنامه‌های انتخاب‌شده را بگیرید، یا فقط هشدار بدهید. مبنا: AppLocker ویندوز (الگو: Application Control در Endpoint Central).',
      alHow: 'در حالتِ «جلوگیری» برنامه اصلاً اجرا نمی‌شود. در «هشدار» و «فقط ثبت»، AppLocker در حالتِ AuditOnly کار می‌کند؛ برنامه اجرا می‌شود ولی تلاش ثبت می‌شود (و در «هشدار» به کاربر پیام داده می‌شود). حذفِ سیاست، فقط قواعدِ لاگ‌بوک را برمی‌دارد و قواعدِ دستیِ مدیر دست‌نخورده می‌ماند.',
      alNew: 'سیاستِ تازهٔ کنترلِ اجرا', alNamePh: 'مثلاً: ممنوعیتِ ابزارهای ریموت',
      alMode: 'رفتار', alList: 'شیوهٔ فهرست', alListHint: 'فهرستِ ممنوع: فقط برنامه‌های انتخاب‌شده کنترل می‌شوند و بقیه آزادند. فقط‌مجاز: فقط برنامه‌های انتخاب‌شده (به‌علاوهٔ خودِ ویندوز و مدیران) اجازهٔ اجرا دارند و بقیه‌ی برنامه‌ها بسته می‌شوند.',
      alProgramsHint: 'هر خط یک برنامه: نامِ فایل (chrome.exe) یا مسیرِ کامل. در حالتِ «فقط‌مجاز» این‌ها فهرستِ مجازند.',
      alHow2: 'رفتار و فهرست', alWarnText: 'متنِ پیام به کاربر', alWarnPh: 'این برنامه مجاز نیست…',
      alModeHint_block: 'برنامه اجرا نمی‌شود و تلاش ثبت می‌شود.', alModeHint_warn: 'برنامه اجرا می‌شود، به کاربر پیام داده و در کنسول ثبت می‌شود.', alModeHint_audit: 'برنامه اجرا می‌شود و فقط بی‌صدا در گزارش‌ها ثبت می‌شود.'
    },
    en: {
      epTabLaunch: 'Application control', al_block: 'Block', al_warn: 'Warn', al_audit: 'Audit only',
      alPolicies: 'Application-control policies', alBlockList: 'Block list', alAllowOnly: 'Allow only',
      alLead: 'Stop chosen programs from running, or just warn. Built on Windows AppLocker (like Application Control in Endpoint Central).',
      alHow: 'In "Block" the program will not run. In "Warn" and "Audit only" AppLocker runs in AuditOnly mode: the program runs but the attempt is logged (and in "Warn" the user gets a message). Deleting the policy removes only LogBok\'s rules; the admin\'s own AppLocker rules stay untouched.',
      alNew: 'New application-control policy', alNamePh: 'e.g. Block remote-access tools',
      alMode: 'Behaviour', alList: 'List type', alListHint: 'Block list: only the chosen programs are controlled, everything else is free. Allow only: only the chosen programs (plus Windows itself and administrators) may run; everything else is blocked.',
      alProgramsHint: 'One program per line: file name (chrome.exe) or a full path. In "Allow only" these are the permitted programs.',
      alHow2: 'Behaviour and list', alWarnText: 'Message shown to the user', alWarnPh: 'This program is not permitted…',
      alModeHint_block: 'The program will not run; the attempt is logged.', alModeHint_warn: 'The program runs, the user is notified, and it is logged in the console.', alModeHint_audit: 'The program runs and is silently recorded in reports only.'
    }
  };
  for (var L5 in D5) { for (var k5 in D5[L5]) { D[L5][k5] = D5[L5][k5]; } }
  var D6 = {
    fa: {
      epExcept: 'به‌جز', epExceptHosts: 'به‌جز سیستم‌ها', epExceptPatterns: 'به‌جز الگوها',
      epExceptHint: 'این سیستم‌ها/الگوها از این سیاست کنار گذاشته می‌شوند، حتی اگر در هدف‌ها باشند (استثنا برنده است).',
      abWho: 'برای کدام کاربران/گروه‌ها', abUsers: 'فقط برای', abUsersHint: 'نامِ کاربر یا گروهِ ویندوز، هر خط یکی (مثلاً DOMAIN\\ali یا Accounting). خالی = همهٔ کاربرانِ آن سیستم.',
      abExceptUsers: 'به‌جز', abExceptHint: 'این کاربران/گروه‌ها مستثنا می‌شوند. اگر «فقط برای» خالی باشد یعنی «برای همه به‌جز این‌ها».',
      abOnly: 'فقط', abEveryoneExcept: 'همه به‌جز'
    },
    en: {
      epExcept: 'except', epExceptHosts: 'Except computers', epExceptPatterns: 'Except patterns',
      epExceptHint: 'These computers/patterns are excluded from this policy even if they match the targets (exclusions win).',
      abWho: 'For which users/groups', abUsers: 'Only for', abUsersHint: 'Windows user or group name, one per line (e.g. DOMAIN\\ali or Accounting). Empty = all users on that computer.',
      abExceptUsers: 'Except', abExceptHint: 'These users/groups are excluded. If "Only for" is empty this means "everyone except these".',
      abOnly: 'only', abEveryoneExcept: 'everyone except'
    }
  };
  for (var L6 in D6) { for (var k6 in D6[L6]) { D[L6][k6] = D6[L6][k6]; } }
  var D7 = {
    fa: { adDomains: 'دامنه‌های اکتیودایرکتوری', adAddDomain: 'افزودنِ دامنه', adNoDomain: 'هنوز دامنه‌ای وصل نشده؛ آدرسِ DC و حسابِ Domain Admin را وارد کنید و «اتصال و ذخیره» را بزنید.',
      adDomain: 'دامنه', adInventory: 'خوانده‌شده از اکتیو', lastCheck: 'آخرین بررسی', adComp: 'کامپیوتر', adSrv: 'سرور', adWks: 'کلاینت', adUsr: 'کاربر', adGrp: 'گروه',
      adReadyOk: 'آماده', adReadyPart: 'ناقص', adComputers: 'کامپیوترها', adRecheck: 'بررسی و خواندنِ دوباره', adConnected: 'دامنه وصل و ذخیره شد',
      adDomainDelQ: 'این دامنه و حسابِ ذخیره‌شده‌اش حذف شود؟', adPwKeep: 'خالی = رمزِ ذخیره‌شده', adConnectSave: 'اتصال و ذخیره',
      adDomainLead: 'لاگ‌بوک به DC وصل می‌شود، آمادگی (LDAP، مجوزِ GPO، SYSVOL) را بررسی می‌کند، کامپیوترها/OUها/کاربران را می‌خواند و دامنه را با رمزِ رمزگذاری‌شده (DPAPI) ذخیره می‌کند. هر تعداد دامنه می‌توانید اضافه کنید.',
      adLastChecks: 'نتیجهٔ آخرین بررسی', adNoAgent: 'بدونِ ایجنت', adReadAd: 'خواندن از اکتیو', adPushHint: 'نصبِ فوری روی سیستم‌های روشن انجام می‌شود (WinRM یا SMB). برای سیستم‌های خاموش یا بدونِ WinRM، یک «سیاستِ استقرار» با روشِ GPO بسازید.',
      adAcctHint: 'حسابِ Domain Admin لازم است و رمزگذاری‌شده (DPAPI) روی همین سرور ذخیره می‌شود. «بررسی و خواندنِ دوباره» آمار را تازه می‌کند.' },
    en: { adDomains: 'Active Directory domains', adAddDomain: 'Add domain', adNoDomain: 'No domain connected yet: enter a DC address and a Domain Admin account, then press "Connect & save".',
      adDomain: 'Domain', adInventory: 'Read from AD', lastCheck: 'Last check', adComp: 'computers', adSrv: 'servers', adWks: 'workstations', adUsr: 'users', adGrp: 'groups',
      adReadyOk: 'ready', adReadyPart: 'incomplete', adComputers: 'Computers', adRecheck: 'Re-check & re-read', adConnected: 'Domain connected and saved',
      adDomainDelQ: 'Remove this domain and its saved account?', adPwKeep: 'blank = saved password', adConnectSave: 'Connect & save',
      adDomainLead: 'LogBok connects to the DC, checks readiness (LDAP, GPO rights, SYSVOL), reads computers/OUs/users and saves the domain with its password encrypted (DPAPI). You can add any number of domains.',
      adLastChecks: 'Last check result', adNoAgent: 'no agent', adReadAd: 'Read from AD', adPushHint: 'Install now works on computers that are on (WinRM or SMB). For computers that are off or have no WinRM, create a deployment policy with the GPO method.',
      adAcctHint: 'A Domain Admin account is required; it is stored encrypted (DPAPI) on this server. "Re-check & re-read" refreshes the counts.' }
  };
  for (var L7 in D7) { for (var k7 in D7[L7]) { D[L7][k7] = D7[L7][k7]; } }
  var D8 = {
    fa: { agTabWg: 'استقرار در Workgroup', wgLead: 'در Workgroup هیچ سرویسِ مرکزی (مثلِ GPO) نیست، پس روشِ امن این است: یک‌بار روی هر سیستم خطِ نصب یا فایلِ LogBok-Join.cmd را اجرا کنید (تبِ «یک سیستم»). بعد از آن همه‌چیز (به‌روزرسانی، فرمان‌ها، گزارش) خودکار و فقط از راهِ پورتِ 8687ِ همین سرور است. اسکن و نصبِ گروهیِ پایین فقط وقتی کار می‌کند که «نصب از راه دور» را آگاهانه روشن کرده باشید.',
      wgGroups: 'گروه‌های Workgroup', wgAdd: 'افزودنِ گروه', wgNone: 'هنوز گروهی ساخته نشده؛ محدودهٔ IP یا فهرستِ سیستم‌ها و یک حسابِ مدیرِ محلی وارد کنید و «اسکن و ذخیره» را بزنید.',
      wgScope: 'محدوده', wgReach: 'در دسترس', wgAlive: 'روشن', wgHostsN: 'سیستمِ دستی', wgNoCred: 'حسابی ذخیره نشده',
      wgRange: 'محدودهٔ IP', wgHosts: 'فهرستِ نام/IP (هر خط یکی)', wgCred: 'حسابِ مدیرِ محلیِ مشترک', wgCredHint: 'حسابِ مدیرِ محلی که روی همهٔ این سیستم‌ها یکسان است (مثلاً Administrator). رمزگذاری‌شده (DPAPI) ذخیره می‌شود. برای سیستمی که رمزِ متفاوتی دارد، می‌توانید در «افزودنِ سیستم › یک سیستم» حسابِ اختصاصی ثبت کنید.',
      wgScanSave: 'اسکن و ذخیره', wgScanned: 'اسکن و ذخیره شد', wgRescan: 'اسکنِ دوباره', wgDelQ: 'این گروه و حسابِ ذخیره‌شده‌اش حذف شود؟',
      wgDrawerLead: 'محدودهٔ IP را مثلِ 10.1.99.10-60 بنویسید، یا نام/IP سیستم‌ها را خط‌به‌خط. هر دو را هم می‌توانید با هم بدهید.',
      wgReadyWinRm: 'آمادهٔ نصب (WinRM)', wgFilter: 'نمایش:', wgInstallHint: 'نصبِ فوری نیاز به WinRM (۵۹۸۵) یا اشتراکِ C$ دارد و حساب باید مدیرِ محلیِ همان سیستم باشد. روی سیستمی که WinRM ندارد، یا یک‌بار دستور winrm quickconfig -force را آنجا اجرا کنید، یا از «بستهٔ نصبِ دستی» بستهٔ نصب را بگیرید.',
      lastScan: 'آخرین اسکن', wgHint: 'هر گروه حسابِ مشترکِ خودش را دارد و رمزگذاری‌شده نگه داشته می‌شود؛ با رفرش یا ری‌استارت سرور از بین نمی‌رود.' },
    en: { agTabWg: 'Workgroup deployment', wgLead: 'A workgroup has no central service (like GPO), so the secure way is: run the install line or LogBok-Join.cmd once on each computer (the "One computer" tab). After that everything (updates, commands, reports) is automatic and only over port 8687 of this server. The scan and group install below work only if you deliberately turn on "remote push".',
      wgGroups: 'Workgroup groups', wgAdd: 'Add group', wgNone: 'No group yet: enter an IP range or a list of computers and a local-admin account, then press "Scan & save".',
      wgScope: 'Scope', wgReach: 'Reachable', wgAlive: 'on', wgHostsN: 'manual', wgNoCred: 'no account saved',
      wgRange: 'IP range', wgHosts: 'Name/IP list (one per line)', wgCred: 'Shared local-admin account', wgCredHint: 'A local-admin account that is the same on all these computers (e.g. Administrator). Stored encrypted (DPAPI). For a computer with a different password, save a per-computer account under Add computers › One computer.',
      wgScanSave: 'Scan & save', wgScanned: 'Scanned and saved', wgRescan: 'Rescan', wgDelQ: 'Remove this group and its saved account?',
      wgDrawerLead: 'Write an IP range like 10.1.99.10-60, or computer names/IPs one per line. You can give both.',
      wgReadyWinRm: 'ready (WinRM)', wgFilter: 'Show:', wgInstallHint: 'Install now needs WinRM (5985) or the C$ share, and the account must be a local administrator there. On a computer with no WinRM, either run winrm quickconfig -force once there, or grab the installer from Manual installer.',
      lastScan: 'Last scan', wgHint: 'Each group keeps its own shared account, stored encrypted; it survives a refresh or a server restart.' }
  };
  for (var L8 in D8) { for (var k8 in D8[L8]) { D[L8][k8] = D8[L8][k8]; } }
  var D9 = {
    fa: { mgTitle: 'مهاجرتِ سرور و پشتیبانِ هویتِ ایجنت‌ها', mgLead: 'هویتِ هر ایجنت (رازِ اختصاصی)، توکنِ ثبت‌نام و حساب‌های ذخیره‌شده با رمزِ این سرور قفل‌اند. اگر سرور عوض شود یا از نو نصب شود، با این بخش همه‌چیز را به سرورِ تازه منتقل می‌کنید و ایجنت‌ها بدونِ نصبِ دوباره وصل می‌مانند.',
      mgBkTitle: '۱) پشتیبانِ خودکارِ روزانه', mgBkPath: 'پوشهٔ پشتیبان (محلی یا UNC)', mgPass: 'عبارتِ عبورِ فایلِ پشتیبان', mgPassPh: 'عبارتِ عبور (دست‌کم ۸ نویسه)', mgBkNow: 'پشتیبانِ فوری', mgBkOn: 'پشتیبانِ روزانه فعال است', mgBkNoPass: 'عبارتِ عبور ذخیره نشده', mgBkOff: 'پشتیبانِ خودکار تنظیم نشده', mgLastRun: 'آخرین اجرا',
      mgExTitle: '۲) دریافتِ فایلِ پشتیبان همین حالا', mgExport: 'دریافتِ فایل', mgExported: 'فایل آماده شد', mgPassShort: 'عبارتِ عبور دست‌کم ۸ نویسه باشد',
      mgRsTitle: '۳) بازگردانی روی این سرور', mgRsLead: 'روی سرورِ تازه: لاگ‌بوک را نصب کنید، فایلِ .lbk و عبارتِ عبور را اینجا بدهید. رکوردهای هم‌نام جایگزین می‌شوند؛ با «جایگزینیِ کامل» تنظیماتِ سرور هم از فایل می‌آید.', mgRsReplace: 'جایگزینیِ کامل', mgRestore: 'بازگردانی', mgRsNoFile: 'فایلِ .lbk را انتخاب کنید', mgRsQ: 'هویتِ ایجنت‌ها و حساب‌ها از فایل روی این سرور نوشته شود؟', mgRestored: 'بازگردانی شد', mgCreds: 'حساب',
      mgMvTitle: '۴) جابه‌جایی برنامه‌ریزی‌شده به سرورِ دیگر', mgMvLead: 'وقتی سرورِ تازه آماده است (و پشتیبان روی آن بازگردانی شده)، نشانیِ تازه را به همهٔ ایجنت‌های فعال بفرستید. هر ایجنت اول نشانی را می‌آزماید و فقط اگر جواب بدهد، جابه‌جا می‌شود.', mgMvName: 'نامِ سرورِ جدید (DNS)', mgMvIp: 'IPِ سرورِ جدید', mgMvPort: 'پورت (پیش‌فرض ۸۶۸۷)', mgMove: 'ارسال به ایجنت‌ها', mgMvNeed: 'نام یا IP لازم است', mgMvQ: 'به همهٔ ایجنت‌های فعال گفته شود به این سرور بروند؟', mgMoved: 'فرمان فرستاده شد',
      mgTip1: '• بهترین کار: به ایجنت‌ها یک نامِ DNS ثابت بدهید (مثلاً logbok.yas.ir). اگر IPِ سرور عوض شود، ایجنت‌ها خودشان نام را دوباره پیدا می‌کنند و هیچ کاری لازم نیست.',
      mgTip2: '• اگر سرور ناگهان از بین رفت: لاگ‌بوک را با همان نام/IP نصب کنید و آخرین فایلِ پشتیبان را بازگردانید؛ ایجنت‌ها خودشان وصل می‌شوند. بدونِ پشتیبان هم ایجنت‌ها با توکنِ نگه‌داشته‌شان دوباره ثبت‌نام می‌کنند (تا وقتی توکن منقضی نشده باشد)؛ وگرنه نصبِ دوباره از راهِ GPO یا Workgroup.',
      mgTip3: '• تغییرِ نامِ سیستم یا عضویت در دامنه برای ایجنت مشکلی نیست: با شناسهٔ پایدارش شناخته می‌شود و سابقه‌اش حفظ می‌ماند.' },
    en: { mgTitle: 'Server migration & agent identity backup', mgLead: 'Each agent\'s identity (its secret), the enrollment token and saved accounts are locked to this server. When the server changes or is rebuilt, this section moves everything to the new server so the agents keep connecting without a reinstall.',
      mgBkTitle: '1) Daily automatic backup', mgBkPath: 'Backup folder (local or UNC)', mgPass: 'Backup file passphrase', mgPassPh: 'Passphrase (8+ characters)', mgBkNow: 'Back up now', mgBkOn: 'daily backup is on', mgBkNoPass: 'passphrase not saved', mgBkOff: 'automatic backup not configured', mgLastRun: 'last run',
      mgExTitle: '2) Download a backup file now', mgExport: 'Download', mgExported: 'File ready', mgPassShort: 'Passphrase must be at least 8 characters',
      mgRsTitle: '3) Restore onto this server', mgRsLead: 'On the new server: install LogBok, then give the .lbk file and passphrase here. Entries with the same name are replaced; "full replace" also takes the server settings from the file.', mgRsReplace: 'full replace', mgRestore: 'Restore', mgRsNoFile: 'Choose the .lbk file', mgRsQ: 'Write the agent identities and accounts from the file onto this server?', mgRestored: 'Restored', mgCreds: 'accounts',
      mgMvTitle: '4) Planned move to another server', mgMvLead: 'When the new server is ready (with the backup restored), send its address to all active agents. Each agent probes the address first and switches only if it answers.', mgMvName: 'New server name (DNS)', mgMvIp: 'New server IP', mgMvPort: 'Port (default 8687)', mgMove: 'Send to agents', mgMvNeed: 'name or IP required', mgMvQ: 'Tell all active agents to move to this server?', mgMoved: 'Command sent',
      mgTip1: '• Best practice: give agents a stable DNS name (e.g. logbok.yas.ir). If the server IP changes, agents re-resolve the name by themselves; nothing to do.',
      mgTip2: '• If the server is suddenly lost: install LogBok with the same name/IP and restore the latest backup; agents reconnect by themselves. Even without a backup, agents re-enroll with their kept token (while it has not expired); otherwise reinstall via GPO or Workgroup.',
      mgTip3: '• Renaming a computer or joining a domain does not affect the agent: it is recognized by its stable id and keeps its history.' }
  };
  for (var L9 in D9) { for (var k9 in D9[L9]) { D[L9][k9] = D9[L9][k9]; } }
  var D10 = {
    fa: { mgMailOn: 'ارسالِ خودکار به ایمیلِ مدیران', mgMailTo: 'گیرندگان', mgMailDefault: 'پیش‌فرضِ هشدارها', mgMailHint: 'خالی = همان گیرندگانِ هشدارها (Mail.To). فایل رمزگذاری‌شده است؛ عبارتِ عبور هرگز ایمیل نمی‌شود. تنظیماتِ SMTP از بخشِ تنظیمات استفاده می‌شود.', mgMailed: 'آخرین ایمیل', mgMailPending: 'هنوز ایمیلی فرستاده نشده',
      apTitle: 'برنامه‌های در حالِ استفاده از شبکه', apLead: 'ایجنت‌ها فهرستِ برنامه‌هایی را که اتصالِ شبکه دارند می‌فرستند و مشخص می‌کنند کدام به اینترنت می‌روند. یک سیستم را انتخاب کنید یا همهٔ ناوگان را ببینید، برنامه‌ها را تیک بزنید و «مسدودکردن» را بزنید؛ سپس در همان پنجره مشخص کنید روی کدام سیستم‌ها/OU/گروه‌ها/کاربران اعمال شود و چه کسانی مستثنا باشند.',
      apAllHosts: 'همهٔ سیستم‌ها (گروهی)', apOnlyInet: 'فقط دارای اینترنت', apRefresh: 'تازه‌خوانی از سیستم', apRefreshing: 'درخواست فرستاده شد؛ تا ۱۵ ثانیه دیگر فهرست تازه می‌شود', apInet: 'اینترنت', apLan: 'فقط شبکهٔ داخلی', apBlockedBy: 'مسدود توسطِ', apReported: 'گزارش‌شده', apNone: 'هنوز گزارشی از این سیستم نرسیده؛ «تازه‌خوانی» را بزنید', apProgram: 'برنامه', apTraffic: 'ترافیک', apRemotes: 'مقصدها', apUsers: 'کاربران', apBlockSel: 'مسدودکردنِ انتخاب‌شده‌ها', apPick: 'هیچ برنامه‌ای انتخاب نشده', apBlockHint: 'یک سیاستِ تازه با این برنامه‌ها باز می‌شود؛ اهداف و استثناها را همان‌جا تنظیم کنید.',
      tgApplyTo: 'اعمال بر', tgExcept: 'به‌جز', tgComputers: 'سیستم‌ها', tgAd: 'اکتیودایرکتوری', tgAdGroups: 'گروه‌های کامپیوتر', tgAdHint: 'OU: همهٔ سیستم‌های زیرِ آن OU. گروه: عضویتِ مستقیمِ حسابِ کامپیوتر. نقشهٔ OU/گروه با هر «بررسی و خواندنِ دوباره» در بخشِ دامنه‌ها تازه می‌شود. استثناها همیشه برنده‌اند.', tgUsersGroups: 'کاربران / گروه‌های کاربری', adNoDomainShort: 'دامنه‌ای وصل نیست' },
    en: { mgMailOn: 'E-mail to admins automatically', mgMailTo: 'Recipients', mgMailDefault: 'alert default', mgMailHint: 'Blank = the alert recipients (Mail.To). The file is encrypted; the passphrase is never e-mailed. SMTP settings come from Settings.', mgMailed: 'last e-mail', mgMailPending: 'no e-mail sent yet',
      apTitle: 'Programs using the network', apLead: 'Agents report the programs that have network connections and which of them reach the internet. Pick one computer or view the whole fleet, tick programs and press Block; then choose in the same window which computers / OUs / groups / users it applies to and who is excepted.',
      apAllHosts: 'All computers (fleet)', apOnlyInet: 'Internet only', apRefresh: 'Refresh from computer', apRefreshing: 'Request sent; the list refreshes in about 15 seconds', apInet: 'internet', apLan: 'LAN only', apBlockedBy: 'blocked by', apReported: 'reported', apNone: 'No report from this computer yet; press Refresh', apProgram: 'Program', apTraffic: 'Traffic', apRemotes: 'Destinations', apUsers: 'Users', apBlockSel: 'Block selected', apPick: 'No program selected', apBlockHint: 'A new policy opens with these programs; set targets and exceptions there.',
      tgApplyTo: 'apply to', tgExcept: 'except', tgComputers: 'Computers', tgAd: 'Active Directory', tgAdGroups: 'computer groups', tgAdHint: 'OU: every computer under that OU. Group: direct membership of the computer account. The OU/group map refreshes with "Re-check & re-read" under Domains. Exceptions always win.', tgUsersGroups: 'users / user groups', adNoDomainShort: 'no domain connected' }
  };
  for (var L10 in D10) { for (var k10 in D10[L10]) { D[L10][k10] = D10[L10][k10]; } }
  var D11 = {
    fa: { incUrg: 'فوریت', urgNow: 'همین حالا', urgToday: 'امروز', urgWeek: 'این هفته', incNone: 'رخدادِ بازی نیست — همه‌چیز آرام است',
      incHow: 'روشِ کار: ۱) از بالا به پایین، اول «همین حالا»ها. ۲) رخداد را باز کنید؛ «چه شد / چرا / چه کنیم» را بخوانید. ۳) اگر مشکل واقعی است، «در حالِ بررسی» بزنید و رسیدگی کنید؛ بعد «حل شد». ۴) اگر عادی یا آزمایشی است، «بی‌صدا» بزنید تا دیگر ایمیل نیاید.',
      pbWhat: 'چه اتفاقی افتاده؟', pbWhy: 'چرا مهم است؟', pbDo: 'چه کار کنیم؟', pbNormal: 'اگر عادی است', incResolve: '✓ حل شد', incInvestigate: 'در حالِ بررسی',
      muteLead: 'این هشدار برای شما عادی است؟ بی‌صدا کنید: رخداد بسته می‌شود و برای همین سیستم و همین عنوان ایمیلی نمی‌آید (در کنسول دیده می‌شود).', mute: 'بی‌صدا', unmute: 'باصدا', muted: 'بی‌صدا شد', muteForever: 'همیشه', muteAllHosts: 'روی همهٔ سیستم‌ها', days: 'روز' },
    en: { incUrg: 'Urgency', urgNow: 'now', urgToday: 'today', urgWeek: 'this week', incNone: 'No open incidents — all quiet',
      incHow: 'How to work: 1) top to bottom, "now" first. 2) Open the incident; read what / why / what to do. 3) If real, press Investigating and handle it; then Resolved. 4) If normal or a test, press Mute so no more e-mails come.',
      pbWhat: 'What happened?', pbWhy: 'Why it matters', pbDo: 'What to do', pbNormal: 'When this is normal', incResolve: '✓ Resolved', incInvestigate: 'Investigating',
      muteLead: 'Is this alert normal for you? Mute it: the incident closes and no e-mail is sent for this computer and title (still visible in the console).', mute: 'Mute', unmute: 'Unmute', muted: 'Muted', muteForever: 'forever', muteAllHosts: 'on all computers', days: 'days' }
  };
  for (var L11 in D11) { for (var k11 in D11[L11]) { D[L11][k11] = D11[L11][k11]; } }
  var D12 = {
    fa: { sessions: 'نشست‌ها', ssLead: 'چه کسی، از کجا و با چه دستگاهی به کدام سیستم وصل است و چقدر وصل بوده. نشست‌های زنده هر ۳۰ ثانیه تازه می‌شوند؛ تاریخچه از رویدادهای ورود/خروج ساخته می‌شود.',
      ssLiveNow: 'فعال همین حالا', ssDisc: 'قطع ولی باز', ssRdpNow: 'ریموت (RDP)', ssUsersOn: 'کاربرِ آنلاین', ssLive: 'نشست‌های زنده', ssAuto: 'به‌روزرسانیِ خودکار هر ۳۰ ثانیه', ssHistory: 'تاریخچهٔ نشست‌ها', ssAvg: 'میانگینِ مدت:', ssHistLoading: 'در حالِ خواندنِ تاریخچه…', ssHistIdle: 'تاریخچه هنوز خوانده نشده.', ssHistLoad: 'نمایشِ تاریخچه', reqTimeout: 'سرور دیر جواب داد؛ دوباره تلاش کنید', retry: 'تلاشِ دوباره',
      ssType: 'نوع', ssFrom: 'از کجا (دستگاه / IP)', ssFor: 'مدتِ اتصال', ssStart: 'شروع', ssEnd: 'پایان', ssDur: 'مدت', ssHow: 'چطور تمام شد', ssDiscN: 'بار قطع و وصل',
      ssActive: 'فعال', ssIdle: 'بی‌کار', ssDiscOne: 'قطع', ssEstimated: 'تخمینی (بدونِ ایجنت)', ssStale: 'ایجنت دیر گزارش داده', ssNoLive: 'اکنون نشستی باز نیست',
      ssEndLogoff: 'خروج', ssEndReboot: 'ری‌استارت', ssEndOpen: 'هنوز باز', ssEndUnknown: 'نامعلوم', stRdp: 'ریموت', stConsole: 'پشتِ سیستم', stCached: 'آفلاین', stLocal: 'محلی',
      ssLogoff: 'خارج‌کردن', ssDisconnect: 'قطع', ssLogoffQ: 'کاربر از این نشست خارج شود؟ کارهای ذخیره‌نشده‌اش از بین می‌رود.', ssDiscQ: 'این نشستِ ریموت قطع شود؟ برنامه‌ها باز می‌مانند.', ssMsgPh: 'پیام برای کاربر:', ssQueued: 'به ایجنت فرستاده شد؛ تا ۲ دقیقه اجرا می‌شود',
      ssWatch: 'ارزشِ نگاه‌کردن دارد', ssFiltered: 'فقط', ssLogs: 'لاگ‌های این نشست',
      sfExternal: 'از اینترنت', sfForgotten: 'رهاشده', sfMulti: 'هم‌زمان روی چند سیستم', sfAfter: 'بیرون از ساعتِ کاری', sfLong: 'بیش از ۱۲ ساعت', sfAdmin: 'با دسترسیِ مدیر',
      sgExternal: '{n} نشست از IPِ اینترنتی — ریموت‌دسکتاپ نباید مستقیم روی اینترنت باز باشد؛ پشتِ VPN ببرید.', sgForgotten: '{n} نشستِ ریموت بیش از ۲ ساعت قطع ولی باز مانده — حافظه و مجوز می‌گیرد و حساب باز می‌ماند؛ «خارج‌کردن» بزنید.',
      sgMulti: 'یک کاربر هم‌زمان روی چند سیستم وارد است — اگر حسابِ مشترک نیست، بررسی کنید.', sgAfter: '{n} ورود بیرون از ساعتِ کاری — اگر برنامه‌ریزی‌شده نبود، بررسی کنید.', sgLong: '{n} نشست بیش از ۱۲ ساعت باز است.',
      dShort: 'روز', hShort: 'ساعت', mShort: 'دقیقه' },
    en: { sessions: 'Sessions', ssLead: 'Who is connected to which computer, from where and from which device, and for how long. Live sessions refresh every 30 seconds; history is built from logon/logoff events.',
      ssLiveNow: 'Active now', ssDisc: 'Disconnected, still open', ssRdpNow: 'Remote (RDP)', ssUsersOn: 'Users online', ssLive: 'Live sessions', ssAuto: 'auto-refresh every 30 s', ssHistory: 'Session history', ssAvg: 'average:', ssHistLoading: 'Loading history…', ssHistIdle: 'History not loaded yet.', ssHistLoad: 'Show history', reqTimeout: 'The server took too long — try again', retry: 'Retry',
      ssType: 'Type', ssFrom: 'From (device / IP)', ssFor: 'Connected for', ssStart: 'Start', ssEnd: 'End', ssDur: 'Duration', ssHow: 'How it ended', ssDiscN: 'disconnects',
      ssActive: 'active', ssIdle: 'idle', ssDiscOne: 'disconnected', ssEstimated: 'estimated (no agent)', ssStale: 'agent report is late', ssNoLive: 'No open sessions right now',
      ssEndLogoff: 'logoff', ssEndReboot: 'restart', ssEndOpen: 'still open', ssEndUnknown: 'unknown', stRdp: 'remote', stConsole: 'at the computer', stCached: 'offline', stLocal: 'local',
      ssLogoff: 'Log off', ssDisconnect: 'Disconnect', ssLogoffQ: 'Log this user off? Unsaved work is lost.', ssDiscQ: 'Disconnect this remote session? Programs keep running.', ssMsgPh: 'Message to the user:', ssQueued: 'Sent to the agent; runs within 2 minutes',
      ssWatch: 'Worth a look', ssFiltered: 'Only', ssLogs: 'Logs of this session',
      sfExternal: 'from the internet', sfForgotten: 'forgotten', sfMulti: 'on several computers', sfAfter: 'after hours', sfLong: 'over 12 h', sfAdmin: 'admin rights',
      sgExternal: '{n} session(s) from an internet IP — Remote Desktop should not be exposed directly; put it behind a VPN.', sgForgotten: '{n} remote session(s) disconnected for over 2 h but still open — they hold memory and a license and keep the account signed in; log them off.',
      sgMulti: 'A user is signed in on several computers at once — check it unless it is a shared account.', sgAfter: '{n} logon(s) outside business hours — check them if not planned.', sgLong: '{n} session(s) open for over 12 hours.',
      dShort: 'd', hShort: 'h', mShort: 'min' }
  };
  for (var L12 in D12) { for (var k12 in D12[L12]) { D[L12][k12] = D12[L12][k12]; } }
  var D13 = {
    fa: { grpWatch: 'پایش', grpManage: 'مدیریت', nIncidents: 'رخدادها', nInvestigate: 'جست‌وجو و گزارش', nComputers: 'سیستم‌ها', nProtect: 'حفاظت',
      tIncidents: 'رخدادها (برای اقدام)', tDetections: 'همهٔ تشخیص‌ها', tLogSearch: 'جست‌وجوی لاگ', tComputerList: 'سیستم‌ها', tAddComputers: 'افزودنِ سیستم', tSoftware: 'نرم‌افزارها', tConnections: 'عیب‌یابیِ ارتباط',
      tGeneral: 'عمومی', tAgentsBackup: 'ایجنت و پشتیبان',
      dpLead: 'یک راه را انتخاب کنید. بعد از افزودن، هر سیستم در «سیستم‌ها» دیده می‌شود.', dpDomain: 'دامنه (اکتیو)', dpWorkgroup: 'بدونِ دامنه (Workgroup)', dpSingle: 'یک سیستم', dpPackage: 'بستهٔ نصبِ دستی', dpOther: 'تجهیزاتِ شبکه و برنامه‌ها',
      dpWithAgent: 'نصبِ ایجنت (پیشنهادی)', dpRemoteOnly: 'فقط خواندنِ لاگ از راه دور', dpSingleHint: 'ایجنت کاملِ امکانات را می‌دهد (نشست‌ها، کنترلِ برنامه، آپدیت، اقدام از راه دور). «فقط خواندنِ لاگ» برای سیستمی است که نمی‌خواهید رویش چیزی نصب شود.',
      acLead: 'تنظیماتی که یک‌بار انجام می‌شوند: نشانیِ این سرور برای ایجنت‌ها، امنیتِ بستهٔ نصب، حساب‌های ذخیره‌شده و پشتیبان/انتقال به سرورِ دیگر.', acWhere: 'امنیتِ بسته (توکن، تأییدِ مدیر) و نشانیِ سرور در:',
      cpLead: 'همهٔ سیستم‌های زیرِ نظر — با ایجنت یا بدونِ آن — در یک فهرست. روی هر ردیف بزنید تا جزئیات و اقدام‌ها باز شود.',
      cpPaused: 'متوقف', cpApproveHint: 'منتظرِ تأییدِ مدیر — جزئیات را باز کنید', cpInstallFailed: 'نصب ناموفق', cpInstalling: 'در حالِ نصب', cpOnline: 'آنلاین', cpNoContact: 'هنوز تماس نگرفته', cpOffline: 'آفلاین از', cpReading: 'لاگ خوانده می‌شود', cpConnProblem: 'مشکلِ ارتباط', cpNotTested: 'هنوز آزموده نشده',
      cpAll: 'همه', cpNeedAttention: 'نیازمندِ توجه', cpWithAgent: 'با ایجنت', cpWithoutAgent: 'بدونِ ایجنت', cpEmpty: 'هنوز سیستمی اضافه نشده — «افزودنِ سیستم» را بزنید', cpHow: 'روشِ پایش',
      how_agent: 'ایجنت', how_remote: 'خواندنِ لاگ از راه دور', how_syslog: 'Syslog', how_service: 'لاگِ برنامه', cpDetails: 'امنیت، آپدیت و جزئیات', cpSourceSettings: 'تنظیماتِ منبع و حساب', cpForgetQ: 'این سیستم از لاگ‌بوک فراموش شود؟ (کلید، داده‌های دریافتی و منبع پاک می‌شود)',
      guardThisServer: 'همین سرور', guardOthers: 'پروفایل‌های سپرِ ورود برای سیستم‌های دیگر (با ایجنت)',
      mutedTitle: 'هشدارهای بی‌صدا', mutedLead: 'برای این موارد ایمیل نمی‌آید (در کنسول دیده می‌شوند). از دکمهٔ «بی‌صدا» در رخدادها اضافه می‌شوند.', mutedNone: 'هیچ هشداری بی‌صدا نیست', until: 'تا', by: 'توسط' },
    en: { grpWatch: 'Watch', grpManage: 'Manage', nIncidents: 'Incidents', nInvestigate: 'Search & reports', nComputers: 'Computers', nProtect: 'Protection',
      tIncidents: 'Incidents (to act on)', tDetections: 'All detections', tLogSearch: 'Log search', tComputerList: 'Computers', tAddComputers: 'Add computers', tSoftware: 'Software', tConnections: 'Connection troubleshooting',
      tGeneral: 'General', tAgentsBackup: 'Agents & backup',
      dpLead: 'Pick one way. Once added, every computer appears under Computers.', dpDomain: 'Domain (AD)', dpWorkgroup: 'No domain (workgroup)', dpSingle: 'One computer', dpPackage: 'Manual installer', dpOther: 'Network devices & apps',
      dpWithAgent: 'Install the agent (recommended)', dpRemoteOnly: 'Read logs remotely only', dpSingleHint: 'The agent gives every feature (sessions, app control, updates, remote actions). "Read logs remotely" is for a computer you do not want to install anything on.',
      acLead: 'One-time settings: this server address for agents, installer security, saved accounts, and backup / move to another server.', acWhere: 'Installer security (token, admin approval) and server address are in:',
      cpLead: 'Every monitored computer — with or without an agent — in one list. Click a row for details and actions.',
      cpPaused: 'paused', cpApproveHint: 'waiting for admin approval — open details', cpInstallFailed: 'install failed', cpInstalling: 'installing', cpOnline: 'online', cpNoContact: 'not reported yet', cpOffline: 'offline for', cpReading: 'reading logs', cpConnProblem: 'connection problem', cpNotTested: 'not tested yet',
      cpAll: 'All', cpNeedAttention: 'Need attention', cpWithAgent: 'With agent', cpWithoutAgent: 'Without agent', cpEmpty: 'No computers yet — press Add computers', cpHow: 'Monitored by',
      how_agent: 'Agent', how_remote: 'Remote log reading', how_syslog: 'Syslog', how_service: 'Application log', cpDetails: 'Security, updates & details', cpSourceSettings: 'Source & account settings', cpForgetQ: 'Forget this computer in LogBok? (key, received data and source are removed)',
      guardThisServer: 'This server', guardOthers: 'Login-guard profiles for other computers (with agent)',
      mutedTitle: 'Muted alerts', mutedLead: 'No e-mail is sent for these (still visible in the console). Added from the Mute button on incidents.', mutedNone: 'Nothing is muted', until: 'Until', by: 'By' }
  };
  for (var L13 in D13) { for (var k13 in D13[L13]) { D[L13][k13] = D13[L13][k13]; } }
  var D14 = {
    fa: {
      copy: 'کپی', copied: 'کپی شد', copyManual: 'این متن را دستی کپی کنید:',
      dpOneLine: 'امن: یک خط یا فایلِ نصب (پیشنهادی)', dpRemotePush: 'از راه دور با نام‌کاربری و گذرواژه (WinRM/SMB/WMI)', dpRemoteOnly: 'فقط خواندنِ لاگ',
      olTitle: 'نصب با یک دستور — بدونِ بازکردنِ هیچ پورت', olBadge: 'پیشنهادی', 
      olLead: 'این دستور را روی همان سیستمی که می‌خواهید اضافه کنید اجرا کنید. خودِ سیستم ایجنت را از سرور می‌گیرد؛ لازم نیست هیچ پورتی روی آن سیستم باز باشد و با ورک‌گروپ و دامنه هر دو کار می‌کند.',
      olS1b: 'روی آن سیستم', olS1: 'یک «PowerShell» را با «Run as administrator» باز کنید.',
      olS2b: 'بچسبانید', olS2: 'دستورِ زیر را کپی و در همان پنجره «Enter» بزنید.',
      olS3b: 'تمام', olS3: 'تا حدود ۲ دقیقهٔ دیگر، سیستم خودش در «سیستم‌ها» ظاهر می‌شود.',
      olCopy: 'کپیِ دستور', olNote: 'این دستور فقط به پورتِ سرور (پیش‌فرض ۸۶۸۷) وصل می‌شود — همان پورتی که ایجنت برای کارِ عادی هم استفاده می‌کند. هیچ پورتی روی سیستمِ مقصد باز نمی‌شود.',
      olNoToken: 'توکنِ نصب نامعتبر یا منقضی است؛ از «تنظیمات › ایجنت و پشتیبان» یک توکنِ تازه بسازید.',
      olDomainTipB: 'ساده‌ترین راه:', olDomainTip: 'اگر نمی‌خواهید پورتی باز کنید یا GPO بسازید، «نصب با یک دستور» را روی هر سیستم اجرا کنید.',
      olWgTipB: 'ساده‌ترین راه:', olWgTip: 'در ورک‌گروپ نیازی به باز کردنِ پورت نیست — «نصب با یک دستور» را روی هر سیستم اجرا کنید.',
      olShow: 'نمایشِ دستور'
    },
    en: {
      copy: 'Copy', copied: 'Copied', copyManual: 'Copy this text manually:',
      dpOneLine: 'Secure: one line or install file (recommended)', dpRemotePush: 'Remote with username and password (WinRM/SMB/WMI)', dpRemoteOnly: 'Read logs only',
      olTitle: 'Install with one command — no ports to open', olBadge: 'recommended',
      olLead: 'Run this on the very computer you want to add. The computer pulls the agent from the server itself; no inbound port needs to be open on it, and it works for both workgroup and domain.',
      olS1b: 'On that computer', olS1: 'open PowerShell with "Run as administrator".',
      olS2b: 'Paste', olS2: 'copy the command below and press Enter in that window.',
      olS3b: 'Done', olS3: 'within about 2 minutes the computer appears here under Computers.',
      olCopy: 'Copy command', olNote: 'This command only connects to the server port (default 8687) — the same port the agent uses anyway. No port is opened on the target computer.',
      olNoToken: 'The install token is invalid or expired; create a fresh one in Settings › Agents & backup.',
      olDomainTipB: 'Easiest:', olDomainTip: 'If you would rather not open ports or build a GPO, run "Install with one command" on each computer.',
      olWgTipB: 'Easiest:', olWgTip: 'In a workgroup no ports need opening — run "Install with one command" on each computer.',
      olShow: 'Show command'
    }
  };
  for (var L14 in D14) { for (var k14 in D14[L14]) { D[L14][k14] = D14[L14][k14]; } }
  var D15 = {
    fa: {
      alWhat: 'دربارهٔ چه چیزی به شما ایمیل بزنیم؟', alWho: 'ایمیل به چه کسی برود؟', alHow: 'چطور به شما خبر بدهیم؟', alName: 'نام و تنظیماتِ بیشتر',
      alPickWhat: 'اول یکی از گزینه‌های «دربارهٔ چه چیزی» را انتخاب کنید', alNeedTo: 'حداقل یک ایمیلِ گیرنده لازم است (یا گیرندهٔ پیش‌فرض را در پایین تنظیم کنید)',
      alProfileNamePh: 'مثلاً: هشدارهای مدیرِ شبکه', alDefaultTo: 'اگر خالی بگذارید، به گیرندگانِ پیش‌فرض می‌رود',
      dvInstantB: 'فوری (هر رویداد جدا)', dvHourlyB: 'خلاصهٔ ساعتی', dvDailyB: 'خلاصهٔ روزانه',
      alDelivHint: 'فوری: هر رویداد بلافاصله یک ایمیل. خلاصه: چند رویداد در یک ایمیل جمع می‌شوند تا صندوقتان شلوغ نشود. برای موارد بحرانی «فوری» و برای موارد اطلاعی «خلاصه» بهتر است.',
      alAdvShow: '▸ تنظیمِ دستیِ دسته‌ها (پیشرفته)', alAdvHide: '▾ تنظیمِ دستیِ دسته‌ها (پیشرفته)',
      alCatHint: 'اگر از گزینه‌های بالا یکی را انتخاب کنید، این دسته‌ها خودکار تیک می‌خورند. فقط وقتی دست بزنید که دقیقاً می‌دانید چه می‌خواهید.',
      alSevHint: 'کمینهٔ اهمیت: فقط رویدادهایی که از این سطح جدی‌تر باشند ایمیل می‌شوند. «بحرانی+» یعنی فقط بحرانی‌ها.',
      alKeywords: 'کلمات کلیدی (اختیاری)', alKwHint: 'اگر پر شود، فقط رویدادهایی که یکی از این کلمات در متنشان باشد ایمیل می‌شوند. معمولاً خالی بماند.',
      alMoreFilters: 'محدودکردن به سیستم‌های خاص، ساعتِ کاری و فاصلهٔ ایمیل‌ها', alSystems: 'فقط این سیستم‌ها', alAllSystems: 'همهٔ سیستم‌ها (پیش‌فرض)', alAddSystemPh: 'نامِ سیستم را بنویسید یا انتخاب کنید',
      alSystemsHint: 'خالی = همهٔ سیستم‌ها. برای چند سیستمِ خاص، نامشان را اضافه کنید. (کاربرِ حرفه‌ای می‌تواند الگو بدهد، مثلِ SRV-*)',
      alBhHint: 'می‌توانید بگویید فقط در ساعتِ کاری، یا فقط بیرون از ساعتِ کاری خبر بدهد.',
      alThrottleHint: 'اگر یک رویداد پشتِ هم تکرار شود، تا این چند دقیقه فقط یک ایمیل می‌آید تا صندوقتان پر نشود.',
      tplCriticalN: 'همهٔ موارد بحرانی', tplCriticalD: 'هر رویدادِ بحرانی روی هر سیستم — امن‌ترین انتخاب اگر مطمئن نیستید',
      tplLogonN: 'ورود ناموفق و حملهٔ رمز', tplLogonD: 'وقتی کسی چند بار رمز را اشتباه می‌زند یا حملهٔ حدسِ رمز رخ می‌دهد',
      tplAdminN: 'تغییر در حساب‌های مدیر', tplAdminD: 'عضو شدن در گروه‌های مدیریتی، ساخت/حذفِ کاربر، ریستِ رمز',
      tplMalwareN: 'بدافزار و آنتی‌ویروس', tplMalwareD: 'یافتنِ بدافزار یا خاموش‌شدنِ محافظتِ ویندوز (Defender)',
      tplRansomN: 'باج‌افزار', tplRansomD: 'تغییرِ ناگهانی و انبوهِ فایل‌ها که نشانهٔ باج‌افزار است',
      tplTamperN: 'پاک‌شدنِ لاگ و دستکاری', tplTamperD: 'وقتی کسی لاگ را پاک می‌کند یا حسابرسی را خاموش می‌کند',
      tplAdAttackN: 'حملاتِ پیشرفتهٔ اکتیو', tplAdAttackD: 'الگوهای حملهٔ شناخته‌شده روی دامنه (مثلِ Kerberoasting، DCSync)',
      tplFilesN: 'فایل‌های حساس', tplFilesD: 'تغییر یا تغییرِ مجوزِ فایل‌ها و پوشه‌های مهم',
      tplServerN: 'تغییرِ مشکوک روی سرور', tplServerD: 'سرویس یا تسکِ جدید، تغییرِ GPO و فایروال',
      tplVulnN: 'آسیب‌پذیری و آپدیت‌نشده', tplVulnD: 'نرم‌افزارِ قدیمی، آپدیتِ نصب‌نشده، تنظیماتِ ناامن (خلاصهٔ روزانه)',
      tplNetN: 'تجهیزاتِ شبکه', tplNetD: 'سوییچ، روتر و فایروال (از طریقِ syslog)',
      tplCustomN: 'سفارشی (پیشرفته)', tplCustomD: 'خودتان دقیقاً دسته‌ها و فیلترها را انتخاب می‌کنید'
    },
    en: {
      alWhat: 'What should we email you about?', alWho: 'Who gets the email?', alHow: 'How should we tell you?', alName: 'Name & more settings',
      alPickWhat: 'First pick one of the "what about" options', alNeedTo: 'At least one recipient email is needed (or set the default recipient below)',
      alProfileNamePh: 'e.g. Network admin alerts', alDefaultTo: 'Leave empty to use the default recipients',
      dvInstantB: 'Instant (each event)', dvHourlyB: 'Hourly summary', dvDailyB: 'Daily summary',
      alDelivHint: 'Instant: one email per event, right away. Summary: several events bundled into one email so your inbox stays calm. Use Instant for urgent things, Summary for informational ones.',
      alAdvShow: '▸ Set categories by hand (advanced)', alAdvHide: '▾ Set categories by hand (advanced)',
      alCatHint: 'Picking an option above ticks these for you. Only touch this if you know exactly what you want.',
      alSevHint: 'Minimum importance: only events at least this serious are emailed. "Critical+" means only critical ones.',
      alKeywords: 'Keywords (optional)', alKwHint: 'If filled, only events whose text contains one of these words are emailed. Usually leave empty.',
      alMoreFilters: 'Limit to specific computers, business hours and email spacing', alSystems: 'Only these computers', alAllSystems: 'All computers (default)', alAddSystemPh: 'Type or pick a computer name',
      alSystemsHint: 'Empty = all computers. Add names for specific ones. (Power users can use a pattern like SRV-*)',
      alBhHint: 'You can tell it to alert only during business hours, or only outside them.',
      alThrottleHint: 'If one event repeats, only one email is sent within this many minutes so your inbox is not flooded.',
      tplCriticalN: 'All critical events', tplCriticalD: 'Every critical event on any computer — safest if unsure',
      tplLogonN: 'Failed logons & password attacks', tplLogonD: 'When someone mistypes the password repeatedly or a guessing attack happens',
      tplAdminN: 'Changes to admin accounts', tplAdminD: 'Joining admin groups, creating/deleting users, password resets',
      tplMalwareN: 'Malware & antivirus', tplMalwareD: 'Malware found or Windows protection (Defender) turned off',
      tplRansomN: 'Ransomware', tplRansomD: 'Sudden mass file changes that signal ransomware',
      tplTamperN: 'Log cleared & tampering', tplTamperD: 'When someone clears logs or disables auditing',
      tplAdAttackN: 'Advanced AD attacks', tplAdAttackD: 'Known attack patterns on the domain (Kerberoasting, DCSync…)',
      tplFilesN: 'Sensitive files', tplFilesD: 'Changes or permission changes on important files and folders',
      tplServerN: 'Suspicious server changes', tplServerD: 'New service or task, GPO and firewall changes',
      tplVulnN: 'Vulnerabilities & missing updates', tplVulnD: 'Old software, missing updates, insecure settings (daily summary)',
      tplNetN: 'Network devices', tplNetD: 'Switches, routers and firewalls (via syslog)',
      tplCustomN: 'Custom (advanced)', tplCustomD: 'You pick the exact categories and filters yourself'
    }
  };
  for (var L15 in D15) { for (var k15 in D15[L15]) { D[L15][k15] = D15[L15][k15]; } }
  // D16 — نصبِ «فقط نام‌کاربری و گذرواژه» | credential-only install
  var D16 = {
    fa: { qiTitle: 'افزودنِ سیستم — فقط نام‌کاربری و گذرواژه', qiBadge: 'پیشنهادی',
      qiLead: 'فقط سه چیز بدهید؛ بقیه خودکار است. لاگ‌بوک خودش راهِ باز را پیدا می‌کند (WinRM، اشتراکِ فایل یا WMI)، ایجنت را نصب می‌کند و صبر می‌کند تا وصل شود. روی سیستم هیچ پورتی باز نمی‌ماند و بعد از نصب، عوض شدنِ این گذرواژه هم مهم نیست.',
      qiTarget: 'نام یا IPِ سیستم', qiUser: 'نام‌کاربریِ مدیر', qiPass: 'گذرواژه', qiGo: 'نصب کن',
      qiUserHint: 'بدونِ دامنه (Workgroup): حسابِ داخلیِ Administrator. در دامنه: YAS\\نام‌کاربر (عضوِ Domain Admins).',
      qiMore: 'گزینه‌های بیشتر', qiNeed: 'نام یا IP، نام‌کاربری و گذرواژه را پر کنید.',
      qiS1: 'اتصال و پیدا کردنِ راه', qiS2: 'نصبِ ایجنت', qiS3: 'منتظرِ اولین ارتباط', qiS4: 'وصل شد',
      qiVia: 'راهِ استفاده‌شده', qiOk: 'تمام شد. این سیستم در «سیستم‌ها» دیده می‌شود.', qiOpen: 'رفتن به سیستم‌ها',
      qiFail: 'نصب انجام نشد', qiWhatNow: 'چه کنم؟', qiRetry: 'دوباره امتحان کن', qiStill: 'هنوز در حالِ کار… (معمولاً کمتر از ۲ دقیقه)',
      qiManualIntro: 'فایروالِ این سیستم همهٔ راه‌ها را بسته است. فقط یک‌بار این خط را روی خودِ سیستم در PowerShell (Run as administrator) بزنید؛ از این به بعد همه‌چیز خودکار است:',
      qi_winrm: 'WinRM', qi_smb: 'اشتراکِ فایل (SMB/445)', qi_wmi: 'WMI', qi_closed: 'بسته', qi_ok: 'موفق', qi_denied: 'اجازه نداد', qi_badpass: 'گذرواژهٔ نادرست', qi_other: 'خطا',
      qiTried: 'راه‌هایی که امتحان شد' },
    en: { qiTitle: 'Add a computer — username and password only', qiBadge: 'Recommended',
      qiLead: 'Give three things; the rest is automatic. LogBok finds an open channel by itself (WinRM, file sharing or WMI), installs the agent and waits until it connects. No port stays open on the computer, and changing this password later does not matter.',
      qiTarget: 'Computer name or IP', qiUser: 'Admin username', qiPass: 'Password', qiGo: 'Install',
      qiUserHint: 'Workgroup (no domain): the built-in Administrator account. Domain: YAS\\username (a Domain Admin).',
      qiMore: 'More options', qiNeed: 'Fill in the name or IP, username and password.',
      qiS1: 'Connect and find a channel', qiS2: 'Install the agent', qiS3: 'Wait for first contact', qiS4: 'Connected',
      qiVia: 'Channel used', qiOk: 'Done. This computer now shows under Computers.', qiOpen: 'Go to Computers',
      qiFail: 'Install did not complete', qiWhatNow: 'What to do', qiRetry: 'Try again', qiStill: 'Still working… (usually under 2 minutes)',
      qiManualIntro: 'This computer\'s firewall blocks every channel. Run this line once on the computer itself in PowerShell (Run as administrator); after that everything is automatic:',
      qi_winrm: 'WinRM', qi_smb: 'File sharing (SMB/445)', qi_wmi: 'WMI', qi_closed: 'closed', qi_ok: 'worked', qi_denied: 'refused', qi_badpass: 'wrong password', qi_other: 'error',
      qiTried: 'Channels tried' }
  };
  for (var L16 in D16) { for (var k16 in D16[L16]) { D[L16][k16] = D16[L16][k16]; } }
  // D17 — امن به‌طورِ پیش‌فرض | secure by default
  var D17 = {
    fa: { spOffShort: 'خاموش (نصب از راه دور غیرفعال است)', spAdvanced: 'پیشرفته: نصب از راه دور با WinRM / SMB / WMI (پیشنهاد نمی‌شود)',
      spPushExplain: 'این روش به پورت‌های 5985، 445 و 135 روی سیستم‌ها نیاز دارد. این پورت‌ها سطحِ حملهٔ بزرگی دارند (مثلِ EternalBlue و PrintNightmare و حرکتِ جانبیِ باج‌افزارها)، برای همین لاگ‌بوک به‌طورِ پیش‌فرض از آن‌ها استفاده نمی‌کند. فقط اگر این پورت‌ها همین حالا در شبکهٔ شما باز هستند و آگاهانه می‌خواهید، روشنش کنید.',
      spPushOffOk: 'خاموش (امن)', spPushOn: 'روشن — لاگ‌بوک از WinRM/SMB/WMI استفاده می‌کند', spTurnOn: 'روشن کردن', spTurnOff: 'خاموش کردن (پیشنهادی)',
      spConfirmOn: 'نصب از راه دور به پورت‌های مدیریتیِ باز روی سیستم‌ها نیاز دارد و امن نیست. مطمئنید؟',
      spJoinLead: 'یا برای فلش / پوشهٔ اشتراکی: روی سیستم دوبار کلیک کنید، خودش اجازهٔ مدیر می‌گیرد:',
      spVerified: 'این خط قبل از اجرا اثرِ انگشتِ (SHA-256) نصب‌کننده و بسته را می‌سنجد؛ اگر کسی در مسیر چیزی را عوض کند، هیچ چیز اجرا نمی‌شود.',
      spDomTitle: 'نصبِ امن روی همهٔ سیستم‌های دامنه', spNoPorts: 'بدونِ باز کردنِ هیچ پورت',
      spDomLead: 'فقط نام‌کاربری و گذرواژهٔ Domain Admin را یک‌بار در «دامنه‌ها» (پایین) وارد کنید و این دکمه را بزنید. لاگ‌بوک یک Group Policy می‌سازد؛ هر سیستمِ دامنه خودش از کنترلرِ دامنه و پورتِ 8687ِ این سرور ایجنت را می‌گیرد. روی هیچ کلاینتی پورتی باز نمی‌شود و سرور هم به هیچ کلاینتی وصل نمی‌شود.',
      spDom1b: 'یک‌بار', spDom1: 'دامنه را با حسابِ Domain Admin اضافه کنید (همین صفحه، «دامنه‌ها»).',
      spDom2b: 'یک کلیک', spDom2: '«نصبِ امن» را بزنید.',
      spDom3b: 'خودکار', spDom3: 'سیستم‌ها در به‌روزرسانیِ بعدیِ Group Policy (حداکثر حدودِ ۹۰ دقیقه، یا با ری‌استارت) نصب و وصل می‌شوند؛ سیستم‌های تازهٔ دامنه هم خودشان اضافه می‌شوند.',
      spDomNone: 'اول در کادرِ «دامنه‌ها» (پایین) یک دامنه اضافه کنید.', spDomGo: 'نصبِ امن روی', spDomConfirm: 'یک Group Policy برای نصبِ ایجنت روی همهٔ سیستم‌های این دامنه ساخته و لینک شود؟',
      spDomDone: 'Group Policy ساخته و لینک شد.', spLinks: 'لینک', spDomWhen: 'سیستم‌ها تا حدودِ ۹۰ دقیقه (یا با ری‌استارت) یکی‌یکی در «سیستم‌ها» ظاهر می‌شوند. برای سرعت می‌توانید روی یک سیستم gpupdate /force بزنید.' },
    en: { spOffShort: 'off (remote push disabled)', spAdvanced: 'Advanced: remote push over WinRM / SMB / WMI (not recommended)',
      spPushExplain: 'This needs ports 5985, 445 and 135 open on the computers. These ports have a large attack surface (EternalBlue, PrintNightmare, ransomware lateral movement), so LogBok does not use them by default. Turn it on only if these ports are already open in your network and you choose to.',
      spPushOffOk: 'Off (secure)', spPushOn: 'On — LogBok uses WinRM/SMB/WMI', spTurnOn: 'Turn on', spTurnOff: 'Turn off (recommended)',
      spConfirmOn: 'Remote push needs management ports open on the computers and is not secure. Are you sure?',
      spJoinLead: 'Or for a USB stick / shared folder: double-click it on the computer, it asks for admin rights itself:',
      spVerified: 'Before running, this line checks the SHA-256 fingerprint of the installer and the package; if anything is changed on the way, nothing runs.',
      spDomTitle: 'Secure install on every domain computer', spNoPorts: 'no ports to open',
      spDomLead: 'Enter a Domain Admin username and password once under "Domains" (below) and press this button. LogBok creates a Group Policy; every domain computer pulls the agent itself from the domain controller and port 8687 of this server. No port is opened on any client and the server never connects to a client.',
      spDom1b: 'Once', spDom1: 'add the domain with a Domain Admin account (this page, "Domains").',
      spDom2b: 'One click', spDom2: 'press "Secure install".',
      spDom3b: 'Automatic', spDom3: 'computers install and connect at their next Group Policy refresh (about 90 minutes at most, or on restart); new domain computers join by themselves too.',
      spDomNone: 'First add a domain in the "Domains" box (below).', spDomGo: 'Secure install on', spDomConfirm: 'Create and link a Group Policy that installs the agent on every computer of this domain?',
      spDomDone: 'Group Policy created and linked.', spLinks: 'link(s)', spDomWhen: 'Computers appear under Computers one by one within ~90 minutes (or on restart). To speed one up, run gpupdate /force on it.' }
  };
  for (var L17 in D17) { for (var k17 in D17[L17]) { D[L17][k17] = D17[L17][k17]; } }
  var D18 = {
    fa: { hiSearch: 'جست‌وجو در عنوان، سیستم، گیرنده…', hiAllStatus: 'همهٔ وضعیت‌ها', hiAllSev: 'همهٔ سطح‌ها', hiAllProf: 'همهٔ پروفایل‌ها', hiNoMatch: 'هشداری با این فیلترها نیست', hiCount: '{n} هشدار · {ok} ارسال‌شده · {bad} ناموفق',
      uaRecent: 'کاربرانِ فعال در ۲۴ ساعتِ گذشته', uaWhat: '«کاربر ۳۶۰» همهٔ کارهای یک نفر را یک‌جا نشان می‌دهد: کجا و کی وارد شده، ورودهای ناموفق و قفل‌شدن‌ها، استفاده از دسترسیِ مدیر، تغییراتی که روی حساب یا توسطِ آن انجام شده و هشدارهای مرتبط. یک کاربر را از فهرستِ زیر انتخاب کنید یا نامش را بالا بنویسید.', uaSlow: 'جست‌وجو طولانی شد؛ بازهٔ زمانیِ کوتاه‌تری انتخاب کنید و دوباره بزنید', uaHostsN: 'سیستم‌ها', uaLast: 'آخرین بار',
      agOutdated: 'قدیمی', watchT: 'دیده‌بانیِ ۲۴ ساعتِ گذشته', watchSub: 'هر ستون یک ساعت است؛ رنگ‌ها شدتِ رویدادها را نشان می‌دهند.', watchNow: 'اکنون', watchAgo: '{n} ساعت پیش', themeLabel: 'حالتِ نمایش', userLbl: 'کاربر' },
    en: { hiSearch: 'Search title, computer, recipient…', hiAllStatus: 'Any status', hiAllSev: 'Any severity', hiAllProf: 'Any profile', hiNoMatch: 'No alert matches these filters', hiCount: '{n} alerts · {ok} sent · {bad} failed',
      uaRecent: 'Users active in the last 24 hours', uaWhat: 'User 360 shows everything one person did: where and when they signed in, failed logons and lockouts, admin rights used, changes made to or by the account, and related alerts. Pick a user below or type a name above.', uaSlow: 'the search took too long; choose a shorter time range and try again', uaHostsN: 'Computers', uaLast: 'Last seen',
      agOutdated: 'outdated', watchT: 'Last 24 hours', watchSub: 'Each column is one hour; colours show how serious the events were.', watchNow: 'now', watchAgo: '{n}h ago', themeLabel: 'Display mode', userLbl: 'User' }
  };
  for (var L18 in D18) { for (var k18 in D18[L18]) { D[L18][k18] = D18[L18][k18]; } }
  var D19 = {
    fa: { ncTitle: 'فایلِ تنظیمِ ایجنتِ EXE', ncLead: 'فایلِ LogBokAgent.config مخصوصِ همین سرور (نشانیِ سرور + توکنِ ثبت‌نام). آن را کنارِ LogBokAgent.exe بگذارید و روی EXE دوبار-کلیک کنید. برای هر شرکت، همین فایل را از کنسولِ سرورِ همان شرکت بگیرید؛ خودِ EXE همه‌جا یکی است.',
          ncDl: 'دانلودِ LogBokAgent.config', ncNote: 'توکنِ داخلِ فایل بعد از اولین اتصال خودکار از آن پاک می‌شود. اگر «نیاز به تأییدِ مدیر» روشن باشد، سیستمِ تازه تا تأییدِ شما در «سیستم‌ها» داده‌ای ثبت نمی‌کند.' },
    en: { ncTitle: 'EXE agent settings file', ncLead: 'LogBokAgent.config for this server (server address + enrollment token). Put it next to LogBokAgent.exe and double-click the EXE. For each company, download this file from that company\'s own LogBok console; the EXE itself is the same everywhere.',
          ncDl: 'Download LogBokAgent.config', ncNote: 'The token inside is removed automatically after the first connection. With "require admin approval" on, a new computer records nothing until you approve it under Computers.' }
  };
  for (var L19 in D19) { for (var k19 in D19[L19]) { D[L19][k19] = D19[L19][k19]; } }
  var D20 = {
    fa: {
      adDashTitle: 'داشبورد Active Directory', adDash7d: 'Active Directory — ۷ روز', adLogonFail: 'ورود ناموفق', adLogonOk: 'ورود موفق',
      adAcctCreated: 'حساب ساخته‌شده', adAcctModified: 'حساب تغییرکرده', adAcctDeleted: 'حساب حذف‌شده', adGroupChg: 'تغییر گروه', adGpoChg: 'تغییر GPO',
      adTopFail: 'بیشترین ورودهای ناموفق', adUser: 'کاربر', adCount: 'تعداد', adByHour: 'ورود بر اساس ساعت', adRecentUba: 'آخرین ناهنجاری‌های رفتاری (UBA)',
      adNoItems: 'موردی نیست', adLearning: 'هنوز ناهنجاری‌ای ثبت نشده (در حال یادگیری یا بدون انحراف)', adNoData: 'داشبورد AD در دسترس نیست',
      ubaTitle: 'تحلیل رفتار (UBA)', ubaEnabled: 'فعال باشد', ubaRuleC: 'قاعده', ubaModeC: 'حالت', ubaActC: 'واکنش',
      uba_offhours_user: 'ورود خارج از ساعت کاری کاربر', uba_offhours_host: 'ورود در ساعت غیرعادی میزبان', uba_firsttime_host: 'اولین ورود به میزبان تازه',
      uba_firsttime_remote: 'اولین دسترسی ریموت', uba_firsttime_proc: 'اولین اجرای پردازش روی سرور', uba_firsttime_priv: 'اولین استفاده از Privilege',
      ubaHint: 'حالت: off خاموش · alert فقط هشدار · ask هشدار + پیشنهادِ واکنش (خودت اعمال کن) · auto اجرای خودکار. در auto، واکنشِ isolate و block-ip روی همان سیستم خودکار اجرا می‌شوند؛ disableuser فعلاً فقط هشدار می‌دهد (نیازِ نوشتن در AD). پیش‌فرضِ همهٔ قاعده‌ها alert است.',
      epTabRemove: 'حذف برنامه', arPolicies: 'سیاست‌های حذفِ برنامه', arLead: 'برنامه‌های انتخاب‌شده روی سیستم‌های هدف حذف (Uninstall) می‌شوند و اگر باز باشند بسته می‌شوند؛ اگر دوباره نصب شوند، در چرخهٔ بعد دوباره حذف می‌شوند.', arHow: 'OneDrive با آنینستالِ رسمی و Copilot با حذفِ بسته‌اش حذف می‌شود؛ نام‌های دیگر به‌عنوان نامِ برنامهٔ Store یا نامِ نمایشیِ برنامهٔ نصب‌شده حذف می‌شوند. این کار برگشت‌ناپذیر است.', arNew: 'سیاستِ حذفِ جدید', arNamePh: 'نامِ سیاست (مثلاً حذفِ OneDrive)', arHead: 'برنامه‌هایی که باید حذف شوند', arApps: 'برنامه‌ها', arAppsHint: 'هر خط یک برنامه: OneDrive یا Copilot (پریست)، یا نامِ برنامهٔ Store، یا نامِ نمایشیِ برنامهٔ نصب‌شده.', arWarn: '⚠ این سیاست برنامه‌ها را روی سیستم‌های هدف حذف می‌کند (برگشت‌ناپذیر). با دقت هدف‌گذاری کنید.', arRemovesNote: 'حذف + بستن در صورتِ باز بودن',
      epTabServices: 'سرویس‌ها', svcPolicies: 'سیاست‌های سرویسِ ویندوز', svcLead: 'برای سرویس‌های ویندوزِ انتخاب‌شده، نوعِ راه‌اندازی و وضعیتِ اجرا را روی سیستم‌های هدف تعیین و در هر چرخه اعمال می‌کند.', svcHow: 'هر چرخه، نوعِ راه‌اندازیِ سرویس (خودکار/باتأخیر/دستی/غیرفعال) و وضعیتش (در حالِ اجرا/متوقف) طبقِ سیاست تنظیم می‌شود. «بدون تغییر» یعنی دست نخورَد.', svcNew: 'سیاستِ سرویسِ جدید', svcPolNamePh: 'نامِ سیاست (مثلاً غیرفعال‌کردنِ Spooler)', svcHead: 'سرویس‌ها', svcHint: 'نامِ سرویس را دقیق وارد کنید (نامِ سرویس، نه نامِ نمایشی). مثال: Spooler، Fax، RemoteRegistry.', svcNamePh: 'نامِ سرویس (مثلاً Spooler)', svcAdd: 'افزودنِ سرویس', svcLeave: 'بدون تغییر', svcAuto: 'خودکار', svcDelayed: 'خودکار (باتأخیر)', svcManual: 'دستی', svcDisabled: 'غیرفعال', svcRunning: 'در حالِ اجرا', svcStopped: 'متوقف',
      nMail: 'امنیتِ ایمیل', mailLead: 'امنیتِ ایمیلِ Exchange: اسکنِ ایمیل، احرازِ فرستنده (SPF/DKIM/DMARC)، اعتبارِ IP، فیلترِ محتوا، قرنطینه و حذفِ امن از mailbox. (کاملاً جدا از FireBok)', mailTabDash: 'داشبورد', mailTabQuar: 'قرنطینه', mailTabPolicy: 'سیاست‌ها', mailTabPurge: 'حذف از mailbox', mailNoExch: 'روی این سرور Exchange شناسایی نشد؛ داده‌ها پس از نصبِ Exchange و اولین اسکن ظاهر می‌شوند.', mailFlagged: 'ایمیلِ مشکوک', mailQuarantined: 'قرنطینه‌شده', MailSpam: 'هرزنامه', MailPhish: 'فیشینگ', MailAuth: 'احرازِ فرستنده', MailAttach: 'پیوستِ مسدود', mailByDay: 'ایمیلِ مشکوک در روز', mailTopSources: 'بیشترین منابعِ اسپم (IP)', mailTopTargets: 'بیشترین mailboxهای هدف', mailRecent: 'آخرین موارد', mailIp: 'IP', mailMailbox: 'صندوق', mailMailboxHint: 'صندوقِ موردنظر را انتخاب کنید، یا «همهٔ صندوق‌ها».', mailAllMailboxes: 'همهٔ صندوق‌ها', mailDatabase: 'دیتابیس', mailAllDbs: 'همهٔ دیتابیس‌ها', mailDbHint: 'اگر صندوقِ خاصی انتخاب نشده باشد، حذف به این دیتابیس محدود می‌شود.', mailNoExchPick: 'Exchange روی این سرور شناسایی نشد؛ فهرستِ صندوق‌ها و دیتابیس‌ها پس از اتصالِ خودکار پر می‌شود. اتصال خودکار است و به تنظیمِ خاصی نیاز ندارد.', mailFrom: 'فرستنده', mailTo: 'گیرنده', mailSubject: 'موضوع', mailScore: 'امتیاز', mailReasons: 'دلایل', mailRelease: 'آزادسازی', mailReleased: 'آزاد شد', mailDeleted: 'حذف شد', mailSpamScore: 'آستانهٔ اسپم (۰ تا ۱۰۰)', mailSpamScoreHint: 'ایمیل با امتیازِ برابر یا بیشتر، مشکوک علامت می‌خورد.', mailQuarScore: 'آستانهٔ قرنطینه', mailQuarScoreHint: 'ایمیل با امتیازِ برابر یا بیشتر، قرنطینه می‌شود.', mailUseShared: 'استفاده از بلاک‌لیستِ مشترکِ همهٔ کلاینت‌های LogBok', mailAbuseHint: 'کلیدِ AbuseIPDB (اختیاری) برای امتیازِ اعتبارِ IP.', mailBlockedAtt: 'پیوست‌های مسدود (پسوند)', mailBlockedAttHint: 'هر خط یک پسوند؛ پسوندهای خطرناکِ رایج از پیش مسدودند.', mailBlockSenders: 'فرستنده‌های مسدود (ایمیل/دامنه)', mailAllowSenders: 'فرستنده‌های مجاز (Allowlist)', mailMode: 'حالتِ حذف', mailModeHint: 'Soft: قابلِ‌بازیابی از Recoverable Items · Hard: حذفِ دائمی.', mailSoft: 'Soft (قابلِ‌بازیابی)', mailHard: 'Hard (دائمی)', mailPurgeWarn: '⚠ حذف از صندوقِ کاربران از مسیرِ رسمیِ Exchange (Compliance Search) انجام می‌شود تا دیتابیس و Outlook سالم بمانند.', mailPurgeBtn: 'حذفِ ایمیل', mailPurgeNeed: 'حداقل موضوع، فرستنده یا Message-Id لازم است.', mailHardConfirm: 'حذفِ دائمی (Hard) غیرقابلِ‌بازگشت است. ادامه؟', mailPurgeDone: 'حذف شد', mailPrevBtn: 'پیش‌نمایش (بدونِ حذف)', mailPrevHint: 'اول «پیش‌نمایش» بزن تا ایمیل‌های منطبق را ببینی؛ بعد یا دکمهٔ قرمزِ «حذفِ ایمیل» همهٔ منطبق‌ها را حذف می‌کند، یا در هر ردیف «حذفِ همین» فقط همان ایمیل را.', mailPrevFound: 'ایمیل‌های یافت‌شده', mailPrevNone: 'هیچ ایمیلِ منطبقی یافت نشد.', mailDelThis: 'حذفِ همین', mailDate: 'تاریخ', mailPurgeConfirmAll: 'همهٔ ایمیل‌های منطبق با این شرط حذف می‌شوند. مطمئنی؟ (بهتر است اول پیش‌نمایش بگیری)',
      nUpdates: 'به‌روزرسانی', updStatus: 'وضعیت', updInstalled: 'نسخهٔ نصب‌شده', updServerVer: 'نسخهٔ دریافتی از سازنده', updNone: '—', updPublished: 'آخرین نسخهٔ منتشرشده', updPublishTitle: 'انتشارِ آپدیت (سازنده)', updPublishLead: 'کدِ فعلی را امضا و منتشر می‌کند؛ سرورِ همهٔ شرکت‌ها آن را امن می‌گیرند و ایجنت‌ها هم از سرورِ خودشان. تنظیمات، سیاست‌ها و لایسنسِ هر شرکت دست‌نخورده می‌ماند.', updVersion: 'شمارهٔ نسخه', updVersionPh: 'خالی = خودکار از تاریخ و ساعت', updVersionHint: 'خالی بگذاری، خودکار از تاریخ و ساعت ساخته می‌شود.', updNotes: 'توضیحات', updNotesPh: 'چه چیزی تغییر کرد', updCopyTo: 'کپی به مقصد (اختیاری)', updCopyHint: 'پوشه یا اشتراکِ شبکه‌ای که بسته هم آنجا کپی شود؛ برای آپلود به میزبانِ HTTPS از همان پوشهٔ dist استفاده کن.', updPublishBtn: 'انتشارِ آپدیت', updPublishConfirm: 'کدِ فعلی منتشر می‌شود و به همهٔ سرورها و ایجنت‌ها می‌رسد. ادامه؟', updPublished: 'منتشر شد', updFiles: 'فایل', updCopied: 'در مقصد کپی شد', updZip: 'بستهٔ zip', updHistory: 'تاریخچهٔ انتشار', updWhen: 'زمان', updBy: 'توسط', updFeedTitle: 'دریافتِ آپدیت از سازنده', updFeedLead: 'این سرور از این آدرس، آپدیتِ امضاشدهٔ سازنده را خودکار می‌گیرد و اعمال می‌کند. قبل از اعمال امضا بررسی می‌شود، پشتیبان گرفته می‌شود و اگر کدِ تازه سالم نبود خودکار به نسخهٔ قبل برمی‌گردد.', updFeedUrl: 'آدرسِ فید', updFeedHint: 'HTTPS مثل https://bokernet.ir/logbok یا مسیرِ اشتراکیِ شبکه.', updInterval: 'هر چند ساعت بررسی شود', updAuto: 'به‌روزرسانیِ خودکار', updAutoOn: 'روشن', updPullNow: 'دریافتِ همین حالا', updPulled: 'دریافت و اعمال شد؛ فایل', updUpToDate: 'نسخهٔ تازه‌ای نبود', updTwoModes: 'دو راهِ به‌روزرسانیِ سرورها: (۱) دستی/آفلاین — بستهٔ zip را روی سرور ببر و Update-LogBok.cmd را اجرا کن (بدونِ اینترنت). (۲) خودکار — سرور در بازهٔ زمانی از فیدِ تو می‌گیرد. هیچ‌کدام به نسخهٔ میانی وابسته نیست؛ از هر نسخه‌ای (مثلاً 1.9.1) مستقیم به نسخهٔ تازه (مثلاً 2.6.1) می‌رود.', updManualHint: 'بستهٔ دستی (شاملِ فایلِ اجرا): ', updManualHow: 'این پوشه/zip را روی هر سرور کپی کن و Update-LogBok.cmd را اجرا کن؛ امضا بررسی و امن اعمال می‌شود.', updTabStatus: 'وضعیت', updTabPublish: 'انتشار', updTabAuto: 'دریافتِ خودکار', updHowTitle: 'چطور کار می‌کند', updStep1: 'کدِ محصول را توسعه بده و تست کن.', updStep2: 'به تبِ «انتشار» برو؛ یک شمارهٔ نسخه بنویس (یا خالی بگذار تا خودکار از تاریخ ساخته شود) و دکمهٔ «انتشارِ آپدیت» را بزن.', updStep3: 'یک بستهٔ امضاشده در پوشهٔ dist ساخته می‌شود؛ شاملِ یک فایلِ zip که Update-LogBok.cmd هم داخلش است.', updStep4: 'برای رساندن به سرورها دو راه داری: یا zip را روی سرور ببر و Update-LogBok.cmd را اجرا کن (دستی/آفلاین)، یا در تبِ «دریافتِ خودکار» آدرسِ فید را تنظیم کن تا سرورها خودکار بگیرند.', updStepC1: 'این سرور آپدیت را از سازنده می‌گیرد؛ یا دستی با اجرای Update-LogBok.cmd، یا خودکار از فیدی که در تبِ «دریافتِ خودکار» تنظیم شده.', updStepC2: 'هر آپدیت امضا بررسی می‌شود، پشتیبان گرفته می‌شود و اگر خراب بود خودکار به نسخهٔ قبل برمی‌گردد؛ تنظیماتِ محلیِ این سرور دست‌نخورده می‌ماند.',
      updTabLicense: 'صدورِ لایسنس', licTitle: 'صدورِ لایسنس', licLead: 'برای هر سرورِ مشتری یک لایسنسِ امضاشده و قفل به همان دستگاه بساز. «کدِ دستگاه» را پنجرهٔ فعال‌سازیِ همان سرور نشان می‌دهد. کلیدِ خصوصی فقط روی همین سرور می‌ماند و جایی نمی‌رود.', licCompany: 'نامِ شرکت', licCompanyPh: 'مثلاً شرکت نمونه', licDevice: 'کدِ دستگاه', licDeviceHint: 'به شکلِ XXXXX-XXXXX-XXXXX-XXXXX — از پنجرهٔ فعال‌سازیِ سرورِ مشتری کپی می‌شود.', licExpiry: 'انقضا', licModeDays: 'تا چند روز', licModeDate: 'تا تاریخِ مشخص', licModePerm: 'دائمی', licDaysUnit: 'روز', licLimits: 'سقف‌ها', licClients: 'کلاینت', licFileServers: 'فایل‌سرور', licDC: 'دامین‌کنترلر', licIssueBtn: 'ساختِ لایسنس', licNeedCompany: 'نامِ شرکت را وارد کن', licNeedDevice: 'کدِ دستگاه را وارد کن', licDone: 'لایسنس ساخته شد', licExpires: 'انقضا', licPermNote: 'دائمی', licCopy: 'کپی', licDownload: 'دانلودِ فایل', licSendHint: 'این متن را برای مشتری بفرست؛ در پنجرهٔ «فعال‌سازی» روی سرورِ خودش بچسباند یا فایل را Import کند.', licIssuedTitle: 'لایسنس‌های صادرشده', licNoneYet: 'هنوز لایسنسی صادر نشده.', licWhen: 'تاریخِ صدور',
      tAccounts: 'کاربران', accTitle: 'کاربرانِ کنسول', accLead: 'ورود به کنسول با این کاربران یا با حساب‌های ویندوزِ سرور', accMode: 'حالت', accUser: 'نام کاربری', accRole: 'نقش', accAdmin: 'مدیر', accViewer: 'فقط‌خواندنی', accActive: 'فعال', accDisabled: 'غیرفعال', accReset: 'تغییر رمز', accNewPw: 'رمزِ تازه', accEnable: 'فعال‌سازی', accDisable: 'غیرفعال‌سازی', accRemove: 'حذف', accRemoveConfirm: 'این کاربر حذف شود؟', accAdd: 'افزودنِ کاربر', accAddBtn: 'افزودن', accNeed: 'نام کاربری و رمز لازم است',
      loginLead: 'برای ورود، نام کاربری و رمز را وارد کنید.', loginSetupLead: 'اولین اجرا: یک حسابِ مدیر بسازید تا کنسول محافظت شود.', loginUser: 'نام کاربری', loginPass: 'رمز عبور', loginPass2: 'تکرارِ رمز', loginBtn: 'ورود', loginCreateBtn: 'ساختِ حساب و ورود', loginNeed: 'نام کاربری و رمز لازم است', loginMismatch: 'رمزها یکسان نیستند', loginFail: 'ورود ناموفق بود', logout: 'خروج',
      loginRemember: 'مرا به‌خاطر بسپار', remThis: 'فقط این نشست', rem30: '۳۰ روز', rem180: '۱۸۰ روز', rem360: '۳۶۰ روز',
      login2faTitle: 'تأییدِ دومرحله‌ای', login2faTotpLead: 'کدِ ۶رقمیِ برنامهٔ Authenticator را وارد کنید (بدونِ اینترنت هم کار می‌کند).', login2faEmailLead: 'کدِ ۶رقمی به ایمیلت فرستاده شد.', login2faTotp: 'Authenticator', login2faEmail: 'ایمیل', login2faCode: 'کدِ تأیید', login2faNeed: 'کدِ ۶رقمی را وارد کنید', login2faBack: 'بازگشت',
      acc2faTitle: 'احراز هویتِ دومرحله‌ایِ من', acc2faLead: 'یک لایهٔ امنیتیِ دوم هنگامِ ورود. Authenticator بدونِ اینترنت کار می‌کند؛ کدِ ایمیلی به اینترنت نیاز دارد.', acc2faOn: 'روشن', acc2faOff: 'خاموش', acc2faTotp: 'اپِ Authenticator (آفلاین)', acc2faEmail: 'کدِ ایمیلی', acc2faEnableTotp: 'فعال‌سازیِ Authenticator', acc2faTotpStep: 'این کدِ مخفی را در Google Authenticator وارد کن (ورودِ دستیِ کلید)، بعد کدِ ۶رقمی را اینجا بزن:', acc2faSecret: 'کدِ مخفی', acc2faConfirm: 'تأیید و فعال‌سازی', acc2faEmailAddr: 'آدرسِ ایمیل برای کد', acc2faEmailOn: 'فعال‌سازیِ کدِ ایمیلی', acc2faDisable: 'خاموش‌کردن', acc2faReset: 'ریستِ دومرحله‌ای', acc2faNeedConsole: 'دومرحله‌ای فقط برای کاربرانِ داخلیِ کنسول است.', acc2faWindows: 'شما با حسابِ ویندوز وارد شده‌اید.',
      tbSummary: 'خلاصه', tbCategories: 'دسته‌ها', tbAD: 'اکتیو دایرکتوری', tbHealth: 'سلامتِ سامانه', tbProfiles: 'پروفایل‌ها', tbSmtp: 'ایمیل (SMTP)', tbOptions: 'گزینه‌ها', tbSent: 'ارسال‌شده‌ها', tbMuted: 'بی‌صداشده‌ها', tbGeneral: 'عمومی', tbMgmt: 'مسیرِ مدیریت', tbGuard: 'سپرِ ورود', tbThresholds: 'آستانه‌ها', tbWeb: 'کنسولِ وب', tbJobs: 'جاب‌ها', tbUba: 'تحلیلِ رفتار', tbServer: 'نشانیِ سرور', tbInstallSec: 'امنیتِ نصب', tbCreds: 'حساب‌های ذخیره‌شده', tbBackup: 'پشتیبان و انتقال', tbLive: 'نشست‌های زنده', tbHistory: 'تاریخچه', tbFindings: 'یافته‌ها', tbTimeline: 'خطِ زمانی',
      tRemote: 'دسترسیِ راه‌دور', remTitle: 'دسترسیِ راه‌دور به کنسول', remLead: 'انتخاب کن کنسول از کجا در دسترس باشد: فقط همین سرور، شبکهٔ داخلی، یا اینترنت (با NAT/UPnP).', remMode: 'حالتِ دسترسی', remModeLocal: 'فقط همین سرور (امن‌ترین)', remModeLan: 'شبکهٔ داخلی (LAN)', remModeNet: 'اینترنت (NAT/UPnP)', remModeHint: 'برای مدیریت از راه دور «اینترنت» را انتخاب کن؛ اگر روترت UPnP داشته باشد، port-forward خودکار انجام می‌شود.', remExtPort: 'پورتِ خارجی (اینترنت)', remExtHint: 'پورتی که روی اینترنت باز می‌شود و به کنسول وصل می‌شود (پیش‌فرض همان پورتِ کنسول).', remAllowIps: 'IPهای مجاز (اختیاری)', remAllowHint: 'اگر پر شود، فقط همین IP/ساب‌نت‌ها اجازهٔ اتصال دارند — برای امنیتِ بیشتر توصیه می‌شود.', remWarn: 'ترافیکِ کنسول HTTP است؛ برای اینترنت حتماً احراز دومرحله‌ای را روشن نگه دار و در صورت امکان IPهای مجاز را محدود کن.', remApply: 'اعمال', remRefresh: 'تازه‌سازی', remNetConfirm: 'کنسول روی اینترنت باز می‌شود. مطمئنی؟ (۲FA را روشن نگه دار)', remRestart: 'برای گوش‌دادن روی شبکه، سرویسِ وبِ LogBok در چرخهٔ بعدیِ watchdog خودکار ری‌استارت می‌شود (حداکثر چند دقیقه).', remStatus: 'وضعیت', remCurMode: 'حالتِ فعلی', remLocalIp: 'IP محلی', remPublicIp: 'IP عمومی (اینترنت)', remFw: 'قانونِ فایروال', remNat: 'نگاشتِ NAT روی روتر', remNatNo: 'انجام نشد (روتر UPnP ندارد یا خاموش است)', remUrl: 'نشانیِ دسترسی', remUnknown: 'نامشخص'
    },
    en: {
      adDashTitle: 'Active Directory dashboard', adDash7d: 'Active Directory — 7 days', adLogonFail: 'Logon failures', adLogonOk: 'Successful logons',
      adAcctCreated: 'Accounts created', adAcctModified: 'Accounts modified', adAcctDeleted: 'Accounts deleted', adGroupChg: 'Group changes', adGpoChg: 'GPO changes',
      adTopFail: 'Top logon failures', adUser: 'User', adCount: 'Count', adByHour: 'Logons by hour', adRecentUba: 'Recent behaviour anomalies (UBA)',
      adNoItems: 'None', adLearning: 'No anomalies yet (still learning or no deviation)', adNoData: 'AD dashboard unavailable',
      ubaTitle: 'Behaviour analytics (UBA)', ubaEnabled: 'Enabled', ubaRuleC: 'Rule', ubaModeC: 'Mode', ubaActC: 'Action',
      uba_offhours_user: "Logon outside the user's work hours", uba_offhours_host: 'Logon at an unusual hour for the host', uba_firsttime_host: 'First logon to a new host',
      uba_firsttime_remote: 'First remote access', uba_firsttime_proc: 'First process on a server', uba_firsttime_priv: 'First privilege use',
      ubaHint: 'Mode: off · alert (notify only) · ask (notify + a suggested response you apply) · auto (enforce automatically). In auto, the isolate and block-ip responses run on that computer automatically; disableuser only alerts for now (needs an AD write). Every rule defaults to alert.',
      epTabRemove: 'Remove app', arPolicies: 'App removal policies', arLead: 'The chosen apps are uninstalled on the targeted computers and closed if running; if they are reinstalled they are removed again on the next cycle.', arHow: 'OneDrive is removed with its official uninstaller and Copilot by removing its package; any other name is removed as a Store app and/or via its classic uninstall string. This is irreversible.', arNew: 'New removal policy', arNamePh: 'Policy name (e.g. Remove OneDrive)', arHead: 'Apps to remove', arApps: 'Apps', arAppsHint: 'One app per line: OneDrive or Copilot (presets), a Store app name, or an installed app\'s display name.', arWarn: '⚠ This policy uninstalls apps on the targeted computers (irreversible). Target carefully.', arRemovesNote: 'Uninstalled; closed if running',
      epTabServices: 'Services', svcPolicies: 'Windows service policies', svcLead: 'Set the startup type and running state for the chosen Windows services on the targeted computers, enforced every cycle.', svcHow: 'Each cycle the service startup type (automatic/delayed/manual/disabled) and its state (running/stopped) are set to match the policy. "Leave" means do not touch it.', svcNew: 'New service policy', svcPolNamePh: 'Policy name (e.g. Disable Spooler)', svcHead: 'Services', svcHint: 'Enter the exact service name (the service name, not the display name). e.g. Spooler, Fax, RemoteRegistry.', svcNamePh: 'Service name (e.g. Spooler)', svcAdd: 'Add service', svcLeave: 'Leave', svcAuto: 'Automatic', svcDelayed: 'Automatic (delayed)', svcManual: 'Manual', svcDisabled: 'Disabled', svcRunning: 'Running', svcStopped: 'Stopped',
      nMail: 'Mail Security', mailLead: 'Exchange email security: mail scanning, sender auth (SPF/DKIM/DMARC), IP reputation, content filtering, quarantine and safe mailbox removal. (Completely separate from FireBok)', mailTabDash: 'Dashboard', mailTabQuar: 'Quarantine', mailTabPolicy: 'Policies', mailTabPurge: 'Remove from mailbox', mailNoExch: 'No Exchange detected on this server; data appears once Exchange is installed and the first scan runs.', mailFlagged: 'Flagged mail', mailQuarantined: 'Quarantined', MailSpam: 'Spam', MailPhish: 'Phishing', MailAuth: 'Sender auth', MailAttach: 'Blocked attachment', mailByDay: 'Flagged mail per day', mailTopSources: 'Top spam sources (IP)', mailTopTargets: 'Most targeted mailboxes', mailRecent: 'Recent', mailIp: 'IP', mailMailbox: 'Mailbox', mailMailboxHint: 'Pick a mailbox, or “All mailboxes”.', mailAllMailboxes: 'All mailboxes', mailDatabase: 'Database', mailAllDbs: 'All databases', mailDbHint: 'When no specific mailbox is chosen, removal is scoped to this database.', mailNoExchPick: 'No Exchange detected on this server; the mailbox and database lists fill in after auto-connect. Connection is automatic and needs no configuration.', mailFrom: 'From', mailTo: 'To', mailSubject: 'Subject', mailScore: 'Score', mailReasons: 'Reasons', mailRelease: 'Release', mailReleased: 'Released', mailDeleted: 'Deleted', mailSpamScore: 'Spam threshold (0..100)', mailSpamScoreHint: 'Mail scoring at or above this is flagged as suspicious.', mailQuarScore: 'Quarantine threshold', mailQuarScoreHint: 'Mail scoring at or above this is quarantined.', mailUseShared: 'Use the blocklist shared across all LogBok clients', mailAbuseHint: 'Optional AbuseIPDB key for IP reputation scoring.', mailBlockedAtt: 'Blocked attachments (extension)', mailBlockedAttHint: 'One extension per line; common dangerous types are blocked already.', mailBlockSenders: 'Blocked senders (email/domain)', mailAllowSenders: 'Allowed senders (allowlist)', mailMode: 'Removal mode', mailModeHint: 'Soft: recoverable from Recoverable Items · Hard: permanent delete.', mailSoft: 'Soft (recoverable)', mailHard: 'Hard (permanent)', mailPurgeWarn: '⚠ Removal from user mailboxes uses the native Exchange path (Compliance Search) so the database and Outlook stay consistent.', mailPurgeBtn: 'Remove mail', mailPurgeNeed: 'Need at least a subject, sender or Message-Id.', mailHardConfirm: 'Hard (permanent) delete cannot be undone. Continue?', mailPurgeDone: 'Removed', mailPrevBtn: 'Preview (no delete)', mailPrevHint: 'Click “Preview” first to see the matching mail; then either the red “Remove mail” deletes every match, or “Remove this” on a row deletes just that one.', mailPrevFound: 'Messages found', mailPrevNone: 'No matching messages found.', mailDelThis: 'Remove this', mailDate: 'Date', mailPurgeConfirmAll: 'This removes every message matching the criteria. Are you sure? (Better to preview first.)',
      nUpdates: 'Updates', updStatus: 'Status', updInstalled: 'Installed version', updServerVer: 'Version from vendor', updNone: '—', updPublished: 'Last published', updPublishTitle: 'Publish update (vendor)', updPublishLead: 'Signs and publishes the current code; every company server receives it safely and their agents pick it up from their own server. Each company’s config, policies and license are left untouched.', updVersion: 'Version', updVersionPh: 'blank = auto from date-time', updVersionHint: 'Leave blank to auto-generate from the date and time.', updNotes: 'Notes', updNotesPh: 'what changed', updCopyTo: 'Copy to target (optional)', updCopyHint: 'A folder or network share to also copy the package to; to upload to an HTTPS host, use that same dist folder.', updPublishBtn: 'Publish update', updPublishConfirm: 'The current code will be published and reach every server and agent. Continue?', updPublished: 'Published', updFiles: 'files', updCopied: 'copied to target', updZip: 'zip package', updHistory: 'Publish history', updWhen: 'When', updBy: 'By', updFeedTitle: 'Receiving updates', updFeedLead: 'This server pulls the vendor’s signed update from this address and applies it automatically. The signature is verified first, a backup is taken, and if the new code fails its health check it rolls back automatically.', updFeedUrl: 'Feed address', updFeedHint: 'HTTPS such as https://bokernet.ir/logbok, or a network share path.', updInterval: 'Check every N hours', updAuto: 'Automatic updates', updAutoOn: 'On', updPullNow: 'Pull now', updPulled: 'Pulled & applied; files', updUpToDate: 'Up to date', updTwoModes: 'Two ways to update servers: (1) Manual/offline — copy the zip to a server and run Update-LogBok.cmd (no internet). (2) Automatic — the server pulls from your feed on a schedule. Neither needs intermediate versions; any version (e.g. 1.9.1) jumps straight to the new one (e.g. 2.6.1).', updManualHint: 'Manual package (with a run-to-update file): ', updManualHow: 'Copy this folder/zip to any server and run Update-LogBok.cmd; the signature is verified and applied safely.', updTabStatus: 'Status', updTabPublish: 'Publish', updTabAuto: 'Auto-update', updHowTitle: 'How it works', updStep1: 'Develop and test the product code.', updStep2: 'Go to the Publish tab; set a version (or leave blank to auto-generate from the date) and click Publish update.', updStep3: 'A signed package is built in the dist folder, including a zip that also contains Update-LogBok.cmd.', updStep4: 'Two ways to reach your servers: carry the zip to a server and run Update-LogBok.cmd (manual/offline), or set the feed address in the Auto-update tab so servers pull it automatically.', updStepC1: 'This server receives updates from the vendor: either manually by running Update-LogBok.cmd, or automatically from the feed set in the Auto-update tab.', updStepC2: 'Every update is signature-verified, backed up, and rolled back automatically if it fails; this server’s local settings are left untouched.',
      updTabLicense: 'Issue license', licTitle: 'Issue license', licLead: 'Create a signed, device-locked license for each client server. The device code is shown by that server’s own Activation window. The private signing key stays on this server only and never leaves it.', licCompany: 'Company', licCompanyPh: 'e.g. Acme Co', licDevice: 'Device code', licDeviceHint: 'Format XXXXX-XXXXX-XXXXX-XXXXX — copied from the client server’s Activation window.', licExpiry: 'Expiry', licModeDays: 'For N days', licModeDate: 'Until a date', licModePerm: 'Permanent', licDaysUnit: 'days', licLimits: 'Limits', licClients: 'Clients', licFileServers: 'File servers', licDC: 'Domain controllers', licIssueBtn: 'Create license', licNeedCompany: 'Enter the company name', licNeedDevice: 'Enter the device code', licDone: 'License created', licExpires: 'Expires', licPermNote: 'Permanent', licCopy: 'Copy', licDownload: 'Download file', licSendHint: 'Send this text to the customer to paste in their server’s Activation window, or import it as a file.', licIssuedTitle: 'Issued licenses', licNoneYet: 'No licenses issued yet.', licWhen: 'Issued',
      tAccounts: 'Accounts', accTitle: 'Console users', accLead: 'Sign in to the console with these users or with the server’s Windows accounts', accMode: 'mode', accUser: 'Username', accRole: 'Role', accAdmin: 'Admin', accViewer: 'Viewer', accActive: 'Active', accDisabled: 'Disabled', accReset: 'Reset password', accNewPw: 'New password', accEnable: 'Enable', accDisable: 'Disable', accRemove: 'Remove', accRemoveConfirm: 'Remove this user?', accAdd: 'Add user', accAddBtn: 'Add', accNeed: 'Username and password required',
      loginLead: 'Sign in with your username and password.', loginSetupLead: 'First run: create an admin account to protect the console.', loginUser: 'Username', loginPass: 'Password', loginPass2: 'Confirm password', loginBtn: 'Sign in', loginCreateBtn: 'Create & sign in', loginNeed: 'Username and password required', loginMismatch: 'Passwords do not match', loginFail: 'Sign-in failed', logout: 'Sign out',
      loginRemember: 'Keep me signed in', remThis: 'This session only', rem30: '30 days', rem180: '180 days', rem360: '360 days',
      login2faTitle: 'Two-factor verification', login2faTotpLead: 'Enter the 6-digit code from your Authenticator app (works offline).', login2faEmailLead: 'A 6-digit code was emailed to you.', login2faTotp: 'Authenticator', login2faEmail: 'Email', login2faCode: 'Verification code', login2faNeed: 'Enter the 6-digit code', login2faBack: 'Back',
      acc2faTitle: 'My two-factor authentication', acc2faLead: 'A second layer at sign-in. Authenticator works without internet; email codes need internet.', acc2faOn: 'On', acc2faOff: 'Off', acc2faTotp: 'Authenticator app (offline)', acc2faEmail: 'Email code', acc2faEnableTotp: 'Enable Authenticator', acc2faTotpStep: 'Add this secret key to Google Authenticator (manual key entry), then enter the 6-digit code:', acc2faSecret: 'Secret key', acc2faConfirm: 'Confirm & enable', acc2faEmailAddr: 'Email for the code', acc2faEmailOn: 'Enable email code', acc2faDisable: 'Turn off', acc2faReset: 'Reset 2FA', acc2faNeedConsole: '2FA is only for console users.', acc2faWindows: 'You are signed in with a Windows account.',
      tbSummary: 'Summary', tbCategories: 'Categories', tbAD: 'Active Directory', tbHealth: 'System health', tbProfiles: 'Profiles', tbSmtp: 'Email (SMTP)', tbOptions: 'Options', tbSent: 'Sent alerts', tbMuted: 'Muted', tbGeneral: 'General', tbMgmt: 'Management path', tbGuard: 'Login guard', tbThresholds: 'Thresholds', tbWeb: 'Web console', tbJobs: 'Jobs', tbUba: 'Behaviour (UBA)', tbServer: 'Server address', tbInstallSec: 'Install security', tbCreds: 'Saved accounts', tbBackup: 'Backup & migration', tbLive: 'Live now', tbHistory: 'History', tbFindings: 'Findings', tbTimeline: 'Timeline',
      tRemote: 'Remote access', remTitle: 'Remote access to the console', remLead: 'Choose where the console is reachable from: this server only, the internal network, or the internet (NAT/UPnP).', remMode: 'Access mode', remModeLocal: 'Local only (most secure)', remModeLan: 'Internal network (LAN)', remModeNet: 'Internet (NAT/UPnP)', remModeHint: 'For remote management choose Internet; if your router supports UPnP the port is forwarded automatically.', remExtPort: 'External port (internet)', remExtHint: 'The port opened on the internet that maps to the console (defaults to the console port).', remAllowIps: 'Allowed IPs (optional)', remAllowHint: 'If set, only these IPs/subnets may connect — recommended for extra security.', remWarn: 'Console traffic is HTTP; for internet access keep two-factor on and restrict allowed IPs where possible.', remApply: 'Apply', remRefresh: 'Refresh', remNetConfirm: 'The console will be exposed to the internet. Are you sure? (Keep 2FA on.)', remRestart: 'To listen on the network, the LogBok web service restarts automatically on the next watchdog cycle (a few minutes at most).', remStatus: 'Status', remCurMode: 'Current mode', remLocalIp: 'Local IP', remPublicIp: 'Public IP', remFw: 'Firewall rule', remNat: 'Router NAT mapping', remNatNo: 'not set (router UPnP off/unsupported)', remUrl: 'Access URL', remUnknown: 'unknown'
    }
  };
  for (var L20 in D20) { for (var k20 in D20[L20]) { D[L20][k20] = D20[L20][k20]; } }
  function titleCase(s) { return s.replace(/(^|[\s\/(\-–·])([a-z])/g, function (m, a, b) { return a + b.toUpperCase(); }); }
  function t(k) {
    var d = D[S.lang] || D.fa; var v = (k in d) ? d[k] : ((k in D.en) ? D.en[k] : k);
    // English UI labels in Title Case (short labels only; sentences, hints and placeholders are left as written)
    if (S.lang === 'en' && typeof v === 'string' && v.length <= 48 && !/[.!?:]\s|[.!?]$/.test(v) && !/^(https?:|[A-Z]:\\)/.test(v)) v = titleCase(v);
    return v;
  }

  // ------------------------------------------------------------------ DOM
  function el(tag, attrs) {
    var n = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        var v = attrs[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === 'text') n.textContent = String(v);
        else if (k === 'cls') n.className = v;
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') n.addEventListener(k.slice(2), v);
        else if (k === 'style') n.style.cssText = String(v);   // CSSOM: allowed under the strict CSP (no inline style attributes)
        else if (k === 'value') n.value = v;
        else if (k === 'checked') n.checked = !!v;
        else n.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (var i = 2; i < arguments.length; i++) add(n, arguments[i]);
    return n;
  }
  function add(n, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(n, x); }); return; }
    if (typeof c === 'string' || typeof c === 'number') { n.appendChild(document.createTextNode(String(c))); return; }
    n.appendChild(c);
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
  function arr(x) { return Array.isArray(x) ? x : (x === null || x === undefined ? [] : [x]); }
  function $(id) { return document.getElementById(id); }
  function splitList(s) { return String(s || '').split(/[,;\n]+/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function bil(s) { s = String(s || ''); var i = s.indexOf(' | '); if (i < 0) return s; return S.lang === 'en' ? s.slice(i + 3) : s.slice(0, i); }
  // bilingual name that may carry a 'digest: ' prefix (alert history)
  function bilp(s) { s = String(s || ''); var m = /^(digest:\s*)([\s\S]*)$/.exec(s); return m ? m[1] + bil(m[2]) : bil(s); }
  function sevName(s) { return s === 'Critical' ? t('crit') : (s === 'Warning' ? t('warn') : t('info')); }
  function sevDot(s) { return el('span', { cls: 'sev ' + (s || 'Info') }); }
  function pill(state, label) { return el('span', { cls: 'pill ' + (state || 'none'), text: label }); }
  function spinner() { return el('div', { cls: 'empty' }, el('span', { cls: 'spin' }), ' ', t('loading')); }
  function emptyRow(cols, txt) { return el('tr', null, el('td', { colspan: cols, cls: 'empty', text: txt || t('none') })); }
  function btn(label, fn, cls) { return el('button', { type: 'button', cls: 'btn' + (cls ? ' ' + cls : ''), text: label, onclick: fn }); }

  // ------------------------------------------------------------------ API
  // server messages are bilingual ("فارسی | English" or "English / فارسی"): show only the current language
  function loc(v) {
    if (typeof v !== 'string' || !v) return v;
    var fa = /[\u0600-\u06FF]/;
    if (!fa.test(v)) return v;
    var parts = v.split(/\s+[|\/]\s+/);
    if (parts.length < 2) return v;
    var want = parts.filter(function (p) { return S.lang === 'en' ? !fa.test(p) : fa.test(p); });
    return want.length ? want.join(' — ') : v;
  }
  function api(path, body, opts) {
    var opt = { credentials: 'same-origin', headers: {} };
    if (body !== undefined) { opt.method = 'POST'; opt.headers['Content-Type'] = 'application/json'; opt.headers['X-LogBok-Token'] = S.token; opt.body = JSON.stringify(body); }
    var tmo = opts && opts.timeoutMs, ac = null, tid = null;
    if (tmo && typeof AbortController !== 'undefined') { ac = new AbortController(); opt.signal = ac.signal; tid = setTimeout(function () { try { ac.abort(); } catch (e) { } }, tmo); }
    return fetch(path, opt).then(function (r) {
      if (tid) { clearTimeout(tid); tid = null; }
      return r.text().then(function (txt) {
        var j = null; try { j = txt ? JSON.parse(txt) : null; } catch (e) { j = { error: txt }; }
        // session expired → back to the login screen instead of a raw error
        if (r.status === 401 && j && j.error === 'auth') { location.reload(); return new Promise(function () { }); }
        // server restarted (new CSRF token) → fetch a fresh token and retry once, silently
        if (r.status === 403 && j && /invalid token/i.test(String(j.error || '')) && !(opts && opts._retried)) {
          return fetch('/api/meta', { credentials: 'same-origin' }).then(function (mr) { return mr.json(); }).then(function (mj) {
            if (mj && mj.authed === false) { location.reload(); return new Promise(function () { }); }
            if (mj && mj.token) S.token = mj.token;
            var o2 = {}; if (opts) { for (var k in opts) o2[k] = opts[k]; } o2._retried = true;
            return api(path, body, o2);
          });
        }
        if (!r.ok) { var m = (j && j.error) ? loc(j.error) : ('HTTP ' + r.status); if (r.status === 403) m = t('denied') + ' — ' + m; throw new Error(m); }
        return j;
      });
    }, function (e) {
      if (tid) { clearTimeout(tid); tid = null; }
      if (e && (e.name === 'AbortError' || /abort/i.test(e.message || ''))) throw new Error(t('reqTimeout'));
      throw e;
    });
  }
  var flashTimer = null;
  function flash(msg, ok) {
    var f = $('flash'); clear(f); f.className = 'flash ' + (ok === false ? 'err' : 'ok'); f.textContent = msg; f.hidden = false;
    if (flashTimer) clearTimeout(flashTimer);
    flashTimer = setTimeout(function () { f.hidden = true; }, ok === false ? 9000 : 4000);
    window.scrollTo(0, 0);
  }
  function fail(e) { flash(t('err') + ': ' + loc(e && e.message ? e.message : String(e)), false); }

  // ------------------------------------------------------------------ theme
  // ------------------------------------------------------------------ icons (inline SVG, stroke = currentColor)
  var ICONS = {
    overview: 'M4 4h7v7H4zM13 4h7v4h-7zM13 10h7v10h-7zM4 13h7v7H4z',
    incidents: 'M12 3.5 2.8 19.5h18.4zM12 10v4.2M12 17.2v.1',
    sessions: 'M3 4.5h18v11.5H3zM8 20h8M12 16v4',
    users: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.5 20.5a7.5 7.5 0 0 1 15 0',
    investigate: 'M10.5 17.5a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM20.5 20.5l-5-5',
    computers: 'M4 4h16v6.5H4zM4 13.5h16V20H4zM7.5 7.2h.1M7.5 16.7h.1',
    protect: 'M12 3l7.5 3v5.6c0 4.6-3.2 7.9-7.5 9.4-4.3-1.5-7.5-4.8-7.5-9.4V6zM8.8 12l2.2 2.2 4.2-4.4',
    mailsec: 'M3.5 6h17v12h-17zM4 6.6l8 5.4 8-5.4',
    updates: 'M12 3.5v10M8 10l4 4 4-4M5 17.5a6 6 0 0 1 2-11 7 7 0 0 1 13 2.5 4.5 4.5 0 0 1-1 8.9',
    alerts: 'M6 9.5a6 6 0 1 1 12 0c0 5.5 2 7.5 2 7.5H4s2-2 2-7.5zM10 20.5a2.2 2.2 0 0 0 4 0',
    settings: 'M4 6.5h9M17 6.5h3M15 4.5v4M4 12h3M11 12h9M9 10v4M4 17.5h11M19 17.5h1M17 15.5v4',
    sun: 'M12 16.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9zM12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4',
    moon: 'M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z'
  };
  function ico(name) {
    var ns = 'http://www.w3.org/2000/svg', sv = document.createElementNS(ns, 'svg');
    sv.setAttribute('viewBox', '0 0 24 24'); sv.setAttribute('class', 'ic'); sv.setAttribute('aria-hidden', 'true');
    var p = document.createElementNS(ns, 'path'); p.setAttribute('d', ICONS[name] || ''); sv.appendChild(p);
    return sv;
  }

  // ------------------------------------------------------------------ theme: dark / light switch (follows Windows until the user picks)
  function sysTheme() { try { return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark'; } catch (e) { return 'dark'; } }
  function applyTheme(th) {
    document.documentElement.setAttribute('data-theme', th);
    var w = $('themeSw'); if (!w) return; clear(w); w.setAttribute('role', 'group'); w.setAttribute('aria-label', t('themeLabel'));
    [['light', 'sun'], ['dark', 'moon']].forEach(function (o) {
      w.appendChild(el('button', { type: 'button', cls: th === o[0] ? 'on' : '', 'aria-pressed': th === o[0] ? 'true' : 'false', title: t(o[0]),
        onclick: function () { applyTheme(o[0]); try { localStorage.setItem('logbok-theme', o[0]); } catch (e) { } } }, ico(o[1]), el('span', { text: t(o[0]) })));
    });
  }
  function initTheme() { var th = null; try { th = localStorage.getItem('logbok-theme'); } catch (e) { } applyTheme(th === 'dark' || th === 'light' ? th : 'light'); }

  // ------------------------------------------------------------------ nav
  // ---- navigation: few sections; related pages are tabs inside a section (no feature in two places)
  var SECTIONS = {
    overview:    { t: 'overview',     v: ['overview'] },
    incidents:   { t: 'nIncidents',   v: ['incidents', 'events'] },
    sessions:    { t: 'sessions',     v: ['sessions'] },
    users:       { t: 'users',        v: ['users'] },
    investigate: { t: 'nInvestigate', v: ['logs', 'reports'] },
    computers:   { t: 'nComputers',   v: ['computers', 'deploy', 'software', 'connections'] },
    protect:     { t: 'nProtect',     v: ['endpoints'] },
    mailsec:     { t: 'nMail',        v: ['mailsec'] },
    updates:     { t: 'nUpdates',     v: ['updates'] },
    alerts:      { t: 'alerts',       v: ['alerts'] },
    settings:    { t: 'settings',     v: ['settings', 'accounts', 'remote', 'agentcfg', 'jobs'] }
  };
  var VIEWTAB = { incidents: 'tIncidents', events: 'tDetections', logs: 'tLogSearch', reports: 'reports', computers: 'tComputerList', deploy: 'tAddComputers', software: 'tSoftware', connections: 'tConnections', settings: 'tGeneral', accounts: 'tAccounts', remote: 'tRemote', agentcfg: 'tAgentsBackup', jobs: 'jobs' };
  var NAV = [['grp', 'grpWatch'], ['overview'], ['incidents'], ['sessions'], ['users'], ['investigate'], ['grp', 'grpManage'], ['computers'], ['protect'], ['mailsec'], ['grp', 'grpSystem'], ['updates'], ['alerts'], ['settings']];
  function sectionOf(view) { for (var k in SECTIONS) { if (SECTIONS[k].v.indexOf(view) >= 0) return k; } return view; }
  var badges = {};
  function renderNav() {
    var nav = clear($('nav')), cur = sectionOf(S.view);
    NAV.forEach(function (it) {
      if (it[0] === 'grp') { nav.appendChild(el('div', { cls: 'grp', text: t(it[1]) })); return; }
      var sec = SECTIONS[it[0]], first = sec ? sec.v[0] : it[0];
      // nav badge reflects only the section's default (first) tab, so a count that lives
      // in another tab — e.g. a down connection under Computers — never makes the default
      // tab look wrong. The owning tab carries its own badge (see the section tab bar).
      var b = (badges[first] && badges[first].n) ? badges[first] : null;
      nav.appendChild(el('a', { href: '#/' + first, cls: cur === it[0] ? 'on' : '', 'aria-current': cur === it[0] ? 'page' : null }, ico(it[0]), el('span', { text: t(sec ? sec.t : it[0]) }), b ? el('span', { cls: 'b', style: 'background:' + b.c, text: b.n }) : null));
    });
  }

  // ------------------------------------------------------------------ drawer
  function openDrawer(build) {
    var d = clear($('drawer')); d.hidden = false; $('scrim').hidden = false;
    build(d);
    d.scrollTop = 0;
  }
  function closeDrawer() {
    $('drawer').hidden = true; $('scrim').hidden = true;
    if (/^#\/event\//.test(location.hash)) { try { history.replaceState(null, '', '#/' + (S.view || 'events')); } catch (e) { } }
  }
  function drawerHead(d, titleNode) { d.appendChild(el('div', { cls: 'dh' }, el('h2', null, titleNode), el('button', { type: 'button', cls: 'x', text: '✕', 'aria-label': t('close'), onclick: closeDrawer }))); }

  // ------------------------------------------------------------------ helpers for views
  function page(title, lead) {
    var v = clear($('view')), secK = sectionOf(S.view), sec = SECTIONS[secK];
    if (sec && sec.v.length > 1) {
      v.appendChild(el('h1', { text: t(sec.t) }));
      v.appendChild(el('div', { cls: 'stabs' }, sec.v.map(function (vv) {
        var tb = (badges[vv] && badges[vv].n) ? badges[vv] : null;
        return el('a', { href: '#/' + vv, cls: vv === S.view ? 'on' : '' }, el('span', { text: t(VIEWTAB[vv] || vv) }), tb ? el('span', { cls: 'stabB', style: 'background:' + tb.c, text: tb.n }) : null);
      })));
    } else { v.appendChild(el('h1', { text: title })); }
    if (lead) v.appendChild(el('p', { cls: 'lead', text: lead }));
    return v;
  }
  function card(title, extra) { var c = el('div', { cls: 'card' }); var h = el('h3', null, el('span', { text: title })); if (extra) h.appendChild(el('span', { cls: 'end' }, extra)); c.appendChild(h); return c; }
  // sub-tabs inside a section: groups = [[id, labelKey, [elements]]]; shows one group at a time, remembers the last tab
  var SUBTAB = {}; try { SUBTAB = JSON.parse(localStorage.getItem('lb.subtab') || '{}') || {}; } catch (e) { SUBTAB = {}; }
  function tabify(box, key, groups) {
    groups = groups.map(function (g) { return [g[0], g[1], arr(g[2]).filter(function (n) { return !!n; })]; }).filter(function (g) { return g[2].length; });
    if (groups.length < 2) return null;
    var cur = SUBTAB[key]; if (!groups.some(function (g) { return g[0] === cur; })) cur = groups[0][0];
    var bar = el('div', { cls: 'tabs subtabs' }), all = [];
    groups.forEach(function (g) { g[2].forEach(function (n) { all.push(n); }); });
    function show(id) {
      SUBTAB[key] = id; try { localStorage.setItem('lb.subtab', JSON.stringify(SUBTAB)); } catch (e) { }
      groups.forEach(function (g) { g[2].forEach(function (n) { n.style.display = g[0] === id ? '' : 'none'; }); });
      [].forEach.call(bar.children, function (b) { b.className = b._id === id ? 'on' : ''; });
    }
    groups.forEach(function (g) { var b = el('button', { type: 'button', text: t(g[1]), onclick: function () { show(g[0]); } }); b._id = g[0]; bar.appendChild(b); });
    var anchor = null; for (var i = 0; i < box.children.length; i++) { if (all.indexOf(box.children[i]) >= 0) { anchor = box.children[i]; break; } }
    if (anchor) box.insertBefore(bar, anchor); else box.appendChild(bar);
    show(cur);
    return { show: show };
  }
  function table(heads, rows) {
    return el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, heads.map(function (h) { return el('th', { text: h }); }))), el('tbody', null, rows)));
  }
  function rangeSelect(val, onch) {
    var s = el('select', { onchange: function () { onch(+s.value); } });
    [[1, 'h1'], [6, 'h6'], [24, 'h24'], [168, 'd7'], [720, 'd30']].forEach(function (o) { s.appendChild(el('option', { value: o[0], text: t(o[1]), selected: o[0] === val ? 'selected' : null })); });
    return s;
  }
  function chanTable(chs) {
    var rows = arr(chs).map(function (c) {
      var why = (!c.ok && c.reason) ? el('div', { cls: 'why', text: c.reason }, c.remedy ? el('div', { cls: 'rmd', text: t('fix') + ': ' + c.remedy }) : null) : null;
      return el('tr', null, el('td', { style: 'width:18px' }, sevDot(!c.ok ? 'Fail' : (c.state === 'Warn' ? 'Warn' : 'OK'))), el('td', { cls: 'nw mono', text: c.channel }), el('td', null, c.detail || '', why), el('td', { cls: 'num muted nw', text: c.ms ? c.ms + 'ms' : '' }));
    });
    if (!rows.length) rows = [emptyRow(4)];
    return el('div', { cls: 'tw' }, el('table', null, el('tbody', null, rows)));
  }
  function statusPill(st) { return st === 'Fail' ? pill('Fail', t('down')) : (st === 'Warn' ? pill('Warn', t('warning')) : (st === 'OK' ? pill('OK', t('connected')) : pill('none', '—'))); }

  // 24 hourly columns, stacked by severity; time flows with the reading direction (Persian: "now" on the left, English: on the right)
  function watchStrip(s) {
    var tl = arr(s.timeline), n = tl.length || 24, max = 1;
    tl.forEach(function (b) { var x = (b.c || 0) + (b.w || 0) + (b.i || 0); if (x > max) max = x; });
    var bars = el('div', { cls: 'wbars', style: '--n:' + n }), ticks = el('div', { cls: 'wtick', style: '--n:' + n });
    for (var i = 0; i < n; i++) {
      var b = tl[i] || {}, c = b.c || 0, w = b.w || 0, inf = b.i || 0, tot = c + w + inf, ago = n - 1 - i;
      var when = ago === 0 ? t('watchNow') : t('watchAgo').replace('{n}', ago);
      var col = el('div', { cls: 'wcol' + (tot ? '' : ' zero'), title: when + ' — ' + t('crit') + ' ' + c + ' · ' + t('warn') + ' ' + w + ' · ' + t('info') + ' ' + inf });
      [['c', c], ['w', w], ['i', inf]].forEach(function (p) { if (p[1]) col.appendChild(el('span', { cls: p[0], style: 'height:' + (p[1] * 100 / max).toFixed(2) + '%' })); });
      bars.appendChild(col);
      ticks.appendChild(el('span', { text: (ago % 6 === 0) ? when : '' }));
    }
    function sum(val, label, color, k) { return el('div', { cls: 'ws' }, el('i', { cls: k || null, style: 'background:' + color }), el('b', { cls: 'num', text: val }), label); }
    return el('div', { cls: 'watch' },
      el('div', { cls: 'wh' }, el('div', null, el('div', { cls: 'wt', text: t('watchT') }), el('div', { cls: 'wsub', text: t('watchSub') })),
        el('div', { cls: 'wsum' }, sum(s.crit, t('crit'), 'var(--crit)'), sum(s.warn, t('warn'), 'var(--warn)', 'w'), sum(s.info, t('info'), 'var(--info)'))),
      bars, ticks);
  }

  // ================================================================== VIEWS
  // ---------------- overview
  function vOverview() {
    var v = page(t('overview'), t('ovLead')); v.appendChild(spinner());
    api('/api/summary?hours=' + S.ev.hours).then(function (s) {
      v = page(t('overview'), t('ovLead'));
      badges.events = { n: s.crit, c: 'var(--crit)' }; badges.incidents = { n: s.incidentsOpen, c: 'var(--warn)' }; badges.guard = { n: s.guard.blocked, c: 'var(--crit)' }; badges.connections = { n: s.conn.down, c: 'var(--crit)' };
      renderNav();
      var lic = s.license;
      if (!lic.valid) v.appendChild(el('div', { cls: 'flash err', text: t('license') + ': ' + (lic.reason || t('invalid')) }));
      v.appendChild(watchStrip(s));
      function kpi(val, label, color, go) { return el('div', { cls: 'kpi' + (go ? ' go' : ''), onclick: go || null, style: color ? '--kc:' + color : null }, el('div', { cls: 'v num', style: color ? 'color:' + color : null, text: val }), el('div', { cls: 'l', text: label })); }
      v.appendChild(el('div', { cls: 'kpis' },
        kpi(s.crit, t('crit') + ' · ' + s.hours + 'h', 'var(--crit)', function () { S.ev.sev = '=Critical'; S.ev.skip = 0; go('events'); }),
        kpi(s.warn, t('warn'), 'var(--warn)', function () { S.ev.sev = '=Warning'; S.ev.skip = 0; go('events'); }),
        kpi(s.info, t('info'), 'var(--info)', function () { S.ev.sev = '=Info'; S.ev.skip = 0; go('events'); }),
        kpi(s.incidentsOpen, t('openInc'), 'var(--warn)', function () { go('incidents'); }),
        kpi(s.sessionsLive || 0, t('ssLiveNow'), 'var(--mint)', function () { go('sessions'); }),
        kpi(s.guard.blocked, t('blockedIps'), 'var(--crit)', function () { go('endpoints/guard'); }),
        kpi(s.sources, t('srcCount'), null, function () { go('computers'); }),
        kpi(s.conn.down, t('connDown'), s.conn.down ? 'var(--crit)' : 'var(--mint)', function () { go('connections'); }),
        kpi(s.jobsOn + ' / ' + s.jobsTotal, t('jobsOn'), 'var(--mint)', function () { go('jobs'); })));
      var tiles = el('div', { cls: 'tiles' });
      arr(s.categories).forEach(function (c) {
        var z = !c.n;
        tiles.appendChild(el('div', { cls: 'tile' + (z ? ' zero' : ''), onclick: z ? null : function () { S.ev.cat = c.key; S.ev.sev = ''; S.ev.skip = 0; go('events'); } },
          el('span', { cls: 'dot', style: 'background:' + (c.crit ? 'var(--crit)' : (c.n ? 'var(--warn)' : 'var(--line)')) }), el('div', { cls: 'tl', text: c.title }), el('div', { cls: 'tv num', text: c.n })));
      });
      var cc = card(t('categories')); cc.appendChild(tiles); v.appendChild(cc);
      var latest = arr(s.latest).map(function (f) { return el('tr', { cls: 'clk', onclick: function () { openFinding(f.id); } }, el('td', { cls: 'num muted nw', text: f.time.slice(5, 16) }), el('td', { text: f.host }), el('td', null, f.title, f.mitre ? el('span', { cls: 'mitre', text: f.mitre }) : null)); });
      if (!latest.length) latest = [emptyRow(3, t('noEvents'))];
      var c1 = card(t('latestCrit'), btn(t('all'), function () { S.ev.sev = '=Critical'; S.ev.cat = ''; S.ev.skip = 0; go('events'); }, 'sm')); c1.appendChild(table([t('time'), t('host'), t('title')], latest));
      var max = 1; arr(s.topHosts).forEach(function (h) { if (h.n > max) max = h.n; });
      var hr = arr(s.topHosts).map(function (h) { return el('tr', { cls: 'clk', onclick: function () { S.ev.host = h.host; S.ev.cat = ''; S.ev.sev = ''; S.ev.skip = 0; go('events'); } }, el('td', { text: h.host }), el('td', { style: 'width:45%' }, el('div', { cls: 'bar' }, el('i', { style: 'width:' + Math.round(h.n * 100 / max) + '%' }))), el('td', { cls: 'num', text: h.n })); });
      if (!hr.length) hr = [emptyRow(3)];
      var c2 = card(t('topHosts')); c2.appendChild(table([t('host'), '', t('count')], hr));
      v.appendChild(el('div', { cls: 'cols3' }, c1, c2));
      var hc = card(t('health'));
      hc.appendChild(el('div', { cls: 'kv' },
        el('div', { cls: 'k', text: t('license') }), el('div', null, lic.valid ? pill('ok', t('valid') + (lic.permanent ? ' · ' + t('permanent') : '')) : pill('bad', t('invalid')), ' ', lic.company || '', lic.device ? el('span', { cls: 'muted mono', text: '  ' + lic.device }) : null),
        el('div', { cls: 'k', text: t('connections') }), el('div', null, s.conn.targets + ' · ', s.conn.down ? pill('Fail', s.conn.down + ' ' + t('down')) : pill('OK', t('connected'))),
        el('div', { cls: 'k', text: t('guard') }), el('div', { text: s.guard.blocked + ' ' + t('blockedNow') + ' · ' + s.guard.rules + ' ' + t('rules') }),
        el('div', { cls: 'k', text: t('jobs') }), el('div', null, s.jobsOn + ' / ' + s.jobsTotal, s.jobsBad ? el('span', { style: 'color:var(--warn)', text: '  ⚠ ' + s.jobsBad }) : null)));
      v.appendChild(hc);
      // AD dashboard tiles (ADAuditPlus-style)
      var adc = card(t('adDashTitle')); adc.appendChild(spinner()); v.appendChild(adc);
      tabify(v, 'overview', [['sum', 'tbSummary', [v.querySelector(':scope > .kpis'), v.querySelector(':scope > .cols3')]], ['cat', 'tbCategories', [cc]], ['ad', 'tbAD', [adc]], ['health', 'tbHealth', [hc]]]);
      api('/api/ad/dashboard?days=7').then(function (A) {
        clear(adc); adc.appendChild(el('h3', { text: t('adDash7d') }));
        function stt(val, lab, col) { return el('div', { cls: 'kpi', style: col ? '--kc:' + col : null }, el('div', { cls: 'v num', style: col ? 'color:' + col : null, text: String(val) }), el('div', { cls: 'l', text: lab })); }
        var ac = A.account || {};
        adc.appendChild(el('div', { cls: 'kpis' },
          stt(A.totalFail || 0, t('adLogonFail'), 'var(--crit)'),
          stt(A.totalLogon || 0, t('adLogonOk')),
          stt(ac.created || 0, t('adAcctCreated')),
          stt(ac.modified || 0, t('adAcctModified'), 'var(--warn)'),
          stt(ac.deleted || 0, t('adAcctDeleted'), 'var(--crit)'),
          stt(ac.groups || 0, t('adGroupChg'), 'var(--warn)'),
          stt(ac.gpo || 0, t('adGpoChg'), 'var(--warn)')));
        var tf = arr(A.topFail);
        var tfc = el('div'); tfc.appendChild(el('h4', { text: t('adTopFail') }));
        if (tf.length) { var tb = el('tbody'); tf.forEach(function (x) { tb.appendChild(el('tr', null, el('td', { text: x.user }), el('td', { cls: 'num', text: String(x.n) }))); }); tfc.appendChild(el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, el('th', { text: t('adUser') }), el('th', { text: t('adCount') }))), tb))); } else { tfc.appendChild(el('div', { cls: 'muted', text: t('adNoItems') })); }
        var bh = arr(A.byHour); var mx = 1; bh.forEach(function (n) { if (n > mx) mx = n; });
        var chart = el('div', { style: 'display:flex;align-items:flex-end;gap:2px;height:70px;margin-top:6px' });
        bh.forEach(function (n, h) { chart.appendChild(el('div', { title: h + ':00 — ' + n, style: 'flex:1;background:var(--accent,#4FD1B5);height:' + Math.round((n / mx) * 100) + '%;min-height:1px;border-radius:2px 2px 0 0' })); });
        var hc2 = el('div'); hc2.appendChild(el('h4', { text: t('adByHour') })); hc2.appendChild(chart);
        var ub = arr(A.uba); var uc2 = el('div'); uc2.appendChild(el('h4', { text: t('adRecentUba') }));
        if (ub.length) { var ul2 = el('div'); ub.forEach(function (x) { ul2.appendChild(el('div', { cls: 'muted', style: 'padding:3px 0;border-bottom:1px solid var(--line,#2226)', text: (x.title || '') })); }); uc2.appendChild(ul2); } else { uc2.appendChild(el('div', { cls: 'muted', text: t('adLearning') })); }
        adc.appendChild(el('div', { cls: 'cols3' }, tfc, hc2, uc2));
      }).catch(function () { clear(adc); adc.appendChild(el('div', { cls: 'muted', text: t('adNoData') })); });
    }).catch(fail);
  }

  // ---------------- events
  function vEvents() {
    var v = page(t('events'), t('evLead'));
    var host = el('input', { type: 'text', placeholder: t('hostFilter'), value: S.ev.host });
    var q = el('input', { type: 'search', placeholder: t('textFilter'), value: S.ev.q });
    var sev = el('select');
    [['', 'anySev'], ['Warning', 'minWarn'], ['=Critical', 'onlyCrit'], ['=Warning', 'warn'], ['=Info', 'info']].forEach(function (o) { sev.appendChild(el('option', { value: o[0], text: t(o[1]), selected: S.ev.sev === o[0] ? 'selected' : null })); });
    var cat = el('select'); cat.appendChild(el('option', { value: '', text: t('anyCat') }));
    S.cats.forEach(function (c) { cat.appendChild(el('option', { value: c.key, text: c.title, selected: S.ev.cat === c.key ? 'selected' : null })); });
    // فیلتر فوراً اعمال می‌شود (بدونِ دکمه) | filters apply instantly — no Apply button
    function applyF() { S.ev.host = host.value.trim(); S.ev.q = q.value.trim(); S.ev.sev = sev.value; S.ev.cat = cat.value; S.ev.skip = 0; load(); }
    var deb = null; function soon() { clearTimeout(deb); deb = setTimeout(applyF, 350); }
    sev.addEventListener('change', applyF); cat.addEventListener('change', applyF);
    q.addEventListener('input', soon); host.addEventListener('input', soon);
    q.addEventListener('keydown', function (e) { if (e.key === 'Enter') { clearTimeout(deb); applyF(); } });
    host.addEventListener('keydown', function (e) { if (e.key === 'Enter') { clearTimeout(deb); applyF(); } });
    var clr = btn('✕ ' + t('clearF'), function () { host.value = ''; q.value = ''; sev.value = ''; cat.value = ''; applyF(); }, 'sm');
    v.appendChild(el('div', { cls: 'fbar' }, rangeSelect(S.ev.hours, function (h) { S.ev.hours = h; S.ev.skip = 0; load(); }), sev, cat, host, q, clr));
    var box = el('div', { cls: 'card' }); v.appendChild(box);
    var seq = 0;
    function load() {
      var my = ++seq;
      if (!box.firstChild) box.appendChild(spinner()); else box.style.opacity = '.55';
      var qs = '?hours=' + S.ev.hours + '&skip=' + S.ev.skip + '&max=100' + (S.ev.sev ? '&sev=' + encodeURIComponent(S.ev.sev) : '') + (S.ev.cat ? '&cat=' + encodeURIComponent(S.ev.cat) : '') + (S.ev.host ? '&host=' + encodeURIComponent(S.ev.host) : '') + (S.ev.q ? '&q=' + encodeURIComponent(S.ev.q) : '');
      api('/api/findings' + qs).then(function (r) {
        if (my !== seq) return;
        clear(box); box.style.opacity = '';
        var rows = arr(r.items).map(function (f) {
          return el('tr', { cls: 'clk', onclick: function () { openFinding(f.id); } }, el('td', { cls: 'num muted nw', text: f.time }), el('td', { cls: 'nw' }, sevDot(f.sev), sevName(f.sev)), el('td', { cls: 'muted', text: f.catTitle }), el('td', { text: f.host }), el('td', null, f.title, f.note ? el('div', { cls: 'note', text: '📝 ' + f.note }) : null, f.mitre ? el('span', { cls: 'mitre', text: f.mitre }) : null));
        });
        if (!rows.length) rows = [emptyRow(5, t('noEvents'))];
        box.appendChild(table([t('time'), t('sev'), t('cat'), t('host'), t('title')], rows));
        var from = r.total ? S.ev.skip + 1 : 0, to = S.ev.skip + arr(r.items).length;
        box.appendChild(el('div', { cls: 'pager' }, from + '–' + to + ' ' + t('of') + ' ' + r.total,
          el('button', { type: 'button', cls: 'btn sm', text: t('prev'), disabled: S.ev.skip <= 0 ? 'disabled' : null, onclick: function () { S.ev.skip = Math.max(0, S.ev.skip - 100); load(); } }),
          el('button', { type: 'button', cls: 'btn sm', text: t('next'), disabled: to >= r.total ? 'disabled' : null, onclick: function () { S.ev.skip += 100; load(); } })));
      }).catch(function (e) { if (my !== seq) return; clear(box); box.style.opacity = ''; fail(e); });
    }
    load();
  }

  // ---------------- finding drawer
  function openFinding(id) {
    try { history.replaceState(null, '', '#/event/' + id); } catch (e) { }
    openDrawer(function (d) { d.appendChild(spinner()); });
    api('/api/finding?id=' + encodeURIComponent(id)).then(function (f) {
      openDrawer(function (d) {
        drawerHead(d, el('span', null, sevDot(f.sev), f.title));
        d.appendChild(el('div', { cls: 'kv' },
          el('div', { cls: 'k', text: t('time') }), el('div', { cls: 'num', text: f.time }),
          el('div', { cls: 'k', text: t('sev') }), el('div', null, sevName(f.sev)),
          el('div', { cls: 'k', text: t('host') }), el('div', { text: f.host }),
          el('div', { cls: 'k', text: t('cat') }), el('div', { text: f.catTitle }),
          arr(f.mitreInfo).length ? [el('div', { cls: 'k', text: t('mitre') }), el('div', null, arr(f.mitreInfo).map(function (m) { return el('span', { cls: 'chip' }, el('span', { cls: 'mono', text: m.id }), ' ', m.name); }))] : null));
        d.appendChild(el('h4', { text: t('details') }));
        d.appendChild(el('div', { cls: 'pre', text: f.details || '—' }));
        var ex = f.extra || {}; var exKeys = Object.keys(ex);
        if (exKeys.length) d.appendChild(el('div', { cls: 'kv', style: 'margin-top:10px' }, exKeys.map(function (k) { return [el('div', { cls: 'k mono', text: k }), el('div', { cls: 'mono', text: ex[k] })]; })));
        // admin notes: this event, and every event of this type (optional custom title)
        var nn = f.notes || {};
        d.appendChild(el('h4', { text: '📝 ' + t('notes2') }));
        var ne = el('textarea', { rows: 2, placeholder: t('noteEventPh') }); ne.value = nn.eventText || '';
        var tt = el('input', { type: 'text', placeholder: f.origTitle || f.title }); tt.value = nn.typeTitle || '';
        var nt = el('textarea', { rows: 2, placeholder: t('noteTypePh') }); nt.value = nn.typeText || '';
        function saveNote(body, b) { b.disabled = true; api('/api/note', body).then(function () { b.disabled = false; flash(t('saved')); openFinding(id); }).catch(function (er) { b.disabled = false; fail(er); }); }
        d.appendChild(el('div', { cls: 'notebox' },
          el('label', { text: t('noteEvent') }), ne,
          el('div', { cls: 'acts' }, btn(t('save'), function (e) { saveNote({ scope: 'event', id: f.id, text: ne.value }, e.target); }, 'sm pri'), nn.eventBy ? el('span', { cls: 'muted', text: nn.eventBy + ' · ' + String(nn.eventAt || '').replace('T', ' ').slice(0, 16) }) : null),
          el('label', { text: t('noteType') }), tt, nt,
          el('div', { cls: 'acts' }, btn(t('save'), function (e) { saveNote({ scope: 'type', sig: f.sig, title: tt.value, text: nt.value }, e.target); }, 'sm pri'), nn.typeBy ? el('span', { cls: 'muted', text: nn.typeBy + ' · ' + String(nn.typeAt || '').replace('T', ' ').slice(0, 16) }) : null)));
        // actions
        d.appendChild(el('h4', { text: t('actions') }));
        var acts = el('div', { cls: 'acts' });
        function act(label, body, confirmMsg, cls) {
          return btn(label, function (e) {
            if (confirmMsg && !window.confirm(confirmMsg)) return;
            var b = e.target; b.disabled = true;
            api('/api/action', body).then(function (r) { flash(r.message || t('saved')); openFinding(id); }).catch(function (er) { b.disabled = false; fail(er); });
          }, cls);
        }
        var ents = f.entities || {};
        arr(ents.guard).forEach(function (g) {
          var lab = el('span', { cls: 'chip' }, el('span', { cls: 'mono', text: g.ip }), ' · ', g.blocked ? t('isBlocked') : t('notBlocked'));
          acts.appendChild(lab);
          if (g.blocked) acts.appendChild(act(t('unblockIp'), { type: 'unblock-ip', value: g.ip }));
          else { acts.appendChild(act(t('blockIp1h'), { type: 'block-ip', value: g.ip, minutes: 60 }, null, 'danger')); acts.appendChild(act(t('blockIpPerm'), { type: 'block-ip', value: g.ip, minutes: 0 }, null, 'danger')); }
          acts.appendChild(act(t('whitelistIp'), { type: 'whitelist-ip', value: g.ip }));
        });
        arr(ents.users).forEach(function (u) {
          acts.appendChild(el('span', { cls: 'chip' }, '👤 ', el('span', { cls: 'mono', text: u })));
          acts.appendChild(act(t('disableUser'), { type: 'disable-user', value: u, host: f.host }, t('confirmDisable') + ' ' + u, 'danger'));
          acts.appendChild(act(t('disableAdUser'), { type: 'disable-user', value: u, host: f.host, domain: true }, t('confirmDisable') + ' ' + u, 'danger'));
          acts.appendChild(act(t('unlockUser'), { type: 'unlock-user', value: u, host: f.host }));
          acts.appendChild(act(t('enableUser'), { type: 'enable-user', value: u, host: f.host }));
        });
        if (!f.isSelf) { acts.appendChild(act(t('isolate'), { type: 'isolate-host', host: f.host }, t('confirmIsolate'), 'danger')); acts.appendChild(act(t('restore'), { type: 'restore-host', host: f.host })); }
        if (f.incident) acts.appendChild(btn(t('viewIncident') + ' (' + f.incident.status + ')', function () { closeDrawer(); go('incidents'); }));
        else acts.appendChild(act(t('openIncident'), { type: 'open-incident', findingId: f.id }));
        acts.appendChild(btn(t('searchAround'), function () { S.logs.host = String(f.host || '').split(/[ (]/)[0]; S.logs.q = ''; S.logs.hours = 24; closeDrawer(); go('logs'); }));
        acts.appendChild(btn(t('copyLink'), function (e) { var u = location.origin + location.pathname + '#/event/' + f.id; try { navigator.clipboard.writeText(u); e.target.textContent = t('copied'); } catch (x) { window.prompt('', u); } }));
        d.appendChild(acts);
        // related raw logs
        d.appendChild(el('h4', { text: t('related') + ' · ' + arr(f.related).length }));
        var rr = arr(f.related).map(function (r) { return rawRow(r); });
        if (!rr.length) rr = [emptyRow(5)];
        d.appendChild(table([t('time'), t('log'), 'ID', t('user'), t('message')], rr));
      });
    }).catch(function (e) { closeDrawer(); fail(e); });
  }
  function rawRow(r) {
    var tr = el('tr', { cls: 'clk' }, el('td', { cls: 'num muted nw', text: (r.t || '').slice(5) }), el('td', { cls: 'muted', text: r.log }), el('td', { cls: 'mono', text: r.id }), el('td', { text: r.user || (r.ip || '') }), el('td', { cls: 'wrap', text: r.msg }));
    tr.addEventListener('click', function () {
      var nx = tr.nextSibling;
      if (nx && nx.className === 'rawx') { nx.parentNode.removeChild(nx); return; }
      var x = el('tr', { cls: 'rawx' }, el('td', { colspan: 5 }, el('div', { cls: 'code', text: JSON.stringify(r, null, 2) })));
      tr.parentNode.insertBefore(x, tr.nextSibling);
    });
    return tr;
  }

  // ---------------- raw log search
  function vLogs() {
    var v = page(t('logs'), null);
    v.appendChild(el('p', { cls: 'lead' }, t('logsLead') + ' ', el('span', { cls: 'mono', text: t('logsEx') })));
    var q = el('input', { type: 'search', placeholder: t('query'), value: S.logs.q, style: 'flex:2;min-width:260px' });
    var host = el('input', { type: 'text', placeholder: t('host'), value: S.logs.host });
    var user = el('input', { type: 'text', placeholder: t('user'), value: S.logs.user });
    var eid = el('input', { type: 'text', placeholder: t('eventId'), value: S.logs.id, style: 'width:90px;min-width:0' });
    var src = el('select'); [['all', 'srcAll'], ['windows', 'srcWin'], ['syslog', 'srcSys']].forEach(function (o) { src.appendChild(el('option', { value: o[0], text: t(o[1]), selected: S.logs.source === o[0] ? 'selected' : null })); });
    function run() { S.logs.q = q.value.trim(); S.logs.host = host.value.trim(); S.logs.user = user.value.trim(); S.logs.id = eid.value.trim(); S.logs.source = src.value; load(); }
    var deb = null; function soon() { clearTimeout(deb); deb = setTimeout(run, 500); }
    [q, host, user, eid].forEach(function (i) { i.addEventListener('input', soon); i.addEventListener('keydown', function (e) { if (e.key === 'Enter') { clearTimeout(deb); run(); } }); });
    src.addEventListener('change', run);
    var clr = btn('✕ ' + t('clearF'), function () { q.value = ''; host.value = ''; user.value = ''; eid.value = ''; src.value = 'all'; run(); }, 'sm');
    v.appendChild(el('div', { cls: 'fbar' }, rangeSelect(S.logs.hours, function (h) { S.logs.hours = h; run(); }), q, host, user, eid, src, clr));
    var box = el('div', { cls: 'card' }); v.appendChild(box);
    var seq = 0;
    function load() {
      var my = ++seq;
      if (!box.firstChild) box.appendChild(spinner()); else box.style.opacity = '.55';
      var L = S.logs;
      api('/api/logs?hours=' + L.hours + '&max=300' + (L.q ? '&q=' + encodeURIComponent(L.q) : '') + (L.host ? '&host=' + encodeURIComponent(L.host) : '') + (L.user ? '&user=' + encodeURIComponent(L.user) : '') + (L.id ? '&id=' + encodeURIComponent(L.id) : '') + '&source=' + L.source).then(function (r) {
        if (my !== seq) return; box.style.opacity = '';
        clear(box);
        box.appendChild(el('div', { cls: 'muted', style: 'font-size:12px;margin-bottom:6px', text: r.count + ' ' + t('results') }));
        var rows = arr(r.items).map(function (x) {
          var tr = el('tr', { cls: 'clk' }, el('td', { cls: 'num muted nw', text: x.t }), el('td', { text: x.host }), el('td', { cls: 'muted', text: x.log }), el('td', { cls: 'mono', text: x.id }), el('td', { text: x.user }), el('td', { cls: 'mono', text: x.ip }), el('td', { cls: 'wrap', text: x.msg }));
          tr.addEventListener('click', function () { openDrawer(function (d) { drawerHead(d, t('rawRecord')); d.appendChild(el('div', { cls: 'code', text: JSON.stringify(x, null, 2) })); }); });
          return tr;
        });
        if (!rows.length) rows = [emptyRow(7, t('noEvents'))];
        box.appendChild(table([t('time'), t('host'), t('log'), 'ID', t('user'), t('ip'), t('message')], rows));
      }).catch(function (e) { if (my !== seq) return; box.style.opacity = ''; clear(box); fail(e); });
    }
    load();
  }

  // ---------------- incidents
  function urgPill(u) { return pill(u === 'now' ? 'Fail' : (u === 'today' ? 'Warn' : 'none'), t(u === 'now' ? 'urgNow' : (u === 'today' ? 'urgToday' : 'urgWeek'))); }
  function playbookView(p) {
    var w = el('div', { cls: 'pbv' });
    function sec(h, body, cls) { w.appendChild(el('div', { cls: 'pbsec ' + (cls || '') }, el('div', { cls: 'pbh', text: h }), body)); }
    if (p.what) sec(t('pbWhat'), el('div', { text: p.what }));
    if (p.why) sec(t('pbWhy'), el('div', { text: p.why }));
    if (arr(p.do).length) sec(t('pbDo'), el('ol', null, arr(p.do).map(function (x) { return el('li', { text: x }); })), 'do');
    if (p.normal && p.normal !== '—') sec(t('pbNormal'), el('div', { cls: 'muted', text: p.normal }));
    return w;
  }
  function vIncidents() {
    var v = page(t('incidents'), t('incLead'));
    var mode = 'open';
    var bar = el('div', { cls: 'fbar' }); v.appendChild(bar);
    var box = el('div', { cls: 'card' }); v.appendChild(box);
    function drawBar() { clear(bar); ['open', 'all'].forEach(function (m) { bar.appendChild(el('button', { type: 'button', cls: 'fchip' + (mode === m ? ' on' : ''), text: t(m === 'open' ? 'showOpen' : 'showAll'), onclick: function () { mode = m; drawBar(); load(); } })); }); }
    function stName(s) { return s === 'Closed' ? t('stClosed') : (s === 'Investigating' ? t('stInv') : t('stOpen')); }
    function load() {
      clear(box).appendChild(spinner());
      api('/api/incidents?status=' + mode).then(function (r) {
        clear(box);
        var rows = arr(r.items).map(function (i) {
          return el('tr', { cls: 'clk', onclick: function () { incDrawer(i); } }, el('td', null, urgPill(i.urgency), i.muted ? el('span', { cls: 'muted', text: ' 🔕' }) : null), el('td', null, sevDot(i.sev), i.host), el('td', { text: i.title }), el('td', { cls: 'muted', text: i.catTitle }), el('td', { cls: 'num', text: i.count }), el('td', { text: stName(i.status) }), el('td', { text: i.owner || '' }), el('td', { cls: 'num muted nw', text: (i.last || '').slice(0, 16) }));
        });
        if (!rows.length) rows = [emptyRow(8, t('incNone'))];
        box.appendChild(el('p', { cls: 'lead', text: t('incHow') }));
        box.appendChild(table([t('incUrg'), t('host'), t('title'), t('cat'), t('count'), t('status'), t('owner'), t('last')], rows));
      }).catch(function (e) { clear(box); fail(e); });
    }
    function incDrawer(i) {
      openDrawer(function (d) {
        drawerHead(d, el('span', null, sevDot(i.sev), i.title));
        d.appendChild(el('div', { cls: 'kv' }, el('div', { cls: 'k', text: 'ID' }), el('div', { cls: 'mono', text: i.id }), el('div', { cls: 'k', text: t('host') }), el('div', { text: i.host }), el('div', { cls: 'k', text: t('cat') }), el('div', { text: i.catTitle }),
          el('div', { cls: 'k', text: 'MITRE' }), el('div', { cls: 'mono', text: i.mitre || '—' }), el('div', { cls: 'k', text: t('count') }), el('div', { text: i.count }), el('div', { cls: 'k', text: t('first') }), el('div', { cls: 'num', text: i.first }), el('div', { cls: 'k', text: t('last') }), el('div', { cls: 'num', text: i.last })));
        // what happened / why / what to do — plain language
        var pbBox = el('div', { cls: 'pb' }); d.appendChild(pbBox); pbBox.appendChild(spinner());
        api('/api/playbook', { cat: i.cat, title: i.rawTitle || i.title }).then(function (p) { clear(pbBox); pbBox.appendChild(playbookView(p)); }).catch(function () { clear(pbBox); });
        var st = el('select'); [['Open', 'stOpen'], ['Investigating', 'stInv'], ['Closed', 'stClosed']].forEach(function (o) { st.appendChild(el('option', { value: o[0], text: t(o[1]), selected: i.status === o[0] ? 'selected' : null })); });
        var ow = el('input', { type: 'text', value: i.owner || '' }); var nt = el('textarea', { text: i.note || '' }); nt.value = i.note || '';
        d.appendChild(el('h4', { text: t('status') }));
        d.appendChild(el('div', { cls: 'form' }, el('label', { text: t('status') }), st, el('label', { text: t('owner') }), ow, el('label', { text: t('note') }), nt));
        var days = el('select'); [[7, '7 ' + t('days')], [30, '30 ' + t('days')], [0, t('muteForever')]].forEach(function (o) { days.appendChild(el('option', { value: o[0], text: o[1] })); });
        var allH = el('input', { type: 'checkbox' });
        d.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' },
          btn(t('incResolve'), function () { api('/api/incident', { id: i.id, status: 'Closed', owner: ow.value, note: nt.value }).then(function () { flash(t('saved')); closeDrawer(); load(); }).catch(fail); }, 'pri'),
          btn(t('incInvestigate'), function () { api('/api/incident', { id: i.id, status: 'Investigating', owner: ow.value || ((S.meta && S.meta.user) || ''), note: nt.value }).then(function () { flash(t('saved')); closeDrawer(); load(); }).catch(fail); }),
          btn(t('save'), function () { api('/api/incident', { id: i.id, status: st.value, owner: ow.value, note: nt.value }).then(function () { flash(t('saved')); closeDrawer(); load(); }).catch(fail); }),
          btn(t('relatedEvents'), function () { S.ev.host = i.host; S.ev.cat = i.cat; S.ev.sev = ''; S.ev.skip = 0; S.ev.hours = 720; closeDrawer(); go('events'); })));
        d.appendChild(el('div', { cls: 'mutebox' }, el('div', { cls: 'muted', text: t('muteLead') }), el('div', { cls: 'row', style: 'margin-top:6px' }, days, el('label', null, allH, ' ', t('muteAllHosts')),
          i.muted ? btn('🔔 ' + t('unmute'), function () { api('/api/incident/mute', { id: i.id, unmute: true, allHosts: allH.checked }).then(function () { flash(t('saved')); closeDrawer(); load(); }).catch(fail); }, 'sm')
                  : btn('🔕 ' + t('mute'), function () { api('/api/incident/mute', { id: i.id, days: +days.value, allHosts: allH.checked }).then(function () { flash(t('muted')); closeDrawer(); load(); }).catch(fail); }, 'sm danger'))));
      });
    }
    drawBar(); load();
  }

  // ---------------- alerts & email
  function vAlerts() {
    var v = page(t('alerts'), t('alLead')); v.appendChild(spinner());
    Promise.all([api('/api/alerts'), api('/api/mail')]).then(function (res) {
      var a = res[0], m = res[1];
      S.alDefaultTo = arr(m.to);
      v = page(t('alerts'), t('alLead'));
      var sc0 = null, alTabs = null;
      if (!a.mailConfigured) {
        v.appendChild(el('div', { cls: 'banner' }, el('span', { text: '⚠ ' + t('alNoMail') }), btn(t('alNoMailFix'), function () { if (alTabs) alTabs.show('smtp'); else if (sc0) sc0.scrollIntoView({ behavior: 'smooth' }); }, 'pri sm')));
      }
      // profiles
      var pc = card(t('profiles') + ' (' + arr(a.profiles).length + ')', [btn(t('alDefaults'), function (e) { var b = e.target; b.disabled = true; api('/api/alerts/defaults', {}).then(function (x) { flash(t('alRestored') + ': ' + x.added); vAlerts(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'sm'), ' ', btn('+ ' + t('newProfile'), function () { profileDrawer(null); }, 'pri sm')]);
      var rows = arr(a.profiles).map(function (p) {
        var cats = arr(p.categories).map(function (k) { var c = S.cats.filter(function (x) { return x.key === k; })[0]; return el('span', { cls: 'chip', text: c ? c.title : k }); });
        return el('tr', { cls: 'clk', onclick: function () { profileDrawer(p); } }, el('td', null, p.enabled ? '' : '⏸ ', bil(p.name), p.builtin ? el('span', { cls: 'chip', text: t('alBuiltin') }) : null, el('span', { cls: 'chip' + (p.delivery === 'digest' ? '' : ' on'), text: p.delivery === 'digest' ? t('dvDigestShort') + ' ' + (p.digestMinutes || 60) + 'm' : t('dvInstantShort') })), el('td', null, sevDot(p.minSeverity), sevName(p.minSeverity) + '+'), el('td', null, cats.length ? cats : el('span', { cls: 'muted', text: t('all') })), el('td', { cls: arr(p.recipients).length ? 'mono' : 'muted', text: arr(p.recipients).length ? arr(p.recipients).join(', ') : t('alRcptDefault') + (arr(m.to).length ? ' (' + arr(m.to).join(', ') + ')' : '') }), el('td', { cls: 'num', text: p.throttleMinutes }));
      });
      if (!rows.length) rows = [emptyRow(5, '—')];
      pc.appendChild(table([t('name'), t('minSev'), t('cat'), t('recipients'), t('throttle')], rows));
      v.appendChild(pc);
      // smtp
      var f = { srv: el('input', { type: 'text', value: m.smtpServer }), port: el('input', { type: 'number', value: m.port || 587, style: 'width:110px' }), ssl: el('input', { type: 'checkbox', checked: m.useSsl }),
        from: el('input', { type: 'email', value: m.from }), to: el('input', { type: 'text', value: arr(m.to).join(', ') }), user: el('input', { type: 'text', value: m.user }), pass: el('input', { type: 'password', placeholder: t('passKeep'), autocomplete: 'new-password' }), tag: el('input', { type: 'text', value: m.subjectTag }) };
      var testTo = el('input', { type: 'email', placeholder: t('to') });
      var sc = card(t('smtp'), m.hasPassword ? el('span', { cls: 'muted', text: '🔒 ' + t('hasPass') }) : null);
      sc0 = sc;
      sc.appendChild(el('div', { cls: 'form' },
        el('label', { text: t('smtpServer') }), f.srv, el('label', { text: t('port') }), el('div', { cls: 'row' }, f.port, el('label', null, f.ssl, ' ', t('useSsl'))),
        el('label', { text: t('from') }), f.from, el('label', { text: t('to') }), f.to, el('div', { cls: 'hint', text: t('commaHint') }),
        el('label', { text: t('smtpUser') }), f.user, el('label', { text: t('smtpPass') }), f.pass, el('label', { text: t('subjTag') }), f.tag));
      sc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' },
        btn(t('save'), function () { api('/api/mail', { smtpServer: f.srv.value.trim(), port: +f.port.value || 587, useSsl: f.ssl.checked, from: f.from.value.trim(), to: splitList(f.to.value), user: f.user.value.trim(), password: f.pass.value, subjectTag: f.tag.value }).then(function () { flash(t('saved')); vAlerts(); }).catch(fail); }, 'pri'),
        testTo, btn(t('sendTest'), function (e) { var b = e.target; b.disabled = true; api('/api/mail/test', { to: splitList(testTo.value) }).then(function (r) { b.disabled = false; if (r.ok) flash(t('testSent') + ' → ' + arr(r.to).join(', ')); else flash(t('err') + ': ' + loc(r.error || ''), false); }).catch(function (er) { b.disabled = false; fail(er); }); })));
      v.appendChild(sc);
      // options
      var dm = el('input', { type: 'checkbox', checked: a.defaultToMailTo });
      var days = el('div', { cls: 'checks' }); var DAYS = ['Saturday', 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
      var DAYS_FA = { Saturday: 'شنبه', Sunday: 'یکشنبه', Monday: 'دوشنبه', Tuesday: 'سه‌شنبه', Wednesday: 'چهارشنبه', Thursday: 'پنجشنبه', Friday: 'جمعه' };
      var bh = a.businessHours || {}; var dset = arr(bh.days);
      var dBoxes = DAYS.map(function (dn) { var c = el('input', { type: 'checkbox', checked: dset.indexOf(dn) >= 0, value: dn }); days.appendChild(el('label', null, c, ' ', S.lang === 'fa' ? DAYS_FA[dn] : dn)); return c; });
      var bs = el('input', { type: 'text', value: bh.start || '08:00', style: 'width:90px' }), be = el('input', { type: 'text', value: bh.end || '17:00', style: 'width:90px' });
      var oc = card(t('options'));
      oc.appendChild(el('div', { cls: 'form' }, el('label', { cls: 'full' }, dm, ' ', t('defaultMail')), el('label', { text: t('bhDays') }), days, el('label', { text: t('bh') }), el('div', { cls: 'row' }, t('bhStart'), bs, t('bhEnd'), be)));
      oc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function () { api('/api/alerts/options', { defaultToMailTo: dm.checked, businessHours: { days: dBoxes.filter(function (c) { return c.checked; }).map(function (c) { return c.value; }), start: bs.value.trim(), end: be.value.trim() } }).then(function () { flash(t('saved')); }).catch(fail); }, 'pri')));
      v.appendChild(oc);
      // history
      // هشدارهای ارسال‌شده: جست‌وجو، فیلترِ وضعیت/پروفایل/شدت و صفحه‌بندی | sent alerts: search, status/profile/severity filters, paging
      var HI = arr(a.history), HF = { q: '', st: '', prof: '', sev: '', page: 0 }, HP = 25;
      var hc = card(t('history'));
      var hq = el('input', { type: 'search', placeholder: t('hiSearch') });
      var hst = el('select', null, el('option', { value: '', text: t('hiAllStatus') }), el('option', { value: 'ok', text: t('sent') }), el('option', { value: 'fail', text: t('failed') }));
      var hsv = el('select', null, el('option', { value: '', text: t('hiAllSev') }), el('option', { value: 'Critical', text: t('crit') }), el('option', { value: 'Warning', text: t('warn') }), el('option', { value: 'Info', text: t('info') }));
      var profs = {}; HI.forEach(function (h) { if (h.profile) profs[h.profile] = 1; });
      var hpf = el('select', null, el('option', { value: '', text: t('hiAllProf') }), Object.keys(profs).sort().map(function (p) { return el('option', { value: p, text: bilp(p) }); }));
      var hbox = el('div'), hinfo = el('span', { cls: 'muted' });
      function hdraw() {
        HF.q = hq.value.trim().toLowerCase(); HF.st = hst.value; HF.sev = hsv.value; HF.prof = hpf.value;
        var list = HI.filter(function (h) {
          if (HF.st === 'ok' && !h.ok) return false; if (HF.st === 'fail' && h.ok) return false;
          if (HF.sev && h.sev !== HF.sev) return false; if (HF.prof && h.profile !== HF.prof) return false;
          if (HF.q && [h.title, h.host, h.to, h.profile, h.err].join(' ').toLowerCase().indexOf(HF.q) < 0) return false;
          return true;
        });
        var pages = Math.max(1, Math.ceil(list.length / HP)); if (HF.page >= pages) HF.page = pages - 1;
        var rows = list.slice(HF.page * HP, HF.page * HP + HP).map(function (h) { return el('tr', null, el('td', { cls: 'num muted nw', text: String(h.t || '').replace('T', ' ').slice(0, 16) }), el('td', { text: bilp(h.profile) }), el('td', null, sevDot(h.sev), h.host), el('td', { cls: 'wrap', text: loc(h.title) }), el('td', { cls: 'mono', text: h.to }), el('td', null, h.ok ? pill('OK', t('sent')) : pill('Fail', t('failed'))), el('td', { cls: 'why', text: h.err || '' })); });
        if (!rows.length) rows = [emptyRow(7, HI.length ? t('hiNoMatch') : t('none'))];
        clear(hbox); hbox.appendChild(table([t('time'), t('profile'), t('host'), t('title'), t('recipients'), t('status'), ''], rows));
        var nOk = list.filter(function (h) { return h.ok; }).length;
        hinfo.textContent = t('hiCount').replace('{n}', list.length).replace('{ok}', nOk).replace('{bad}', list.length - nOk);
        hbox.appendChild(el('div', { cls: 'pager' },
          btn('‹', function () { if (HF.page > 0) { HF.page--; hdraw(); } }, 'sm'), (HF.page + 1) + ' / ' + pages,
          btn('›', function () { if (HF.page < pages - 1) { HF.page++; hdraw(); } }, 'sm')));
      }
      [hst, hsv, hpf].forEach(function (s) { s.addEventListener('change', function () { HF.page = 0; hdraw(); }); });
      hq.addEventListener('input', function () { HF.page = 0; hdraw(); });
      hc.appendChild(el('div', { cls: 'fbar' }, hq, hst, hsv, hpf, hinfo));
      hc.appendChild(hbox); hdraw(); v.appendChild(hc);
      // هشدارهای بی‌صداشده (از دکمهٔ «بی‌صدا» در رخدادها) | muted alerts (from the Mute button on incidents)
      var mc = card(t('mutedTitle')); var mb = el('div'); mc.appendChild(el('p', { cls: 'muted', text: t('mutedLead') })); mc.appendChild(mb); v.appendChild(mc);
      function loadMutes() { api('/api/alerts/mutes').then(function (x) {
        clear(mb);
        var rows = arr(x.items).map(function (m0) { return el('tr', null, el('td', { text: m0.host === '*' ? t('muteAllHosts') : m0.host }), el('td', { text: m0.title || m0.cat }), el('td', { cls: 'num muted', text: m0.until ? fmtT(m0.until) : t('muteForever') }), el('td', { cls: 'muted', text: m0.by || '' }),
          el('td', null, btn('🔔 ' + t('unmute'), function () { api('/api/alerts/mutes', { remove: true, host: m0.host, cat: m0.cat, title: m0.rawTitle }).then(loadMutes).catch(fail); }, 'sm'))); });
        if (!rows.length) rows = [emptyRow(5, t('mutedNone'))];
        mb.appendChild(table([t('host'), t('title'), t('until'), t('by'), ''], rows));
      }).catch(fail); }
      loadMutes();
      alTabs = tabify(v, 'alerts', [['profiles', 'tbProfiles', [pc]], ['smtp', 'tbSmtp', [sc]], ['options', 'tbOptions', [oc]], ['sent', 'tbSent', [hc]], ['muted', 'tbMuted', [mc]]]);
    }).catch(fail);
  }
  // دسته‌بندیِ ساده برای ساختِ پروفایلِ هشدار | plain-language templates for a new alert
  var ALERT_TEMPLATES = [
    { id: 't-critical', icon: '🔴', cats: [], sev: 'Critical', kw: [], dv: 'instant', nameKey: 'tplCriticalN', descKey: 'tplCriticalD' },
    { id: 't-logon', icon: '🔑', cats: ['BruteForce', 'Guard'], sev: 'Warning', kw: [], dv: 'instant', nameKey: 'tplLogonN', descKey: 'tplLogonD' },
    { id: 't-admin', icon: '👑', cats: ['ActiveDirectory'], sev: 'Warning', kw: ['Admins', 'Administrators', 'Operators', 'SENSITIVE'], dv: 'instant', nameKey: 'tplAdminN', descKey: 'tplAdminD' },
    { id: 't-malware', icon: '🦠', cats: ['Defender'], sev: 'Warning', kw: [], dv: 'instant', nameKey: 'tplMalwareN', descKey: 'tplMalwareD' },
    { id: 't-ransom', icon: '🔒', cats: ['Ransomware', 'MassFile'], sev: 'Warning', kw: [], dv: 'instant', nameKey: 'tplRansomN', descKey: 'tplRansomD' },
    { id: 't-tamper', icon: '🧹', cats: ['Tamper'], sev: 'Warning', kw: [], dv: 'instant', nameKey: 'tplTamperN', descKey: 'tplTamperD' },
    { id: 't-adattack', icon: '🎯', cats: ['ADAttack', 'Correlation'], sev: 'Warning', kw: [], dv: 'instant', nameKey: 'tplAdAttackN', descKey: 'tplAdAttackD' },
    { id: 't-files', icon: '📄', cats: ['FIM', 'FileSuspicion', 'FileACL'], sev: 'Warning', kw: [], dv: 'digest', dm: 60, nameKey: 'tplFilesN', descKey: 'tplFilesD' },
    { id: 't-server', icon: '🖥', cats: ['MemberServer', 'Behavior', 'GPO', 'Firewall'], sev: 'Warning', kw: [], dv: 'digest', dm: 60, nameKey: 'tplServerN', descKey: 'tplServerD' },
    { id: 't-vuln', icon: '🩹', cats: ['Vulnerability', 'Policy', 'EndpointHealth'], sev: 'Warning', kw: [], dv: 'digest', dm: 1440, nameKey: 'tplVulnN', descKey: 'tplVulnD' },
    { id: 't-net', icon: '🌐', cats: ['Network'], sev: 'Warning', kw: [], dv: 'digest', dm: 60, nameKey: 'tplNetN', descKey: 'tplNetD' },
    { id: 't-custom', icon: '⚙️', custom: true, nameKey: 'tplCustomN', descKey: 'tplCustomD' }
  ];
  function profileDrawer(p) {
    var isNew = !p;
    p = p || { name: '', enabled: true, categories: [], minSeverity: 'Critical', hosts: [], keywords: [], recipients: [], throttleMinutes: 15, businessHours: 'any', delivery: 'instant', digestMinutes: 60 };
    openDrawer(function (d) {
      drawerHead(d, isNew ? t('newProfile') : t('edit') + ': ' + bil(p.name));
      // ---- advanced fields (built first so templates can fill them) ----
      var nm = inp(t('alProfileNamePh'), 'text', p.name || ''), en = el('input', { type: 'checkbox', checked: p.enabled !== false });
      var ms = el('select'); [['Critical', 'crit'], ['Warning', 'warn'], ['Info', 'info']].forEach(function (o) { ms.appendChild(el('option', { value: o[0], text: t(o[1]) + '+', selected: p.minSeverity === o[0] ? 'selected' : null })); });
      var cb = el('div', { cls: 'checks' }); var sel = arr(p.categories);
      var boxes = S.cats.map(function (c) { var x = el('input', { type: 'checkbox', value: c.key, checked: sel.indexOf(c.key) >= 0 }); cb.appendChild(el('label', null, x, ' ', c.title)); return x; });
      var kw = inp('', 'text', arr(p.keywords).join(', '));
      var th = el('input', { type: 'number', value: p.throttleMinutes || 15, style: 'width:120px' });
      var bh = el('select'); [['any', 'bhAny'], ['inside', 'bhIn'], ['outside', 'bhOut']].forEach(function (o) { bh.appendChild(el('option', { value: o[0], text: t(o[1]), selected: p.businessHours === o[0] ? 'selected' : null })); });
      // ---- systems picker (chips; default = all) ----
      var hostList = arr(p.hosts).slice(), hostWrap = el('div');
      function drawHosts() {
        clear(hostWrap);
        var chips = el('div', { cls: 'chips' });
        if (!hostList.length) chips.appendChild(el('span', { cls: 'muted', text: t('alAllSystems') }));
        hostList.forEach(function (h, i) { chips.appendChild(el('span', { cls: 'chip on' }, h, ' ', el('a', { href: '#', cls: 'x', text: '✕', onclick: function (e) { e.preventDefault(); hostList.splice(i, 1); drawHosts(); } }))); });
        var dl = el('datalist', { id: 'alhosts' }); (S.alHostNames || []).forEach(function (n) { dl.appendChild(el('option', { value: n })); });
        var ipt = el('input', { type: 'text', placeholder: t('alAddSystemPh'), list: 'alhosts', style: 'min-width:160px' });
        function add() { var v = ipt.value.trim(); if (v && hostList.indexOf(v) < 0) { hostList.push(v); } ipt.value = ''; drawHosts(); }
        ipt.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); add(); } });
        hostWrap.appendChild(chips); hostWrap.appendChild(el('div', { cls: 'row', style: 'margin-top:6px' }, ipt, dl, btn(t('add'), add, 'sm')));
      }
      drawHosts();
      if (!S.alHostNames) { api('/api/sources').then(function (r) { S.alHostNames = arr(r.items).map(function (x) { return x.name; }); drawHosts(); }).catch(function () { S.alHostNames = []; }); }
      // ---- recipients + delivery ----
      var rc = el('textarea', { rows: 2 }); rc.value = arr(p.recipients).join(', ');
      var defTo = (S.alDefaultTo || []).join(', ');
      var deliv = p.delivery === 'digest' ? ((p.digestMinutes || 60) >= 1440 ? 'daily' : 'hourly') : 'instant';
      var dvWrap = el('div', { cls: 'seg' });
      function drawDeliv() { clear(dvWrap); [['instant', 'dvInstantB'], ['hourly', 'dvHourlyB'], ['daily', 'dvDailyB']].forEach(function (o) { dvWrap.appendChild(el('button', { type: 'button', cls: deliv === o[0] ? 'on' : '', text: t(o[1]), onclick: function () { deliv = o[0]; drawDeliv(); } })); }); }
      drawDeliv();

      // ---- STEP 1: what to alert on (templates) ----
      var chosenTpl = null;
      var advBox = el('div', { hidden: true });
      var tplGrid = el('div', { cls: 'tplgrid' });
      function applyTpl(tpl) {
        chosenTpl = tpl;
        Array.prototype.forEach.call(tplGrid.children, function (ch) { ch.classList.toggle('on', ch._tid === tpl.id); });
        if (tpl.custom) { advBox.hidden = false; if (!nm.value) nm.value = ''; return; }
        advBox.hidden = true;
        boxes.forEach(function (b) { b.checked = tpl.cats.indexOf(b.value) >= 0; });
        ms.value = tpl.sev; kw.value = (tpl.kw || []).join(', ');
        if (isNew || !nm.value) nm.value = t(tpl.nameKey);
        deliv = tpl.dv === 'digest' ? ((tpl.dm || 60) >= 1440 ? 'daily' : 'hourly') : 'instant'; drawDeliv();
      }
      ALERT_TEMPLATES.forEach(function (tpl) {
        var card2 = el('div', { cls: 'tpl' }, el('div', { cls: 'tpi', text: tpl.icon }), el('div', null, el('div', { cls: 'tpn', text: t(tpl.nameKey) }), el('div', { cls: 'tpd', text: t(tpl.descKey) })));
        card2._tid = tpl.id; card2.onclick = function () { applyTpl(tpl); };
        tplGrid.appendChild(card2);
      });
      d.appendChild(el('h4', { text: '1 · ' + t('alWhat') }));
      d.appendChild(tplGrid);

      // advanced (categories / severity / keywords) — shown for custom or on expand
      advBox.appendChild(el('div', { cls: 'form' },
        el('label', { text: t('cat') }), cb, el('div', { cls: 'hint', text: t('alCatHint') }),
        el('label', { text: t('minSev') }), ms, el('div', { cls: 'hint', text: t('alSevHint') }),
        el('label', { text: t('alKeywords') }), kw, el('div', { cls: 'hint', text: t('alKwHint') })));
      var advToggle = el('a', { href: '#', cls: 'advlink', text: t('alAdvShow'), onclick: function (e) { e.preventDefault(); advBox.hidden = !advBox.hidden; advToggle.textContent = advBox.hidden ? t('alAdvShow') : t('alAdvHide'); } });
      d.appendChild(advToggle); d.appendChild(advBox);

      // ---- STEP 2: recipients ----
      d.appendChild(el('h4', { text: '2 · ' + t('alWho') }));
      d.appendChild(el('div', { cls: 'form' }, el('label', { text: t('recipients') }), rc, el('div', { cls: 'hint', text: defTo ? (t('alDefaultTo') + ': ' + defTo) : t('commaHint') })));

      // ---- STEP 3: how ----
      d.appendChild(el('h4', { text: '3 · ' + t('alHow') }));
      d.appendChild(el('div', null, dvWrap, el('div', { cls: 'hint', text: t('alDelivHint') })));

      // ---- name + filters ----
      d.appendChild(el('h4', { text: '4 · ' + t('alName') }));
      var sysDet = el('details', { cls: 'moredet' }, el('summary', { text: t('alMoreFilters') }),
        el('div', { cls: 'form', style: 'margin-top:8px' },
          el('label', { text: t('alSystems') }), hostWrap, el('div', { cls: 'hint', text: t('alSystemsHint') }),
          el('label', { text: t('bh') }), bh, el('div', { cls: 'hint', text: t('alBhHint') }),
          el('label', { text: t('throttle') }), th, el('div', { cls: 'hint', text: t('alThrottleHint') })));
      d.appendChild(el('div', { cls: 'form' }, el('label', { text: t('name') }), nm, el('label', null, en, ' ', t('enabled'))));
      d.appendChild(sysDet);

      // preselect template when editing
      if (!isNew) {
        var match = ALERT_TEMPLATES.filter(function (x) { return !x.custom && x.cats.length === arr(p.categories).length && x.cats.every(function (c) { return arr(p.categories).indexOf(c) >= 0; }); })[0];
        if (match) { Array.prototype.forEach.call(tplGrid.children, function (ch) { ch.classList.toggle('on', ch._tid === match.id); }); chosenTpl = match; }
        else { var cst = ALERT_TEMPLATES[ALERT_TEMPLATES.length - 1]; chosenTpl = cst; Array.prototype.forEach.call(tplGrid.children, function (ch) { ch.classList.toggle('on', ch._tid === cst.id); }); advBox.hidden = false; advToggle.textContent = t('alAdvHide'); }
      }

      d.appendChild(el('div', { cls: 'acts', style: 'margin-top:16px' },
        btn(t('save'), function (e) {
          if (!chosenTpl) { fail(new Error(t('alPickWhat'))); return; }
          if (!splitList(rc.value).length && !(S.alDefaultTo || []).length) { fail(new Error(t('alNeedTo'))); return; }
          var cats = boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
          var dmv = deliv === 'daily' ? 1440 : 60;
          e.target.disabled = true;
          api('/api/alerts/profile', { id: p.id || '', delivery: deliv === 'instant' ? 'instant' : 'digest', digestMinutes: dmv,
            name: nm.value.trim() || (chosenTpl && !chosenTpl.custom ? t(chosenTpl.nameKey) : t('newProfile')), enabled: en.checked,
            recipients: splitList(rc.value), minSeverity: ms.value, categories: cats, hosts: hostList, keywords: splitList(kw.value),
            throttleMinutes: +th.value || 15, businessHours: bh.value })
            .then(function () { flash(t('saved')); closeDrawer(); vAlerts(); }).catch(function (er) { e.target.disabled = false; fail(er); });
        }, 'pri'),
        p.id ? btn(t('remove'), function () { if (!window.confirm(t('delProfile'))) return; api('/api/alerts/profile/delete', { id: p.id }).then(function () { closeDrawer(); vAlerts(); }).catch(fail); }, 'danger') : null));
    });
  }

  // ---------------- sources
  var srcTab = 'list';
  // «منابع» دیگر صفحهٔ جدا نیست: فهرست → سیستم‌ها، افزودن → افزودنِ سیستم، اعتبارنامه → تنظیمات
  function vSources(sub) {
    if (sub && sub[0]) srcTab = sub[0];
    var to = srcTab === 'list' ? 'computers' : (srcTab === 'cred' ? 'agentcfg' : 'deploy/' + (({ win: 'single', ad: 'domain' })[srcTab] || 'other'));
    srcTab = 'list'; go(to);
  }
  function kindLabel(s) { var k = s.kind; if (k === 'NetworkDevice') return (s.deviceType || 'Device'); if (k === 'Linux') return 'Linux'; if (k === 'Service') return t('kService'); return 'Windows'; }
  function srcDrawer(s, all) {
    openDrawer(function (d) {
      drawerHead(d, el('span', null, s.name, ' ', statusPill(s.status)));
      d.appendChild(el('div', { cls: 'kv' }, el('div', { cls: 'k', text: t('kind') }), el('div', null, kindLabel(s), arr(s.roles).map(function (x) { return el('span', { cls: 'chip', text: x }); })),
        el('div', { cls: 'k', text: t('address') }), el('div', { cls: 'mono', text: s.address || s.name }), el('div', { cls: 'k', text: t('monitor') }), el('div', { text: s.monitor }),
        s.os ? [el('div', { cls: 'k', text: t('os') }), el('div', { text: s.os })] : null, arr(s.ports).length ? [el('div', { cls: 'k', text: t('ports') }), el('div', { cls: 'mono', text: arr(s.ports).join(', ') })] : null,
        el('div', { cls: 'k', text: t('cred') }), el('div', { text: s.hasCred ? t('hasCred') : t('noCred') }), s.notes ? [el('div', { cls: 'k', text: t('notes') }), el('div', { text: s.notes })] : null));
      d.appendChild(el('h4', { text: t('testResult') }));
      d.appendChild(chanTable(s.channels));
      var acts = el('div', { cls: 'acts', style: 'margin-top:10px' },
        btn(t('testNow'), function (e) { var b = e.target; b.disabled = true; b.textContent = t('loading'); api('/api/sources/test', { names: [s.address || s.name] }).then(function () { return api('/api/sources'); }).then(function (r) { var n = arr(r.items).filter(function (x) { return x.name === s.name; })[0]; if (n) srcDrawer(n, r); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'pri'),
        btn(s.enabled ? t('disable') : t('enable'), function () { api('/api/sources/enable', { name: s.name, enabled: !s.enabled }).then(function () { closeDrawer(); vSources(); }).catch(fail); }),
        btn(t('remove'), function () { if (!window.confirm(t('confirmRemove'))) return; api('/api/sources/remove', { name: s.name }).then(function () { closeDrawer(); vSources(); }).catch(fail); }, 'danger'));
      d.appendChild(acts);
      // credential
      d.appendChild(el('h4', { text: t('setCred') }));
      var cu = el('input', { type: 'text', placeholder: 'DOMAIN\\user' }), cp = el('input', { type: 'password', autocomplete: 'new-password' });
      d.appendChild(el('div', { cls: 'row' }, cu, cp, btn(t('save'), function () { api('/api/sources/cred', { name: s.name, user: cu.value.trim(), password: cp.value }).then(function () { flash(t('saved')); closeDrawer(); vSources(); }).catch(fail); }, 'pri'),
        s.hasCred ? btn(t('clearCred'), function () { api('/api/sources/cred', { name: s.name, clear: true }).then(function () { closeDrawer(); vSources(); }).catch(fail); }) : null));
      // custom logs on this source
      d.appendChild(el('h4', { text: t('existingCustom') }));
      var cr = arr(s.custom).map(function (c) { return el('tr', null, el('td', { text: c.name }), el('td', { cls: 'mono', text: c.type === 'File' ? c.path : c.log }), el('td', { cls: 'mono', text: arr(c.ids).join(',') }), el('td', { text: arr(c.keywords).join(', ') }), el('td', null, sevDot(c.severity), sevName(c.severity)), el('td', null, btn(t('remove'), function () { api('/api/sources/custom/remove', { target: s.name, id: c.id }).then(function () { closeDrawer(); vSources(); }).catch(fail); }, 'sm danger'))); });
      if (!cr.length) cr = [emptyRow(6)];
      d.appendChild(table([t('name'), t('log'), 'ID', t('keywords'), t('sev'), ''], cr));
      d.appendChild(el('div', { style: 'margin-top:8px' }, btn('+ ' + t('tabCustom'), function () { srcTab = 'custom'; S.customTarget = s.name; closeDrawer(); vSources(); })));
    });
  }
  function testBox(res) {
    var c = card(t('testResult')); c.appendChild(chanTable(res)); return c;
  }
  function roleChecks(sel) {
    var box = el('div', { cls: 'checks' }); var list = ['DC', 'SQL', 'IIS', 'FTP', 'DHCP', 'Apache', 'File'];
    var boxes = list.map(function (r) { var c = el('input', { type: 'checkbox', value: r, checked: arr(sel).indexOf(r) >= 0 }); box.appendChild(el('label', null, c, ' ', r)); return c; });
    return { node: box, val: function () { return boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; }); } };
  }
  function addResult(holder, r) {
    clear(holder);
    holder.appendChild(el('div', { cls: 'flash ok', text: t('added') + ': ' + r.name + (arr(r.roles).length ? ' · ' + arr(r.roles).join(', ') : '') }));
    if (arr(r.syslogHint).length) { var h = card(t('syslogHint')); h.appendChild(el('div', { cls: 'code', text: arr(r.syslogHint).join('\n') })); holder.appendChild(h); }
    holder.appendChild(testBox(r.test));
  }
  function srcWin(body) {
    var c = card(t('tabWin'));
    var nm = el('input', { type: 'text', placeholder: 'SRV01' }), ad = el('input', { type: 'text', placeholder: 'SRV01.corp.local / 192.168.1.20' });
    var rl = roleChecks([]); var det = el('input', { type: 'checkbox', checked: true });
    var mon = el('select'); [['remote', 'monRemote'], ['agent', 'monAgent'], ['none', 'monNone']].forEach(function (o) { mon.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
    var cu = el('input', { type: 'text', placeholder: 'DOMAIN\\user  ' }), cp = el('input', { type: 'password', autocomplete: 'new-password' }), nt = el('input', { type: 'text' });
    c.appendChild(el('div', { cls: 'form' }, el('label', { text: t('name') }), nm, el('label', { text: t('address') }), ad, el('label', { text: t('roles') }), rl.node, el('label', null, ''), el('label', null, det, ' ', t('detectRoles')),
      el('label', { text: t('monitor') }), mon, el('label', { text: t('credOptional') }), el('div', { cls: 'row' }, cu, cp), el('label', { text: t('notes') }), nt));
    var out = el('div');
    c.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('add') + ' + ' + t('test'), function (e) {
      var b = e.target; b.disabled = true; b.textContent = t('loading');
      api('/api/sources/add', { kind: 'Windows', name: nm.value.trim(), address: ad.value.trim(), roles: rl.val(), detectRoles: det.checked, monitor: mon.value, user: cu.value.trim(), password: cp.value, notes: nt.value })
        .then(function (r) { b.disabled = false; b.textContent = t('add') + ' + ' + t('test'); addResult(out, r); }).catch(function (er) { b.disabled = false; b.textContent = t('add') + ' + ' + t('test'); fail(er); });
    }, 'pri')));
    body.appendChild(el('p', { cls: 'lead', text: t('srcLead') })); body.appendChild(c); body.appendChild(out);
  }
  function srcNet(body) {
    body.appendChild(el('p', { cls: 'lead', text: t('netLead') }));
    var c = card(t('tabNet'));
    var nm = el('input', { type: 'text', placeholder: 'CoreSwitch' }), ad = el('input', { type: 'text', placeholder: '192.168.1.2' });
    var dt = el('select'); ['Switch', 'Router', 'Firewall', 'AccessPoint', 'NVR', 'Printer', 'UPS', 'Storage', 'Other'].forEach(function (x) { dt.appendChild(el('option', { value: x, text: x })); });
    var pt = el('input', { type: 'text', placeholder: '22, 443, 8291' });
    c.appendChild(el('div', { cls: 'form' }, el('label', { text: t('name') }), nm, el('label', { text: t('address') }), ad, el('label', { text: t('devType') }), dt, el('label', { text: t('extraPorts') }), pt));
    var out = el('div');
    c.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('add') + ' + ' + t('test'), function (e) {
      var b = e.target; b.disabled = true;
      api('/api/sources/add', { kind: 'NetworkDevice', name: nm.value.trim(), address: ad.value.trim(), deviceType: dt.value, ports: splitList(pt.value) }).then(function (r) { b.disabled = false; addResult(out, r); }).catch(function (er) { b.disabled = false; fail(er); });
    }, 'pri')));
    body.appendChild(c); body.appendChild(out);
  }
  function srcSvc(body) {
    body.appendChild(el('p', { cls: 'lead', text: t('svcLead') }));
    var c = card(t('tabSvc'));
    var nm = el('input', { type: 'text', placeholder: 'MaliBook-API' }), ad = el('input', { type: 'text', placeholder: '192.168.1.30' });
    var kd = el('select'); [['Service', 'kService'], ['Linux', 'kLinux']].forEach(function (o) { kd.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
    var pt = el('input', { type: 'text', placeholder: '8090, 443' }), nt = el('input', { type: 'text' });
    c.appendChild(el('div', { cls: 'form' }, el('label', { text: t('name') }), nm, el('label', { text: t('address') }), ad, el('label', { text: t('svcKind') }), kd, el('label', { text: t('ports') }), pt, el('label', { text: t('notes') }), nt));
    var out = el('div');
    c.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('add') + ' + ' + t('test'), function (e) {
      var b = e.target; b.disabled = true;
      api('/api/sources/add', { kind: kd.value, name: nm.value.trim(), address: ad.value.trim(), ports: splitList(pt.value), notes: nt.value }).then(function (r) { b.disabled = false; addResult(out, r); }).catch(function (er) { b.disabled = false; fail(er); });
    }, 'pri')));
    body.appendChild(c); body.appendChild(out);
  }
  function srcCustom(body) {
    body.appendChild(el('p', { cls: 'lead', text: t('customLead') }));
    body.appendChild(spinner());
    api('/api/sources').then(function (r) {
      clear(body); body.appendChild(el('p', { cls: 'lead', text: t('customLead') }));
      var c = card(t('tabCustom'));
      var tg = el('select'); tg.appendChild(el('option', { value: '__self__', text: t('thisServer') }));
      arr(r.items).filter(function (s) { return s.kind === 'Windows'; }).forEach(function (s) { tg.appendChild(el('option', { value: s.name, text: s.name, selected: S.customTarget === s.name ? 'selected' : null })); });
      var ty = el('select'); [['EventLog', 'cEvent'], ['File', 'cFile']].forEach(function (o) { ty.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
      var dl = el('datalist', { id: 'chanlist' });
      var lg = el('input', { type: 'text', list: 'chanlist', placeholder: 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', style: 'width:100%' });
      var ids = el('input', { type: 'text', placeholder: '21, 24, 25' }), pth = el('input', { type: 'text', placeholder: 'D:\\App\\logs\\app.log', style: 'width:100%' });
      var nm = el('input', { type: 'text' }), kw = el('input', { type: 'text', placeholder: 'error, failed, denied' });
      var sv = el('select'); [['Warning', 'warn'], ['Critical', 'crit'], ['Info', 'info']].forEach(function (o) { sv.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
      var al = el('input', { type: 'checkbox', checked: true });
      var evRow = [el('label', { text: t('channelName') }), el('div', null, lg, dl, el('div', { style: 'margin-top:6px' }, btn(t('loadChannels'), function (e) {
        var b = e.target; b.disabled = true; var h = tg.value === '__self__' ? 'localhost' : (arr(r.items).filter(function (s) { return s.name === tg.value; })[0] || {}).address || tg.value;
        api('/api/sources/channels?host=' + encodeURIComponent(h)).then(function (x) { b.disabled = false; clear(dl); arr(x.items).forEach(function (i) { dl.appendChild(el('option', { value: i.name })); }); flash(arr(x.items).length + ' ' + t('results')); }).catch(function (er) { b.disabled = false; fail(er); });
      }, 'sm'))), el('label', { text: t('ids') }), ids];
      var fileRow = [el('label', { text: t('path') }), pth];
      var form = el('div', { cls: 'form' });
      function draw() { clear(form); add(form, [el('label', { text: t('onSource') }), tg, el('label', { text: t('cType') }), ty]); add(form, ty.value === 'File' ? fileRow : evRow); add(form, [el('label', { text: t('name') }), nm, el('label', { text: t('keywords') }), kw, el('div', { cls: 'hint', text: t('commaHint') }), el('label', { text: t('sev') }), sv, el('label', null, ''), el('label', null, al, ' ', t('alertOn'))]); }
      ty.addEventListener('change', draw); draw();
      c.appendChild(form);
      c.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('add'), function (e) {
        var b = e.target; b.disabled = true;
        api('/api/sources/custom', { target: tg.value, type: ty.value, log: lg.value.trim(), path: pth.value.trim(), ids: splitList(ids.value), keywords: splitList(kw.value), name: nm.value.trim(), severity: sv.value, alert: al.checked })
          .then(function () { b.disabled = false; flash(t('saved')); srcCustom(clear(body)); }).catch(function (er) { b.disabled = false; fail(er); });
      }, 'pri')));
      body.appendChild(c);
      var lc = card(t('existingCustom'));
      var rows = [];
      arr(r.items).forEach(function (s) { arr(s.custom).forEach(function (cx) { rows.push(el('tr', null, el('td', { text: s.name }), el('td', { text: cx.name }), el('td', { cls: 'mono', text: cx.type === 'File' ? cx.path : cx.log }), el('td', { cls: 'mono', text: arr(cx.ids).join(',') }), el('td', { text: arr(cx.keywords).join(', ') }), el('td', null, sevDot(cx.severity), sevName(cx.severity)), el('td', null, btn(t('remove'), function () { api('/api/sources/custom/remove', { target: s.name, id: cx.id }).then(function () { srcCustom(clear(body)); }).catch(fail); }, 'sm danger')))); }); });
      if (!rows.length) rows = [emptyRow(7)];
      lc.appendChild(table([t('onSource'), t('name'), t('log'), 'ID', t('keywords'), t('sev'), ''], rows));
      body.appendChild(lc);
    }).catch(function (e) { clear(body); fail(e); });
  }
  function srcCred(body) {
    body.appendChild(el('p', { cls: 'lead', text: t('credLead') }));
    api('/api/sources').then(function (r) {
      var c = card(t('defCred'), el('span', { cls: 'muted', text: r.hasDefaultCred ? '🔑 ' + t('hasCred') : t('noCred') }));
      var cu = el('input', { type: 'text', placeholder: 'DOMAIN\\svc_logbok' }), cp = el('input', { type: 'password', autocomplete: 'new-password' });
      c.appendChild(el('div', { cls: 'row' }, cu, cp, btn(t('save'), function () { api('/api/sources/cred', { name: '_default', user: cu.value.trim(), password: cp.value }).then(function () { flash(t('saved')); vSources(); }).catch(fail); }, 'pri'),
        r.hasDefaultCred ? btn(t('clearCred'), function () { api('/api/sources/cred', { name: '_default', clear: true }).then(function () { vSources(); }).catch(fail); }) : null));
      body.appendChild(c);
    }).catch(fail);
  }

  // ---------------- guard
  // سپرِ ورودِ همین سرور (IPهای مسدود، لیستِ سفید/سیاه) — در «حفاظت › سپرِ ورود» کنارِ پروفایل‌های سیستم‌ها
  // the LogBok server's own login guard; shown under Protect › Login guard next to the per-computer profiles
  function guardInto(host) {
    var v = el('div'); host.appendChild(v); v.appendChild(spinner());
    api('/api/guard').then(function (g) {
      clear(v); v.appendChild(el('h3', { cls: 'sech', text: t('guardThisServer') }));
      var st = g.status;
      v.appendChild(el('div', { cls: 'kpis' }, [[st.blocked, t('blockedNow'), 'var(--crit)'], [st.permanent, t('permanent'), null], [st.watching, t('watching'), 'var(--warn)'], [st.rules, t('rules'), 'var(--mint)']].map(function (k) { return el('div', { cls: 'kpi' }, el('div', { cls: 'v num', style: k[2] ? 'color:' + k[2] : null, text: k[0] }), el('div', { cls: 'l', text: k[1] })); })));
      var ip = el('input', { type: 'text', placeholder: '203.0.113.5' }), mn = el('input', { type: 'number', placeholder: t('minutes'), style: 'width:170px' });
      var bc = card(t('blockedNow'), el('span', { cls: 'row' }, ip, mn, btn(t('block'), function () { api('/api/guard', { op: 'block', value: ip.value.trim(), minutes: +mn.value || 0 }).then(function () { flash(t('saved')); vEndpoints(); }).catch(fail); }, 'danger sm')));
      var rows = arr(g.blocks).map(function (b) { return el('tr', null, el('td', { cls: 'mono', text: b.ip }), el('td', { text: b.country || '-' }), el('td', { cls: 'muted', text: b.reason + ' · ' + b.source }), el('td', { cls: 'num muted nw', text: String(b.since || '').replace('T', ' ').slice(0, 16) }), el('td', { cls: 'num nw', text: b.until === 'permanent' ? t('permanent') : String(b.until || '').replace('T', ' ').slice(0, 16) }), el('td', { cls: 'num', text: b.count }), el('td', { text: b.users }), el('td', null, btn(t('unblock'), function () { api('/api/guard', { op: 'unblock', value: b.ip }).then(function () { vEndpoints(); }).catch(fail); }, 'sm'))); });
      if (!rows.length) rows = [emptyRow(8)];
      bc.appendChild(table([t('ip'), t('country'), t('reasonCol'), t('since'), t('until'), t('count'), t('usersTried'), ''], rows));
      v.appendChild(bc);
      function listCard(kind, items) {
        var inp = el('input', { type: 'text', placeholder: 'IP / CIDR / a-b' });
        var c = card(t(kind), el('span', { cls: 'row' }, inp, btn(t('add'), function () { api('/api/guard', { op: (kind === 'whitelist' ? 'white' : 'black') + '-add', value: inp.value.trim() }).then(function () { vEndpoints(); }).catch(fail); }, 'sm')));
        var r = arr(items).map(function (x) { return el('tr', null, el('td', { cls: 'mono', text: x }), el('td', null, btn(t('remove'), function () { api('/api/guard', { op: (kind === 'whitelist' ? 'white' : 'black') + '-remove', value: x }).then(function () { vEndpoints(); }).catch(fail); }, 'sm'))); });
        if (!r.length) r = [emptyRow(2)];
        c.appendChild(table([t('ip'), ''], r)); return c;
      }
      v.appendChild(el('div', { cls: 'cols' }, listCard('whitelist', g.whitelist), listCard('blacklist', g.blacklist)));
      var s = g.settings; var sc = card(t('guardSettings'), btn(t('editInSettings'), function () { go('settings'); }, 'sm'));
      sc.appendChild(el('div', { cls: 'kv' },
        el('div', { cls: 'k', text: t('gMax') }), el('div', { text: s.maxFailed + ' / ' + s.window + ' min' }), el('div', { cls: 'k', text: t('gBlock') }), el('div', { text: s.block + ' min · ×' + s.factor + ' · ' + t('gPerm') + ' ' + s.permanentAfter }),
        el('div', { cls: 'k', text: t('gGeo') }), el('div', { text: s.geo }),
        el('div', { cls: 'k', text: 'Protect' }), el('div', null, [['RDP', s.rdp], ['Logon', s.logon], ['SQL', s.sql], ['FTP', s.ftp], ['Web', s.web], ['SSH', s.ssh]].map(function (p) { return el('span', { cls: 'chip' + (p[1] ? ' on' : ''), text: (p[1] ? '✓ ' : '✕ ') + p[0] }); }))));
      v.appendChild(sc);
    }).catch(fail);
  }

  // ---------------- connections
  function vConnections() {
    var v = page(t('connections'), t('connLead')); v.appendChild(spinner());
    api('/api/connectivity').then(function (c) {
      v = page(t('connections'), t('connLead'));
      var mc = card(t('mgmtPath'));
      var mr = arr(c.mgmt).map(function (m) { return el('tr', null, el('td', { style: 'width:18px' }, sevDot(m.enabled ? 'OK' : 'Fail')), el('td', { text: m.name }), el('td', { cls: 'mono', text: m.ports }), el('td', { cls: 'mono', text: m.remote }), el('td', { text: m.enabled ? t('active') : t('missing') })); });
      if (!mr.length) mr = [emptyRow(5)];
      mc.appendChild(table(['', t('channel'), t('ports'), t('from'), t('state')], mr)); v.appendChild(mc);
      v.appendChild(el('div', { cls: 'fbar' }, el('span', { cls: 'muted', text: t('lastTest') + ': ' + (String(c.generated || '').replace('T', ' ').slice(0, 16) || '—') }), btn(t('testAll'), function (e) { var b = e.target; b.disabled = true; b.textContent = t('loading'); api('/api/sources/test', {}).then(function () { vConnections(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'pri sm')));
      arr(c.targets).forEach(function (tg) {
        var k = card(tg.name + (tg.name !== tg.target ? ' (' + tg.target + ')' : ''), [tg.self ? el('span', { cls: 'chip', text: t('thisServer') }) : el('span', { cls: 'chip', text: tg.kind || 'Windows' }), arr(tg.roles).map(function (r) { return el('span', { cls: 'chip', text: r }); }), statusPill(tg.status)]);
        k.appendChild(chanTable(tg.channels)); v.appendChild(k);
      });
    }).catch(fail);
  }

  // ---------------- jobs
  function vJobs() {
    var v = page(t('jobs'), t('jobsLead')); v.appendChild(spinner());
    api('/api/jobs').then(function (j) {
      v = page(t('jobs'), t('jobsLead'));
      var rows = arr(j.items).map(function (x) { return el('tr', null, el('td', null, sevDot(!x.enabled ? 'Info' : (x.state === 'Missing' ? 'Fail' : (x.healthy ? 'OK' : 'Warn'))), x.name), el('td', { cls: 'muted', text: x.purpose }), el('td', { text: x.enabled ? x.state : 'off' }), el('td', { cls: 'num muted nw', text: x.last }), el('td', { cls: 'mono muted', text: x.code }), el('td', { cls: 'num muted nw', text: x.next }), el('td', null, x.enabled && x.state !== 'Missing' ? btn(t('runNow'), function (e) { var b = e.target; b.disabled = true; api('/api/jobs/run', { name: x.name }).then(function () { flash(t('started') + ': ' + x.name); setTimeout(vJobs, 3000); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'sm') : null)); });
      var c = card(t('jobs')); c.appendChild(table([t('name'), t('purpose'), t('state'), t('lastRun'), 'code', t('next'), ''], rows)); v.appendChild(c);
    }).catch(fail);
  }

  // ---------------- settings
  function vSettings() {
    var v = page(t('settings'), t('setLead')); v.appendChild(spinner());
    api('/api/settings').then(function (s) {
      v = page(t('settings'), t('setLead'));
      function save(obj, after) { api('/api/settings', obj).then(function (r) { flash(t('saved') + (r.restart ? ' — ' + t('webRestart') : '')); if (after) after(); }).catch(fail); }
      function sel(opts, val) { var x = el('select'); opts.forEach(function (o) { x.appendChild(el('option', { value: o[0], text: o[1], selected: String(val) === String(o[0]) ? 'selected' : null })); }); return x; }
      // general
      var lang = sel([['fa', 'فارسی'], ['en', 'English'], ['both', 'فارسی / English']], s.Language || 'both');
      var mode = sel([['Local', 'Local'], ['Collector', 'Collector (WEF)'], ['Remote', 'Remote']], s.CollectionMode);
      var col = el('input', { type: 'text', value: s.CollectorFqdn }), thr = el('input', { type: 'number', value: s.AlertThrottleMinutes || 15, style: 'width:110px' }), ret = el('input', { type: 'number', value: s.ArchiveRetentionDays, style: 'width:110px' });
      var g = card(t('general')); g.appendChild(el('div', { cls: 'form' }, el('label', { text: t('language') }), lang, el('label', { text: t('collMode') }), mode, el('label', { text: t('collector') }), col, el('label', { text: t('throttleAll') }), thr, el('label', { text: t('retention') }), ret));
      g.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function () { save({ Language: lang.value, CollectionMode: mode.value, CollectorFqdn: col.value.trim(), AlertThrottleMinutes: +thr.value || 15, ArchiveRetentionDays: +ret.value || 180 }, function () { if (lang.value !== s.Language) location.reload(); }); }, 'pri')));
      v.appendChild(g);
      // management
      var m = s.Management || {};
      var aips = el('input', { type: 'text', value: arr(m.AdminIPs).join(', '), placeholder: '192.168.1.10, 192.168.1.0/24' }), lan = el('input', { type: 'checkbox', checked: m.AllowFromLan });
      var rdp = el('input', { type: 'checkbox', checked: m.AllowRDP }), wrm = el('input', { type: 'checkbox', checked: m.AllowWinRM }), wef = el('input', { type: 'checkbox', checked: m.AllowWEF }), smb = el('input', { type: 'checkbox', checked: m.AllowSMB });
      var xp = el('input', { type: 'text', value: arr(m.ExtraPorts).join(', ') });
      var mc = card(t('mgmt')); mc.appendChild(el('div', { cls: 'form' }, el('label', { text: t('adminIps') }), aips, el('div', { cls: 'hint', text: t('commaHint') }), el('label', null, ''), el('label', null, lan, ' ', t('fromLan')),
        el('label', { text: t('ports') }), el('div', { cls: 'checks' }, el('label', null, wrm, ' WinRM 5985/5986'), el('label', null, rdp, ' RDP 3389'), el('label', null, wef, ' WEF'), el('label', null, smb, ' SMB 445')), el('label', { text: t('extraPorts') }), xp));
      mc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function () { save({ 'Management.AdminIPs': splitList(aips.value), 'Management.AllowFromLan': lan.checked, 'Management.AllowRDP': rdp.checked, 'Management.AllowWinRM': wrm.checked, 'Management.AllowWEF': wef.checked, 'Management.AllowSMB': smb.checked, 'Management.ExtraPorts': splitList(xp.value).map(Number).filter(Boolean) }); }, 'pri')));
      v.appendChild(mc);
      // guard
      var G = s.Guard || {};
      var gi = {}; [['MaxFailedAttempts', 'gMax'], ['AttemptWindowMinutes', 'gWin'], ['BlockMinutes', 'gBlock'], ['EscalationFactor', 'gFactor'], ['PermanentAfterBlocks', 'gPerm'], ['WebMaxFailures', 'gWeb']].forEach(function (k) { gi[k[0]] = [el('input', { type: 'number', value: G[k[0]], style: 'width:110px' }), k[1]]; });
      var geo = sel([['Off', 'Off'], ['AllowOnly', 'AllowOnly'], ['BlockListed', 'BlockListed']], G.GeoMode || 'Off');
      var gal = el('input', { type: 'text', value: arr(G.AllowedCountries).join(', ') }), gbl = el('input', { type: 'text', value: arr(G.BlockedCountries).join(', ') });
      var gc = card(t('guard')); var gf = el('div', { cls: 'form' });
      Object.keys(gi).forEach(function (k) { gf.appendChild(el('label', { text: t(gi[k][1]) })); gf.appendChild(gi[k][0]); });
      add(gf, [el('label', { text: t('gGeo') }), geo, el('label', { text: t('gAllowed') }), gal, el('label', { text: t('gBlocked') }), gbl]); gc.appendChild(gf);
      gc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function () { var o = {}; Object.keys(gi).forEach(function (k) { o['Guard.' + k] = +gi[k][0].value; }); o['Guard.GeoMode'] = geo.value; o['Guard.AllowedCountries'] = splitList(gal.value).map(function (x) { return x.toUpperCase(); }); o['Guard.BlockedCountries'] = splitList(gbl.value).map(function (x) { return x.toUpperCase(); }); save(o); }, 'pri')));
      v.appendChild(gc);
      // thresholds
      var T = s.Thresholds || {}; var ti = {};
      var tc = card(t('thresholds')); var tf = el('div', { cls: 'form' });
      Object.keys(T).forEach(function (k) { ti[k] = el('input', { type: 'number', value: T[k], style: 'width:110px' }); tf.appendChild(el('label', { cls: 'mono', text: k })); tf.appendChild(ti[k]); });
      tc.appendChild(tf); tc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function () { var o = {}; Object.keys(ti).forEach(function (k) { o['Thresholds.' + k] = +ti[k].value; }); save(o); }, 'pri')));
      v.appendChild(tc);
      // web
      var W = s.Web || {};
      var ls = sel([['local', t('lLocal')], ['lan', t('lLan')]], W.Listen || 'local'); var wp = el('input', { type: 'number', value: W.Port || 8686, style: 'width:110px' });
      var wc = card(t('web')); wc.appendChild(el('div', { cls: 'form' }, el('label', { text: t('listen') }), ls, el('label', { text: t('port') }), wp, el('div', { cls: 'hint', text: t('webRestart') })));
      wc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function () { save({ 'Web.Listen': ls.value, 'Web.Port': +wp.value || 8686 }); }, 'pri')));
      v.appendChild(wc);
      // jobs toggles
      var J = s.Jobs || {}; var jb = {};
      var jc = card(t('jobToggles')); var jw = el('div', { cls: 'checks' });
      Object.keys(J).forEach(function (k) { jb[k] = el('input', { type: 'checkbox', checked: J[k] }); jw.appendChild(el('label', null, jb[k], ' ', k)); });
      jc.appendChild(jw); jc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function () { var o = {}; Object.keys(jb).forEach(function (k) { if (jb[k].checked !== J[k]) o['Jobs.' + k] = jb[k].checked; }); save(o); }, 'pri')));
      v.appendChild(jc);
      // UBA — تحلیلِ رفتار (زمانی/اولین‌بار)
      var uc = card(t('ubaTitle')); uc.appendChild(spinner()); v.appendChild(uc);
      tabify(v, 'settings', [['general', 'tbGeneral', [g]], ['mgmt', 'tbMgmt', [mc]], ['guard', 'tbGuard', [gc]], ['thr', 'tbThresholds', [tc]], ['web', 'tbWeb', [wc]], ['jobs', 'tbJobs', [jc]], ['uba', 'tbUba', [uc]]]);
      api('/api/uba').then(function (U) {
        clear(uc); uc.appendChild(el('h3', { text: t('ubaTitle') }));
        var uen = el('input', { type: 'checkbox', checked: U.enabled !== false });
        uc.appendChild(el('label', null, uen, ' ' + t('ubaEnabled')));
        var uRules = { 'offhours-user': t('uba_offhours_user'), 'offhours-host': t('uba_offhours_host'), 'firsttime-host': t('uba_firsttime_host'), 'firsttime-remote': t('uba_firsttime_remote'), 'firsttime-proc': t('uba_firsttime_proc'), 'firsttime-priv': t('uba_firsttime_priv') };
        var mOpts = (U.modes || ['off', 'alert', 'ask', 'auto']).map(function (m) { return [m, m]; });
        var aOpts = (U.actions || ['none', 'blockip', 'disableuser', 'isolate']).map(function (a) { return [a, a]; });
        var uSel = {};
        var utb = el('tbody');
        Object.keys(uRules).forEach(function (r) {
          var rc = (U.rules && U.rules[r]) || { mode: 'alert', action: 'none' };
          var ms = sel(mOpts, rc.mode), as = sel(aOpts, rc.action);
          uSel[r] = { m: ms, a: as };
          utb.appendChild(el('tr', null, el('td', { text: uRules[r] }), el('td', null, ms), el('td', null, as)));
        });
        uc.appendChild(el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, el('th', { text: t('ubaRuleC') }), el('th', { text: t('ubaModeC') }), el('th', { text: t('ubaActC') }))), utb)));
        uc.appendChild(el('div', { cls: 'hint', text: t('ubaHint') }));
        uc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function () {
          var rules = {}; Object.keys(uSel).forEach(function (r) { rules[r] = { mode: uSel[r].m.value, action: uSel[r].a.value }; });
          api('/api/uba', { enabled: uen.checked, rules: rules }).then(function () { flash(t('saved')); }).catch(fail);
        }, 'pri')));
      }).catch(function () { clear(uc); uc.appendChild(el('div', { cls: 'hint', text: 'UBA' })); });
    }).catch(fail);
  }


  // ------------------------------------------------------------------ agents
  function download(url) { var a = el('a', { href: url, download: '' }); document.body.appendChild(a); a.click(); setTimeout(function () { if (a.parentNode) a.parentNode.removeChild(a); }, 1000); }
  var agTimer = null, agTab = '';
  S.ad = { server: '', user: '', password: '', domainId: '', domains: [] };
  try { S.ad.domainId = localStorage.getItem('lb.adDomain') || ''; } catch (e0) { }
  function adSetDomain(id) { S.ad.domainId = id || ''; try { localStorage.setItem('lb.adDomain', S.ad.domainId); } catch (e1) { } }
  function adBody(extra) { var o = {}; if (S.ad.domainId) { o.domainId = S.ad.domainId; } else { o.server = S.ad.server; if (S.ad.user && S.ad.password) { o.user = S.ad.user; o.password = S.ad.password; } } for (var k in (extra || {})) o[k] = extra[k]; return o; }
  function inp(ph, type, val) { return el('input', { type: type || 'text', placeholder: ph || '', value: val || '', autocomplete: type === 'password' ? 'new-password' : null }); }
  // «افزودنِ سیستم»: همهٔ راه‌های افزودن در یک صفحه | every way to add computers on one page
  var dpTab = 'single';
  function vAgents(sub) {
    if (sub && sub[0]) dpTab = sub[0];
    if (agTimer) { clearTimeout(agTimer); agTimer = null; }
    // سازگاری: agTab='status' یعنی «فهرستِ سیستم‌ها» | compat: callers that set agTab='status' want the list
    if (agTab === 'status' && !(sub && sub[0])) { agTab = ''; if (S.view === 'deploy') { go('computers'); return; } }
    if (agTab) { dpTab = ({ manual: 'package', push: 'single', ad: 'domain', wg: 'workgroup' })[agTab] || dpTab; agTab = ''; }
    if (S.view !== 'deploy') { go('deploy/' + dpTab); return; }
    var v = page(t('tAddComputers'), t('dpLead'));
    var tabs = el('div', { cls: 'tabs' });
    [['single', 'dpSingle'], ['domain', 'dpDomain'], ['workgroup', 'dpWorkgroup'], ['package', 'dpPackage'], ['other', 'dpOther']].forEach(function (x) {
      tabs.appendChild(el('button', { type: 'button', cls: dpTab === x[0] ? 'on' : '', text: t(x[1]), onclick: function () { dpTab = x[0]; try { history.replaceState(null, '', '#/deploy/' + x[0]); } catch (e) { } vAgents(); } }));
    });
    v.appendChild(tabs);
    var box = el('div'); v.appendChild(box); box.appendChild(spinner());
    api('/api/agents').then(function (r) {
      clear(box);
      if (dpTab === 'single') {
        // یک سیستم: دستورِ یک‌خطی (پیشنهادی)، نصب از راه دور، یا فقط خواندنِ لاگ
        var mode = S.dpSingle || 'oneline'; if (mode === 'remote' && !r.remotePush) mode = 'oneline'; var sw = el('div', { cls: 'seg' }), inner = el('div');
        function drawSingle() { clear(sw); [['oneline', 'dpOneLine']].concat(r.remotePush ? [['remote', 'dpRemotePush']] : []).concat([['read', 'dpRemoteOnly']]).forEach(function (m) { sw.appendChild(el('button', { type: 'button', cls: mode === m[0] ? 'on' : '', text: t(m[1]), onclick: function () { mode = m[0]; S.dpSingle = mode; drawSingle(); } })); }); clear(inner); if (mode === 'oneline') inner.appendChild(oneLineCard(r)); else if (mode === 'remote') agPush(inner, r); else srcWin(inner); }
        box.appendChild(sw); box.appendChild(el('p', { cls: 'lead', text: t('dpSingleHint') })); box.appendChild(inner); drawSingle(); box.appendChild(pushToggle(r));
      } else if (dpTab === 'other') {
        var kind = S.dpOther || 'net', sw2 = el('div', { cls: 'seg' }), inner2 = el('div');
        function drawOther() { clear(sw2); [['net', 'tabNet'], ['svc', 'tabSvc'], ['custom', 'tabCustom']].forEach(function (m) { sw2.appendChild(el('button', { type: 'button', cls: kind === m[0] ? 'on' : '', text: t(m[1]), onclick: function () { kind = m[0]; S.dpOther = kind; drawOther(); } })); }); clear(inner2); ({ net: srcNet, svc: srcSvc, custom: srcCustom })[kind](inner2); }
        box.appendChild(sw2); box.appendChild(inner2); drawOther();
      } else {
        ({ domain: agAd, workgroup: agWg, package: agManual }[dpTab] || agAd)(box, r);
      }
    }).catch(function (e) { clear(box); fail(e); });
  }
  // ---- Settings › Agents & backup: server address, package security, credentials, migration/backup
  function vAgentCfg() {
    var v = page(t('tAgentsBackup'), t('acLead'));
    var box = el('div'); v.appendChild(box); box.appendChild(spinner());
    api('/api/agents').then(function (r) {
      clear(box);
      var c1 = serverCard(r), c2 = enrollCard(r), cb = el('div'), c4 = migrationCard(r);
      box.appendChild(c1); box.appendChild(c2); box.appendChild(cb); srcCred(cb); box.appendChild(c4);
      tabify(box, 'agentcfg', [['server', 'tbServer', [c1]], ['sec', 'tbInstallSec', [c2]], ['cred', 'tbCreds', [cb]], ['backup', 'tbBackup', [c4]]]);
    }).catch(function (e) { clear(box); fail(e); });
  }
  // ---- Computers: ONE list of everything monitored (agent or not), one status, details in a drawer
  var CP = { filter: '', q: '' };
  // نسخهٔ ایجنت + نشانِ «قدیمی» اگر از نسخهٔ جاریِ سرور عقب باشد | agent version + "outdated" badge when behind the server's current build
  function agentVerCell(x) {
    var v = x.agent && x.agent.version ? String(x.agent.version) : '';
    if (!v) return el('span', { cls: 'muted', text: '—' });
    // ایجنتِ EXE شیوهٔ نسخه‌گذاریِ جدا دارد (native-*)؛ با نسخهٔ ایجنتِ پاورشلی مقایسه نمی‌شود
    // the EXE agent uses a separate version scheme (native-*); do not compare it to the PowerShell agent version
    if (v.indexOf('native-') === 0) {
      return el('span', { cls: 'nw' }, el('span', { cls: 'mono', text: v.slice(7) }),
        el('span', { cls: 'pill Info', style: 'margin-inline-start:6px', text: 'EXE' }));
    }
    var cur = S.meta && S.meta.agentVersion ? String(S.meta.agentVersion) : '';
    var old = cur && v !== cur;
    return el('span', { cls: 'nw' }, el('span', { cls: 'mono', text: v }),
      old ? el('span', { cls: 'pill Warn', style: 'margin-inline-start:6px', text: t('agOutdated') }) : null);
  }
  function vComputers() {
    if (agTimer) { clearTimeout(agTimer); agTimer = null; }
    var v = page(t('tComputerList'), t('cpLead'));
    var out = el('div'); v.appendChild(out); out.appendChild(spinner());
    var seq = 0;
    function load(quiet) {
      var my = ++seq; if (!quiet) { clear(out).appendChild(spinner()); }
      Promise.all([api('/api/agents'), api('/api/sources')]).then(function (res) {
        if (my !== seq || S.view !== 'computers') return;
        var ag = res[0], src = res[1], by = {}, list = [];
        function key(n) { return String(n || '').split('.')[0].toUpperCase(); }
        arr(src.items).forEach(function (s0) { var k = key(s0.name); by[k] = { name: s0.name, address: s0.address || '', src: s0, agent: null }; list.push(by[k]); });
        arr(ag.items).forEach(function (a) { var k = key(a.name); if (!by[k]) { by[k] = { name: a.name, address: a.address || '', src: null, agent: null }; list.push(by[k]); } by[k].agent = a; if (!by[k].address) by[k].address = a.address || ''; });
        var now = Date.now(), busy = false;
        list.forEach(function (x) {
          var a = x.agent, s0 = x.src, seen = a && a.lastSeen ? Date.parse(String(a.lastSeen).replace(' ', 'T')) : NaN, mins = isNaN(seen) ? null : Math.round((now - seen) / 60000);
          x.how = (a && a.approval) || (s0 && s0.monitor === 'agent') ? 'agent' : (s0 ? (s0.kind === 'NetworkDevice' || s0.kind === 'Linux' ? 'syslog' : (s0.kind === 'Service' ? 'service' : 'remote')) : 'agent');
          x.st = 'none'; x.label = '—'; x.why = '';
          if (s0 && s0.enabled === false) { x.st = 'none'; x.label = t('cpPaused'); }
          else if (a && a.approval === 'revoked') { x.st = 'none'; x.label = t('apRevoked'); }
          else if (a && (a.approval === 'pending' || a.approval === 'pending-reenroll')) { x.st = 'Warn'; x.label = t('apPending'); x.why = t('cpApproveHint'); }
          else if (a && a.ok === false) { x.st = 'Fail'; x.label = t('cpInstallFailed'); x.why = a.message || ''; }
          else if (a && a.ok === null && a.step && a.step !== 'waiting' && a.step !== 'enrolled') { x.st = 'Info'; x.label = t('cpInstalling') + ' · ' + a.step; busy = true; }
          else if (a && a.approval === 'active') { if (mins !== null && mins <= 10) { x.st = 'OK'; x.label = t('cpOnline'); } else { x.st = 'Warn'; x.label = mins === null ? t('cpNoContact') : t('cpOffline') + ' ' + fmtDur(mins); } }
          else if (a && a.step === 'waiting') { x.st = 'Warn'; x.label = t('agWaiting'); }
          else if (s0) { var fl = arr(s0.channels).filter(function (c) { return !c.ok; }); x.st = s0.status === 'OK' ? 'OK' : (s0.status === 'Fail' ? 'Fail' : (s0.status === 'Warn' ? 'Warn' : 'none')); x.label = s0.status === 'OK' ? t('cpReading') : (s0.status ? t('cpConnProblem') : t('cpNotTested')); if (fl.length) x.why = fl[0].channel + ': ' + fl[0].reason; }
          x.seenTxt = a && a.lastSeen ? fmtT(a.lastSeen) : '';
          x.problem = x.st === 'Fail' || x.st === 'Warn';
        });
        clear(out);
        var cnt = function (f) { return list.filter(f).length; };
        function kpi(val, label, color, flt) { return el('div', { cls: 'kpi go' + (CP.filter === flt ? ' sel' : ''), style: color ? '--kc:' + color : null, onclick: function () { CP.filter = CP.filter === flt ? '' : flt; draw(); } }, el('div', { cls: 'v num', style: color ? 'color:' + color : null, text: val }), el('div', { cls: 'l', text: label })); }
        var kp = el('div'); out.appendChild(kp);
        var lc = card(t('tComputerList'), el('span', { cls: 'row' }, btn('+ ' + t('tAddComputers'), function () { go('deploy'); }, 'pri sm'),
          btn(t('testAll'), function (e) { var b = e.target; b.disabled = true; b.textContent = t('loading'); api('/api/sources/test', {}).then(function () { load(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'sm')));
        var q = inp(t('search'), 'search', CP.q); q.addEventListener('input', function () { CP.q = q.value.trim().toLowerCase(); draw(); });
        lc.appendChild(el('div', { cls: 'fbar' }, q)); var tb = el('div'); lc.appendChild(tb); out.appendChild(lc);
        function draw() {
          clear(kp);
          kp.appendChild(el('div', { cls: 'kpis' }, kpi(list.length, t('cpAll'), null, ''), kpi(cnt(function (x) { return x.st === 'OK'; }), t('cpOnline'), 'var(--mint)', 'ok'),
            kpi(cnt(function (x) { return x.problem; }), t('cpNeedAttention'), cnt(function (x) { return x.problem; }) ? 'var(--warn)' : null, 'problem'),
            kpi(cnt(function (x) { return x.how === 'agent'; }), t('cpWithAgent'), null, 'agent'), kpi(cnt(function (x) { return x.how !== 'agent'; }), t('cpWithoutAgent'), null, 'noagent')));
          var rows = list.filter(function (x) {
            if (CP.filter === 'ok' && x.st !== 'OK') return false; if (CP.filter === 'problem' && !x.problem) return false;
            if (CP.filter === 'agent' && x.how !== 'agent') return false; if (CP.filter === 'noagent' && x.how === 'agent') return false;
            return !CP.q || (x.name + ' ' + x.address).toLowerCase().indexOf(CP.q) >= 0;
          }).sort(function (a, b) { return (b.problem - a.problem) || a.name.localeCompare(b.name); }).map(function (x) {
            return el('tr', { cls: 'clk', onclick: function () { computerDrawer(x); } },
              el('td', null, el('b', { text: x.name }), x.address && x.address.toUpperCase() !== x.name.toUpperCase() ? el('div', { cls: 'mono muted', text: x.address }) : null),
              el('td', { text: t('how_' + x.how) }),
              el('td', null, agentVerCell(x)),
              el('td', null, pill(x.st, x.label)), el('td', { cls: 'why', text: x.why }), el('td', { cls: 'num muted nw', text: x.seenTxt }));
          });
          if (!rows.length) rows = [emptyRow(6, list.length ? t('none') : t('cpEmpty'))];
          clear(tb); tb.appendChild(table([t('tComputerList'), t('cpHow'), t('adAgentVer'), t('status'), t('reason'), t('lastSeen')], rows));
        }
        draw();
        if (busy) agTimer = setTimeout(function () { if (S.view === 'computers') load(true); }, 5000);
        // سرورِ لاگ‌بوک | the LogBok server itself
        if (src.self) { var sc = card(t('thisServer') + ' · ' + src.self.name, statusPill(src.self.status)); sc.appendChild(chanTable(src.self.channels)); out.appendChild(sc); }
      }).catch(function (e) { if (my === seq) { clear(out); fail(e); } });
    }
    function computerDrawer(x) {
      var a = x.agent, s0 = x.src;
      if (s0 && !a) { srcDrawer(s0, null); return; }
      openDrawer(function (d) {
        drawerHead(d, el('span', null, x.name, ' ', pill(x.st, x.label)));
        d.appendChild(el('div', { cls: 'kv' },
          el('div', { cls: 'k', text: t('address') }), el('div', { cls: 'mono', text: x.address || '—' }),
          el('div', { cls: 'k', text: t('cpHow') }), el('div', { text: t('how_' + x.how) + (a && a.version ? ' ' + a.version : '') }),
          el('div', { cls: 'k', text: t('lastSeen') }), el('div', { cls: 'num', text: x.seenTxt || '—' }),
          a && a.perf ? [el('div', { cls: 'k', text: t('agPerf') }), el('div', { text: a.perf.cpu + 's CPU · ' + a.perf.mem + ' MB' })] : null,
          x.why ? [el('div', { cls: 'k', text: t('reason') }), el('div', { cls: 'why', text: x.why })] : null));
        if (a && a.approval === 'active') d.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' },
          btn(t('cpDetails'), function () { agentDrawer(a.name); }, 'pri'),
          btn(t('sessions'), function () { SS.host = a.name; closeDrawer(); go('sessions'); })));
        var acts = el('div', { cls: 'acts', style: 'margin-top:10px' });
        if (a && (a.approval === 'pending' || a.approval === 'pending-reenroll')) acts.appendChild(btn(t('apApprove'), function () { api('/api/agent/approve', { name: a.name, action: a.approval === 'pending' ? 'approve' : 'approve-reenroll' }).then(function () { closeDrawer(); load(); }).catch(fail); }, 'pri'));
        if (a && a.ok === false && a.method === 'push') acts.appendChild(btn(t('agRetry'), function () { api('/api/agent/push', { name: a.name, address: a.address, collector: a.collector }).then(function () { closeDrawer(); load(); }).catch(fail); }));
        if (a && a.approval === 'active') acts.appendChild(btn(t('unCode'), function (e) { var b = e.target; api('/api/agent/uninstall-code', { name: a.name }).then(function (y) { b.textContent = y.code; b.disabled = true; }).catch(fail); }));
        acts.appendChild(btn(t('test'), function (e) { var b = e.target; b.disabled = true; b.textContent = t('loading'); api('/api/sources/test', { names: [x.address || x.name] }).then(function () { closeDrawer(); load(); }).catch(function (er) { b.disabled = false; fail(er); }); }));
        if (s0) acts.appendChild(btn(t('cpSourceSettings'), function () { srcDrawer(s0, null); }));
        if (a && a.approval && a.approval !== 'revoked') acts.appendChild(btn(t('apRevoke'), function () { if (!window.confirm(t('apRevokeQ'))) return; api('/api/agent/approve', { name: a.name, action: 'revoke' }).then(function () { closeDrawer(); load(); }).catch(fail); }, 'danger'));
        if (a && a.approval === 'active') acts.appendChild(btn(t('cpRemove'), function () { if (!window.confirm(t('cpRemoveQ'))) return; api('/api/agent/remove', { name: a.name }).then(function () { flash(t('cpRemoveSent')); closeDrawer(); load(); }).catch(fail); }, 'danger'));
        if (a) acts.appendChild(btn(t('cpClearQueue'), function () { if (!window.confirm(t('cpClearQueueQ'))) return; api('/api/agent/clear-queue', { name: a.name }).then(function () { flash(t('cpClearQueueDone')); closeDrawer(); load(); }).catch(fail); }));
        acts.appendChild(btn(t('forget'), function () { if (!window.confirm(t('cpForgetQ'))) return; api('/api/agent/forget', { name: a ? a.name : x.name }).then(function () { closeDrawer(); load(); }).catch(fail); }, 'danger'));
        d.appendChild(acts);
        if (a && a.ok === false && a.message) d.appendChild(el('div', { cls: 'flash err', style: 'margin-top:10px', text: a.message }));
      });
    }
    load();
  }
  function colSelect(r, val) {
    var ci = r.collector || {}, s = el('select'), seen = {};
    [ci['default']].concat(arr(ci.names), arr(ci.ips)).forEach(function (o) { if (o && !seen[o]) { seen[o] = 1; s.appendChild(el('option', { value: o, text: o + (o === ci['default'] ? '  ★' : ''), selected: o === (val || ci['default']) ? 'selected' : null })); } });
    return s;
  }
  // server identity, read live from this server
  function serverCard(r) {
    var ci = r.collector || {};
    var c = card(t('agServer'), pill('OK', t('agAuto')));
    c.appendChild(el('p', { cls: 'lead', text: t('agServerLead') }));
    c.appendChild(el('div', { cls: 'kv' },
      el('div', { cls: 'k', text: t('agSrvName') }), el('div', { cls: 'mono', text: ci.host || '' }),
      el('div', { cls: 'k', text: 'FQDN' }), el('div', { cls: 'mono', text: ci.fqdn || '' }),
      el('div', { cls: 'k', text: 'IP' }), el('div', { cls: 'mono', text: arr(ci.ips).join(', ') }),
      el('div', { cls: 'k', text: t('agDomain') }), el('div', { text: ci.domain || t('agWorkgroup') }),
      el('div', { cls: 'k', text: t('agUsedAddr') }), el('div', null, el('b', { cls: 'mono', text: ci['default'] || '' }), ' ', el('span', { cls: 'muted', text: ci.override ? t('agManualSet') : t('agAutoSet') })),
      el('div', { cls: 'k', text: t('agBuild') }), el('div', { cls: 'mono muted', text: r.build || '—' })));
    var ov = inp(t('agOverridePh'), 'text', ci.override || '');
    c.appendChild(el('div', { cls: 'row', style: 'margin-top:10px' }, ov,
      btn(t('save'), function (e) { var b = e.target; b.disabled = true; api('/api/agent/collector', { collector: ov.value.trim() }).then(function (x) { flash(t('agRebuilt') + ': ' + x['default']); vAgents(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'pri sm'),
      btn(t('agRebuild'), function (e) { var b = e.target; b.disabled = true; api('/api/agent/rebuild', {}).then(function () { flash(t('agRebuilt')); vAgents(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'sm')));
    return c;
  }
  function stPill(i) { if (i.ok === true) return pill('OK', t('agInstalled')); if (i.ok === false) return pill('Fail', t('failed')); if (i.step === 'waiting') return pill('Warn', t('agWaiting')); return pill('none', t('agRunning') + ' · ' + i.step); }
  function mName(m) { return m === 'push' ? t('mPush') : (m === 'linux' ? t('mLinux') : (m === 'deploy' ? t('mDeploy') : t('mPackage'))); }
  // ---- server migration + agent identity backup/restore
  function migrationCard(r) {
    var c = card(t('mgTitle'));
    c.appendChild(el('p', { cls: 'lead', text: t('mgLead') }));
    // 1) daily backup settings
    var bp = inp('C:\\Backup\\LogBok  |  \\\\NAS\\Backups\\LogBok'), bpw = inp(t('mgPassPh'), 'password'), bst = el('div', { cls: 'muted', style: 'margin-top:6px' });
    var bem = el('input', { type: 'checkbox' }), bto = inp('admin@yas.ir, it@yas.ir');
    function loadBk() { api('/api/agent/backup/settings').then(function (x) { bp.value = x.path || ''; bem.checked = !!x.email; bto.value = arr(x.emailTo).join(', '); bto.placeholder = arr(x.defaultTo).length ? arr(x.defaultTo).join(', ') + ' (' + t('mgMailDefault') + ')' : 'admin@yas.ir'; clear(bst); bst.appendChild(el('span', { text: (x.path ? (x.hasPass ? t('mgBkOn') : t('mgBkNoPass')) : t('mgBkOff')) + (x.lastRun ? ' · ' + t('mgLastRun') + ' ' + fmtT(x.lastRun) : '') })); if (x.lastFile) bst.appendChild(el('div', { cls: 'mono', text: x.lastFile })); if (x.lastError) bst.appendChild(el('div', { cls: 'why', text: x.lastError })); if (x.email) bst.appendChild(el('div', { text: '✉ ' + (x.lastMail ? t('mgMailed') + ' ' + fmtT(x.lastMail) : t('mgMailPending')) })); if (x.lastMailError) bst.appendChild(el('div', { cls: 'why', text: '✉ ' + x.lastMailError })); }).catch(function () { }); }
    c.appendChild(el('h4', { text: t('mgBkTitle') }));
    c.appendChild(el('div', { cls: 'form' }, el('label', { text: t('mgBkPath') }), bp, el('label', { text: t('mgPass') }), bpw,
      el('label', null, ''), el('label', null, bem, ' ', t('mgMailOn')), el('label', { text: t('mgMailTo') }), bto, el('div', { cls: 'hint', text: t('mgMailHint') })));
    c.appendChild(el('div', { cls: 'acts', style: 'margin-top:8px' },
      btn(t('save'), function (e) { var b = e.target; b.disabled = true; var o = { path: bp.value.trim(), email: bem.checked, emailTo: splitList(bto.value) }; if (bpw.value) o.passphrase = bpw.value; api('/api/agent/backup/settings', o).then(function () { b.disabled = false; bpw.value = ''; flash(t('saved')); loadBk(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'pri sm'),
      btn(t('mgBkNow'), function (e) { var b = e.target; b.disabled = true; b.textContent = t('loading'); api('/api/agent/backup/now', {}).then(function (x) { b.disabled = false; b.textContent = t('mgBkNow'); flash(x.message); loadBk(); }).catch(function (er) { b.disabled = false; b.textContent = t('mgBkNow'); fail(er); }); }, 'sm')));
    c.appendChild(bst); loadBk();
    // 2) export a bundle now (download)
    var xpw = inp(t('mgPassPh'), 'password');
    c.appendChild(el('h4', { text: t('mgExTitle') }));
    c.appendChild(el('div', { cls: 'row' }, xpw, btn('⬇ ' + t('mgExport'), function (e) {
      if (!xpw.value || xpw.value.length < 8) { fail(new Error(t('mgPassShort'))); return; }
      var b = e.target; b.disabled = true;
      api('/api/agent/backup/export', { passphrase: xpw.value }).then(function (x) {
        b.disabled = false; xpw.value = '';
        var bin = atob(x.data), u8 = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        var url = URL.createObjectURL(new Blob([u8], { type: 'application/octet-stream' })); var a = el('a', { href: url, download: x.name }); document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(url); if (a.parentNode) a.parentNode.removeChild(a); }, 2000);
        flash(t('mgExported') + ': ' + x.agents + ' ' + t('agents'));
      }).catch(function (er) { b.disabled = false; fail(er); });
    }, 'pri sm')));
    // 3) restore on this server
    var rf = el('input', { type: 'file', accept: '.lbk' }), rpw = inp(t('mgPassPh'), 'password'), rrep = el('input', { type: 'checkbox' });
    c.appendChild(el('h4', { text: t('mgRsTitle') }));
    c.appendChild(el('p', { cls: 'muted', text: t('mgRsLead') }));
    c.appendChild(el('div', { cls: 'row' }, rf, rpw, el('label', null, rrep, ' ', t('mgRsReplace')), btn(t('mgRestore'), function (e) {
      if (!rf.files || !rf.files[0]) { fail(new Error(t('mgRsNoFile'))); return; }
      if (!window.confirm(t('mgRsQ'))) return;
      var b = e.target; b.disabled = true; var rd = new FileReader();
      rd.onload = function () {
        var b64 = String(rd.result).split(',')[1] || '';
        api('/api/agent/restore', { data: b64, passphrase: rpw.value, replace: rrep.checked }).then(function (x) { b.disabled = false; rpw.value = ''; flash(t('mgRestored') + ': ' + x.agents + ' ' + t('agents') + ' · ' + x.creds + ' ' + t('mgCreds') + ' (' + x.from + ')'); vAgents(); }).catch(function (er) { b.disabled = false; fail(er); });
      };
      rd.readAsDataURL(rf.files[0]);
    }, 'danger sm')));
    // 4) planned move: tell agents the new address
    var mn = inp('logbok.yas.ir'), mi = inp('10.1.99.50'), mp = el('input', { type: 'number', min: 1, max: 65535, placeholder: '8687', style: 'width:90px' });
    c.appendChild(el('h4', { text: t('mgMvTitle') }));
    c.appendChild(el('p', { cls: 'muted', text: t('mgMvLead') }));
    c.appendChild(el('div', { cls: 'form' }, el('label', { text: t('mgMvName') }), mn, el('label', { text: t('mgMvIp') }), mi, el('label', { text: t('mgMvPort') }), mp));
    c.appendChild(el('div', { cls: 'acts', style: 'margin-top:8px' }, btn(t('mgMove'), function (e) {
      var names = mn.value.split(/[,\s]+/).filter(function (z) { return z; }), ips = mi.value.split(/[,\s]+/).filter(function (z) { return z; });
      if (!names.length && !ips.length) { fail(new Error(t('mgMvNeed'))); return; }
      if (!window.confirm(t('mgMvQ') + ' ' + names.concat(ips).join(', '))) return;
      var b = e.target; b.disabled = true;
      api('/api/agent/move-server', { names: names, ips: ips, port: +mp.value || 0 }).then(function (x) { b.disabled = false; flash(t('mgMoved') + ': ' + x.queued + ' ' + t('agents')); }).catch(function (er) { b.disabled = false; fail(er); });
    }, 'pri sm')));
    c.appendChild(el('div', { cls: 'muted', style: 'margin-top:8px' }, el('div', { text: t('mgTip1') }), el('div', { text: t('mgTip2') }), el('div', { text: t('mgTip3') })));
    return c;
  }
  function agManual(box, r) {
    var c1 = card(t('agWinPkg'));
    c1.appendChild(el('p', { cls: 'lead', text: t('agWinPkgLead') }));
    c1.appendChild(el('div', { cls: 'acts' }, btn('⬇ ' + t('agDlWin'), function () { download('/api/agent/package'); flash(t('agDownloaded')); }, 'pri')));
    c1.appendChild(el('h4', { text: t('agSteps') }));
    c1.appendChild(el('ol', { cls: 'steps' }, el('li', { text: t('agS1') }), el('li', { text: t('agS2') }), el('li', { text: t('agS3') })));
    c1.appendChild(el('div', { cls: 'muted', text: t('agAutoList') }));
    c1.appendChild(el('div', { cls: 'muted', style: 'margin-top:6px', text: t('agS4') }));
    if (r.packagesReady) { c1.appendChild(el('h4', { text: t('agReady') })); c1.appendChild(el('div', { cls: 'code', text: r.packagesDir + '\\Windows\\LogBok-Agent' })); }
    box.appendChild(c1);
    // EXE agent install hidden — unified on the PowerShell agent. Restore this block to re-enable the native EXE download card.
    var c3 = card(t('agLinux'));
    c3.appendChild(el('p', { cls: 'lead', text: t('agLinuxLead') }));
    c3.appendChild(el('div', { cls: 'acts' }, btn('⬇ ' + t('agDlLinux'), function () { download('/api/agent/linux'); flash(t('agDownloaded')); }, 'pri')));
    c3.appendChild(el('h4', { text: t('agLinuxRun') }));
    c3.appendChild(el('div', { cls: 'code', text: 'sudo sh install-logbok-agent.sh\n# ' + t('remove') + ':\nsudo sh install-logbok-agent.sh --uninstall' }));
    box.appendChild(c3);
    box.appendChild(el('div', { cls: 'muted', style: 'margin-top:6px' }, t('acWhere') + ' ', el('a', { href: '#/agentcfg', text: t('tAgentsBackup') })));
  }
  // امنیتِ بستهٔ ایجنت (توکنِ ثبت‌نام، تأیید، اثرانگشت) | agent package security
  function enrollCard(r) {
    // security of the package: enrollment token, approval, fingerprint
    var en = r.enroll || {};
    var sc = card(t('secTitle'), en.valid ? pill('OK', t('secValid')) : pill('Fail', t('secInvalid')));
    sc.appendChild(el('p', { cls: 'lead', text: t('secLead') }));
    var days = el('input', { type: 'number', min: 1, max: 365, value: en.days || 30, style: 'width:90px' }), mx = el('input', { type: 'number', min: 1, value: en.maxUses || 1000, style: 'width:110px' });
    var appr = el('input', { type: 'checkbox', checked: !!en.requireApproval });
    sc.appendChild(el('div', { cls: 'kv' },
      el('div', { cls: 'k', text: t('secExpires') }), el('div', { cls: 'num', text: String(en.expires || '').replace('T', ' ').slice(0, 16) }),
      el('div', { cls: 'k', text: t('secUses') }), el('div', { cls: 'num', text: (en.uses || 0) + ' / ' + (en.maxUses || 0) }),
      el('div', { cls: 'k', text: t('secSigner') }), el('div', { cls: 'mono', text: r.signer || t('secUnsigned') }),
      el('div', { cls: 'k', text: 'SHA-256 (ZIP)' }), el('div', { cls: 'mono', style: 'word-break:break-all', text: r.packageSha || '—' })));
    sc.appendChild(el('div', { cls: 'form', style: 'margin-top:10px' },
      el('label', { text: t('secDays') }), days, el('label', { text: t('secMax') }), mx,
      el('label', null, ''), el('label', null, appr, ' ', t('secApproval'))));
    sc.appendChild(el('div', { cls: 'acts', style: 'margin-top:10px' },
      btn(t('save'), function (e) { var b = e.target; b.disabled = true; api('/api/agent/enroll', { days: +days.value || 30, maxUses: +mx.value || 1000, requireApproval: appr.checked }).then(function () { flash(t('saved')); vAgentCfg(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'pri sm'),
      btn(t('secRotate'), function (e) { if (!window.confirm(t('secRotateQ'))) return; var b = e.target; b.disabled = true; api('/api/agent/enroll', { rotate: true }).then(function () { flash(t('secRotated')); vAgentCfg(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'sm danger')));
    sc.appendChild(el('div', { cls: 'muted', style: 'margin-top:8px', text: t('secList') }));
    return sc;
  }
  function copyBtn(getText, label) {
    return btn('⧉ ' + (label || t('copy')), function (e) {
      var txt = getText(), b = e.target;
      try { navigator.clipboard.writeText(txt).then(function () { b.textContent = '✓ ' + t('copied'); setTimeout(function () { b.textContent = '⧉ ' + (label || t('copy')); }, 1500); }); }
      catch (x) { window.prompt(t('copyManual'), txt); }
    }, 'pri sm');
  }
  // نصبِ تک‌پورتی: یک دستور روی سیستم، بدونِ بازکردنِ هیچ پورت | one-line install, no inbound ports
  function oneLineCard(r) {
    var c = card(t('olTitle'), pill('OK', t('olBadge')));
    c.appendChild(el('p', { cls: 'lead', text: t('olLead') }));
    var cmd = r.installCmd || '';
    if (!cmd) { c.appendChild(el('div', { cls: 'banner' }, el('span', { text: t('olNoToken') }), btn(t('tAgentsBackup'), function () { go('agentcfg'); }, 'sm'))); return c; }
    // steps
    c.appendChild(el('ol', { cls: 'steps big' },
      el('li', null, el('b', { text: t('olS1b') }), ' ', t('olS1')),
      el('li', null, el('b', { text: t('olS2b') }), ' ', t('olS2')),
      el('li', null, el('b', { text: t('olS3b') }), ' ', t('olS3'))));
    var pre = el('div', { cls: 'cmd' }, el('code', { text: cmd }));
    c.appendChild(el('div', { cls: 'cmdwrap' }, pre, copyBtn(function () { return cmd; }, t('olCopy'))));
    c.appendChild(el('div', { cls: 'acts', style: 'margin-top:10px' }, el('span', { text: t('spJoinLead') }), ' ', btn('⬇ LogBok-Join.cmd', function () {
      api('/api/agent/joinfile').then(function (x) {
        var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([x.text], { type: 'application/octet-stream' })); a.download = x.name || 'LogBok-Join.cmd';
        document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
      }).catch(fail);
    }, 'sm')));
    c.appendChild(el('p', { cls: 'lead', text: t('olNote') }));
    c.appendChild(el('p', { cls: 'lead', text: '🔒 ' + t('spVerified') }));
    return c;
  }
  // نصبِ از راه دور: پیش‌فرض خاموش؛ روشن کردنش هشدار دارد | remote push: off by default, enabling warns
  function pushToggle(r) {
    var d = el('details', { cls: 'moredet', style: 'margin-top:18px' }, el('summary', { text: t('spAdvanced') }));
    var c = el('div', { cls: 'card' });
    c.appendChild(el('p', { cls: 'lead', text: t('spPushExplain') }));
    var st = el('div', null, r.remotePush ? pill('Warn', t('spPushOn')) : pill('OK', t('spPushOffOk')));
    c.appendChild(st);
    c.appendChild(el('div', { cls: 'acts', style: 'margin-top:10px' }, r.remotePush
      ? btn(t('spTurnOff'), function () { api('/api/agent/remote-push', { enabled: false }).then(function () { flash(t('spPushOffOk')); S.dpSingle = 'oneline'; vAgents(); }).catch(fail); }, 'pri')
      : btn(t('spTurnOn'), function () { if (!window.confirm(t('spConfirmOn'))) return; api('/api/agent/remote-push', { enabled: true }).then(function () { flash(t('spPushOn')); vAgents(); }).catch(fail); }, 'danger sm')));
    d.appendChild(c);
    return d;
  }
  // نصبِ امن روی کلِ دامنه با GPO (کلاینت‌ها خودشان می‌کشند) | secure domain-wide install via GPO (clients pull)
  function secureDomainCard(r) {
    var c = card(t('spDomTitle'), pill('OK', t('spNoPorts')));
    c.appendChild(el('p', { cls: 'lead', text: t('spDomLead') }));
    c.appendChild(el('ol', { cls: 'steps big' },
      el('li', null, el('b', { text: t('spDom1b') }), ' ', t('spDom1')),
      el('li', null, el('b', { text: t('spDom2b') }), ' ', t('spDom2')),
      el('li', null, el('b', { text: t('spDom3b') }), ' ', t('spDom3'))));
    var body = el('div'); c.appendChild(body);
    function draw() {
      clear(body);
      var ds = arr(S.ad.domains);
      if (!ds.length) { body.appendChild(el('div', { cls: 'muted', text: t('spDomNone') })); return; }
      ds.forEach(function (d) {
        var res = el('div', { cls: 'muted' });
        var b = btn(t('spDomGo') + ' ' + d.fqdn, function () {
          if (!window.confirm(t('spDomConfirm') + ' ' + d.fqdn)) return;
          b.disabled = true; b.textContent = t('loading');
          api('/api/ad/secure-rollout', { domainId: d.id }).then(function (x) {
            b.disabled = false; b.textContent = t('spDomGo') + ' ' + d.fqdn;
            clear(res); res.appendChild(el('b', { text: '✓ ' + t('spDomDone') })); res.appendChild(el('div', { text: 'GPO: ' + ((x.gpo && x.gpo.name) || '') + ' · ' + arr(x.gpo && x.gpo.links).length + ' ' + t('spLinks') }));
            res.appendChild(el('div', { text: t('spDomWhen') }));
          }).catch(function (er) { b.disabled = false; b.textContent = t('spDomGo') + ' ' + d.fqdn; fail(er); });
        }, d.hasCred ? 'pri' : 'pri');
        body.appendChild(el('div', { style: 'margin:8px 0' }, b, res));
      });
    }
    c._draw = draw; draw();
    return c;
  }
  function agPush(box, r) {
    var c2 = card(t('qiTitle'), pill('OK', t('qiBadge')));
    c2.appendChild(el('p', { cls: 'lead', text: t('qiLead') }));
    var dl = el('datalist', { id: 'qiSrc' });
    arr(r.windowsSources).forEach(function (w) { dl.appendChild(el('option', { value: w.address || w.name, label: w.name })); });
    var tg = inp('PC-SALES  /  10.1.99.50'); tg.setAttribute('list', 'qiSrc'); tg.setAttribute('dir', 'ltr');
    var u2 = inp('Administrator'); u2.setAttribute('dir', 'ltr');
    var p2 = inp('', 'password'); p2.setAttribute('dir', 'ltr');
    var col2 = colSelect(r);
    c2.appendChild(dl);
    c2.appendChild(el('div', { cls: 'form' }, el('label', { text: t('qiTarget') }), tg, el('label', { text: t('qiUser') }), u2, el('label', { text: t('qiPass') }), p2));
    c2.appendChild(el('div', { cls: 'muted', style: 'margin-top:4px', text: t('qiUserHint') }));
    var more = el('details', { cls: 'moredet' }, el('summary', { text: t('qiMore') }), el('div', { cls: 'form' }, el('label', { text: t('agCollector') }), col2));
    c2.appendChild(more);
    var prog = el('div', { cls: 'qiprog' });
    var go1 = btn(t('qiGo'), function () {
      var target = tg.value.trim(), user = u2.value.trim(), pw = p2.value;
      if (!target || !user || !pw) { fail(new Error(t('qiNeed'))); return; }
      var isIp = /^\d+\.\d+\.\d+\.\d+$/.test(target);
      var name = isIp ? target.replace(/\./g, '-') : target.split('.')[0].toUpperCase();
      go1.disabled = true;
      api('/api/agent/push', { name: isIp ? '' : name, address: target, collector: col2.value, user: user, password: pw })
        .then(function (x) { p2.value = ''; qiTrack(prog, (x && x.name) || name, r, function () { go1.disabled = false; }); })
        .catch(function (er) { go1.disabled = false; fail(er); });
    }, 'pri');
    c2.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, go1));
    c2.appendChild(prog);
    box.appendChild(c2);
  }
  // پیشرفتِ زندهٔ نصب به زبانِ ساده | live, plain-language install progress
  function qiTried(list) {
    return arr(list).map(function (x) { var a = String(x).split(':'); return t('qi_' + a[0]) + ': ' + t('qi_' + (a[1] || 'other')); }).join(' · ');
  }
  function qiTrack(prog, name, r, done) {
    var started = Date.now(), timer = null;
    function stage(it) {
      if (!it) return 1;
      if (it.step === 'done' && it.ok === true) return 5;
      if (it.step === 'waiting' || it.step === 'enrolled' || it.step === 'approval') return 3;
      if (it.step === 'install') return 2;
      return 1;
    }
    function draw(it) {
      clear(prog);
      var st = stage(it), failed = it && it.ok === false;
      var ol = el('ol', { cls: 'qisteps' });
      ['qiS1', 'qiS2', 'qiS3', 'qiS4'].forEach(function (k, ix) {
        var n = ix + 1, cls = (st > n || st === 5) ? 'done' : (st === n ? (failed ? 'bad' : 'now') : '');
        ol.appendChild(el('li', { cls: cls }, el('span', { cls: 'dot', text: cls === 'done' ? '✓' : (cls === 'bad' ? '✕' : String(n)) }), el('span', { text: t(k) })));
      });
      prog.appendChild(ol);
      if (it && it.message) prog.appendChild(el('div', { cls: failed ? 'why' : 'muted', style: 'margin-top:8px', text: it.message }));
      var via = arr(it && it.tried).filter(function (x) { return /:ok$/.test(x); })[0];
      if (via) prog.appendChild(el('div', { cls: 'muted', text: t('qiVia') + ': ' + t('qi_' + via.split(':')[0]) }));
      if (failed) {
        if (arr(it.tried).length) prog.appendChild(el('div', { cls: 'muted', style: 'margin-top:4px', text: t('qiTried') + ': ' + qiTried(it.tried) }));
        if (it.fix === 'manual' && r.installCmd) {
          prog.appendChild(el('p', { style: 'margin-top:10px', text: t('qiManualIntro') }));
          prog.appendChild(el('div', { cls: 'cmdwrap' }, el('div', { cls: 'cmd' }, el('code', { text: r.installCmd })), copyBtn(function () { return r.installCmd; }, t('olCopy'))));
        }
      } else if (st === 5) {
        prog.appendChild(el('div', { cls: 'acts', style: 'margin-top:8px' }, el('b', { text: t('qiOk') }), ' ', btn(t('qiOpen'), function () { go('computers'); }, 'sm')));
      } else if (Date.now() - started > 20000) {
        prog.appendChild(el('div', { cls: 'muted', text: t('qiStill') }));
      }
    }
    function poll() {
      if (!document.body.contains(prog)) return;
      api('/api/agents').then(function (x) {
        var it = arr(x.items).filter(function (i) { return String(i.name).toUpperCase() === String(name).toUpperCase(); })[0];
        draw(it);
        var fin = it && (it.ok === false || (it.step === 'done' && it.ok === true));
        if (fin || Date.now() - started > 300000) { done(); return; }
        timer = setTimeout(poll, 3000);
      }).catch(function () { timer = setTimeout(poll, 5000); });
    }
    draw(null); poll();
  }
  // ---- Active Directory: deployment policies (push now / GPO / auto)
  function agAd(box, r) {
    box.appendChild(el('p', { cls: 'lead', text: t('adDepLead') }));
    // saved domains (multi-domain, persisted + encrypted credential)
    var secCard = secureDomainCard(r); box.appendChild(secCard);
    var dcard = card(t('adDomains'), btn('+ ' + t('adAddDomain'), function () { domainDrawer(null); }, 'pri sm'));
    var dl = el('div'); dcard.appendChild(dl); dl.appendChild(spinner()); box.appendChild(dcard);
    api('/api/ad/domains').then(function (x) {
      clear(dl); S.ad.domains = arr(x.items); try { secCard._draw(); } catch (e0) { }
      if (S.ad.domainId && !S.ad.domains.filter(function (d) { return d.id === S.ad.domainId; }).length) adSetDomain('');
      if (!S.ad.domainId && S.ad.domains.length) adSetDomain(S.ad.domains[0].id);
      if (!S.ad.domains.length) { dl.appendChild(el('div', { cls: 'muted', text: t('adNoDomain') })); domainForm(dl, null); return; }
      dl.appendChild(table([t('adDomain'), 'DC', t('adUser'), t('status'), t('adInventory'), t('lastCheck'), ''], S.ad.domains.map(function (d) {
        var st = d.stats;
        var inv = st ? (st.computers + ' ' + t('adComp') + ' (' + st.servers + ' ' + t('adSrv') + ' · ' + st.workstations + ' ' + t('adWks') + ' · ' + st.dcs + ' DC) · ' + st.ous + ' OU · ' + st.users + ' ' + t('adUsr') + ' · ' + st.groups + ' ' + t('adGrp')) : '—';
        return el('tr', null,
          el('td', null, el('b', { text: d.fqdn }), d.netbios ? el('span', { cls: 'muted', text: ' (' + d.netbios + ')' }) : null),
          el('td', { cls: 'mono', text: d.server + (d.dc && d.dc !== d.server ? ' → ' + d.dc : '') }),
          el('td', { cls: 'mono', text: d.user }),
          el('td', null, d.ready ? pill('OK', t('adReadyOk')) : pill('Warn', t('adReadyPart')), d.hasCred ? '' : pill('Fail', t('adAcctNone'))),
          el('td', { cls: 'muted', text: inv }),
          el('td', { cls: 'muted', text: fmtT(d.lastCheck) }),
          el('td', null, el('div', { cls: 'row' },
            btn(t('adComputers'), function () { adSetDomain(d.id); domainComputers(d, r); }, 'sm pri'),
            btn(t('adRecheck'), function (e) { var bb = e.target; bb.disabled = true; bb.textContent = t('loading'); api('/api/ad/domain/connect', { id: d.id }).then(function (y) { flash(y.ok ? t('adConnected') + ': ' + d.fqdn : (t('failed') + ': ' + y.error), y.ok); vAgents(); }).catch(function (er) { bb.disabled = false; fail(er); }); }, 'sm'),
            btn(t('edit'), function () { domainDrawer(d); }, 'sm'),
            btn(t('remove'), function () { if (!window.confirm(t('adDomainDelQ') + ' ' + d.fqdn)) return; api('/api/ad/domain/delete', { id: d.id }).then(function () { if (S.ad.domainId === d.id) adSetDomain(''); vAgents(); }).catch(fail); }, 'sm danger'))));
      })));
      dl.appendChild(el('div', { cls: 'muted', style: 'margin-top:6px', text: t('adAcctHint') }));
    }).catch(function (e) { clear(dl); fail(e); });
    // policies
    var pc = card(t('adPolicies'), btn('+ ' + t('adNewPolicy'), function () { if (!S.ad.domains.length) { fail(new Error(t('adNoDomain'))); return; } policyDrawer(null, r); }, 'pri sm'));
    var pl = el('div'); pc.appendChild(pl); box.appendChild(pc); pl.appendChild(spinner());
    api('/api/agent/policies').then(function (x) {
      clear(pl);
      var rows = arr(x.items).map(function (p) {
        var lr = p.lastResult || {};
        var scope = (arr(p.ous).length ? arr(p.ous).length + ' OU' : t('anyOu')) + (arr(p.includeGroups).length ? ' · +' + arr(p.includeGroups).join(', ') : '') + (arr(p.excludeGroups).length ? ' · −' + arr(p.excludeGroups).join(', ') : '');
        return el('tr', { cls: 'clk', onclick: function () { if (p.domainId) adSetDomain(p.domainId); policyDrawer(p, r); } },
          el('td', null, p.enabled ? '' : '⏸ ', p.name), el('td', { cls: 'mono', text: p.domain || p.server || '—' }), el('td', { text: t('dm_' + p.method) }), el('td', { cls: 'muted', text: scope }),
          el('td', { text: p.auto ? '✓' : '' }), el('td', null, p.gpo ? pill('OK', 'GPO v' + p.gpo.version) : (p.method !== 'push' ? pill('Warn', t('adGpoNot')) : '—')),
          el('td', { cls: 'num', text: lr.Matched !== undefined ? (lr.Matched + ' / ' + lr.Installed + ' / ' + lr.Queued) : '' }),
          el('td', { cls: p.lastError ? 'why' : 'muted', text: p.lastError || String(p.lastRun || '').replace('T', ' ').slice(0, 16) }));
      });
      if (!rows.length) rows = [emptyRow(8, t('adNoPolicy'))];
      pl.appendChild(table([t('name'), t('adDomain'), t('adMethod'), t('adScope'), t('adAutoCol'), 'GPO', t('adCounts'), t('lastRun')], rows));
    }).catch(function (e) { clear(pl); fail(e); });
    // how it works
    var hw = card(t('adHow'));
    hw.appendChild(el('div', { cls: 'muted' }, el('div', { text: t('adHow1') }), el('div', { text: t('adHow2') }), el('div', { text: t('adHow3') }), el('div', { text: t('adHow4') })));
    box.appendChild(hw);
  }
  // connect form: DC + account -> check, read inventory, save (encrypted) — survives refresh
  function domainForm(host, d) {
    var sv = inp('dc01.corp.local', 'text', d ? d.server : ''), us = inp('CORP\\Administrator', 'text', d ? d.user : ''), pw = inp(d ? t('adPwKeep') : '', 'password');
    host.appendChild(el('div', { cls: 'form', style: 'margin-top:10px' }, el('label', { text: t('dcAddr') }), sv, el('label', { text: t('adUser') }), el('div', { cls: 'row' }, us, pw)));
    var out = el('div');
    host.appendChild(el('div', { cls: 'acts', style: 'margin-top:10px' }, btn(t('adConnectSave'), function (e) {
      var b = e.target; b.disabled = true; clear(out).appendChild(spinner());
      var o = { server: sv.value.trim() }; if (d) o.id = d.id;
      if (us.value.trim() && pw.value) { o.user = us.value.trim(); o.password = pw.value; }
      api('/api/ad/domain/connect', o).then(function (x) {
        b.disabled = false; clear(out);
        out.appendChild(table([t('channel'), t('status'), t('details'), t('fix')], arr(x.checks).map(function (c) { return el('tr', null, el('td', { cls: 'mono', text: c.check }), el('td', null, c.ok ? pill('OK', t('connected')) : pill('Fail', t('failed'))), el('td', { text: c.detail }), el('td', { cls: 'why', text: c.ok ? '' : c.fix })); })));
        if (x.ok && x.domain) { pw.value = ''; adSetDomain(x.domain.id); flash(t('adConnected') + ': ' + x.domain.fqdn); setTimeout(function () { closeDrawer(); vAgents(); }, 900); }
      }).catch(function (er) { b.disabled = false; clear(out); fail(er); });
    }, 'pri')));
    host.appendChild(out);
  }
  function domainDrawer(d) {
    openDrawer(function (dw) {
      drawerHead(dw, el('span', { text: d ? d.fqdn : t('adAddDomain') }));
      dw.appendChild(el('p', { cls: 'lead', text: t('adDomainLead') }));
      domainForm(dw, d);
      if (d && arr(d.checks).length) {
        dw.appendChild(el('h4', { text: t('adLastChecks') + ' · ' + fmtT(d.lastCheck) }));
        dw.appendChild(table([t('channel'), t('status'), t('details')], arr(d.checks).map(function (c) { return el('tr', null, el('td', { cls: 'mono', text: c.check }), el('td', null, c.ok ? pill('OK', t('connected')) : pill('Fail', t('failed'))), el('td', { text: c.detail })); })));
      }
    });
  }
  // computers read live from AD, with agent status + install on selected
  function domainComputers(d, r) {
    openDrawer(function (dw) {
      drawerHead(dw, el('span', { text: d.fqdn + ' · ' + t('adComputers') }));
      var ty = el('select'); [['All', 'tAll'], ['Servers', 'tServers'], ['Workstations', 'tWks'], ['DCs', 'tDcs']].forEach(function (o) { ty.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
      var nl = inp('PC*'), ag = el('select'); [['', 'tAll'], ['none', 'adNoAgent'], ['ok', 'agInstalled']].forEach(function (o) { ag.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
      var res = el('div'), data = [];
      function draw() {
        clear(res);
        var rows0 = data.filter(function (c) { return !ag.value || (ag.value === 'ok' ? c.agent === 'ok' : c.agent !== 'ok'); });
        var allc = el('input', { type: 'checkbox' }), boxes = [];
        var rows = rows0.map(function (c) { var ck = el('input', { type: 'checkbox' }); if (c.agent !== 'ok') boxes.push({ c: ck, x: c }); else ck.disabled = true;
          return el('tr', null, el('td', null, ck), el('td', null, el('b', { text: c.name }), c.isDC ? el('span', { cls: 'muted', text: ' DC' }) : null), el('td', { cls: 'mono', text: c.address }), el('td', { text: c.os }), el('td', { cls: 'muted mono', text: c.ou }), el('td', { cls: 'num muted', text: c.lastLogon || '' }),
            el('td', null, c.agent === 'ok' ? pill('OK', t('agInstalled')) : (c.agent === 'failed' ? pill('Fail', t('failed')) : (c.agent ? pill('none', c.agent) : pill('none', t('adNoAgent')))))); });
        allc.addEventListener('change', function () { boxes.forEach(function (bx) { bx.c.checked = allc.checked; }); });
        if (!rows.length) rows = [emptyRow(7)];
        var withAg = data.filter(function (c) { return c.agent === 'ok'; }).length;
        res.appendChild(el('div', { cls: 'muted', style: 'margin:10px 0 6px', text: data.length + ' ' + t('results') + ' · ' + withAg + ' ' + t('agInstalled') + ' · ' + (data.length - withAg) + ' ' + t('adNoAgent') }));
        var col = colSelect(r);
        res.appendChild(el('div', { cls: 'acts', style: 'margin:4px 0 10px' }, el('span', { cls: 'muted', text: t('agCollector') }), col, btn(t('adInstallSel'), function (ev) {
          var sel = boxes.filter(function (bx) { return bx.c.checked; }).map(function (bx) { return bx.x; });
          if (!sel.length) return; var bb = ev.target; bb.disabled = true;
          api('/api/agent/batch', { domainId: d.id, computers: sel, collector: col.value }).then(function (y) { flash(y.message ? loc(y.message) : (t('agQueued') + ' (' + y.queued + ')')); closeDrawer(); agTab = 'status'; vAgents(); }).catch(function (er) { bb.disabled = false; fail(er); });
        }, 'pri sm'), btn(t('dpRemoteOnly'), function (ev) {
          var sel = boxes.filter(function (bx) { return bx.c.checked; }).map(function (bx) { return bx.x; });
          if (!sel.length) return; var bb = ev.target; bb.disabled = true;
          api('/api/ad/import', { domainId: d.id, computers: sel }).then(function (y) { flash(t('imported') + ': ' + y.imported); closeDrawer(); go('computers'); api('/api/sources/test', {}).catch(function () { }); }).catch(function (er) { bb.disabled = false; fail(er); });
        }, 'sm')));
        res.appendChild(el('div', { cls: 'tw', style: 'max-height:52vh;overflow:auto' }, el('table', null, el('thead', null, el('tr', null, el('th', null, allc), el('th', { text: t('name') }), el('th', { text: 'DNS' }), el('th', { text: t('os') }), el('th', { text: 'OU' }), el('th', { text: t('lastLogon') }), el('th', { text: t('agents') }))), el('tbody', null, rows))));
        res.appendChild(el('div', { cls: 'muted', style: 'margin-top:6px', text: t('adPushHint') }));
      }
      function load(e) {
        var b = e && e.target; if (b) b.disabled = true; clear(res).appendChild(spinner());
        api('/api/ad/discover', { domainId: d.id, type: ty.value, nameLike: nl.value.trim() }).then(function (x) { if (b) b.disabled = false; data = arr(x.items); draw(); }).catch(function (er) { if (b) b.disabled = false; clear(res); fail(er); });
      }
      ag.addEventListener('change', draw);
      dw.appendChild(el('div', { cls: 'row' }, ty, nl, ag, btn(t('adReadAd'), load, 'pri sm')));
      dw.appendChild(res); load();
    });
  }
  // ---- Workgroup: saved groups of non-domain computers (shared local-admin credential), scan + install
  S.wg = { groups: [] };
  function wgCard(r) { return function (box) {
    box.appendChild(el('p', { cls: 'lead', text: t('wgLead') }));
    box.appendChild(el('div', { cls: 'tipbar' }, el('b', { text: t('olWgTipB') }), ' ', el('span', { text: t('olWgTip') }), ' ', btn(t('olShow'), function () { S.dpSingle = 'oneline'; dpTab = 'single'; try { history.replaceState(null, '', '#/deploy/single'); } catch (e) { } vAgents(); }, 'sm')));
    var gc = card(t('wgGroups'), btn('+ ' + t('wgAdd'), function () { wgDrawer(null); }, 'pri sm'));
    var gl = el('div'); gc.appendChild(gl); gl.appendChild(spinner()); box.appendChild(gc);
    api('/api/wg/groups').then(function (x) {
      clear(gl); S.wg.groups = arr(x.items);
      if (!S.wg.groups.length) { gl.appendChild(el('div', { cls: 'muted', text: t('wgNone') })); wgForm(gl, null); return; }
      gl.appendChild(table([t('name'), t('wgScope'), t('wgReach'), t('agents'), t('lastScan'), ''], S.wg.groups.map(function (g) {
        var st = g.stats || {};
        var scope = (g.range ? g.range : '') + (arr(g.hostList).length ? (g.range ? ' · ' : '') + arr(g.hostList).length + ' ' + t('wgHostsN') : '');
        return el('tr', null,
          el('td', null, el('b', { text: g.name }), g.hasCred ? '' : pill('Warn', t('wgNoCred'))),
          el('td', { cls: 'mono muted', text: scope || '—' }),
          el('td', null, el('b', { text: st.total || 0 }), el('span', { cls: 'muted', text: ' ' + t('wgAlive') + ' · ' + (st.winrm || 0) + ' WinRM · ' + (st.smb || 0) + ' SMB' })),
          el('td', null, pill('OK', (g.withAgent || 0) + ' ' + t('agInstalled'))),
          el('td', { cls: 'muted', text: fmtT(g.lastScan) }),
          el('td', null, el('div', { cls: 'row' },
            btn(t('adComputers'), function () { wgComputers(g, r); }, 'sm pri'),
            btn(t('wgRescan'), function (e) { var bb = e.target; bb.disabled = true; bb.textContent = t('loading'); api('/api/wg/connect', { id: g.id }).then(function () { flash(t('wgScanned')); vAgents(); }).catch(function (er) { bb.disabled = false; fail(er); }); }, 'sm'),
            btn(t('edit'), function () { wgDrawer(g); }, 'sm'),
            btn(t('remove'), function () { if (!window.confirm(t('wgDelQ') + ' ' + g.name)) return; api('/api/wg/delete', { id: g.id }).then(vAgents).catch(fail); }, 'sm danger'))));
      })));
      gl.appendChild(el('div', { cls: 'muted', style: 'margin-top:6px', text: t('wgHint') }));
    }).catch(function (e) { clear(gl); fail(e); });
  }; }
  function wgForm(host, g) {
    var nm = inp('Office PCs', 'text', g ? g.name : ''), rg = inp('10.1.99.10-60', 'text', g ? g.range : '');
    var hl = el('textarea', { rows: 2, placeholder: 'PC-1\nPC-2\n192.168.1.50' }); if (g) hl.value = arr(g.hostList).join('\n');
    var us = inp('Administrator', 'text', ''), pw = inp(g && g.hasCred ? t('adPwKeep') : '', 'password');
    host.appendChild(el('div', { cls: 'form', style: 'margin-top:10px' },
      el('label', { text: t('name') }), nm,
      el('label', { text: t('wgRange') }), rg,
      el('label', { text: t('wgHosts') }), hl,
      el('label', { text: t('wgCred') }), el('div', { cls: 'row' }, us, pw)));
    host.appendChild(el('div', { cls: 'muted', style: 'margin-top:4px', text: t('wgCredHint') }));
    var out = el('div');
    host.appendChild(el('div', { cls: 'acts', style: 'margin-top:10px' }, btn(t('wgScanSave'), function (e) {
      var b = e.target; b.disabled = true; clear(out).appendChild(spinner());
      var o = { name: nm.value.trim(), range: rg.value.trim(), hosts: hl.value.split('\n').map(function (z) { return z.trim(); }).filter(function (z) { return z; }) };
      if (g) o.id = g.id;
      if (us.value.trim() && pw.value && pw.value !== t('adPwKeep')) { o.user = us.value.trim(); o.password = pw.value; }
      api('/api/wg/connect', o).then(function (x) {
        b.disabled = false; clear(out); pw.value = '';
        if (x.ok && x.group) { flash(t('wgScanned') + ': ' + (x.group.stats ? x.group.stats.total : 0) + ' ' + t('wgAlive')); setTimeout(function () { closeDrawer(); vAgents(); }, 700); }
      }).catch(function (er) { b.disabled = false; clear(out); fail(er); });
    }, 'pri')));
    host.appendChild(out);
  }
  function wgDrawer(g) {
    openDrawer(function (dw) {
      drawerHead(dw, el('span', { text: g ? g.name : t('wgAdd') }));
      dw.appendChild(el('p', { cls: 'lead', text: t('wgDrawerLead') }));
      wgForm(dw, g);
    });
  }
  function wgComputers(g, r) {
    openDrawer(function (dw) {
      drawerHead(dw, el('span', { text: g.name + ' · ' + t('adComputers') }));
      var only = el('select'); [['', 'tAll'], ['none', 'adNoAgent'], ['ok', 'agInstalled'], ['winrm', 'wgReadyWinRm']].forEach(function (o) { only.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
      var res = el('div');
      function draw() {
        clear(res);
        var ms = arr(g.machines).filter(function (m) { return !only.value || (only.value === 'ok' ? m.agent === 'ok' : (only.value === 'winrm' ? m.winrm : m.agent !== 'ok')); });
        var allc = el('input', { type: 'checkbox' }), boxes = [];
        var rows = ms.map(function (m) {
          var ck = el('input', { type: 'checkbox' }); if (m.agent !== 'ok') boxes.push({ c: ck, x: m }); else ck.disabled = true;
          return el('tr', null, el('td', null, ck), el('td', null, el('b', { text: m.name || '—' })), el('td', { cls: 'mono', text: m.address }),
            el('td', null, m.winrm ? pill('OK', 'WinRM') : pill('none', '—')), el('td', null, m.smb ? pill('OK', 'SMB') : pill('none', '—')),
            el('td', null, m.agent === 'ok' ? pill('OK', t('agInstalled')) : pill('none', t('adNoAgent'))));
        });
        allc.addEventListener('change', function () { boxes.forEach(function (bx) { bx.c.checked = allc.checked; }); });
        if (!rows.length) rows = [emptyRow(6)];
        res.appendChild(el('div', { cls: 'muted', style: 'margin:10px 0 6px', text: arr(g.machines).length + ' ' + t('wgAlive') + ' · ' + (g.withAgent || 0) + ' ' + t('agInstalled') }));
        res.appendChild(el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, el('th', null, allc), el('th', { text: t('name') }), el('th', { text: t('address') }), el('th', { text: 'WinRM' }), el('th', { text: 'SMB' }), el('th', { text: t('agents') }))), el('tbody', null, rows))));
        var col = colSelect(r);
        res.appendChild(el('div', { cls: 'acts', style: 'margin-top:10px' }, el('span', { cls: 'muted', text: t('agCollector') }), col, btn(t('adInstallSel'), function (ev) {
          var sel = boxes.filter(function (bx) { return bx.c.checked; }).map(function (bx) { return bx.x; });
          if (!sel.length) return; var bb = ev.target; bb.disabled = true;
          api('/api/wg/install', { id: g.id, computers: sel, collector: col.value }).then(function (y) { flash(y.message ? loc(y.message) : (t('agQueued') + ' (' + y.queued + ')')); closeDrawer(); agTab = 'status'; vAgents(); }).catch(function (er) { bb.disabled = false; fail(er); });
        }, 'pri sm')));
        res.appendChild(el('div', { cls: 'muted', style: 'margin-top:6px', text: t('wgInstallHint') }));
      }
      only.addEventListener('change', draw);
      dw.appendChild(el('div', { cls: 'row' }, el('span', { cls: 'muted', text: t('wgFilter') }), only, btn(t('wgRescan'), function (e) { var b = e.target; b.disabled = true; api('/api/wg/connect', { id: g.id }).then(function (x) { b.disabled = false; if (x.group) { g = x.group; draw(); } }).catch(function (er) { b.disabled = false; fail(er); }); }, 'sm')));
      dw.appendChild(res); draw();
    });
  }
  function agWg(box, r) { wgCard(r)(box); }

  // group chips with AD search
  function groupPicker(initial) {
    var list = arr(initial).slice(), wrap = el('div'), chips = el('div', { cls: 'chips' });
    var q = inp(t('adGroupPh')), sel = el('select', { hidden: true });
    function draw() { clear(chips); list.forEach(function (g, i) { chips.appendChild(el('span', { cls: 'chip on' }, g, ' ', el('a', { href: '#', cls: 'x', text: '✕', onclick: function (e) { e.preventDefault(); list.splice(i, 1); draw(); } }))); }); if (!list.length) chips.appendChild(el('span', { cls: 'muted', text: '—' })); }
    function addName(n) { n = String(n || '').trim(); if (n && list.indexOf(n) < 0) { list.push(n); draw(); } }
    var find = btn(t('search'), function (e) {
      var b = e.target; b.disabled = true;
      api('/api/ad/groups', adBody({ like: q.value.trim() })).then(function (x) {
        b.disabled = false; clear(sel); sel.hidden = false;
        sel.appendChild(el('option', { value: '', text: arr(x.items).length + ' ' + t('results') }));
        arr(x.items).forEach(function (g) { sel.appendChild(el('option', { value: g.sam || g.name, text: g.name + (g.description ? ' — ' + g.description : '') })); });
      }).catch(function (er) { b.disabled = false; fail(er); });
    }, 'sm');
    sel.addEventListener('change', function () { if (sel.value) addName(sel.value); });
    q.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); addName(q.value); q.value = ''; } });
    wrap.appendChild(chips); wrap.appendChild(el('div', { cls: 'row', style: 'margin-top:6px' }, q, find, btn(t('add'), function () { addName(q.value); q.value = ''; }, 'sm'), sel));
    draw();
    return { node: wrap, val: function () { return list.slice(); } };
  }
  function ouPicker(initial) {
    var chosen = arr(initial).slice(), wrap = el('div'), box = el('div', { cls: 'scrollbox' }), flt = inp(t('adOuFilter'));
    var all = chosen.slice();
    function draw() {
      clear(box); var f = flt.value.trim().toLowerCase();
      all.filter(function (o) { return !f || o.toLowerCase().indexOf(f) >= 0; }).forEach(function (o) {
        var c = el('input', { type: 'checkbox', checked: chosen.indexOf(o) >= 0 });
        c.addEventListener('change', function () { var i = chosen.indexOf(o); if (c.checked && i < 0) chosen.push(o); if (!c.checked && i >= 0) chosen.splice(i, 1); sum.textContent = chosen.length ? chosen.length + ' OU' : t('anyOu'); });
        box.appendChild(el('label', { cls: 'ouRow' }, c, ' ', el('span', { cls: 'mono', text: o })));
      });
      if (!all.length) box.appendChild(el('div', { cls: 'muted', text: t('adOuLoadHint') }));
    }
    var sum = el('b', { text: chosen.length ? chosen.length + ' OU' : t('anyOu') });
    flt.addEventListener('input', draw);
    var ld = btn(t('loadOus'), function (e) { var b = e.target; b.disabled = true; api('/api/ad/ous', adBody()).then(function (x) { b.disabled = false; arr(x.items).forEach(function (o) { if (all.indexOf(o) < 0) all.push(o); }); draw(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'sm');
    wrap.appendChild(el('div', { cls: 'row' }, sum, ld, flt)); wrap.appendChild(box); draw();
    return { node: wrap, val: function () { return chosen.slice(); } };
  }
  function policyDrawer(p, r) {
    p = p || { enabled: true, method: 'gpo', auto: true, type: 'All', ous: [], includeGroups: [], excludeGroups: [], parallel: 6 };
    openDrawer(function (d) {
      drawerHead(d, el('span', { text: p.id ? p.name : t('adNewPolicy') }));
      var nm = inp(t('adPolicyPh'), 'text', p.name || ''), en = el('input', { type: 'checkbox', checked: p.enabled !== false }), au = el('input', { type: 'checkbox', checked: !!p.auto });
      var me = el('select'); ['gpo', 'both', 'push'].forEach(function (m) { var off = m !== 'gpo' && !r.remotePush; me.appendChild(el('option', { value: m, text: t('dm_' + m) + (off ? ' — ' + t('spOffShort') : ''), disabled: off ? 'disabled' : null, selected: p.method === m ? 'selected' : null })); }); if (!r.remotePush) me.value = 'gpo';
      var ty = el('select'); [['All', 'tAll'], ['Servers', 'tServers'], ['Workstations', 'tWks'], ['DCs', 'tDcs']].forEach(function (o) { ty.appendChild(el('option', { value: o[0], text: t(o[1]), selected: p.type === o[0] ? 'selected' : null })); });
      var ou = ouPicker(p.ous), ig = groupPicker(p.includeGroups), xg = groupPicker(p.excludeGroups);
      var nl = inp('SRV*', 'text', p.nameLike || ''), dis = el('input', { type: 'checkbox', checked: !!p.includeDisabled }), re = el('input', { type: 'checkbox', checked: !!p.reinstall });
      var col = colSelect(r, p.collector), par = el('input', { type: 'number', min: 1, max: 20, value: p.parallel || 6 });
      var dsel = el('select'); arr(S.ad.domains).forEach(function (dd) { dsel.appendChild(el('option', { value: dd.id, text: dd.fqdn + ' (' + dd.server + ')', selected: (p.domainId || S.ad.domainId) === dd.id ? 'selected' : null })); });
      if (!p.domainId && S.ad.domainId) dsel.value = S.ad.domainId;
      adSetDomain(dsel.value);
      dsel.addEventListener('change', function () { adSetDomain(dsel.value); });
      d.appendChild(el('div', { cls: 'form' },
        el('label', { text: t('name') }), nm, el('label', null, ''), el('label', null, en, ' ', t('enabled')),
        el('label', { text: t('adDomain') }), dsel,
        el('label', { text: t('adMethod') }), el('div', null, me, el('div', { cls: 'muted', text: t('adMethodHint') })),
        el('label', null, ''), el('label', null, au, ' ', t('adAuto')),
        el('label', { text: t('ou') }), ou.node,
        el('label', { text: t('adInclude') }), ig.node,
        el('label', { text: t('adExclude') }), xg.node,
        el('label', { text: t('compType') }), ty, el('label', { text: t('nameLike') }), nl,
        el('label', null, ''), el('label', null, dis, ' ', t('inclDisabled')),
        el('label', { text: t('agCollector') }), col, el('label', { text: t('adParallel') }), par,
        el('label', null, ''), el('label', null, re, ' ', t('adReinstall'))));
      function body() { return adBody({ id: p.id || '', name: nm.value.trim(), enabled: en.checked, method: me.value, auto: au.checked, type: ty.value, ous: ou.val(), includeGroups: ig.val(), excludeGroups: xg.val(), nameLike: nl.value.trim(), includeDisabled: dis.checked, collector: col.value, parallel: +par.value || 6, reinstall: re.checked, domainId: dsel.value }); }
      var out = el('div');
      function preview(e) {
        var b = e.target; b.disabled = true; clear(out).appendChild(spinner());
        api('/api/agent/policy/preview', body()).then(function (x) {
          b.disabled = false; clear(out);
          var allc = el('input', { type: 'checkbox' }), boxes = [];
          var rows = arr(x.items).map(function (c) { var ck = el('input', { type: 'checkbox' }); boxes.push({ c: ck, x: c }); return el('tr', null, el('td', null, ck), el('td', { text: c.name }), el('td', { cls: 'mono', text: c.address }), el('td', { text: c.os }), el('td', { cls: 'muted', text: c.ou }), el('td', null, c.agent === 'ok' ? pill('OK', t('agInstalled')) : (c.agent === 'failed' ? pill('Fail', t('failed')) : (c.agent ? pill('none', c.agent) : '—')))); });
          allc.addEventListener('change', function () { boxes.forEach(function (bx) { bx.c.checked = allc.checked; }); });
          if (!rows.length) rows = [emptyRow(6)];
          out.appendChild(el('h4', { text: t('adPreview') + ': ' + x.count }));
          out.appendChild(el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, el('th', null, allc), el('th', { text: t('name') }), el('th', { text: 'DNS' }), el('th', { text: t('os') }), el('th', { text: 'OU' }), el('th', { text: t('agents') }))), el('tbody', null, rows))));
          out.appendChild(el('div', { cls: 'acts', style: 'margin-top:8px' }, btn(t('adInstallSel'), function (ev) {
            var sel = boxes.filter(function (bx) { return bx.c.checked; }).map(function (bx) { return bx.x; });
            if (!sel.length) return; var bb = ev.target; bb.disabled = true;
            api('/api/agent/batch', adBody({ computers: sel, collector: col.value })).then(function (y) { flash(y.message ? loc(y.message) : (t('agQueued') + ' (' + y.queued + ')')); closeDrawer(); agTab = 'status'; vAgents(); }).catch(function (er) { bb.disabled = false; fail(er); });
          }, 'pri sm')));
        }).catch(function (er) { b.disabled = false; clear(out); fail(er); });
      }
      function save(run) {
        return function (e) {
          var b = e.target; b.disabled = true;
          api('/api/agent/policy', body()).then(function (x) {
            p.id = x.id;
            if (!run) { flash(t('saved')); closeDrawer(); vAgents(); return; }
            b.textContent = t('loading');
            return api('/api/agent/policy/run', { id: x.id }).then(function (y) {
              var msg = t('saved');
              if (y.push) msg += ' · ' + t('adPushRes') + ': ' + y.push.matched + ' / ' + t('agQueued2') + ' ' + y.push.queued;
              if (y.gpo) msg += ' · GPO v' + y.gpo.version + ' → ' + arr(y.gpo.links).length + ' OU';
              if (y.gpoError) { flash('GPO: ' + y.gpoError, false); } else { flash(msg); }
              closeDrawer(); vAgents();
            });
          }).catch(function (er) { b.disabled = false; fail(er); });
        };
      }
      d.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('adPreviewBtn'), preview), btn(t('save'), save(false)), btn(t('adSaveRun'), save(true), 'pri'),
        p.gpo ? btn(t('adGpoRemove'), function () { if (!window.confirm(t('adGpoRemoveQ'))) return; api('/api/agent/policy/gpo-remove', { id: p.id }).then(function () { flash(t('saved')); closeDrawer(); vAgents(); }).catch(fail); }, 'danger') : null,
        p.id ? btn(t('remove'), function () { if (!window.confirm(t('adDelQ'))) return; api('/api/agent/policy/delete', { id: p.id }).then(function () { closeDrawer(); vAgents(); }).catch(fail); }, 'danger') : null));
      if (p.gpo) d.appendChild(el('div', { cls: 'kv', style: 'margin-top:12px' }, el('div', { cls: 'k', text: 'GPO' }), el('div', { cls: 'mono', text: p.gpo.name + ' ' + p.gpo.guid }), el('div', { cls: 'k', text: t('adLinks') }), el('div', { cls: 'mono', text: arr(p.gpo.links).join('\n') }), el('div', { cls: 'k', text: t('lastRun') }), el('div', { text: String(p.gpo.published || '').replace('T', ' ').slice(0, 16) + ' · v' + p.gpo.version })));
      if (p.lastError) d.appendChild(el('div', { cls: 'flash err', style: 'margin-top:10px', text: p.lastError }));
      d.appendChild(out);
    });
  }

  // ------------------------------------------------------------------ endpoint management
  var epTab = 'fleet';
  var DAYS = ['Saturday', 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
  var COMMON_APPS = ['chrome.exe', 'msedge.exe', 'firefox.exe', 'opera.exe', 'Telegram.exe', 'WhatsApp.exe', 'AnyDesk.exe', 'TeamViewer.exe', 'qbittorrent.exe', 'uTorrent.exe', 'Skype.exe', 'Discord.exe', 'steam.exe', 'IDMan.exe'];
  function fmtT(s) { return String(s || '').replace('T', ' ').slice(0, 16); }
  function targetText(p) {
    var tg = p.targets || {}, parts = [];
    if (tg.all) parts.push(t('epAllAgents'));
    if (arr(tg.hosts).length) parts.push(arr(tg.hosts).join(', '));
    if (arr(tg.patterns).length) parts.push(arr(tg.patterns).join(', '));
    if (tg.includeServer) parts.push(t('epServerSelf'));
    var ex = arr(tg.exceptHosts).concat(arr(tg.exceptPatterns)).concat(arr(tg.exceptOus).map(function (o) { return 'OU ' + o.split(',')[0].replace(/^OU=/i, ''); })).concat(arr(tg.exceptGroups).map(function (g) { return '👥 ' + g; }));
    var base = parts.join(' · ') || '—';
    if (ex.length) base += ' − ' + t('epExcept') + ': ' + ex.join(', ');
    return base;
  }
  function dayPicker(sel) {
    var chosen = arr(sel).slice(), w = el('div', { cls: 'row' });
    DAYS.forEach(function (d) { var c = el('input', { type: 'checkbox', checked: chosen.indexOf(d) >= 0 }); c.addEventListener('change', function () { var i = chosen.indexOf(d); if (c.checked && i < 0) chosen.push(d); if (!c.checked && i >= 0) chosen.splice(i, 1); }); w.appendChild(el('label', { cls: 'nw' }, c, ' ', t('day_' + d))); });
    return { node: w, val: function () { return chosen.slice(); } };
  }
  function hostPicker(hosts, chosen) {
    chosen = arr(chosen).slice();
    var w = el('div'), box = el('div', { cls: 'scrollbox' }), flt = inp(t('epFilterHosts'));
    var extra = inp(t('epAddHost'));
    function draw() {
      clear(box); var f = flt.value.trim().toUpperCase();
      var all = arr(hosts).slice(); chosen.forEach(function (h) { if (all.indexOf(h) < 0) all.push(h); });
      all.filter(function (h) { return !f || h.indexOf(f) >= 0; }).forEach(function (h) {
        var c = el('input', { type: 'checkbox', checked: chosen.indexOf(h) >= 0 });
        c.addEventListener('change', function () { var i = chosen.indexOf(h); if (c.checked && i < 0) chosen.push(h); if (!c.checked && i >= 0) chosen.splice(i, 1); });
        box.appendChild(el('label', { cls: 'ouRow' }, c, ' ', el('span', { cls: 'mono', text: h })));
      });
      if (!all.length) box.appendChild(el('div', { cls: 'muted', text: t('noAgents') }));
    }
    flt.addEventListener('input', draw);
    extra.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); var h = extra.value.trim().toUpperCase(); if (h && chosen.indexOf(h) < 0) chosen.push(h); extra.value = ''; draw(); } });
    w.appendChild(el('div', { cls: 'row' }, flt, extra)); w.appendChild(box); draw();
    return { node: w, val: function () { return chosen.slice(); } };
  }
  var EP_TEXT = {
    appblock: ['epAppPolicies', 'epAppLead', 'epAppHow', 'epNewApp', 'epNameAppPh'],
    guard: ['epGuardPolicies', 'epGuardLead', 'epGuardHow', 'epNewGuard', 'epNameGuardPh'],
    hardening: ['hdPolicies', 'hdLead', 'hdHow', 'hdNew', 'hdNamePh'],
    patch: ['ptPolicies', 'ptLead', 'ptHow', 'ptNew', 'ptNamePh'],
    applaunch: ['alPolicies', 'alLead', 'alHow', 'alNew', 'alNamePh'],
    appremove: ['arPolicies', 'arLead', 'arHow', 'arNew', 'arNamePh'],
    services: ['svcPolicies', 'svcLead', 'svcHow', 'svcNew', 'svcPolNamePh']
  };
  function scorePill(sc) { if (sc === null || sc === undefined) return pill('none', '—'); return pill(sc >= 80 ? 'OK' : (sc >= 60 ? 'Warn' : 'Fail'), sc + '/100'); }
  // ---- discovered programs with network activity (from agent inventories) -> pick & block
  function appsPanel(r) {
    var c = card(t('apTitle'));
    c.appendChild(el('p', { cls: 'lead', text: t('apLead') }));
    var hs = el('select'); hs.appendChild(el('option', { value: '', text: t('apAllHosts') })); arr(r.hosts).forEach(function (h) { hs.appendChild(el('option', { value: h, text: h })); });
    var only = el('select'); [['inet', 'apOnlyInet'], ['', 'tAll']].forEach(function (o) { only.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
    var q = inp(t('search')), res = el('div'), data = null;
    function refreshFrom() { var hosts = hs.value ? [hs.value] : arr(r.hosts); if (!hosts.length) return; api('/api/agent/action', { hosts: hosts, type: 'inventory', args: {} }).then(function () { flash(t('apRefreshing')); setTimeout(load, 15000); }).catch(fail); }
    function draw() {
      clear(res); if (!data) return;
      var f = q.value.trim().toLowerCase();
      var allc = el('input', { type: 'checkbox' }), boxes = [];
      var rows;
      if (hs.value) {
        var h = arr(data.hosts).filter(function (x) { return x.host === hs.value; })[0];
        var apps = h ? arr(h.apps) : [];
        apps = apps.filter(function (a) { return (!only.value || a.inet > 0) && (!f || a.n.toLowerCase().indexOf(f) >= 0 || (a.p || '').toLowerCase().indexOf(f) >= 0); });
        rows = apps.map(function (a) {
          var ck = el('input', { type: 'checkbox' }); boxes.push({ c: ck, x: a });
          var bb = (data.apps.filter(function (g) { return g.n.toLowerCase() === a.n.toLowerCase(); })[0] || {}).blockedBy;
          return el('tr', null, el('td', null, ck), el('td', null, el('b', { cls: 'mono', text: a.n }), el('div', { cls: 'muted mono', text: a.p || '' })),
            el('td', null, a.inet > 0 ? pill('Fail', t('apInet') + ' · ' + a.inet) : pill('none', t('apLan') + ' · ' + a.c)), el('td', { cls: 'mono muted', text: arr(a.r).join(', ') }),
            el('td', { cls: 'mono', text: a.u || '' }), el('td', null, bb ? pill('OK', t('apBlockedBy') + ' ' + bb) : ''));
        });
        if (h) res.appendChild(el('div', { cls: 'muted', style: 'margin:8px 0 4px' }, el('span', { text: h.host + ' · ' + t('apReported') + ' ' + fmtT(h.at) }), h.ou ? el('span', { cls: 'mono', text: ' · OU: ' + h.ou }) : null, arr(h.groups).length ? el('span', { text: ' · ' + t('adGrp') + ': ' + arr(h.groups).join(', ') }) : null));
        if (!rows.length) rows = [emptyRow(6, t('apNone'))];
        res.appendChild(el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, el('th', null, allc), el('th', { text: t('apProgram') }), el('th', { text: t('apTraffic') }), el('th', { text: t('apRemotes') }), el('th', { text: t('user') }), el('th', { text: t('status') }))), el('tbody', null, rows))));
      } else {
        var g2 = arr(data.apps).filter(function (a) { return (!only.value || arr(a.inetHosts).length) && (!f || a.n.toLowerCase().indexOf(f) >= 0); });
        rows = g2.map(function (a) {
          var ck = el('input', { type: 'checkbox' }); boxes.push({ c: ck, x: a });
          return el('tr', null, el('td', null, ck), el('td', null, el('b', { cls: 'mono', text: a.n }), el('div', { cls: 'muted mono', text: arr(a.paths)[0] || '' })),
            el('td', null, arr(a.inetHosts).length ? pill('Fail', t('apInet') + ' · ' + arr(a.inetHosts).length + ' ' + t('adComp')) : pill('none', t('apLan'))),
            el('td', null, arr(a.hosts).slice(0, 8).map(function (hh) { return el('span', { cls: 'chip' + (arr(a.inetHosts).indexOf(hh) >= 0 ? ' on' : ''), text: hh }); }), arr(a.hosts).length > 8 ? el('span', { cls: 'muted', text: ' +' + (arr(a.hosts).length - 8) }) : null),
            el('td', { cls: 'mono muted', text: arr(a.users).slice(0, 4).join(', ') }), el('td', null, a.blockedBy ? pill('OK', t('apBlockedBy') + ' ' + a.blockedBy) : ''));
        });
        if (!rows.length) rows = [emptyRow(6, t('apNone'))];
        res.appendChild(el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, el('th', null, allc), el('th', { text: t('apProgram') }), el('th', { text: t('apTraffic') }), el('th', { text: t('hosts') }), el('th', { text: t('apUsers') }), el('th', { text: t('status') }))), el('tbody', null, rows))));
      }
      allc.addEventListener('change', function () { boxes.forEach(function (b) { b.c.checked = allc.checked; }); });
      res.appendChild(el('div', { cls: 'acts', style: 'margin-top:8px' }, btn('⛔ ' + t('apBlockSel'), function () {
        var sel = boxes.filter(function (b) { return b.c.checked; }).map(function (b) { return b.x.n; });
        if (!sel.length) { flash(t('apPick'), false); return; }
        var tg = hs.value ? { all: false, hosts: [hs.value], patterns: [], includeServer: false } : { all: true, hosts: [], patterns: [], includeServer: false };
        epDrawer({ type: 'appblock', enabled: true, priority: 0, name: '', targets: tg, settings: { Programs: sel, Scope: 'internet', Users: [], ExceptUsers: [], Schedule: { Enabled: false, Days: [], Start: '08:00', End: '17:00' } } }, 'appblock', r, true);
      }, 'pri sm'), el('span', { cls: 'muted', text: t('apBlockHint') })));
    }
    function load() { clear(res).appendChild(spinner()); api('/api/endpoint/apps', { host: hs.value }).then(function (x) { data = x; draw(); }).catch(function (e) { clear(res); fail(e); }); }
    hs.addEventListener('change', load); only.addEventListener('change', draw); q.addEventListener('input', draw);
    c.appendChild(el('div', { cls: 'row' }, el('span', { cls: 'muted', text: t('host') }), hs, only, q, btn('↻ ' + t('apRefresh'), refreshFrom, 'sm')));
    c.appendChild(res); load();
    return c;
  }
  function epFleet(box) {
    box.appendChild(spinner());
    api('/api/endpoint/fleet').then(function (f) {
      clear(box);
      var items = arr(f.items);
      box.appendChild(el('div', { cls: 'kpis' },
        el('div', { cls: 'kpi' }, el('div', { cls: 'v num', text: f.avgScore === null || f.avgScore === undefined ? '—' : f.avgScore }), el('div', { cls: 'l', text: t('flAvg') })),
        el('div', { cls: 'kpi' }, el('div', { cls: 'v num', style: 'color:var(--crit)', text: items.filter(function (x) { return x.score !== null && x.score < 60; }).length }), el('div', { cls: 'l', text: t('flWeak') })),
        el('div', { cls: 'kpi' }, el('div', { cls: 'v num', style: 'color:var(--warn)', text: f.missingTotal || 0 }), el('div', { cls: 'l', text: t('flMissing') })),
        el('div', { cls: 'kpi' }, el('div', { cls: 'v num', text: items.filter(function (x) { return x.reboot; }).length }), el('div', { cls: 'l', text: t('adReboot') }))));
      var c = card(t('epTabFleet'), el('span', { cls: 'row' },
        btn(t('flScanAll'), function () { var hs = items.map(function (x) { return x.host; }); if (!hs.length) return; api('/api/agent/action', { hosts: hs, type: 'posture-scan', args: {} }).then(function () { return api('/api/agent/action', { hosts: hs, type: 'patch-scan', args: {} }); }).then(function () { flash(t('acQueued')); }).catch(fail); }, 'sm'),
        btn(t('flInstallAll'), function () { var hs = items.filter(function (x) { return x.security > 0; }).map(function (x) { return x.host; }); if (!hs.length) { flash(t('flNothing')); return; } if (!window.confirm(t('flInstallQ').replace('{n}', hs.length))) return; api('/api/agent/action', { hosts: hs, type: 'install-updates', args: { scope: 'security', reboot: 'never' } }).then(function (x) { flash(t('acQueued') + ' (' + x.queued + ')'); }).catch(fail); }, 'sm pri')));
      c.appendChild(el('p', { cls: 'lead', text: t('flLead') }));
      var ct = {}; arr(f.postureChecks).forEach(function (x) { ct[x.id] = x.title; });
      var rows = items.map(function (x) {
        return el('tr', { cls: 'clk', onclick: function () { agentDrawer(x.host, 'security'); } },
          el('td', null, el('b', { cls: 'mono', text: x.host }), el('div', { cls: 'muted', text: x.os || '' })),
          el('td', null, scorePill(x.score)),
          el('td', null, arr(x.failed).slice(0, 4).map(function (id) { return el('span', { cls: 'chip', text: ct[id] || id }); }), arr(x.failed).length > 4 ? el('span', { cls: 'muted', text: ' +' + (arr(x.failed).length - 4) }) : null),
          el('td', null, x.patchError ? el('span', { cls: 'why', text: x.patchError }) : (x.missing ? pill(x.security ? 'Fail' : 'Warn', x.missing + (x.security ? ' (' + x.security + ' ' + t('flSec') + ')' : '')) : pill('OK', '0'))),
          el('td', { cls: 'num muted nw', text: fmtT(x.patchAt || x.postureAt) }),
          el('td', null, x.reboot ? pill('Warn', t('yes')) : ''));
      });
      if (!rows.length) rows = [emptyRow(6, t('flNoData'))];
      c.appendChild(table([t('host'), t('flScore'), t('flFailed'), t('flUpdates'), t('updated'), t('adReboot')], rows));
      box.appendChild(c);
    }).catch(function (e) { clear(box); fail(e); });
  }
  function postureTab(pane, x, name, reload) {
    var po = x.posture && x.posture.Data;
    if (!po) { pane.appendChild(el('div', { cls: 'muted', text: t('psNone') })); pane.appendChild(el('div', { cls: 'acts', style: 'margin-top:8px' }, btn(t('psScan'), function () { runAction([name], 'posture-scan', reload); }, 'sm'))); return; }
    var bad = arr(po.checks).filter(function (c) { return c.ok === false; });
    var fixable = bad.filter(function (c) { return c.fix; }).map(function (c) { return c.id; });
    pane.appendChild(el('div', { cls: 'row', style: 'margin-bottom:10px' }, el('span', null, t('flScore') + ': '), scorePill(po.score), el('span', { cls: 'muted', text: ' · ' + fmtT(x.posture.At) }),
      btn(t('psScan'), function () { runAction([name], 'posture-scan', reload); }, 'sm'),
      fixable.length ? btn(t('psFixAll') + ' (' + fixable.length + ')', function () { if (!window.confirm(t('psFixQ'))) return; api('/api/agent/action', { hosts: [name], type: 'fix-posture', args: { checks: fixable } }).then(function () { flash(t('acQueued')); reload(); }).catch(fail); }, 'sm pri') : null));
    if (po.enforced) pane.appendChild(el('div', { cls: 'note', text: t('psEnforced') + ': ' + po.enforced }));
    var en = x.lang === 'en';
    var rows = arr(po.checks).map(function (c) {
      return el('tr', null, el('td', null, c.ok === true ? pill('OK', '✓') : (c.ok === false ? pill(c.sev === 'high' ? 'Fail' : 'Warn', '✕') : pill('none', '—'))),
        el('td', { text: en ? c.en : c.fa }), el('td', { cls: 'muted', text: t('sv_' + c.sev) }), el('td', { cls: 'mono muted', text: c.val }),
        el('td', null, c.ok === false ? (c.fix ? btn(en ? c.fixEn : c.fixFa, function () { api('/api/agent/action', { hosts: [name], type: 'fix-posture', args: { checks: [c.id] } }).then(function () { flash(t('acQueued')); reload(); }).catch(fail); }, 'sm') : el('span', { cls: 'muted', text: en ? c.fixEn : c.fixFa })) : ''));
    });
    pane.appendChild(table(['', t('psCheck'), t('psSev'), t('psValue'), t('psFix')], rows));
  }
  function updatesTab(pane, x, name, reload) {
    var pd = x.patches && x.patches.Data;
    var rb = el('select'); [['never', 'ptRebootNever'], ['if-needed', 'ptRebootAuto']].forEach(function (o) { rb.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
    function inst(scope) { if (!window.confirm(t('upInstallQ'))) return; api('/api/agent/action', { hosts: [name], type: 'install-updates', args: { scope: scope, reboot: rb.value } }).then(function () { flash(t('acQueued')); reload(); }).catch(fail); }
    pane.appendChild(el('div', { cls: 'row', style: 'margin-bottom:10px' }, btn(t('upScan'), function () { runAction([name], 'patch-scan', reload); }, 'sm'), btn(t('upInstallSec'), function () { inst('security'); }, 'sm pri'), btn(t('upInstallAll'), function () { inst('all'); }, 'sm'), el('span', { cls: 'muted', text: t('ptReboot') + ':' }), rb));
    if (!pd) { pane.appendChild(el('div', { cls: 'muted', text: t('upNone') })); return; }
    if (pd.error) pane.appendChild(el('div', { cls: 'flash err', text: pd.error }));
    var li = pd.lastInstall;
    if (li) pane.appendChild(el('div', { cls: 'note', text: t('upLast') + ': ' + fmtT(li.at) + ' · ' + li.ok + ' ✓ · ' + li.failed + ' ✕' + (li.rebootRequired ? ' · ' + t('adReboot') : '') }));
    pane.appendChild(el('div', { cls: 'muted', style: 'margin:6px 0', text: arr(pd.missing).length + ' ' + t('upMissing') + ' · ' + fmtT(pd.at) }));
    var rows = arr(pd.missing).map(function (u) { return el('tr', null, el('td', { cls: 'mono', text: u.kb }), el('td', { cls: 'wrap', text: u.title }), el('td', null, u.security ? pill('Fail', u.sev || t('flSec')) : el('span', { cls: 'muted', text: u.sev })), el('td', { cls: 'num muted', text: u.date }), el('td', { cls: 'num', text: u.sizeMB ? u.sizeMB + ' MB' : '' }), el('td', { text: u.reboot ? '↻' : '' })); });
    if (!rows.length) rows = [emptyRow(6, t('upAllGood'))];
    pane.appendChild(table(['KB', t('upTitle'), t('psSev'), t('upDate'), t('adSize'), '']
      , rows));
  }
  // repeatable rows for the Services policy: service name + startup + desired state
  function svcRows(existing) {
    var rows = el('div');
    function addRow(v) {
      v = v || { Name: '', Startup: 'disabled', State: 'stopped' };
      var nm = el('input', { type: 'text', placeholder: t('svcNamePh'), value: v.Name || '', style: 'min-width:200px' });
      var su = el('select'); [['leave', 'svcLeave'], ['auto', 'svcAuto'], ['delayed', 'svcDelayed'], ['manual', 'svcManual'], ['disabled', 'svcDisabled']].forEach(function (o) { su.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (v.Startup || 'disabled') === o[0] ? 'selected' : null })); });
      var stt = el('select'); [['leave', 'svcLeave'], ['running', 'svcRunning'], ['stopped', 'svcStopped']].forEach(function (o) { stt.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (v.State || 'stopped') === o[0] ? 'selected' : null })); });
      var row = el('div', { cls: 'row', style: 'margin-bottom:6px' });
      var rm = el('a', { href: '#', cls: 'chip', text: '✕', onclick: function (e) { e.preventDefault(); if (row.parentNode) row.parentNode.removeChild(row); } });
      row.appendChild(nm); row.appendChild(su); row.appendChild(stt); row.appendChild(rm);
      row._val = function () { return { Name: nm.value.trim(), Startup: su.value, State: stt.value }; };
      rows.appendChild(row);
    }
    arr(existing).forEach(addRow); if (!arr(existing).length) addRow();
    var w = el('div', null, rows, btn('+ ' + t('svcAdd'), function () { addRow(); }, 'sm'));
    return { node: w, val: function () { return Array.prototype.map.call(rows.children, function (r) { return r._val(); }).filter(function (x) { return x.Name; }); } };
  }
  function vEndpoints(sub) {
    if (sub && sub[0]) epTab = sub[0];
    var v = page(t('nProtect'), t('epLead'));
    var tabs = el('div', { cls: 'tabs' });
    [['fleet', 'epTabFleet'], ['appblock', 'epTabApp'], ['applaunch', 'epTabLaunch'], ['appremove', 'epTabRemove'], ['services', 'epTabServices'], ['guard', 'epTabGuard'], ['hardening', 'epTabHarden'], ['patch', 'epTabPatch'], ['status', 'epTabStatus']].forEach(function (x) {
      tabs.appendChild(el('button', { type: 'button', cls: epTab === x[0] ? 'on' : '', text: t(x[1]), onclick: function () { epTab = x[0]; try { history.replaceState(null, '', '#/endpoints/' + x[0]); } catch (e) { } vEndpoints(); } }));
    });
    v.appendChild(tabs);
    var box = el('div'); v.appendChild(box); box.appendChild(spinner());
    api('/api/endpoint/policies').then(function (r) {
      clear(box);
      if (!arr(r.hosts).length) box.appendChild(el('div', { cls: 'banner' }, el('span', { text: t('epNoAgents') }), btn(t('agents'), function () { go('deploy'); }, 'sm')));
      if (epTab === 'status') { epStatus(box, r); return; }
      if (epTab === 'fleet') { epFleet(box); return; }
      var ty = epTab, list = arr(r.items).filter(function (p) { return p.type === ty; });
      var TT = EP_TEXT[ty] || EP_TEXT.appblock;
      if (ty === 'appblock') box.appendChild(appsPanel(r));
      if (ty === 'guard') { guardInto(box); box.appendChild(el('h3', { cls: 'sech', text: t('guardOthers') })); }
      var c = card(t(TT[0]), btn('+ ' + t('epNew'), function () { epDrawer(null, ty, r); }, 'pri sm'));
      c.appendChild(el('p', { cls: 'lead', text: t(TT[1]) }));
      var rows = list.map(function (p) {
        var s = p.settings || {}, what;
        if (ty === 'appblock') {
          what = el('div', null, arr(s.Programs).map(function (x) { return el('span', { cls: 'chip on mono', text: x }); }),
            el('div', { cls: 'muted', text: (s.Scope === 'all' ? t('epScopeAll') : t('epScopeInet')) + (s.Schedule && s.Schedule.Enabled ? ' · ⏱ ' + s.Schedule.Start + '–' + s.Schedule.End : ' · ' + t('epAlways')) }),
            (arr(s.Users).length || arr(s.ExceptUsers).length) ? el('div', { cls: 'muted' }, '👤 ', arr(s.Users).length ? t('abOnly') + ' ' + arr(s.Users).join(', ') : t('abEveryoneExcept') + ' ' + arr(s.ExceptUsers).join(', ')) : null);
        } else if (ty === 'applaunch') {
          var modeC = s.Mode === 'block' ? 'Fail' : (s.Mode === 'warn' ? 'Warn' : 'none');
          what = el('div', null, pill(modeC, t('al_' + (s.Mode || 'block'))), ' ', el('span', { cls: 'muted', text: t(s.List === 'allowlist' ? 'alAllowOnly' : 'alBlockList') }),
            el('div', null, arr(s.Programs).map(function (x) { return el('span', { cls: 'chip on mono', text: x }); })));
        } else if (ty === 'appremove') {
          what = el('div', null, arr(s.Programs).map(function (x) { return el('span', { cls: 'chip on mono', text: x }); }), el('div', { cls: 'muted', text: t('arRemovesNote') }));
        } else if (ty === 'services') {
          what = el('div', null, arr(s.Services).map(function (x) { return el('span', { cls: 'chip on mono', text: x.Name + (x.Startup && x.Startup !== 'leave' ? ' · ' + x.Startup : '') + (x.State && x.State !== 'leave' ? ' · ' + x.State : '') }); }));
        } else if (ty === 'hardening') {
          var ct = {}; arr(r.postureChecks).forEach(function (x) { ct[x.id] = x.title; });
          what = el('div', null, arr(s.Checks).map(function (x) { return el('span', { cls: 'chip on', text: ct[x] || x }); }));
        } else if (ty === 'patch') {
          what = el('div', null, el('span', { text: (s.Scope === 'all' ? t('ptAll') : t('ptSec')) + ' · ' + (arr(s.Days).length ? arr(s.Days).map(function (x) { return t('day_' + x); }).join(' ') : t('epEveryDay')) + ' · ' + String(s.Hour || 0).padStart(2, '0') + ':00' }),
            el('div', { cls: 'muted', text: s.Reboot === 'if-needed' ? t('ptRebootAuto') : t('ptRebootNever') }));
        } else {
          var pr = s.Protect || {};
          what = el('div', null, s.Enabled === false ? pill('Fail', t('epGuardOff')) : el('span', { text: (s.MaxFailedAttempts || 5) + ' / ' + (s.AttemptWindowMinutes || 10) + ' min → ' + (s.BlockMinutes || 20) + ' min' }),
            el('div', null, ['RDP', 'WindowsLogon', 'SQL', 'FTP', 'Web', 'SSH'].map(function (k) { return el('span', { cls: 'chip' + (pr[k] !== false ? ' on' : ''), text: k }); })),
            s.GeoMode && s.GeoMode !== 'Off' ? el('div', { cls: 'muted', text: 'Geo: ' + s.GeoMode + ' ' + arr(s.GeoMode === 'AllowOnly' ? s.AllowedCountries : s.BlockedCountries).join(',') }) : null,
            s.WorkHours && s.WorkHours.Enabled ? el('div', { cls: 'muted', text: '⏱ ' + s.WorkHours.Start + '–' + s.WorkHours.End }) : null);
        }
        var tot = arr(p.hosts).length;
        return el('tr', { cls: 'clk', onclick: function () { epDrawer(p, ty, r); } },
          el('td', null, el('b', { text: p.name }), p.note ? el('div', { cls: 'note', text: p.note }) : null, p.enabled ? null : el('div', null, pill('none', t('disabled')))),
          el('td', null, what), (ty === 'guard' || ty === 'patch' || ty === 'applaunch') ? el('td', { cls: 'num', text: p.priority || 0 }) : null,
          el('td', { text: targetText(p) }),
          el('td', null, tot ? pill(p.applied === tot ? 'OK' : 'Warn', p.applied + ' / ' + tot) : el('span', { cls: 'muted', text: p.targets && p.targets.includeServer ? t('epServerSelf') : '0' })),
          el('td', { cls: 'num muted nw', text: fmtT(p.updated) + (p.by ? ' · ' + p.by : '') }));
      });
      var pc = (ty === 'guard' || ty === 'patch' || ty === 'applaunch');
      if (!rows.length) rows = [emptyRow(pc ? 6 : 5, t('epNone'))];
      var heads = pc ? [t('name'), t('epSettings'), t('epPriority'), t('epTargets'), t('epApplied'), t('updated')] : [t('name'), (ty === 'appblock' || ty === 'appremove') ? t('epPrograms') : t('epSettings'), t('epTargets'), t('epApplied'), t('updated')];
      c.appendChild(table(heads, rows));
      box.appendChild(c);
      box.appendChild(el('div', { cls: 'note', text: t(TT[2]) }));
    }).catch(function (e) { clear(box); fail(e); });
  }
  function epStatus(box, r) {
    var c = card(t('epTabStatus'), btn(t('refresh'), function () { vEndpoints(); }, 'sm'));
    var rows = arr(r.status).map(function (s) {
      var progs = arr(s.items).map(function (i) { return el('span', { cls: 'chip' + (i.active ? ' on' : ''), title: arr(i.paths).join('\n') || t('epNotFound'), text: i.program + (arr(i.paths).length ? ' ×' + arr(i.paths).length : ' ?') }); });
      return el('tr', { cls: 'clk', onclick: function () { agentDrawer(s.host); } },
        el('td', null, el('b', { cls: 'mono', text: s.host })),
        el('td', null, arr(s.appBlocks).join(', ') || '—', progs.length ? el('div', null, progs) : null),
        el('td', { text: s.guard || t('epGuardDefault') }),
        el('td', { cls: 'mono', text: s.appLaunch || '—' }),
        el('td', null, !s.want ? '—' : (s.applied ? pill('OK', t('epAppliedOk')) : pill('Warn', s.have ? t('epPendingSync') : t('epNeverSynced')))),
        el('td', { cls: 'num', text: s.rules || 0 }),
        el('td', { cls: arr(s.errors).length ? 'why' : 'muted', text: arr(s.errors).join(' · ') || '' }),
        el('td', { cls: 'num muted nw', text: fmtT(s.at) }));
    });
    if (!rows.length) rows = [emptyRow(8, t('noAgents'))];
    c.appendChild(table([t('host'), t('epTabApp'), t('epTabGuard'), t('epTabLaunch'), t('status'), t('epRules'), t('message'), t('updated')], rows));
    box.appendChild(c);
    if (r.server && r.server.applied) box.appendChild(el('div', { cls: 'note', text: t('epServerSelf') + ' (' + r.server.name + '): ' + t('epRules') + ' ' + r.server.applied.rules + ' · ' + fmtT(r.server.applied.at) }));
  }
  function numIn(v, min, max) { return el('input', { type: 'number', min: min, max: max, value: (v === undefined || v === null) ? '' : v, style: 'width:110px' }); }
  function epDrawer(p, ty, r, draft) {
    var isNew = !p || draft;
    p = p || { type: ty, enabled: true, priority: 0, targets: { all: false, hosts: [], patterns: [], includeServer: false }, settings: ty === 'applaunch' ? { Programs: [], Mode: 'block', List: 'blocklist', WarnText: '' } : ty === 'hardening' ? { Checks: ['fw-on', 'av-rt', 'smb1', 'rdp-nla', 'uac', 'guest', 'autorun', 'wdigest', 'wuauserv', 'audit-logon'] } : ty === 'patch' ? { Scope: 'security', Days: ['Thursday'], Hour: 13, Reboot: 'never' } : ty === 'services' ? { Services: [] } : ty === 'appremove' ? { Programs: [], Note: '' } : ty === 'appblock' ? { Programs: [], Scope: 'internet', Schedule: { Enabled: false, Days: [], Start: '08:00', End: '17:00' } } : { Enabled: true, MaxFailedAttempts: 5, AttemptWindowMinutes: 10, BlockMinutes: 20, EscalationFactor: 3, PermanentAfterBlocks: 3, Protect: { RDP: true, WindowsLogon: true, SQL: true, FTP: true, Web: true, SSH: true }, AutoWhitelistLan: true, Whitelist: [], Blacklist: [], GeoMode: 'Off', AllowedCountries: ['IR'], BlockedCountries: [], WorkHours: { Enabled: false, Days: ['Saturday', 'Sunday', 'Monday', 'Tuesday', 'Wednesday'], Start: '08:00', End: '17:00' } } };
    var s = p.settings || {}, tg = p.targets || {};
    openDrawer(function (d) {
      var TT = EP_TEXT[ty] || EP_TEXT.appblock;
      drawerHead(d, el('span', { text: isNew ? t(TT[3]) : p.name }));
      var nm = inp(t(TT[4]), 'text', p.name || ''), en = el('input', { type: 'checkbox', checked: p.enabled !== false });
      var note = el('textarea', { rows: 2, placeholder: t('epNotePh') }); note.value = p.note || '';
      var all = el('input', { type: 'checkbox', checked: !!tg.all }), srv = el('input', { type: 'checkbox', checked: !!tg.includeServer });
      var hp = hostPicker(r.hosts, tg.hosts), pat = inp('PC-*, SRV-??', 'text', arr(tg.patterns).join(', '));
      var exHp = hostPicker(r.hosts, tg.exceptHosts), exPat = inp('*-TEST, LAB-*', 'text', arr(tg.exceptPatterns).join(', '));
      var ouI = ouPicker(tg.ous), ouX = ouPicker(tg.exceptOus), grI = groupPicker(tg.groups), grX = groupPicker(tg.exceptGroups);
      if (!arr(S.ad.domains).length) { api('/api/ad/domains').then(function (x) { S.ad.domains = arr(x.items); if (!S.ad.domainId && S.ad.domains.length) adSetDomain(S.ad.domains[0].id); }).catch(function () { }); }
      var f = el('div', { cls: 'form' },
        el('label', { text: t('name') }), nm, el('label', null, ''), el('label', null, en, ' ', t('enabled')),
        el('label', { text: t('notes') }), note);
      d.appendChild(f);
      // ---- one frame: who gets this policy (include) | who is excluded (except) — computers, AD OUs/groups, users
      function tgRow(label, incNode, excNode) { return el('div', { cls: 'tgrow' }, el('div', { cls: 'tgl', text: label }), el('div', { cls: 'tgi' }, incNode), el('div', { cls: 'tgx' }, excNode)); }
      var tgf = el('div', { cls: 'tgframe' },
        el('div', { cls: 'tghead' }, el('div', { cls: 'tgl', text: t('epTargets') }), el('div', { cls: 'tgi', text: '✓ ' + t('tgApplyTo') }), el('div', { cls: 'tgx', text: '✕ ' + t('tgExcept') })),
        el('div', { cls: 'tgsec', text: t('tgComputers') }),
        tgRow(t('tAll'), el('label', null, all, ' ', t('epAllAgents')), el('span', { cls: 'muted', text: '—' })),
        tgRow(t('epChooseHosts'), hp.node, exHp.node),
        tgRow(t('epPatterns'), el('div', null, pat, el('div', { cls: 'hint2', text: t('epPatternsHint') })), exPat),
        tgRow(t('epServerSelf'), el('label', null, srv, ' ', (r.server && r.server.name) || ''), el('span', { cls: 'muted', text: '—' })),
        el('div', { cls: 'tgsec', text: t('tgAd') + ' ' + (arr(S.ad.domains).length ? '' : '(' + t('adNoDomainShort') + ')') }),
        tgRow('OU', ouI.node, ouX.node),
        tgRow(t('tgAdGroups'), grI.node, grX.node),
        el('div', { cls: 'hint2', text: t('tgAdHint') }));
      d.appendChild(tgf);
      var getS;
      if (ty === 'appblock') {
        var progs = el('textarea', { rows: 4, cls: 'mono', placeholder: 'chrome.exe\nTelegram.exe\nC:\\Program Files\\App\\app.exe' }); progs.value = arr(s.Programs).join('\n');
        var quick = el('div', { cls: 'row' }, COMMON_APPS.map(function (a) { return el('a', { href: '#', cls: 'chip', text: '+ ' + a, onclick: function (e) { e.preventDefault(); var l = splitList(progs.value); if (l.indexOf(a) < 0) { l.push(a); progs.value = l.join('\n'); } } }); }));
        var sc = el('select'); [['internet', 'epScopeInet'], ['all', 'epScopeAll']].forEach(function (o) { sc.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (s.Scope || 'internet') === o[0] ? 'selected' : null })); });
        var sch = s.Schedule || {}, se = el('input', { type: 'checkbox', checked: !!sch.Enabled }), dp = dayPicker(sch.Days), st = el('input', { type: 'time', value: sch.Start || '08:00' }), et = el('input', { type: 'time', value: sch.End || '17:00' });
        var ausers = el('textarea', { rows: 2, cls: 'mono', placeholder: 'DOMAIN\\ali\nAccounting' }); ausers.value = arr(s.Users).join('\n');
        var axusers = el('textarea', { rows: 2, cls: 'mono', placeholder: 'DOMAIN\\admin\nIT' }); axusers.value = arr(s.ExceptUsers).join('\n');
        tgf.appendChild(el('div', { cls: 'tgsec', text: t('abWho') }));
        tgf.appendChild(tgRow(t('tgUsersGroups'), el('div', null, ausers, el('div', { cls: 'hint2', text: t('abUsersHint') })), el('div', null, axusers, el('div', { cls: 'hint2', text: t('abExceptHint') }))));
        d.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' },
          el('div', { cls: 'full' }, el('h4', { text: t('epPrograms') })),
          el('label', { text: t('epPrograms') }), progs, el('div', { cls: 'hint', text: t('epProgramsHint') }),
          el('label', { text: t('epQuick') }), quick,
          el('label', { text: t('epScope') }), sc,
          el('div', { cls: 'full' }, el('h4', { text: t('epSchedule') })),
          el('label', null, ''), el('label', null, se, ' ', t('epScheduleOn')),
          el('label', { text: t('epDays') }), dp.node, el('div', { cls: 'hint', text: t('epDaysHint') }),
          el('label', { text: t('epFromTo') }), el('div', { cls: 'row' }, st, '–', et)));
        getS = function () { return { Programs: splitList(progs.value), Scope: sc.value, Users: splitList(ausers.value), ExceptUsers: splitList(axusers.value), Schedule: { Enabled: se.checked, Days: dp.val(), Start: st.value, End: et.value } }; };
      } else if (ty === 'applaunch') {
        var lprogs = el('textarea', { rows: 4, cls: 'mono', placeholder: 'AnyDesk.exe\nTelegram.exe\nC:\\Tools\\thing.exe' }); lprogs.value = arr(s.Programs).join('\n');
        var lquick = el('div', { cls: 'row' }, COMMON_APPS.map(function (a) { return el('a', { href: '#', cls: 'chip', text: '+ ' + a, onclick: function (e) { e.preventDefault(); var l = splitList(lprogs.value); if (l.indexOf(a) < 0) { l.push(a); lprogs.value = l.join('\n'); } } }); }));
        var lmode = el('select'); [['block', 'al_block'], ['warn', 'al_warn'], ['audit', 'al_audit']].forEach(function (o) { lmode.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (s.Mode || 'block') === o[0] ? 'selected' : null })); });
        var llist = el('select'); [['blocklist', 'alBlockList'], ['allowlist', 'alAllowOnly']].forEach(function (o) { llist.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (s.List || 'blocklist') === o[0] ? 'selected' : null })); });
        var lpri = numIn(p.priority || 0, 0, 1000);
        var lwarn = inp(t('alWarnPh'), 'text', s.WarnText || '');
        var warnRow = el('div', { cls: 'full' });
        function syncWarn() { clear(warnRow); if (lmode.value === 'warn') { warnRow.appendChild(el('div', { cls: 'form' }, el('label', { text: t('alWarnText') }), lwarn)); } }
        lmode.addEventListener('change', syncWarn);
        var modeHint = el('div', { cls: 'hint' });
        function syncHint() { modeHint.textContent = t('alModeHint_' + lmode.value); }
        lmode.addEventListener('change', syncHint); syncHint();
        d.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' },
          el('div', { cls: 'full' }, el('h4', { text: t('alHow2') })),
          el('label', { text: t('alMode') }), lmode, modeHint,
          el('label', { text: t('alList') }), llist, el('div', { cls: 'hint', text: t('alListHint') }),
          el('label', { text: t('epPrograms') }), lprogs, el('div', { cls: 'hint', text: t('alProgramsHint') }),
          el('label', { text: t('epQuick') }), lquick,
          el('label', { text: t('epPriority') }), lpri));
        d.appendChild(warnRow); syncWarn();
        getS = function () { return { Programs: splitList(lprogs.value), Mode: lmode.value, List: llist.value, WarnText: lwarn.value.trim() }; };
        p._pri = lpri;
      } else if (ty === 'appremove') {
        var rprogs = el('textarea', { rows: 4, cls: 'mono', placeholder: 'OneDrive\nCopilot\nMicrosoft.ZuneMusic' }); rprogs.value = arr(s.Programs).join('\n');
        var rquick = el('div', { cls: 'row' }, ['OneDrive', 'Copilot'].map(function (a) { return el('a', { href: '#', cls: 'chip', text: '+ ' + a, onclick: function (e) { e.preventDefault(); var l = splitList(rprogs.value); if (l.indexOf(a) < 0) { l.push(a); rprogs.value = l.join('\n'); } } }); }));
        d.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' },
          el('div', { cls: 'full' }, el('h4', { text: t('arHead') })),
          el('div', { cls: 'full' }, el('div', { cls: 'tipbar', text: t('arWarn') })),
          el('label', { text: t('arApps') }), rprogs, el('div', { cls: 'hint', text: t('arAppsHint') }),
          el('label', { text: t('epQuick') }), rquick));
        getS = function () { return { Programs: splitList(rprogs.value) }; };
      } else if (ty === 'services') {
        var svc = svcRows(s.Services);
        d.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' },
          el('div', { cls: 'full' }, el('h4', { text: t('svcHead') })),
          el('div', { cls: 'full' }, el('div', { cls: 'hint', text: t('svcHint') })),
          el('div', { cls: 'full' }, svc.node)));
        getS = function () { return { Services: svc.val() }; };
      } else if (ty === 'hardening') {
        var chosen = arr(s.Checks).slice(), cb = el('div', { cls: 'scrollbox', style: 'max-height:none' });
        arr(r.postureChecks).filter(function (x) { return x.fix; }).forEach(function (x) {
          var ck = el('input', { type: 'checkbox', checked: chosen.indexOf(x.id) >= 0 });
          ck.addEventListener('change', function () { var i = chosen.indexOf(x.id); if (ck.checked && i < 0) chosen.push(x.id); if (!ck.checked && i >= 0) chosen.splice(i, 1); });
          cb.appendChild(el('label', { cls: 'ouRow' }, ck, ' ', x.title, ' ', el('span', { cls: 'chip' + (x.sev === 'high' ? ' on' : ''), text: t('sv_' + x.sev) })));
        });
        d.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' }, el('div', { cls: 'full' }, el('h4', { text: t('hdChecks') })), el('div', { cls: 'full' }, cb), el('div', { cls: 'full note', text: t('hdNote') })));
        getS = function () { return { Checks: chosen }; };
      } else if (ty === 'patch') {
        var psc = el('select'); [['security', 'ptSec'], ['all', 'ptAll']].forEach(function (o) { psc.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (s.Scope || 'security') === o[0] ? 'selected' : null })); });
        var pdp = dayPicker(s.Days), phr = el('select'); for (var hh = 0; hh < 24; hh++) phr.appendChild(el('option', { value: hh, text: String(hh).padStart(2, '0') + ':00', selected: +s.Hour === hh ? 'selected' : null }));
        var prb = el('select'); [['never', 'ptRebootNever'], ['if-needed', 'ptRebootAuto']].forEach(function (o) { prb.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (s.Reboot || 'never') === o[0] ? 'selected' : null })); });
        var ppri = numIn(p.priority || 0, 0, 1000);
        d.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' }, el('div', { cls: 'full' }, el('h4', { text: t('ptWindow') })),
          el('label', { text: t('ptScope') }), psc, el('label', { text: t('epDays') }), pdp.node, el('div', { cls: 'hint', text: t('epDaysHint') }),
          el('label', { text: t('ptHour') }), phr, el('div', { cls: 'hint', text: t('ptHourHint') }), el('label', { text: t('ptReboot') }), prb,
          el('label', { text: t('epPriority') }), ppri, el('div', { cls: 'full note', text: t('ptNote') })));
        getS = function () { return { Scope: psc.value, Days: pdp.val(), Hour: +phr.value, Reboot: prb.value }; };
        p._pri = ppri;
      } else {
        var ge = el('input', { type: 'checkbox', checked: s.Enabled !== false }), pri = numIn(p.priority || 0, 0, 1000);
        function dv(x, d) { return (x === undefined || x === null || x === '') ? d : x; }
        var mx = numIn(dv(s.MaxFailedAttempts, 5), 1, 1000), wn = numIn(dv(s.AttemptWindowMinutes, 10), 1, 1440), bm = numIn(dv(s.BlockMinutes, 20), 1, 43200), ef = numIn(dv(s.EscalationFactor, 3), 1, 100), pa = numIn(dv(s.PermanentAfterBlocks, 3), 0, 100), wm = numIn(dv(s.WebMaxFailures, 20), 1, 10000);
        var pr = s.Protect || {}, pc = {}, prow = el('div', { cls: 'row' });
        ['RDP', 'WindowsLogon', 'SQL', 'FTP', 'Web', 'SSH'].forEach(function (k) { pc[k] = el('input', { type: 'checkbox', checked: pr[k] !== false }); prow.appendChild(el('label', { cls: 'nw' }, pc[k], ' ', k)); });
        var lan = el('input', { type: 'checkbox', checked: s.AutoWhitelistLan !== false });
        var wl = el('textarea', { rows: 2, cls: 'mono', placeholder: '5.6.7.8\n10.0.0.0/8' }); wl.value = arr(s.Whitelist).join('\n');
        var bl = el('textarea', { rows: 2, cls: 'mono', placeholder: '203.0.113.0/24' }); bl.value = arr(s.Blacklist).join('\n');
        var gm = el('select'); [['Off', 'geoOff'], ['AllowOnly', 'geoAllow'], ['BlockListed', 'geoBlock']].forEach(function (o) { gm.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (s.GeoMode || 'Off') === o[0] ? 'selected' : null })); });
        var ac = inp('IR', 'text', arr(s.AllowedCountries).join(', ')), bc = inp('CN, RU', 'text', arr(s.BlockedCountries).join(', '));
        var wh = s.WorkHours || {}, we = el('input', { type: 'checkbox', checked: !!wh.Enabled }), wd = dayPicker(wh.Days), ws = el('input', { type: 'time', value: wh.Start || '08:00' }), wt = el('input', { type: 'time', value: wh.End || '17:00' });
        d.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' },
          el('div', { cls: 'full' }, el('h4', { text: t('epGuardSet') })),
          el('label', null, ''), el('label', null, ge, ' ', t('epGuardOn')),
          el('label', { text: t('epPriority') }), pri, el('div', { cls: 'hint', text: t('epPriorityHint') }),
          el('label', { text: t('gMax') }), el('div', { cls: 'row' }, mx, ' / ', wn, ' ' + t('epMin')),
          el('label', { text: t('gBlock') }), el('div', { cls: 'row' }, bm, ' ' + t('epMin') + ' · ×', ef),
          el('label', { text: t('gPerm') }), pa,
          el('label', { text: t('epWebMax') }), wm,
          el('label', { text: t('epProtect') }), prow,
          el('label', null, ''), el('label', null, lan, ' ', t('epLan')),
          el('label', { text: t('whitelist') }), wl, el('label', { text: t('blacklist') }), bl,
          el('label', { text: t('gGeo') }), gm, el('label', { text: t('epAllowedC') }), ac, el('label', { text: t('epBlockedC') }), bc,
          el('div', { cls: 'full' }, el('h4', { text: t('epWorkHours') })),
          el('label', null, ''), el('label', null, we, ' ', t('epWorkHoursOn')),
          el('label', { text: t('epDays') }), wd.node,
          el('label', { text: t('epFromTo') }), el('div', { cls: 'row' }, ws, '–', wt)));
        getS = function () {
          var pp = {}; for (var k in pc) pp[k] = pc[k].checked;
          return { Enabled: ge.checked, MaxFailedAttempts: mx.value, AttemptWindowMinutes: wn.value, BlockMinutes: bm.value, EscalationFactor: ef.value, PermanentAfterBlocks: pa.value, WebMaxFailures: wm.value, Protect: pp, AutoWhitelistLan: lan.checked,
                   Whitelist: splitList(wl.value), Blacklist: splitList(bl.value), GeoMode: gm.value, AllowedCountries: splitList(ac.value), BlockedCountries: splitList(bc.value), WorkHours: { Enabled: we.checked, Days: wd.val(), Start: ws.value, End: wt.value } };
        };
        p._pri = pri;
      }
      function body() { return { id: p.id || '', type: ty, name: nm.value.trim(), enabled: en.checked, note: note.value.trim(), priority: p._pri ? (+p._pri.value || 0) : 0, targets: { all: all.checked, hosts: hp.val(), patterns: splitList(pat.value), includeServer: srv.checked, exceptHosts: exHp.val(), exceptPatterns: splitList(exPat.value), ous: ouI.val(), exceptOus: ouX.val(), groups: grI.val(), exceptGroups: grX.val() }, settings: getS() }; }
      d.appendChild(el('div', { cls: 'acts', style: 'margin-top:14px' },
        btn(t('epSaveApply'), function (e) { var b = e.target; b.disabled = true; api('/api/endpoint/policy', body()).then(function () { flash(t('epSavedHint')); closeDrawer(); vEndpoints(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'pri'),
        p.id ? btn(t('remove'), function () { if (!window.confirm(t('epDelQ'))) return; api('/api/endpoint/policy/delete', { id: p.id }).then(function () { flash(t('epSavedHint')); closeDrawer(); vEndpoints(); }).catch(fail); }, 'danger') : null));
      if (!isNew && arr(p.hosts).length) d.appendChild(el('div', { cls: 'note', style: 'margin-top:10px', text: t('epAppliesTo') + ': ' + arr(p.hosts).join(', ') }));
    });
  }

  // agent detail drawer: health, hardware, software, policies, remote actions
  var ACTIONS = [['inventory', 'acInventory', ''], ['sync-policy', 'acSync', ''], ['defender-scan', 'acScan', ''], ['defender-update', 'acDefUpd', ''], ['update-agent', 'acUpdate', ''], ['kill-process', 'acKill', ''], ['block-ip', 'acBlockIp', ''], ['unblock-ip', 'acUnblockIp', ''], ['isolate', 'acIsolate', 'danger'], ['unisolate', 'acUnisolate', ''], ['reboot', 'acReboot', 'danger']];
  function runAction(hosts, type, done) {
    var a = {};
    if (type === 'kill-process') { var n = window.prompt(t('acKillQ'), ''); if (!n) return; a.name = n.trim(); }
    if (type === 'block-ip' || type === 'unblock-ip') { var ip = window.prompt(t('acIpQ'), ''); if (!ip) return; a.ip = ip.trim(); if (type === 'block-ip') a.minutes = +(window.prompt(t('acMinQ'), '60') || 0); }
    if (type === 'reboot') { if (!window.confirm(t('acRebootQ'))) return; a.minutes = 5; }
    if (type === 'isolate' && !window.confirm(t('confirmIsolate'))) return;
    api('/api/agent/action', { hosts: hosts, type: type, args: a }).then(function (x) { flash(t('acQueued') + ' (' + x.queued + ')'); if (done) done(); }).catch(fail);
  }
  function agentDrawer(name, firstTab) {
    openDrawer(function (d) {
      drawerHead(d, el('span', { cls: 'mono', text: name }));
      var body = el('div'); d.appendChild(body); body.appendChild(spinner());
      var dtab = firstTab || 'overview';
      function load() {
        api('/api/agent/detail?name=' + encodeURIComponent(name)).then(function (x) {
          clear(body);
          var inv = (x.inventory && x.inventory.Data) || null, hl = (x.health && x.health.Data) || null;
          var tabs = el('div', { cls: 'tabs' });
          [['overview', 'adOverview'], ['security', 'adSecurity'], ['updates', 'adUpdates'], ['hardware', 'adHardware'], ['software', 'adSoftware'], ['policies', 'adPolicies'], ['actions', 'adActions']].forEach(function (z) { tabs.appendChild(el('button', { type: 'button', cls: dtab === z[0] ? 'on' : '', text: t(z[1]), onclick: function () { dtab = z[0]; load(); } })); });
          body.appendChild(tabs);
          var pane = el('div'); body.appendChild(pane);
          if (dtab === 'overview') {
            var os = inv && inv.os || {}, hw = inv && inv.hw || {}, av = hl && hl.av;
            var kv = el('div', { cls: 'kv' });
            function row(k, v) { kv.appendChild(el('div', { cls: 'k', text: k })); kv.appendChild(el('div', null, v === undefined || v === null || v === '' ? '—' : v)); }
            row(t('adOs'), (os.n || '') + (os.v ? ' (' + os.v + ')' : ''));
            row(t('adUser'), (hl && hl.user) || hw.user || '');
            row(t('adUptime'), hl && hl.uptimeH !== undefined ? hl.uptimeH + ' h' : '');
            row('CPU', hl && hl.cpu !== undefined ? hl.cpu + '%' : '');
            row(t('adMemFree'), hl && hl.memFreePct !== undefined ? hl.memFreePct + '%' : '');
            row(t('adDiskC'), hl && hl.cFreeGB !== undefined ? hl.cFreeGB + ' GB (' + hl.cFreePct + '%)' : '');
            row('Defender', av ? el('span', null, pill(av.rt ? 'OK' : 'Fail', av.rt ? t('adRtOn') : t('adRtOff')), ' ', el('span', { cls: av.sigAge > 3 ? 'why' : 'muted', text: t('adSigAge') + ' ' + av.sigAge + 'd' })) : t('adNoAv'));
            row(t('adFirewall'), hl && hl.fw ? el('span', null, Object.keys(hl.fw).map(function (k) { return el('span', { cls: 'chip' + (hl.fw[k] ? ' on' : ''), text: k }); })) : '');
            row('BitLocker', hl && hl.bitlocker ? hl.bitlocker : '');
            row(t('adReboot'), hl ? (hl.rebootPending ? pill('Warn', t('yes')) : t('no')) : '');
            row(t('adIsolated'), hl ? (hl.isolated ? pill('Fail', t('yes')) : t('no')) : '');
            row(t('adPolicy'), x.applied ? pill('OK', t('epAppliedOk')) : pill('Warn', t('epPendingSync')));
            row(t('adAgentVer'), x.last ? (x.last.Version || '') : '');
            row(t('lastSeen'), x.last ? fmtT(x.last.At) : '');
            row(t('agPerf'), x.last && x.last.Perf ? x.last.Perf.CpuSeconds + 's CPU · ' + x.last.Perf.MemMB + 'MB' : '');
            row(t('adInvAt'), x.inventory ? fmtT(x.inventory.At) : t('adNoInv'));
            pane.appendChild(kv);
          } else if (dtab === 'security') { postureTab(pane, x, name, load);
          } else if (dtab === 'updates') { updatesTab(pane, x, name, load);
          } else if (dtab === 'hardware') {
            if (!inv) { pane.appendChild(el('div', { cls: 'muted', text: t('adNoInv') })); }
            else {
              var hw2 = inv.hw || {};
              pane.appendChild(el('div', { cls: 'kv' },
                el('div', { cls: 'k', text: t('adModel') }), el('div', { text: (hw2.mf || '') + ' ' + (hw2.model || '') }),
                el('div', { cls: 'k', text: t('adSerial') }), el('div', { cls: 'mono', text: hw2.serial || '—' }),
                el('div', { cls: 'k', text: 'RAM' }), el('div', { text: (hw2.ramGB || '') + ' GB' }),
                el('div', { cls: 'k', text: 'CPU' }), el('div', { text: arr(inv.cpu).map(function (c) { return c.n + ' (' + c.cores + 'C/' + c.lp + 'T)'; }).join(' · ') }),
                el('div', { cls: 'k', text: t('agDomain') }), el('div', { text: hw2.joined ? hw2.domain : t('agWorkgroup') }),
                el('div', { cls: 'k', text: t('adInstalled') }), el('div', { text: (inv.os && inv.os.inst) || '—' })));
              pane.appendChild(el('h4', { text: t('adDisks') }));
              pane.appendChild(table([t('name'), t('adSize'), t('adFree'), 'FS'], arr(inv.disks).map(function (k) { return el('tr', null, el('td', { text: k.d }), el('td', { cls: 'num', text: k.sizeGB + ' GB' }), el('td', { cls: 'num', text: k.freeGB + ' GB' }), el('td', { text: k.fs })); })));
              pane.appendChild(el('h4', { text: t('adNet') }));
              pane.appendChild(table([t('name'), 'IP', 'MAC', 'Gateway', 'DNS'], arr(inv.net).map(function (n) { return el('tr', null, el('td', { text: n.n }), el('td', { cls: 'mono', text: arr(n.ip).join(', ') }), el('td', { cls: 'mono', text: n.mac }), el('td', { cls: 'mono', text: arr(n.gw).join(', ') }), el('td', { cls: 'mono', text: arr(n.dns).join(', ') })); })));
              pane.appendChild(el('h4', { text: t('adAdmins') }));
              pane.appendChild(el('div', null, arr(inv.admins).map(function (a) { return el('span', { cls: 'chip mono', text: a }); })));
              pane.appendChild(el('h4', { text: t('adHotfix') + ' (' + arr(inv.hotfix).length + ')' }));
              pane.appendChild(el('div', { cls: 'scrollbox' }, arr(inv.hotfix).map(function (h) { return el('span', { cls: 'chip mono', text: h.id + (h.on ? ' · ' + h.on : '') }); })));
            }
          } else if (dtab === 'software') {
            if (!inv) { pane.appendChild(el('div', { cls: 'muted', text: t('adNoInv') })); }
            else {
              var q = inp(t('search')), tb = el('div');
              function drawSw() { clear(tb); var f = q.value.trim().toLowerCase(); var rows = arr(inv.software).filter(function (s) { return !f || (s.n + ' ' + s.p).toLowerCase().indexOf(f) >= 0; }).map(function (s) { return el('tr', null, el('td', { text: s.n }), el('td', { cls: 'mono', text: s.v }), el('td', { cls: 'muted', text: s.p }), el('td', { cls: 'num muted', text: s.d })); }); if (!rows.length) rows = [emptyRow(4)]; tb.appendChild(table([t('name'), t('adVersion'), t('adPublisher'), t('adInstalled')], rows)); }
              q.addEventListener('input', drawSw);
              pane.appendChild(el('div', { cls: 'row' }, q, el('span', { cls: 'muted', text: arr(inv.software).length + ' ' + t('adItems') })));
              pane.appendChild(tb); drawSw();
            }
          } else if (dtab === 'policies') {
            var e2 = x.effective || {};
            pane.appendChild(el('div', { cls: 'kv' },
              el('div', { cls: 'k', text: t('epTabApp') }), el('div', null, arr(e2.appBlocks).length ? arr(e2.appBlocks).map(function (b) { return el('div', null, el('b', { text: b.name }), ' ', arr(b.programs).map(function (p) { return el('span', { cls: 'chip mono', text: p }); }), ' ', el('span', { cls: 'muted', text: b.scope === 'all' ? t('epScopeAll') : t('epScopeInet') })); }) : '—'),
              el('div', { cls: 'k', text: t('epTabGuard') }), el('div', { text: e2.guard || t('epGuardDefault') }),
              el('div', { cls: 'k', text: t('epTabLaunch') }), el('div', null, e2.appLaunch ? el('span', null, pill(e2.appLaunch.mode === 'block' ? 'Fail' : (e2.appLaunch.mode === 'warn' ? 'Warn' : 'none'), t('al_' + e2.appLaunch.mode)), ' ', el('span', { cls: 'muted', text: t(e2.appLaunch.list === 'allowlist' ? 'alAllowOnly' : 'alBlockList') }), ' ', arr(e2.appLaunch.programs).map(function (pg) { return el('span', { cls: 'chip mono', text: pg }); })) : '—'),
              el('div', { cls: 'k', text: t('status') }), el('div', null, x.applied ? pill('OK', t('epAppliedOk')) : pill('Warn', t('epPendingSync')), ' ', el('span', { cls: 'muted mono', text: (e2.rev || '') })) ));
            var ps = x.policyStatus && x.policyStatus.Data;
            if (ps && ps.appblock) {
              pane.appendChild(el('h4', { text: t('epRules') + ': ' + (ps.appblock.rules || 0) }));
              pane.appendChild(table([t('epPrograms'), t('adPaths'), t('status')], arr(ps.appblock.items).map(function (i) { return el('tr', null, el('td', { cls: 'mono', text: i.program }), el('td', { cls: 'mono', text: arr(i.paths).join('\n') || t('epNotFound') }), el('td', null, i.active ? pill('OK', t('epBlocking')) : pill('none', t('epOutside')))); })));
              if (arr(ps.appblock.errors).length) pane.appendChild(el('div', { cls: 'flash err', text: arr(ps.appblock.errors).join('\n') }));
            }
            if (ps && ps.guardError) pane.appendChild(el('div', { cls: 'flash err', text: ps.guardError }));
            pane.appendChild(el('div', { cls: 'acts', style: 'margin-top:10px' }, btn(t('epTabApp') + ' / ' + t('epTabGuard'), function () { closeDrawer(); go('endpoints'); }, 'sm')));
          } else {
            pane.appendChild(el('p', { cls: 'lead', text: t('acLead') }));
            pane.appendChild(el('div', { cls: 'acts' }, ACTIONS.map(function (a) { return btn(t(a[1]), function () { runAction([name], a[0], load); }, 'sm ' + a[2]); })));
            pane.appendChild(el('h4', { text: t('acHistory') }));
            var rows = arr(x.actions).map(function (a) { return el('tr', null, el('td', { cls: 'num muted nw', text: fmtT(a.created) }), el('td', { text: a.type + (a.args && (a.args.name || a.args.ip) ? ' · ' + (a.args.name || a.args.ip) : '') }), el('td', null, a.status === 'done' ? pill('OK', t('acDone')) : (a.status === 'failed' ? pill('Fail', t('failed')) : pill('Warn', a.status === 'sent' ? t('acSent') : t('acQueuedS')))), el('td', { cls: a.ok === false ? 'why' : 'muted', text: a.output || '' }), el('td', { cls: 'muted', text: a.by || '' })); });
            if (!rows.length) rows = [emptyRow(5)];
            pane.appendChild(table([t('time'), t('actions'), t('status'), t('message'), t('user')], rows));
          }
        }).catch(function (e) { clear(body); fail(e); });
      }
      load();
    });
  }

  // software inventory across all agent computers
  function vSoftware() {
    var v = page(t('software'), t('swLead'));
    var q = inp(t('swSearchPh')), out = el('div'), seq = 0, tm = null;
    v.appendChild(el('div', { cls: 'row' }, q)); v.appendChild(out);
    function load() {
      var my = ++seq; clear(out).appendChild(spinner());
      api('/api/inventory/software?q=' + encodeURIComponent(q.value.trim())).then(function (x) {
        if (my !== seq) return; clear(out);
        out.appendChild(el('p', { cls: 'muted', text: x.computers + ' ' + t('swComputers') + ' · ' + x.total + ' ' + t('adItems') }));
        var rows = arr(x.items).map(function (s) { return el('tr', null, el('td', null, el('b', { text: s.name })), el('td', { cls: 'muted', text: s.publisher }), el('td', { cls: 'num', text: s.count }), el('td', { cls: 'mono muted', text: arr(s.versions).slice(0, 6).join(', ') }), el('td', null, arr(s.hosts).slice(0, 30).map(function (h) { return el('a', { href: '#', cls: 'chip mono', text: h, onclick: function (e) { e.preventDefault(); agentDrawer(h); } }); }))); });
        if (!rows.length) rows = [emptyRow(5, x.computers ? t('none') : t('swNoInv'))];
        out.appendChild(table([t('name'), t('adPublisher'), t('swCount'), t('adVersion'), t('swWhere')], rows));
      }).catch(function (e) { if (my === seq) { clear(out); fail(e); } });
    }
    q.addEventListener('input', function () { if (tm) clearTimeout(tm); tm = setTimeout(load, 300); });
    load();
  }

  // ------------------------------------------------------------------ reports center
  var RP = { id: '', hours: 168, host: '', user: '', text: '', q: '' };
  var RANGES = [[24, 'h24'], [168, 'd7'], [720, 'd30'], [2160, 'd90']];
  function rpRange(val, onch) {
    var s = el('select', { onchange: function () { onch(+s.value); } });
    RANGES.forEach(function (o) { s.appendChild(el('option', { value: o[0], text: t(o[1]), selected: o[0] === val ? 'selected' : null })); });
    return s;
  }
  function cellNode(col, v) {
    if ((col.k === 'user' || col.k === 'c:member') && v && v !== '-') return el('a', { href: '#/users/' + encodeURIComponent(v), text: v });
    if (col.k === 'host' && v) return el('span', { cls: 'mono', text: v });
    return v;
  }
  function vReports(sub) {
    if (sub && sub[0]) RP.id = decodeURIComponent(sub[0]);
    var v = page(t('reports'), t('rpLead'));
    var wrap = el('div', { cls: 'repwrap' }); v.appendChild(wrap);
    var left = el('div', { cls: 'card replist' }), right = el('div'); wrap.appendChild(left); wrap.appendChild(right);
    left.appendChild(spinner());
    api('/api/reports').then(function (c) {
      clear(left);
      var f = el('input', { type: 'search', placeholder: t('rpFind'), value: RP.q });
      var lst = el('div'); left.appendChild(f); left.appendChild(lst);
      function drawList() {
        clear(lst); var q = f.value.trim().toLowerCase(); RP.q = f.value;
        arr(c.categories).forEach(function (cat) {
          var items = arr(c.reports).filter(function (r) { return r.cat === cat.key && (!q || (r.title + ' ' + r.desc).toLowerCase().indexOf(q) >= 0); });
          if (!items.length) return;
          lst.appendChild(el('div', { cls: 'rgrp', text: cat.title }));
          items.forEach(function (r) { lst.appendChild(el('a', { href: '#/reports/' + r.id, cls: 'ritem' + (RP.id === r.id ? ' on' : ''), text: r.title })); });
        });
      }
      f.addEventListener('input', drawList); drawList();
      if (!RP.id) RP.id = 'logon-failed';
      var def = arr(c.reports).filter(function (r) { return r.id === RP.id; })[0] || arr(c.reports)[0];
      reportPanel(right, def, c);
    }).catch(function (e) { clear(left); fail(e); });
  }
  function reportPanel(box, def, c) {
    clear(box);
    var head = card(def.title, null); box.appendChild(head);
    if (def.desc) head.appendChild(el('p', { cls: 'lead', text: def.desc }));
    var noTime = def.src === 'agents' || def.src === 'hardware' || def.src === 'software' || def.src === 'riskysoft' || def.src === 'admins' || def.src === 'posture' || def.src === 'patches' || def.src === 'health';
    var host = inp(t('host'), 'text', RP.host), user = inp(t('user'), 'text', RP.user), txt = inp(t('textFilter'), 'search', RP.text);
    var rs = rpRange(RP.hours, function (h) { RP.hours = h; load(); });
    var deb = null; function soon() { clearTimeout(deb); deb = setTimeout(function () { RP.host = host.value.trim(); RP.user = user.value.trim(); RP.text = txt.value.trim(); load(); }, 450); }
    [host, user, txt].forEach(function (i) { i.addEventListener('input', soon); });
    function qs() { return 'id=' + encodeURIComponent(def.id) + '&hours=' + RP.hours + (RP.host ? '&host=' + encodeURIComponent(RP.host) : '') + (RP.user ? '&user=' + encodeURIComponent(RP.user) : '') + (RP.text ? '&text=' + encodeURIComponent(RP.text) : ''); }
    head.appendChild(el('div', { cls: 'fbar' }, noTime ? null : rs, host, noTime ? null : user, txt,
      btn('⬇ CSV', function () { download('/api/report/csv?' + qs()); }, 'sm'),
      btn('✉ ' + t('rpSchedule'), function () { scheduleDrawer(null, c, def.id); }, 'sm')));
    var res = el('div', { cls: 'card' }); box.appendChild(res);
    var sc = card(t('rpSchedules'), btn('+ ' + t('rpNewSchedule'), function () { scheduleDrawer(null, c, def.id); }, 'sm pri')); box.appendChild(sc);
    drawSchedules(sc, c);
    var seq = 0;
    function load() {
      var my = ++seq;
      if (!res.firstChild) res.appendChild(spinner()); else res.style.opacity = '.55';
      api('/api/report/run', { id: def.id, hours: RP.hours, host: RP.host, user: RP.user, text: RP.text }).then(function (r) {
        if (my !== seq) return; res.style.opacity = ''; clear(res);
        res.appendChild(el('div', { cls: 'muted', style: 'font-size:12px;margin-bottom:6px', text: r.total + ' ' + t('results') + (noTime ? '' : ' · ' + r.from + ' — ' + r.to) + ' · ' + r.ms + ' ms' + (r.truncated ? ' · ' + t('rpTrunc') : '') }));
        var cols = arr(r.columns);
        var rows = arr(r.rows).map(function (row) { return el('tr', null, cols.map(function (col, i) { var val = row[i]; return el('td', { cls: col.k === 'time' || col.k === 'first' || col.k === 'last' || col.k === 'start' || col.k === 'end' ? 'num muted nw' : (col.k === 'count' || col.k === 'dur' || col.k === 'fails' ? 'num' : (String(val || '').length > 60 ? 'wrap' : '')) }, cellNode(col, val)); })); });
        if (!rows.length) rows = [emptyRow(cols.length || 1, t('rpEmpty'))];
        res.appendChild(table(cols.map(function (x) { return x.t; }), rows));
      }).catch(function (e) { if (my !== seq) return; res.style.opacity = ''; clear(res); fail(e); });
    }
    load();
  }
  function drawSchedules(sc, c) {
    var items = arr(c.schedules);
    var titles = {}; arr(c.reports).forEach(function (r) { titles[r.id] = r.title; });
    if (!c.mailConfigured) sc.appendChild(el('div', { cls: 'banner' }, el('span', { text: t('rpNoMail') }), btn(t('settings'), function () { go('alerts'); }, 'sm')));
    var rows = items.map(function (s) {
      return el('tr', { cls: 'clk', onclick: function () { scheduleDrawer(s, c); } },
        el('td', null, el('b', { text: s.name }), s.enabled ? null : el('div', null, pill('none', t('disabled')))),
        el('td', null, arr(s.reports).map(function (id) { return el('span', { cls: 'chip', text: titles[id] || id }); })),
        el('td', { text: t('fq_' + s.freq) + ' · ' + String(s.hour).padStart(2, '0') + ':00' }),
        el('td', { cls: 'mono muted', text: arr(s.recipients).join(', ') }),
        el('td', { cls: 'num muted nw', text: String(s.lastRun || '').replace('T', ' ').slice(0, 16) + (s.lastResult && s.lastResult !== 'ok' ? ' ⚠' : '') }));
    });
    if (!rows.length) rows = [emptyRow(5, t('rpNoSchedules'))];
    sc.appendChild(table([t('name'), t('reports'), t('rpWhen'), t('rpTo'), t('lastRun')], rows));
  }
  function scheduleDrawer(s, c, firstId) {
    s = s || { enabled: true, freq: 'weekly', day: 6, hour: 8, reports: firstId ? [firstId] : [], recipients: [] };
    openDrawer(function (d) {
      drawerHead(d, el('span', { text: s.id ? s.name : t('rpNewSchedule') }));
      var nm = inp(t('rpSchedNamePh'), 'text', s.name || ''), en = el('input', { type: 'checkbox', checked: s.enabled !== false });
      var fq = el('select'); ['daily', 'weekly', 'monthly'].forEach(function (x) { fq.appendChild(el('option', { value: x, text: t('fq_' + x), selected: s.freq === x ? 'selected' : null })); });
      var dy = el('select'); function fillDay() { clear(dy); if (fq.value === 'weekly') { DAYS.forEach(function (dn, i) { var wd = [6, 0, 1, 2, 3, 4, 5][i]; dy.appendChild(el('option', { value: wd, text: t('day_' + dn), selected: +s.day === wd ? 'selected' : null })); }); } else if (fq.value === 'monthly') { for (var i = 1; i <= 28; i++) dy.appendChild(el('option', { value: i, text: String(i), selected: +s.day === i ? 'selected' : null })); } dy.hidden = fq.value === 'daily'; }
      fq.addEventListener('change', fillDay); fillDay();
      var hr = el('select'); for (var h = 0; h < 24; h++) hr.appendChild(el('option', { value: h, text: String(h).padStart(2, '0') + ':00', selected: +s.hour === h ? 'selected' : null }));
      var rg = el('select'); [['', 'rpAuto'], ['24h', 'h24'], ['7d', 'd7'], ['30d', 'd30']].forEach(function (o) { rg.appendChild(el('option', { value: o[0], text: t(o[1]), selected: (s.range || '') === o[0] ? 'selected' : null })); });
      var to = el('textarea', { rows: 2, cls: 'mono', placeholder: 'it@company.com' }); to.value = arr(s.recipients).join('\n');
      var hl = inp('PC-*', 'text', s.hostLike || '');
      var chosen = arr(s.reports).slice(), box = el('div', { cls: 'scrollbox' });
      arr(c.categories).forEach(function (cat) {
        var items = arr(c.reports).filter(function (r) { return r.cat === cat.key; }); if (!items.length) return;
        box.appendChild(el('div', { cls: 'rgrp', text: cat.title }));
        items.forEach(function (r) { var ck = el('input', { type: 'checkbox', checked: chosen.indexOf(r.id) >= 0 }); ck.addEventListener('change', function () { var i = chosen.indexOf(r.id); if (ck.checked && i < 0) chosen.push(r.id); if (!ck.checked && i >= 0) chosen.splice(i, 1); }); box.appendChild(el('label', { cls: 'ouRow' }, ck, ' ', r.title)); });
      });
      d.appendChild(el('div', { cls: 'form' },
        el('label', { text: t('name') }), nm, el('label', null, ''), el('label', null, en, ' ', t('enabled')),
        el('label', { text: t('rpWhen') }), el('div', { cls: 'row' }, fq, dy, hr),
        el('label', { text: t('rpRangeL') }), rg,
        el('label', { text: t('rpTo') }), to, el('div', { cls: 'hint', text: t('rpToHint') }),
        el('label', { text: t('host') }), hl, el('div', { cls: 'hint', text: t('rpHostHint') }),
        el('label', { text: t('reports') }), box));
      function body() { return { id: s.id || '', name: nm.value.trim(), enabled: en.checked, freq: fq.value, day: +dy.value || 0, hour: +hr.value, range: rg.value, recipients: splitList(to.value), hostLike: hl.value.trim(), reports: chosen }; }
      d.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' },
        btn(t('save'), function (e) { var b = e.target; b.disabled = true; api('/api/report/schedule', body()).then(function () { flash(t('saved')); closeDrawer(); vReports(); }).catch(function (er) { b.disabled = false; fail(er); }); }, 'pri'),
        btn(t('rpSendNow'), function (e) { var b = e.target; b.disabled = true; b.textContent = t('loading'); api('/api/report/schedule', body()).then(function (x) { return api('/api/report/schedule/run', { id: x.id }); }).then(function (y) { flash(y.result === 'ok' ? t('rpSent') + ' (' + y.files + ' CSV)' : y.result, y.result === 'ok'); closeDrawer(); vReports(); }).catch(function (er) { b.disabled = false; fail(er); }); }),
        s.id ? btn(t('remove'), function () { if (!window.confirm(t('rpDelQ'))) return; api('/api/report/schedule/delete', { id: s.id }).then(function () { closeDrawer(); vReports(); }).catch(fail); }, 'danger') : null));
      if (s.lastResult && s.lastResult !== 'ok') d.appendChild(el('div', { cls: 'flash err', style: 'margin-top:10px', text: s.lastResult }));
    });
  }

  // ------------------------------------------------------------------ user 360
  var UA = { user: '', hours: 24 };
  function vUsers(sub) {
    if (sub && sub[0]) UA.user = decodeURIComponent(sub[0]);
    var v = page(t('users'), t('uaLead'));
    var u = inp(t('uaPh'), 'search', UA.user);
    var out = el('div');
    v.appendChild(el('div', { cls: 'fbar' }, rpRange(UA.hours, function (h) { UA.hours = h; load(); }), u, btn(t('search'), function () { UA.user = u.value.trim(); load(); }, 'pri sm')));
    u.addEventListener('keydown', function (e) { if (e.key === 'Enter') { UA.user = u.value.trim(); try { history.replaceState(null, '', '#/users/' + encodeURIComponent(UA.user)); } catch (x) { } load(); } });
    v.appendChild(out);
    var seq = 0;
    function load() {
      clear(out); if (!UA.user) { recent(); return; }
      var my = ++seq; out.appendChild(spinner());
      api('/api/user/activity', { user: UA.user, hours: UA.hours }, { timeoutMs: 120000 }).then(function (a) {
        if (my !== seq) return; clear(out);
        var s = a.summary || {};
        var rc = a.risk >= 60 ? 'var(--crit)' : (a.risk >= 30 ? 'var(--warn)' : 'var(--mint)');
        out.appendChild(el('div', { cls: 'kpis' }, [[a.risk, t('uaRisk'), rc], [s.logons, t('uaLogons'), null], [s.failed, t('uaFailed'), s.failed ? 'var(--warn)' : null], [s.lockouts, t('uaLock'), s.lockouts ? 'var(--crit)' : null], [s.admin, t('uaAdmin'), null], [s.afterHours, t('uaAfter'), s.afterHours ? 'var(--warn)' : null], [s.changesBy, t('uaChanges'), null], [s.processes, t('uaProc'), null]].map(function (k) { return el('div', { cls: 'kpi' }, el('div', { cls: 'v num', style: k[2] ? 'color:' + k[2] : null, text: k[0] || 0 }), el('div', { cls: 'l', text: k[1] })); })));
        var c1 = card(t('uaWhere'));
        c1.appendChild(el('div', { cls: 'kv' }, el('div', { cls: 'k', text: t('host') }), el('div', null, arr(s.hosts).map(function (h) { return el('span', { cls: 'chip mono', text: h.name + ' ×' + h.n }); })), el('div', { cls: 'k', text: 'IP' }), el('div', null, arr(s.ips).map(function (h) { return el('span', { cls: 'chip mono', text: h.name + ' ×' + h.n }); }))));
        var c2 = card(t('uaFindings'));
        var fr = arr(a.findings).map(function (f) { return el('tr', { cls: 'clk', onclick: function () { openFinding(f.id); } }, el('td', { cls: 'num muted nw', text: f.time }), el('td', null, sevDot(f.sev)), el('td', { text: f.host }), el('td', { text: f.title })); });
        if (!fr.length) fr = [emptyRow(4)];
        c2.appendChild(table([t('time'), t('sev'), t('host'), t('title')], fr));
        out.appendChild(c1); out.appendChild(c2);
        var c3 = card(t('uaTimeline') + ' (' + a.total + ')');
        var tr = arr(a.timeline).map(function (x) { return el('tr', { cls: x.bad ? 'badrow' : null }, el('td', { cls: 'num muted nw', text: x.time }), el('td', { cls: 'mono', text: x.host }), el('td', { text: x.what }), el('td', { cls: 'wrap', text: x.detail }), el('td', { cls: 'mono', text: x.ip })); });
        if (!tr.length) tr = [emptyRow(5, t('rpEmpty'))];
        c3.appendChild(table([t('time'), t('host'), t('actions'), t('details'), 'IP'], tr));
        out.appendChild(c3);
        tabify(out, 'users', [['sum', 'tbSummary', [out.querySelector(':scope > .kpis'), c1]], ['find', 'tbFindings', [c2]], ['tl', 'tbTimeline', [c3]]]);
      }).catch(function (e) { if (my !== seq) return; clear(out); out.appendChild(el('div', { cls: 'flash err' }, (e && e.message ? e.message : String(e)) + ' — ' + t('uaSlow') + ' ', btn(t('retry'), load, 'sm'))); });
    }
    // بدونِ نامِ کاربر: کاربرانِ فعالِ ۲۴ ساعتِ اخیر برای انتخاب | no user yet: pick from users active in the last 24 h
    function recent() {
      var c = card(t('uaRecent')); c.appendChild(el('p', { cls: 'lead', text: t('uaWhat') })); var box = el('div', null, spinner()); c.appendChild(box); out.appendChild(c);
      var my = ++seq;
      api('/api/user/recent?hours=24', undefined, { timeoutMs: 90000 }).then(function (r) {
        if (my !== seq) return; clear(box);
        var rows = arr(r.items).map(function (x) {
          return el('tr', { cls: 'clk', onclick: function () { UA.user = x.user; u.value = x.user; try { history.replaceState(null, '', '#/users/' + encodeURIComponent(x.user)); } catch (e) { } load(); } },
            el('td', { cls: 'mono', text: x.user }), el('td', { cls: 'num', text: x.logons }), el('td', { cls: 'num', style: x.failed ? 'color:var(--warn)' : null, text: x.failed }), el('td', { cls: 'num', text: x.hosts }), el('td', { cls: 'num muted nw', text: x.last }));
        });
        if (!rows.length) rows = [emptyRow(5, t('uaHint'))];
        box.appendChild(table([t('user'), t('uaLogons'), t('uaFailed'), t('uaHostsN'), t('uaLast')], rows));
      }).catch(function () { if (my !== seq) return; clear(box); box.appendChild(el('div', { cls: 'muted', text: t('uaHint') })); });
    }
    load();
  }

  // ------------------------------------------------------------------ sessions (live + history)
  var SS = { hours: 24, host: '', user: '', timer: null, flag: '' };
  function fmtDur(min) {
    if (min === null || min === undefined || min === '') return '—';
    min = Math.max(0, Math.round(+min)); var d = Math.floor(min / 1440), h = Math.floor((min % 1440) / 60), m = min % 60;
    if (d) return d + ' ' + t('dShort') + (h ? ' ' + h + ' ' + t('hShort') : '');
    if (h) return h + ' ' + t('hShort') + (m ? ' ' + m + ' ' + t('mShort') : '');
    return m + ' ' + t('mShort');
  }
  var SFLAG = { external: ['Fail', 'sfExternal'], forgotten: ['Warn', 'sfForgotten'], multi: ['Warn', 'sfMulti'], afterhours: ['Warn', 'sfAfter'], long: ['none', 'sfLong'], admin: ['none', 'sfAdmin'] };
  function flagChips(fl) { return arr(fl).map(function (f) { var x = SFLAG[f]; return x ? pill(x[0], t(x[1])) : null; }); }
  function typeChip(tp) { return el('span', { cls: 'chip' + (tp === 'rdp' ? ' on' : ''), text: tp === 'rdp' ? t('stRdp') : (tp === 'cached' ? t('stCached') : t('stConsole')) }); }
  function fromCell(x) { return el('td', null, x.device ? el('div', { text: x.device }) : null, x.ip ? el('div', { cls: 'mono muted', text: x.ip }) : null, (!x.device && !x.ip) ? el('span', { cls: 'muted', text: x.type === 'rdp' ? '—' : t('stLocal') }) : null); }
  function vSessions() {
    if (SS.timer) { clearTimeout(SS.timer); SS.timer = null; }
    var v = page(t('sessions'), t('ssLead'));
    var hostI = inp(t('host'), 'search', SS.host), userI = inp(t('user'), 'search', SS.user);
    function reload() { SS.histAt = 0; load(); }
    var bar = el('div', { cls: 'fbar' }, rpRange(SS.hours, function (h) { SS.hours = h; reload(); }), hostI, userI, btn(t('search'), function () { SS.host = hostI.value.trim(); SS.user = userI.value.trim(); reload(); }, 'sm pri'));
    [hostI, userI].forEach(function (i) { i.addEventListener('keydown', function (e) { if (e.key === 'Enter') { SS.host = hostI.value.trim(); SS.user = userI.value.trim(); reload(); } }); });
    v.appendChild(bar);
    var out = el('div'); v.appendChild(out);
    var seq = 0;
    function act(x, what) {
      var body = { host: x.host, id: x.id, action: what };
      if (what === 'message') { var tx = window.prompt(t('ssMsgPh')); if (!tx) return; body.text = tx; }
      else if (!window.confirm((what === 'logoff' ? t('ssLogoffQ') : t('ssDiscQ')) + '\n' + x.user + ' @ ' + x.host)) return;
      api('/api/sessions/action', body).then(function (r) { flash(r.queued ? t('ssQueued') : (r.message || t('saved'))); setTimeout(load, r.queued ? 150000 : 1500); }).catch(fail);
    }
    function load(silent, liveOnly) {
      var my = ++seq;
      var qp = (SS.host ? '&host=' + encodeURIComponent(SS.host) : '') + (SS.user ? '&user=' + encodeURIComponent(SS.user) : '');
      var state = { live: [], history: [], sm: {}, hErr: '', hLoaded: false, hLoading: false, built: false };
      var hFresh = SS.histAt && (Date.now() - SS.histAt <= 300000) && SS.histKey === (SS.hours + '|' + qp);
      if (hFresh && SS.histData) { state.history = SS.histData; state.hLoaded = true; state.hErr = SS.histErr || ''; if (SS.histSm) { state.sm.external = SS.histSm.external; state.sm.afterhours = SS.histSm.afterhours; state.sm.total = SS.histSm.total; state.sm.avgMin = SS.histSm.avgMin; } }
      var kpiWrap, tips, lc, lb, hc, hb, hHead;
      function build() {
        if (state.built) return; state.built = true;
        clear(out);
        kpiWrap = el('div', { cls: 'kpis' }); out.appendChild(kpiWrap);
        tips = el('div'); out.appendChild(tips);
        lc = card(t('ssLive'), el('span', { cls: 'muted', text: t('ssAuto') })); lb = el('div'); lc.appendChild(lb); out.appendChild(lc);
        hc = card(t('ssHistory'), el('span', { cls: 'muted' })); hHead = hc.querySelector('.ttl') || hc; hb = el('div'); hc.appendChild(hb); out.appendChild(hc);
        tabify(out, 'sessions', [['live', 'tbLive', [lc]], ['hist', 'tbHistory', [hc]]]);
      }
      function kpi(val, label, color, flag) { return el('div', { cls: 'kpi' + (flag !== undefined ? ' go' : ''), style: color ? '--kc:' + color : null, onclick: flag !== undefined ? function () { SS.flag = (SS.flag === flag ? '' : flag); draw(); } : null }, el('div', { cls: 'v num', style: color ? 'color:' + color : null, text: val }), el('div', { cls: 'l', text: label })); }
      function draw() {
        if (!state.built) return;
        var sm = state.sm, L = arr(state.live), H = arr(state.history);
        clear(kpiWrap);
        kpiWrap.appendChild(kpi(sm.live || 0, t('ssLiveNow'), 'var(--mint)', ''));
        kpiWrap.appendChild(kpi(sm.disconnected || 0, t('ssDisc'), sm.disconnected ? 'var(--warn)' : null, 'forgotten'));
        kpiWrap.appendChild(kpi(sm.rdp || 0, t('ssRdpNow'), null));
        kpiWrap.appendChild(kpi(sm.users || 0, t('ssUsersOn'), null));
        kpiWrap.appendChild(kpi(state.hLoaded ? (sm.external || 0) : '…', t('sfExternal'), sm.external ? 'var(--crit)' : null, 'external'));
        kpiWrap.appendChild(kpi(state.hLoaded ? (sm.afterhours || 0) : '…', t('sfAfter'), sm.afterhours ? 'var(--warn)' : null, 'afterhours'));
        // suggestions
        clear(tips);
        var cnt = function (a, f) { return a.filter(function (x) { return arr(x.flags).indexOf(f) >= 0; }).length; };
        var sug = [];
        if (cnt(L, 'external') || cnt(H, 'external')) sug.push(['Fail', t('sgExternal').replace('{n}', cnt(L, 'external') + cnt(H, 'external')), 'external']);
        if (cnt(L, 'forgotten')) sug.push(['Warn', t('sgForgotten').replace('{n}', cnt(L, 'forgotten')), 'forgotten']);
        if (cnt(L, 'multi')) sug.push(['Warn', t('sgMulti'), 'multi']);
        if (cnt(H, 'afterhours')) sug.push(['Warn', t('sgAfter').replace('{n}', cnt(H, 'afterhours')), 'afterhours']);
        if (cnt(L, 'long')) sug.push(['none', t('sgLong').replace('{n}', cnt(L, 'long')), 'long']);
        if (sug.length) { var sc = card(t('ssWatch')); sug.forEach(function (x) { sc.appendChild(el('div', { cls: 'sug clk', onclick: function () { SS.flag = x[2]; draw(); } }, pill(x[0], '!'), ' ', el('span', { text: x[1] }))); }); tips.appendChild(sc); }
        var fl = function (x) { return !SS.flag || arr(x.flags).indexOf(SS.flag) >= 0; };
        // live table
        clear(lb);
        if (SS.flag) lb.appendChild(el('div', { cls: 'fbar' }, el('span', null, t('ssFiltered') + ': '), pill('Warn', t(SFLAG[SS.flag] ? SFLAG[SS.flag][1] : 'all')), btn('✕', function () { SS.flag = ''; draw(); }, 'sm')));
        var lr = L.filter(fl).map(function (x) {
          var st = x.state === 'Active' ? pill('OK', t('ssActive') + (x.idleMin >= 15 ? ' · ' + t('ssIdle') + ' ' + fmtDur(x.idleMin) : '')) : pill('Warn', t('ssDiscOne') + (x.discMin !== null && x.discMin !== undefined ? ' · ' + fmtDur(x.discMin) : ''));
          var acts = x.canAct && x.id > 0 ? el('div', { cls: 'row nw' }, btn('✉', function () { act(x, 'message'); }, 'sm'), x.type === 'rdp' && x.state === 'Active' ? btn(t('ssDisconnect'), function () { act(x, 'disconnect'); }, 'sm') : null, btn(t('ssLogoff'), function () { act(x, 'logoff'); }, 'sm danger'))
                                       : el('span', { cls: 'muted', text: x.source === 'events' ? t('ssEstimated') : (x.source === 'stale' ? t('ssStale') : '') });
          return el('tr', null, el('td', null, el('a', { href: '#/users/' + encodeURIComponent(x.user), text: x.user })), el('td', { text: x.host }), el('td', null, typeChip(x.type)), fromCell(x), el('td', null, st),
            el('td', { cls: 'num nw', title: fmtT(x.start), text: fmtDur(x.minutes) }), el('td', null, flagChips(x.flags)), el('td', null, acts));
        });
        if (!lr.length) lr = [emptyRow(8, t('ssNoLive'))];
        lb.appendChild(table([t('user'), t('host'), t('ssType'), t('ssFrom'), t('status'), t('ssFor'), '', ''], lr));
        // history table
        clear(hb);
        if (!state.hLoaded) {
          if (state.hLoading) { hb.appendChild(el('div', { cls: 'muted', style: 'padding:8px' }, spinner(), ' ', el('span', { text: t('ssHistLoading') }))); }
          else { hb.appendChild(el('div', { cls: 'acts', style: 'padding:8px' }, el('span', { cls: 'muted', text: t('ssHistIdle') }), btn(t('ssHistLoad'), function () { loadHistory(); }, 'sm pri'))); }
          return;
        }
        if (state.hErr) hb.appendChild(el('div', { cls: 'flash err', text: state.hErr }));
        var hr = H.filter(fl).map(function (x) {
          var how = x.how === 'logoff' ? t('ssEndLogoff') : (x.how === 'reboot' ? t('ssEndReboot') : (x.how === 'open' ? t('ssEndOpen') : t('ssEndUnknown')));
          return el('tr', { cls: 'clk', onclick: function () { sessionDrawer(x); } }, el('td', { text: x.user }), el('td', { text: x.host }), el('td', null, typeChip(x.type)), fromCell(x),
            el('td', { cls: 'num nw', text: fmtT(x.start) }), el('td', { cls: 'num nw muted', text: x.end ? fmtT(x.end) : '' }), el('td', { cls: 'num nw', text: fmtDur(x.minutes) }),
            el('td', { cls: 'muted' }, how, x.disc ? el('span', { text: ' · ' + x.disc + ' ' + t('ssDiscN') }) : null), el('td', null, flagChips(x.flags)));
        });
        if (!hr.length) hr = [emptyRow(9)];
        hb.appendChild(table([t('user'), t('host'), t('ssType'), t('ssFrom'), t('ssStart'), t('ssEnd'), t('ssDur'), t('ssHow'), ''], hr));
      }
      // ساختِ قابِ صفحه بی‌درنگ تا هرگز فقط اسپینر دیده نشود | build the page shell at once so it never shows a lone spinner
      build();
      clear(lb).appendChild(spinner()); draw();
      // ۱) live سریع (با مهلت) | fast live first, with a timeout so it can't hang forever
      api('/api/sessions?part=live&hours=' + SS.hours + qp, undefined, { timeoutMs: 35000 }).then(function (r) {
        if (my !== seq || S.view !== 'sessions') return;
        state.live = arr(r.live); var s0 = r.summary || {}; state.sm.live = s0.live; state.sm.disconnected = s0.disconnected; state.sm.rdp = s0.rdp; state.sm.users = s0.users; draw();
      }).catch(function (e) {
        if (my !== seq || S.view !== 'sessions') return;
        clear(lb).appendChild(el('div', { cls: 'flash err' }, el('span', { text: ((e && e.message) || 'error') + ' · ' }), btn(t('retry'), function () { load(); }, 'sm')));
      });
      // ۲) history سنگین: فقط وقتی لازم است (نه در هر رفرشِ ۳۰ ثانیه‌ای) | heavy history: only when needed, not on every 30s refresh
      function loadHistory() {
        var myh = seq; state.hLoading = true; state.hLoaded = false; if (state.built) draw();
        api('/api/sessions?part=history&hours=' + SS.hours + qp, undefined, { timeoutMs: 60000 }).then(function (r) {
          if (myh !== seq || S.view !== 'sessions') return;
          state.history = arr(r.history); state.hErr = loc(r.error) || ''; state.hLoaded = true; state.hLoading = false;
          var s1 = r.summary || {};
          SS.histAt = Date.now(); SS.histKey = (SS.hours + '|' + qp); SS.histData = state.history; SS.histErr = state.hErr; SS.histSm = { external: s1.external, afterhours: s1.afterhours, total: s1.total, avgMin: s1.avgMin }; state.sm.external = s1.external; state.sm.afterhours = s1.afterhours; state.sm.total = s1.total; state.sm.avgMin = s1.avgMin;
          if (hHead && s1.avgMin) try { hc.querySelector('span.muted').textContent = t('ssAvg') + ' ' + fmtDur(s1.avgMin); } catch (e2) { }
          draw();
        }).catch(function (e) { if (myh === seq) { state.hLoading = false; state.hLoaded = true; state.hErr = (e && e.message) || 'error'; draw(); } });
      }
      SS._loadHistory = loadHistory;
      // تاریخچه را فقط بار اول یا هر ۵ دقیقه یا با تغییرِ فیلتر تازه کن | refresh history only initially / every 5 min / on filter change
      if (!hFresh) { loadHistory(); }
      SS.timer = setTimeout(function () { if (S.view === 'sessions') load(true, true); }, 30000);
    }
    function sessionDrawer(x) {
      openDrawer(function (d) {
        drawerHead(d, el('span', { text: x.user + ' @ ' + x.host }));
        d.appendChild(el('div', { cls: 'kv' },
          el('div', { cls: 'k', text: t('ssType') }), el('div', null, typeChip(x.type), x.elevated ? pill('none', t('sfAdmin')) : null),
          el('div', { cls: 'k', text: t('ssFrom') }), el('div', { text: [x.device, x.ip].filter(function (z) { return z; }).join(' · ') || '—' }),
          el('div', { cls: 'k', text: t('ssStart') }), el('div', { cls: 'num', text: fmtT(x.start) }),
          el('div', { cls: 'k', text: t('ssEnd') }), el('div', { cls: 'num', text: x.end ? fmtT(x.end) : t('ssEndOpen') }),
          el('div', { cls: 'k', text: t('ssDur') }), el('div', { text: fmtDur(x.minutes) }),
          el('div', { cls: 'k', text: t('ssDiscN') }), el('div', { text: x.disc || 0 })));
        if (arr(x.flags).length) d.appendChild(el('div', { style: 'margin-top:10px' }, flagChips(x.flags)));
        d.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' },
          btn(t('users') + ': ' + x.user, function () { closeDrawer(); location.hash = '#/users/' + encodeURIComponent(x.user); }, 'pri'),
          btn(t('ssLogs'), function () { S.logs.host = x.host; S.logs.user = String(x.user).replace(/^.*\\/, ''); closeDrawer(); go('logs'); })));
      });
    }
    load();
  }

  // ------------------------------------------------------------------ router
  // ------------------------------------------------------------------ Mail Security
  var mailTab = 'dash';
  function mailKpi(val, label, col) { return el('div', { cls: 'kpi', style: col ? '--kc:' + col : null }, el('div', { cls: 'v num', style: col ? 'color:' + col : null, text: String(val) }), el('div', { cls: 'l', text: label })); }
  function mailListCard(title, heads, rows) {
    var c = card(title);
    if (rows.length) { c.appendChild(table(heads, rows.map(function (r) { return el('tr', null, r.map(function (cell) { return el('td', { cls: (cell.mono ? 'mono ' : '') + (cell.num ? 'num' : ''), text: cell.text }); })); }))); }
    else { c.appendChild(el('div', { cls: 'empty', text: t('adNoItems') })); }
    return c;
  }
  function vMailSec(sub) {
    if (sub && sub[0]) mailTab = sub[0];
    var v = page(t('nMail'), t('mailLead'));
    var tabs = el('div', { cls: 'tabs' });
    [['dash', 'mailTabDash'], ['quar', 'mailTabQuar'], ['policy', 'mailTabPolicy'], ['purge', 'mailTabPurge']].forEach(function (x) {
      tabs.appendChild(el('button', { type: 'button', cls: mailTab === x[0] ? 'on' : '', text: t(x[1]), onclick: function () { mailTab = x[0]; try { history.replaceState(null, '', '#/mailsec/' + x[0]); } catch (e) { } vMailSec(); } }));
    });
    v.appendChild(tabs);
    var box = el('div'); v.appendChild(box); box.appendChild(spinner());
    if (mailTab === 'quar') { mailQuar(box); return; }
    if (mailTab === 'policy') { mailPolicy(box); return; }
    if (mailTab === 'purge') { mailPurge(box); return; }
    mailDash(box);
  }
  function mailDash(box) {
    api('/api/mail/overview?days=7').then(function (r) {
      clear(box);
      if (!r.exchange) box.appendChild(el('div', { cls: 'banner' }, el('span', { text: t('mailNoExch') })));
      var bc = r.byCat || {};
      box.appendChild(el('div', { cls: 'kpis' },
        mailKpi(r.total || 0, t('mailFlagged'), 'var(--crit)'),
        mailKpi(r.quarantined || 0, t('mailQuarantined'), 'var(--warn)'),
        mailKpi(bc.MailPhish || 0, t('MailPhish'), 'var(--info)'),
        mailKpi(bc.MailSpam || 0, t('MailSpam'), null)));
      var bd = arr(r.byDay), mx = 1; bd.forEach(function (x) { if (x.n > mx) mx = x.n; });
      var ch = el('div', { style: 'display:flex;align-items:flex-end;gap:4px;height:80px;margin-top:6px' });
      bd.forEach(function (x) { ch.appendChild(el('div', { title: x.day + ': ' + x.n, style: 'flex:1;background:var(--accent);height:' + Math.round((x.n / mx) * 100) + '%;min-height:2px;border-radius:3px 3px 0 0' })); });
      var dc = card(t('mailByDay')); dc.appendChild(ch); box.appendChild(dc);
      var cols = el('div', { cls: 'cols' });
      cols.appendChild(mailListCard(t('mailTopSources'), [t('mailIp'), t('adCount')], arr(r.topSources).map(function (x) { return [{ mono: 1, text: x.ip }, { num: 1, text: String(x.n) }]; })));
      cols.appendChild(mailListCard(t('mailTopTargets'), [t('mailMailbox'), t('adCount')], arr(r.topTargets).map(function (x) { return [{ text: x.mailbox }, { num: 1, text: String(x.n) }]; })));
      box.appendChild(cols);
      var rc = card(t('mailRecent'));
      var rows = arr(r.recent).map(function (x) { return el('tr', null, el('td', { cls: 'nw', text: fmtT(x.time) }), el('td', null, pill(x.sev === 'Critical' ? 'Critical' : (x.sev === 'Warning' ? 'Warning' : 'Info'), t(x.cat))), el('td', { cls: 'mono', text: x.from }), el('td', { cls: 'mono', text: x.to }), el('td', { text: x.subject }), el('td', { cls: 'num', text: String(x.score) })); });
      if (!rows.length) rows = [emptyRow(6, t('adNoItems'))];
      rc.appendChild(table([t('time'), t('epSettings'), t('mailFrom'), t('mailTo'), t('mailSubject'), t('mailScore')], rows));
      box.appendChild(rc);
    }).catch(function (e) { clear(box); fail(e); });
  }
  function mailQuar(box) {
    api('/api/mail/quarantine').then(function (r) {
      clear(box);
      var c = card(t('mailTabQuar'));
      var rows = arr(r.items).map(function (q) {
        var acts = q.status === 'held' ? el('div', { cls: 'row' },
          btn(t('mailRelease'), function (e) { e.target.disabled = true; api('/api/mail/quarantine', { id: q.id, action: 'release' }).then(function () { flash(t('saved')); vMailSec(); }).catch(fail); }, 'sm'),
          btn(t('delete'), function (e) { e.target.disabled = true; api('/api/mail/quarantine', { id: q.id, action: 'delete' }).then(function () { flash(t('saved')); vMailSec(); }).catch(fail); }, 'sm danger'))
          : el('span', { cls: 'muted', text: t(q.status === 'released' ? 'mailReleased' : 'mailDeleted') });
        return el('tr', null, el('td', { cls: 'nw', text: fmtT(q.at) }), el('td', { cls: 'mono', text: q.from }), el('td', { cls: 'mono', text: q.to }), el('td', { text: q.subject }), el('td', { cls: 'num', text: String(q.score) }), el('td', { cls: 'muted', text: arr(q.reasons).join('; ') }), el('td', null, acts));
      });
      if (!rows.length) rows = [emptyRow(7, t('adNoItems'))];
      c.appendChild(table([t('time'), t('mailFrom'), t('mailTo'), t('mailSubject'), t('mailScore'), t('mailReasons'), ''], rows));
      box.appendChild(c);
    }).catch(function (e) { clear(box); fail(e); });
  }
  function mailPolicy(box) {
    api('/api/mail/settings').then(function (s) {
      clear(box);
      var en = el('input', { type: 'checkbox', checked: s.enabled !== false });
      var ss = numIn(s.spamScore, 1, 100), qs = numIn(s.quarantineScore, 1, 100);
      var sh = el('input', { type: 'checkbox', checked: s.useShared !== false });
      var ak = inp('AbuseIPDB API key', 'text', s.abuseKey || '');
      var ba = el('textarea', { rows: 2, cls: 'mono' }); ba.value = arr(s.blockedAttachments).join('\n');
      var bs = el('textarea', { rows: 3, cls: 'mono' }); bs.value = arr(s.blockSenders).join('\n');
      var als = el('textarea', { rows: 3, cls: 'mono' }); als.value = arr(s.allowSenders).join('\n');
      var c = card(t('mailTabPolicy'));
      c.appendChild(el('div', { cls: 'form' },
        el('label', null, ''), el('label', null, en, ' ', t('enabled')),
        el('label', { text: t('mailSpamScore') }), ss, el('div', { cls: 'hint', text: t('mailSpamScoreHint') }),
        el('label', { text: t('mailQuarScore') }), qs, el('div', { cls: 'hint', text: t('mailQuarScoreHint') }),
        el('label', null, ''), el('label', null, sh, ' ', t('mailUseShared')),
        el('label', { text: 'AbuseIPDB' }), ak, el('div', { cls: 'hint', text: t('mailAbuseHint') }),
        el('label', { text: t('mailBlockedAtt') }), ba, el('div', { cls: 'hint', text: t('mailBlockedAttHint') }),
        el('label', { text: t('mailBlockSenders') }), bs,
        el('label', { text: t('mailAllowSenders') }), als));
      c.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('save'), function (e) { e.target.disabled = true; api('/api/mail/settings', { enabled: en.checked, spamScore: +ss.value || 50, quarantineScore: +qs.value || 70, useShared: sh.checked, abuseKey: ak.value.trim(), blockedAttachments: splitList(ba.value), blockSenders: splitList(bs.value), allowSenders: splitList(als.value) }).then(function () { flash(t('saved')); }).catch(function (er) { e.target.disabled = false; fail(er); }); }, 'pri')));
      box.appendChild(c);
    }).catch(function (e) { clear(box); fail(e); });
  }
  function mailPurge(box) {
    clear(box); box.appendChild(spinner());
    api('/api/mail/recipients').then(function (rc) {
      clear(box);
      var c = card(t('mailTabPurge'));
      c.appendChild(el('div', { cls: 'tipbar', text: t('mailPurgeWarn') }));
      var subj = inp(t('mailSubject'), 'text', ''), snd = inp(t('mailFrom'), 'text', ''), mid = inp('Message-Id', 'text', '');
      var mbx = el('select'); mbx.appendChild(el('option', { value: 'all', text: t('mailAllMailboxes') }));
      arr(rc.mailboxes).forEach(function (m) { mbx.appendChild(el('option', { value: m, text: m })); });
      var db = el('select'); db.appendChild(el('option', { value: '', text: t('mailAllDbs') }));
      arr(rc.databases).forEach(function (d) { db.appendChild(el('option', { value: d, text: d })); });
      var mode = el('select'); [['soft', 'mailSoft'], ['hard', 'mailHard']].forEach(function (o) { mode.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
      c.appendChild(el('div', { cls: 'form' },
        el('label', { text: t('mailSubject') }), subj,
        el('label', { text: t('mailFrom') }), snd,
        el('label', { text: 'Message-Id' }), mid,
        el('label', { text: t('mailMailbox') }), mbx, el('div', { cls: 'hint', text: t('mailMailboxHint') }),
        el('label', { text: t('mailDatabase') }), db, el('div', { cls: 'hint', text: t('mailDbHint') }),
        el('label', { text: t('mailMode') }), mode, el('div', { cls: 'hint', text: t('mailModeHint') })));
      c.appendChild(el('div', { cls: 'hint', text: t('mailPrevHint') }));
      if (!rc.exchange) c.appendChild(el('div', { cls: 'hint', text: t('mailNoExchPick') }));
      var out = el('div', { style: 'margin-top:10px' });
      var results = el('div', { style: 'margin-top:14px' });
      function needCrit() { return subj.value.trim() || snd.value.trim() || mid.value.trim(); }
      function crit() { return { subject: subj.value.trim(), sender: snd.value.trim(), messageId: mid.value.trim(), mailbox: mbx.value, database: db.value }; }
      function runPurge(payload, modeVal, btnEl) {
        if (modeVal === 'hard' && !window.confirm(t('mailHardConfirm'))) return;
        if (btnEl) btnEl.disabled = true; clear(out); out.appendChild(el('span', { cls: 'spin' }));
        payload.mode = modeVal;
        api('/api/mail/purge', payload).then(function (r) {
          if (btnEl) btnEl.disabled = false; clear(out);
          if (r.ok) out.appendChild(el('div', { cls: 'flash ok', text: t('mailPurgeDone') + ': ' + (r.removed || 0) + ' (' + (r.method || '') + ')' }));
          else out.appendChild(el('div', { cls: 'flash err', text: loc(r.error) || t('err') }));
        }).catch(function (er) { if (btnEl) btnEl.disabled = false; clear(out); fail(er); });
      }
      function renderRows(rows) {
        clear(results);
        if (!rows.length) { results.appendChild(el('div', { cls: 'empty', text: t('mailPrevNone') })); return; }
        results.appendChild(el('div', { cls: 'sech', text: t('mailPrevFound') + ' (' + rows.length + ')' }));
        var trs = rows.map(function (m) {
          var delB = btn(t('mailDelThis'), function (e) {
            var p = m.messageId ? { messageId: m.messageId, mailbox: mbx.value, database: db.value }
                                : { subject: m.subject, sender: m.from, mailbox: mbx.value, database: db.value };
            runPurge(p, mode.value, e.target);
          }, 'pri danger sm');
          var idCell = m.messageId ? el('td', null, el('code', { text: m.messageId })) : el('td', { cls: 'muted', text: '—' });
          return el('tr', null,
            el('td', { text: m.date || '' }),
            el('td', { text: m.from || '' }),
            el('td', { text: m.to || '' }),
            el('td', { text: m.subject || '' }),
            idCell,
            el('td', null, delB));
        });
        results.appendChild(el('div', { cls: 'tw' }, el('table', null,
          el('thead', null, el('tr', null, el('th', { text: t('mailDate') }), el('th', { text: t('mailFrom') }), el('th', { text: t('mailTo') }), el('th', { text: t('mailSubject') }), el('th', { text: 'Message-Id' }), el('th', null))),
          el('tbody', null, trs))));
      }
      var bPrev = btn(t('mailPrevBtn'), function (e) {
        if (!needCrit()) { flash(t('mailPurgeNeed'), false); return; }
        e.target.disabled = true; clear(results); results.appendChild(el('span', { cls: 'spin' }));
        api('/api/mail/preview', { subject: subj.value.trim(), sender: snd.value.trim(), messageId: mid.value.trim(), mailbox: mbx.value, database: db.value }).then(function (r) {
          e.target.disabled = false;
          if (!r.exchange) { clear(results); results.appendChild(el('div', { cls: 'hint', text: t('mailNoExchPick') })); return; }
          renderRows(arr(r.rows));
        }).catch(function (er) { e.target.disabled = false; clear(results); fail(er); });
      }, 'pri');
      var bPurge = btn(t('mailPurgeBtn'), function (e) {
        if (!needCrit()) { flash(t('mailPurgeNeed'), false); return; }
        if (!window.confirm(t('mailPurgeConfirmAll'))) return;
        runPurge(crit(), mode.value, e.target);
      }, 'pri danger');
      c.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, bPrev, ' ', bPurge));
      c.appendChild(out);
      c.appendChild(results);
      box.appendChild(c);
    }).catch(function (e) { clear(box); fail(e); });
  }
  // ------------------------------------------------------------------ updates (tabs: status / publish / auto)
  var updTab = 'status';
  function vUpdates(sub) {
    if (sub && sub[0]) updTab = sub[0];
    var v = page(t('nUpdates'));
    var tabsEl = el('div', { cls: 'tabs' }); v.appendChild(tabsEl);
    var box = el('div'); v.appendChild(box); box.appendChild(spinner());
    api('/api/update/status').then(function (s) {
      var defs = [['status', 'updTabStatus'], ['feed', 'updTabAuto']];
      if (s.isVendor) defs.splice(1, 0, ['publish', 'updTabPublish']);
      if (s.canIssue) defs.push(['license', 'updTabLicense']);
      if (updTab === 'publish' && !s.isVendor) updTab = 'status';
      if (updTab === 'license' && !s.canIssue) updTab = 'status';
      if (['status', 'publish', 'feed', 'license'].indexOf(updTab) < 0) updTab = 'status';
      clear(tabsEl);
      defs.forEach(function (x) { tabsEl.appendChild(el('button', { type: 'button', cls: updTab === x[0] ? 'on' : '', text: t(x[1]), onclick: function () { updTab = x[0]; try { history.replaceState(null, '', '#/updates/' + x[0]); } catch (e) { } vUpdates(); } })); });
      clear(box);
      if (updTab === 'publish') updPublishTab(box, s);
      else if (updTab === 'feed') updFeedTab(box, s);
      else if (updTab === 'license') updLicenseTab(box, s);
      else updStatusTab(box, s);
    }).catch(function (e) { clear(box); fail(e); });
  }
  function updStatusTab(box, s) {
    var sc = card(t('updStatus'));
    sc.appendChild(el('div', { cls: 'form' },
      el('label', { text: t('updInstalled') }), el('div', { text: 'v' + (s.installedVersion || '?') }),
      el('label', { text: t('updServerVer') }), el('div', { text: s.serverVersion ? ('v' + s.serverVersion) : t('updNone') }),
      el('label', { text: t('updPublished') }), el('div', { text: s.publishedVersion ? ('v' + s.publishedVersion + (s.publishedAt ? ' · ' + String(s.publishedAt).replace('T', ' ') : '')) : t('updNone') })));
    box.appendChild(sc);
    var hc = card(t('updHowTitle'));
    hc.appendChild(el('div', { cls: 'tipbar', text: t('updTwoModes') }));
    var steps = s.isVendor ? ['updStep1', 'updStep2', 'updStep3', 'updStep4'] : ['updStepC1', 'updStepC2'];
    hc.appendChild(el('ol', { cls: 'steps', style: 'margin:10px 18px 2px;line-height:1.9' }, steps.map(function (k) { return el('li', { text: t(k) }); })));
    box.appendChild(hc);
  }
  function updPublishTab(box, s) {
    var pc = card(t('updPublishTitle'));
    pc.appendChild(el('p', { cls: 'lead', text: t('updPublishLead') }));
    var ver = inp(t('updVersionPh'), 'text', ''), notes = el('textarea', { rows: '2', placeholder: t('updNotesPh') }), copyTo = inp('\\\\SRV\\LogBokPublish', 'text', '');
    pc.appendChild(el('div', { cls: 'form' },
      el('label', { text: t('updVersion') }), ver, el('div', { cls: 'hint', text: t('updVersionHint') }),
      el('label', { text: t('updNotes') }), notes,
      el('label', { text: t('updCopyTo') }), copyTo, el('div', { cls: 'hint', text: t('updCopyHint') })));
    var pout = el('div', { style: 'margin-top:10px' });
    pc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('updPublishBtn'), function (e) {
      if (!window.confirm(t('updPublishConfirm'))) return;
      e.target.disabled = true; clear(pout); pout.appendChild(el('span', { cls: 'spin' }));
      api('/api/update/publish', { version: ver.value.trim(), notes: notes.value.trim(), copyTo: copyTo.value.trim() }).then(function (r) {
        e.target.disabled = false; clear(pout);
        if (r.ok) {
          pout.appendChild(el('div', { cls: 'flash ok', text: t('updPublished') + ' v' + r.version + ' — ' + ((r.codeFiles || 0) + (r.webFiles || 0)) + ' ' + t('updFiles') + (r.copiedTo ? ' · ' + t('updCopied') : '') }));
          if (r.zip) pout.appendChild(el('div', { cls: 'hint', text: t('updManualHint') + r.zip }));
          pout.appendChild(el('div', { cls: 'hint', text: t('updManualHow') }));
        } else pout.appendChild(el('div', { cls: 'flash err', text: loc(r.error) || t('err') }));
      }).catch(function (er) { e.target.disabled = false; clear(pout); fail(er); });
    }, 'pri')));
    pc.appendChild(pout);
    box.appendChild(pc);
    if (arr(s.history).length) {
      var hc = card(t('updHistory'));
      var hrows = arr(s.history).map(function (h) { return el('tr', null, el('td', { text: 'v' + (h.version || '') }), el('td', { text: String(h.published || '').replace('T', ' ') }), el('td', { text: String(h.files || '') }), el('td', { text: h.notes || '' }), el('td', { text: h.by || '' })); });
      hc.appendChild(el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, el('th', { text: t('updVersion') }), el('th', { text: t('updWhen') }), el('th', { text: t('updFiles') }), el('th', { text: t('updNotes') }), el('th', { text: t('updBy') }))), el('tbody', null, hrows))));
      box.appendChild(hc);
    }
  }
  function updFeedTab(box, s) {
    var fc = card(t('updFeedTitle'));
    fc.appendChild(el('p', { cls: 'lead', text: t('updFeedLead') }));
    var feed = inp('https://bokernet.ir/logbok', 'text', s.feed || ''), iv = inp('', 'number', String(s.intervalHours || 6));
    var en = el('input', { type: 'checkbox' }); en.checked = s.enabled !== false;
    fc.appendChild(el('div', { cls: 'form' },
      el('label', { text: t('updFeedUrl') }), feed, el('div', { cls: 'hint', text: t('updFeedHint') }),
      el('label', { text: t('updInterval') }), iv,
      el('label', { text: t('updAuto') }), el('label', { cls: 'chk' }, en, ' ', el('span', { text: t('updAutoOn') }))));
    var fout = el('div', { style: 'margin-top:10px' });
    fc.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' },
      btn(t('save'), function (e) {
        e.target.disabled = true; clear(fout);
        api('/api/update/settings', { feed: feed.value.trim(), intervalHours: parseInt(iv.value, 10) || 6, enabled: en.checked }).then(function () { e.target.disabled = false; fout.appendChild(el('div', { cls: 'flash ok', text: t('saved') })); }).catch(function (er) { e.target.disabled = false; fail(er); });
      }, 'pri'), ' ',
      btn(t('updPullNow'), function (e) {
        e.target.disabled = true; clear(fout); fout.appendChild(el('span', { cls: 'spin' }));
        api('/api/update/pull', {}).then(function (r) { e.target.disabled = false; clear(fout); if (r.ok) fout.appendChild(el('div', { cls: 'flash ok', text: r.changed ? (t('updPulled') + ': ' + r.changed) : (loc(r.note) || t('updUpToDate')) })); else fout.appendChild(el('div', { cls: 'flash err', text: loc(r.error) || t('err') })); }).catch(function (er) { e.target.disabled = false; clear(fout); fail(er); });
      })));
    fc.appendChild(fout);
    box.appendChild(fc);
  }
  // vendor only: issue a device-locked, signed license from the console
  function updLicenseTab(box, s) {
    var c = card(t('licTitle'));
    c.appendChild(el('p', { cls: 'lead', text: t('licLead') }));
    var company = inp(t('licCompanyPh'), 'text', '');
    var device = inp('1A2B3-C4D5E-6F708-192A3', 'text', ''); device.style.cssText = 'font-family:monospace;letter-spacing:1px;text-transform:uppercase';
    var modeSel = el('select', null,
      el('option', { value: 'days', text: t('licModeDays') }),
      el('option', { value: 'date', text: t('licModeDate') }),
      el('option', { value: 'permanent', text: t('licModePerm') }));
    var days = inp('', 'number', '365'); days.style.cssText = 'width:120px';
    var dateI = inp('', 'date', '');
    var dateWrap = el('span', null, dateI); dateWrap.style.display = 'none';
    var daysWrap = el('span', null, days, ' ', el('span', { cls: 'hint', text: t('licDaysUnit') }));
    modeSel.onchange = function () {
      daysWrap.style.display = modeSel.value === 'days' ? '' : 'none';
      dateWrap.style.display = modeSel.value === 'date' ? '' : 'none';
    };
    var clients = inp('', 'number', '50'), fsv = inp('', 'number', '2'), iis = inp('', 'number', '2'), sql = inp('', 'number', '2'), dc = inp('', 'number', '1');
    [clients, fsv, iis, sql, dc].forEach(function (x) { x.style.cssText = 'width:90px'; });
    c.appendChild(el('div', { cls: 'form' },
      el('label', { text: t('licCompany') }), company,
      el('label', { text: t('licDevice') }), device, el('div', { cls: 'hint', text: t('licDeviceHint') }),
      el('label', { text: t('licExpiry') }), el('div', { style: 'display:flex;gap:10px;align-items:center;flex-wrap:wrap' }, modeSel, daysWrap, dateWrap)));
    c.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' },
      el('label', { text: t('licLimits') }),
      el('div', { style: 'display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end' },
        el('label', { cls: 'hint', style: 'display:flex;flex-direction:column;gap:3px' }, el('span', { text: t('licClients') }), clients),
        el('label', { cls: 'hint', style: 'display:flex;flex-direction:column;gap:3px' }, el('span', { text: t('licFileServers') }), fsv),
        el('label', { cls: 'hint', style: 'display:flex;flex-direction:column;gap:3px' }, el('span', { text: 'IIS' }), iis),
        el('label', { cls: 'hint', style: 'display:flex;flex-direction:column;gap:3px' }, el('span', { text: 'SQL' }), sql),
        el('label', { cls: 'hint', style: 'display:flex;flex-direction:column;gap:3px' }, el('span', { text: t('licDC') }), dc))));
    var lout = el('div', { style: 'margin-top:12px' });
    c.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('licIssueBtn'), function (e) {
      var co = company.value.trim(), dv = device.value.trim().toUpperCase();
      if (!co) { flash(t('licNeedCompany'), false); return; }
      if (!dv) { flash(t('licNeedDevice'), false); return; }
      var payload = { company: co, device: dv, mode: modeSel.value, days: parseInt(days.value, 10) || 365, expiry: dateI.value,
        clients: parseInt(clients.value, 10) || 0, fileServers: parseInt(fsv.value, 10) || 0, iis: parseInt(iis.value, 10) || 0, sql: parseInt(sql.value, 10) || 0, dc: parseInt(dc.value, 10) || 0 };
      e.target.disabled = true; clear(lout); lout.appendChild(el('span', { cls: 'spin' }));
      api('/api/license/issue', payload).then(function (r) {
        e.target.disabled = false; clear(lout);
        if (!r.ok) { lout.appendChild(el('div', { cls: 'flash err', text: loc(r.error) || t('err') })); return; }
        lout.appendChild(el('div', { cls: 'flash ok', text: t('licDone') + ' · ' + t('licExpires') + ': ' + (r.expires === 'never' ? t('licPermNote') : r.expires) }));
        var ta = el('textarea', { rows: '8', readonly: 'readonly' }); ta.value = r.license; ta.style.cssText = 'width:100%;font-family:monospace;font-size:12px;direction:ltr;margin-top:8px';
        lout.appendChild(ta);
        lout.appendChild(el('div', { cls: 'acts', style: 'margin-top:8px' },
          btn(t('licCopy'), function () { ta.select(); try { document.execCommand('copy'); flash(t('copied')); } catch (x) { } }, 'sm'),
          btn(t('licDownload'), function () { try { var blob = new Blob([r.license], { type: 'text/plain' }); download(URL.createObjectURL(blob)); } catch (x) { } }, 'sm')));
        lout.appendChild(el('div', { cls: 'hint', style: 'margin-top:6px', text: t('licSendHint') }));
        loadIssued();
      }).catch(function (er) { e.target.disabled = false; clear(lout); fail(er); });
    }, 'pri')));
    c.appendChild(lout);
    box.appendChild(c);

    var ic = card(t('licIssuedTitle'));
    var ibox = el('div'); ic.appendChild(ibox); box.appendChild(ic);
    function loadIssued() {
      clear(ibox); ibox.appendChild(el('span', { cls: 'spin' }));
      api('/api/license/issued').then(function (d) {
        clear(ibox);
        var rows = arr(d.rows);
        if (!rows.length) { ibox.appendChild(el('div', { cls: 'hint', text: t('licNoneYet') })); return; }
        var trs = rows.map(function (r) { return el('tr', null,
          el('td', { text: r.company || '' }),
          el('td', { cls: 'mono', text: r.device || '' }),
          el('td', { text: r.expires === 'never' ? t('licPermNote') : (r.expires || '') }),
          el('td', { text: String(r.issued || '').replace('T', ' ') })); });
        ibox.appendChild(el('div', { cls: 'tw' }, el('table', null,
          el('thead', null, el('tr', null, el('th', { text: t('licCompany') }), el('th', { text: t('licDevice') }), el('th', { text: t('licExpires') }), el('th', { text: t('licWhen') }))),
          el('tbody', null, trs))));
      }).catch(function () { clear(ibox); });
    }
    loadIssued();
  }

  // ------------------------------------------------------------------ console users
  function my2faCard(box) {
    var c = card(t('acc2faTitle'));
    c.appendChild(el('p', { cls: 'lead', text: t('acc2faLead') }));
    var body = el('div'); c.appendChild(body);
    function load() {
      clear(body); body.appendChild(el('span', { cls: 'spin' }));
      api('/api/me/2fa').then(function (s) {
        clear(body);
        if (!s.isConsoleUser) { body.appendChild(el('div', { cls: 'hint', text: t('acc2faWindows') + ' ' + t('acc2faNeedConsole') })); return; }
        // status line
        body.appendChild(el('div', { cls: 'form' },
          el('label', { text: t('acc2faTotp') }), el('div', { text: s.totp ? t('acc2faOn') : t('acc2faOff') }),
          el('label', { text: t('acc2faEmail') }), el('div', { text: s.email ? (t('acc2faOn') + (s.emailAddr ? ' · ' + s.emailAddr : '')) : t('acc2faOff') })));
        // TOTP enable
        if (!s.totp) {
          var startB = btn(t('acc2faEnableTotp'), function (e) {
            e.target.disabled = true;
            api('/api/me/2fa/totp/start', {}).then(function (r) {
              e.target.disabled = false;
              var wrap = el('div', { style: 'margin-top:10px' });
              wrap.appendChild(el('div', { cls: 'hint', text: t('acc2faTotpStep') }));
              var sec = el('div', { style: 'font-family:monospace;font-size:16px;letter-spacing:2px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:6px 0;word-break:break-all', text: r.secret });
              wrap.appendChild(el('label', { cls: 'hint', text: t('acc2faSecret') })); wrap.appendChild(sec);
              wrap.appendChild(el('div', { cls: 'hint', style: 'word-break:break-all;opacity:.6', text: r.uri }));
              var code = inp('------', 'text', ''); code.setAttribute('maxlength', '6'); code.setAttribute('inputmode', 'numeric'); code.style.cssText = 'letter-spacing:4px;text-align:center';
              wrap.appendChild(el('div', { cls: 'form', style: 'margin-top:8px' }, el('label', { text: t('login2faCode') }), code));
              wrap.appendChild(el('div', { cls: 'acts', style: 'margin-top:8px' }, btn(t('acc2faConfirm'), function (ev) {
                var cc = (code.value || '').replace(/\D/g, ''); if (cc.length !== 6) { flash(t('login2faNeed'), false); return; }
                ev.target.disabled = true; api('/api/me/2fa/totp/confirm', { code: cc }).then(function () { flash(t('saved')); load(); }).catch(function (er) { ev.target.disabled = false; fail(er); });
              }, 'pri')));
              body.appendChild(wrap);
            }).catch(function (er) { e.target.disabled = false; fail(er); });
          }, 'pri');
          body.appendChild(el('div', { cls: 'acts', style: 'margin-top:10px' }, startB));
        }
        // Email enable
        var em = inp('you@company.com', 'text', s.emailAddr || '');
        body.appendChild(el('div', { cls: 'form', style: 'margin-top:12px' }, el('label', { text: t('acc2faEmailAddr') }), em));
        var emActs = el('div', { cls: 'acts', style: 'margin-top:8px' });
        emActs.appendChild(btn(s.email ? t('acc2faDisable') : t('acc2faEmailOn'), function (e) {
          e.target.disabled = true;
          api('/api/me/2fa/email', { email: em.value.trim(), enable: !s.email }).then(function () { flash(t('saved')); load(); }).catch(function (er) { e.target.disabled = false; fail(er); });
        }, 'sm'));
        if (s.on) emActs.appendChild(btn(t('acc2faDisable') + ' (' + t('acc2faTotp') + ')', function (e) { if (!window.confirm(t('acc2faDisable') + '؟')) return; api('/api/me/2fa/disable', { which: 'all' }).then(function () { flash(t('saved')); load(); }).catch(fail); }, 'pri danger sm'));
        body.appendChild(emActs);
      }).catch(function (e) { clear(body); fail(e); });
    }
    load();
    box.appendChild(c);
  }
  function vAccounts() {
    var box = page(t('settings')); box.appendChild(spinner());
    api('/api/users').then(function (d) {
      box = page(t('settings'));
      my2faCard(box);
      var c = card(t('accTitle'));
      c.appendChild(el('p', { cls: 'lead', text: t('accLead') + ' (' + t('accMode') + ': ' + d.mode + ')' }));
      var rows = arr(d.users).map(function (u) {
        var rst = btn(t('accReset'), function () { var np = window.prompt(t('accNewPw')); if (!np) return; api('/api/users/password', { name: u.name, password: np }).then(function () { flash(t('saved')); }).catch(fail); }, 'sm');
        var tog = btn(u.disabled ? t('accEnable') : t('accDisable'), function () { api('/api/users/state', { name: u.name, disabled: !u.disabled }).then(function () { vAccounts(); }).catch(fail); }, 'sm');
        var r2fa = u.twofa ? btn(t('acc2faReset'), function () { if (!window.confirm(t('acc2faReset') + ' ' + u.name + '؟')) return; api('/api/users/2fa/disable', { name: u.name }).then(function () { flash(t('saved')); vAccounts(); }).catch(fail); }, 'sm') : null;
        var del = btn(t('accRemove'), function () { if (!window.confirm(t('accRemoveConfirm') + ' ' + u.name)) return; api('/api/users/remove', { name: u.name }).then(function () { vAccounts(); }).catch(fail); }, 'pri danger sm');
        var acts = [rst, ' ', tog, ' ']; if (r2fa) { acts.push(r2fa); acts.push(' '); } acts.push(del);
        return el('tr', null, el('td', { text: u.name }), el('td', { text: t(u.role === 'admin' ? 'accAdmin' : 'accViewer') }), el('td', { text: (u.disabled ? t('accDisabled') : t('accActive')) + (u.twofa ? ' · 2FA' : '') }), el('td', null, acts));
      });
      c.appendChild(el('div', { cls: 'tw' }, el('table', null, el('thead', null, el('tr', null, el('th', { text: t('accUser') }), el('th', { text: t('accRole') }), el('th', { text: t('status') }), el('th', null))), el('tbody', null, rows))));
      box.appendChild(c);
      var ac = card(t('accAdd'));
      var nm = inp(t('accUser'), 'text', ''), pw = inp(t('accNewPw'), 'password', ''), role = el('select');
      [['admin', 'accAdmin'], ['viewer', 'accViewer']].forEach(function (o) { role.appendChild(el('option', { value: o[0], text: t(o[1]) })); });
      ac.appendChild(el('div', { cls: 'form' }, el('label', { text: t('accUser') }), nm, el('label', { text: t('accNewPw') }), pw, el('label', { text: t('accRole') }), role));
      ac.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' }, btn(t('accAddBtn'), function (e) {
        if (!nm.value.trim() || !pw.value) { flash(t('accNeed'), false); return; }
        e.target.disabled = true;
        api('/api/users/add', { name: nm.value.trim(), password: pw.value, role: role.value }).then(function () { vAccounts(); }).catch(function (er) { e.target.disabled = false; fail(er); });
      }, 'pri')));
      box.appendChild(ac);
    }).catch(function (e) { fail(e); });
  }

  // ------------------------------------------------------------------ remote access (LAN / internet NAT)
  function remStatusInto(container, s) {
    var rows = [];
    rows.push([t('remCurMode'), t(s.mode === 'internet' ? 'remModeNet' : (s.mode === 'lan' ? 'remModeLan' : 'remModeLocal'))]);
    rows.push([t('remLocalIp'), s.localIp || '—']);
    if (s.mode === 'internet') rows.push([t('remPublicIp'), s.publicIp || t('remUnknown')]);
    rows.push([t('remFw'), s.firewall ? t('acc2faOn') : t('acc2faOff')]);
    if (s.mode === 'internet') rows.push([t('remNat'), (s.nat && s.nat.external) ? (t('acc2faOn') + ' (' + s.nat.external + '→' + s.nat.internal + ')') : t('remNatNo')]);
    rows.push([t('remUrl'), s.url || '—']);
    var g = el('div', { cls: 'form' });
    rows.forEach(function (r) { g.appendChild(el('label', { text: r[0] })); g.appendChild(el('div', { text: String(r[1]) })); });
    container.appendChild(g);
    arr(s.notes).forEach(function (n) { container.appendChild(el('div', { cls: 'hint', text: '• ' + loc(n) })); });
  }
  function vRemote() {
    var box = page(t('settings')); box.appendChild(spinner());
    api('/api/remote').then(function (s) {
      box = page(t('settings'));
      var c = card(t('remTitle'));
      c.appendChild(el('p', { cls: 'lead', text: t('remLead') }));
      var mode = el('select'); [['local', 'remModeLocal'], ['lan', 'remModeLan'], ['internet', 'remModeNet']].forEach(function (o) { mode.appendChild(el('option', { value: o[0], text: t(o[1]) })); }); mode.value = s.mode || 'local';
      var ext = inp('', 'number', String(s.externalPort || s.port || 8686));
      var ips = inp('192.168.1.10, 203.0.113.5', 'text', (arr(s.allowedIps) || []).join(', '));
      c.appendChild(el('div', { cls: 'form' },
        el('label', { text: t('remMode') }), mode, el('div', { cls: 'hint', text: t('remModeHint') }),
        el('label', { text: t('remExtPort') }), ext, el('div', { cls: 'hint', text: t('remExtHint') }),
        el('label', { text: t('remAllowIps') }), ips, el('div', { cls: 'hint', text: t('remAllowHint') })));
      c.appendChild(el('div', { cls: 'banner', style: 'margin-top:10px' }, el('span', { text: '⚠ ' + t('remWarn') })));
      var out = el('div', { style: 'margin-top:10px' });
      c.appendChild(el('div', { cls: 'acts', style: 'margin-top:12px' },
        btn(t('remApply'), function (e) {
          if (mode.value === 'internet' && !window.confirm(t('remNetConfirm'))) return;
          e.target.disabled = true; clear(out); out.appendChild(el('span', { cls: 'spin' }));
          api('/api/remote/apply', { mode: mode.value, externalPort: parseInt(ext.value, 10) || 0, allowedIps: ips.value }).then(function (r) {
            e.target.disabled = false; clear(out);
            out.appendChild(el('div', { cls: 'flash ok', text: t('saved') }));
            if (r.restartNeeded) out.appendChild(el('div', { cls: 'hint', text: t('remRestart') }));
            remStatusInto(out, r);
          }).catch(function (er) { e.target.disabled = false; clear(out); fail(er); });
        }, 'pri'), ' ',
        btn(t('remRefresh'), function () { vRemote(); })));
      c.appendChild(out);
      box.appendChild(c);
      var stc = card(t('remStatus'));
      remStatusInto(stc, s);
      box.appendChild(stc);
    }).catch(function (e) { fail(e); });
  }

  var VIEWS = { computers: vComputers, deploy: vAgents, agentcfg: vAgentCfg, sessions: vSessions, reports: vReports, users: vUsers, endpoints: vEndpoints, software: vSoftware, overview: vOverview, events: vEvents, logs: vLogs, incidents: vIncidents, alerts: vAlerts, connections: vConnections, jobs: vJobs, settings: vSettings, mailsec: vMailSec, updates: vUpdates, accounts: vAccounts, remote: vRemote };
  function go(name) { if (location.hash === '#/' + name) { route(); } else { location.hash = '#/' + name; } }
  function route() {
    var h = (location.hash || '').replace(/^#\/?/, '');
    var parts = h.split('/'); var name = parts[0];
    if (name === 'event' && parts[1]) { if (!S.view) { S.view = 'events'; renderNav(); vEvents(); } openFinding(parts[1]); return; }
    // نشانی‌های قدیمی (ایمیل‌ها و نشانک‌ها) به جای تازه می‌روند | old links (mails, bookmarks) land on the new place
    var AL = { agents: function (p) { return (!p[0] || p[0] === 'status') ? ['computers'] : ['deploy', ({ manual: 'package', push: 'single', ad: 'domain', wg: 'workgroup' })[p[0]] || p[0]]; },
               sources: function (p) { return (!p[0] || p[0] === 'list') ? ['computers'] : (p[0] === 'cred' ? ['agentcfg'] : ['deploy', ({ win: 'single', ad: 'domain', net: 'other', svc: 'other', custom: 'other' })[p[0]] || 'single']); },
               guard: function () { return ['endpoints', 'guard']; }, investigate: function () { return ['logs']; }, protect: function () { return ['endpoints']; } };
    if (AL[name]) { var np = AL[name](parts.slice(1)); try { history.replaceState(null, '', '#/' + np.join('/')); } catch (e) { } parts = np; name = np[0]; }
    if (!VIEWS[name]) name = 'overview';
    if (!$('drawer').hidden) { $('drawer').hidden = true; $('scrim').hidden = true; }
    S.view = name; renderNav();
    var secT = SECTIONS[sectionOf(name)]; $('crumbs').textContent = (S.meta && S.meta.host ? S.meta.host + ' · ' : '') + t(secT ? secT.t : name) + (secT && secT.v.length > 1 ? ' · ' + t(VIEWTAB[name] || name) : '');
    VIEWS[name](parts.slice(1));
  }

  // ------------------------------------------------------------------ boot
  function renderAuthScreen(m) {
    var old = document.getElementById('authOverlay'); if (old) old.remove();
    var ov = el('div', { id: 'authOverlay' });
    ov.style.cssText = 'position:fixed;top:0;right:0;bottom:0;left:0;z-index:9999;display:flex;align-items:center;justify-content:center;overflow:auto;background:var(--bg);padding:16px';
    var host = el('div'); host.style.cssText = 'width:100%;max-width:380px';
    ov.appendChild(host); document.body.appendChild(ov);
    var isSetup = !!m.needSetup;
    function shell() { var c = el('div'); c.style.cssText = 'background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:26px 24px;box-shadow:0 24px 70px -24px rgba(0,0,0,.55)'; return c; }
    function lbl(txt, mar) { return el('label', { text: txt, style: 'display:block;font-size:12px;opacity:.75;margin:' + (mar || '10px 0 4px') }); }
    function remSel() { var s = el('select'); s.style.cssText = 'width:100%'; [['0', 'remThis'], ['30', 'rem30'], ['180', 'rem180'], ['360', 'rem360']].forEach(function (o) { s.appendChild(el('option', { value: o[0], text: t(o[1]) })); }); return s; }

    function step1() {
      clear(host); var c = shell();
      c.appendChild(el('div', { text: 'LogBok', style: 'font-size:24px;font-weight:800;letter-spacing:.5px' }));
      c.appendChild(el('div', { text: isSetup ? t('loginSetupLead') : t('loginLead'), style: 'opacity:.7;margin:4px 0 18px;font-size:13px;line-height:1.7' }));
      var user = inp(t('loginUser'), 'text', ''), pass = inp(t('loginPass'), 'password', ''), pass2 = null, rem = null;
      user.style.cssText = 'width:100%'; pass.style.cssText = 'width:100%';
      c.appendChild(lbl(t('loginUser'), '0 0 4px')); c.appendChild(user);
      c.appendChild(lbl(t('loginPass'))); c.appendChild(pass);
      if (isSetup) { pass2 = inp(t('loginPass2'), 'password', ''); pass2.style.cssText = 'width:100%'; c.appendChild(lbl(t('loginPass2'))); c.appendChild(pass2); }
      else { rem = remSel(); c.appendChild(lbl(t('loginRemember'))); c.appendChild(rem); }
      var msg = el('div', { style: 'min-height:18px;margin:10px 0 2px;font-size:13px;color:var(--crit)' });
      var go = el('button', { type: 'button', cls: 'btn pri', text: isSetup ? t('loginCreateBtn') : t('loginBtn'), style: 'width:100%;justify-content:center;margin-top:8px' });
      function submit() {
        var u = user.value.trim(), p = pass.value;
        if (!u || !p) { msg.textContent = t('loginNeed'); return; }
        if (isSetup && pass2 && p !== pass2.value) { msg.textContent = t('loginMismatch'); return; }
        var rd = rem ? parseInt(rem.value, 10) : 0;
        go.disabled = true; msg.style.color = 'var(--muted)'; msg.textContent = '…';
        fetch(isSetup ? '/api/setup' : '/api/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: u, password: p, rememberDays: rd }) })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
          .then(function (x) {
            if (x.ok && x.j && x.j.ok) { location.reload(); return; }
            if (x.j && x.j.twofa) { step2(x.j, rd); return; }
            go.disabled = false; msg.style.color = 'var(--crit)'; msg.textContent = (x.j && x.j.error) ? loc(x.j.error) : t('loginFail');
          })
          .catch(function () { go.disabled = false; msg.style.color = 'var(--crit)'; msg.textContent = t('loginFail'); });
      }
      go.onclick = submit;
      [user, pass].concat(pass2 ? [pass2] : []).forEach(function (f) { f.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); }); });
      c.appendChild(msg); c.appendChild(go); host.appendChild(c); try { user.focus(); } catch (e) { }
    }

    function step2(info, rd) {
      clear(host); var c = shell();
      c.appendChild(el('div', { text: t('login2faTitle'), style: 'font-size:20px;font-weight:800' }));
      var methods = arr(info.methods), method = methods.indexOf('totp') >= 0 ? 'totp' : (methods[0] || 'totp');
      function leadText() { return method === 'email' ? (t('login2faEmailLead') + (info.emailHint ? ' (' + info.emailHint + ')' : '')) : t('login2faTotpLead'); }
      var leadEl = el('div', { text: leadText(), style: 'opacity:.7;margin:4px 0 14px;font-size:13px;line-height:1.7' });
      c.appendChild(leadEl);
      var methRow = null;
      if (methods.length > 1) {
        methRow = el('div', { style: 'display:flex;gap:8px;margin-bottom:12px' });
        methods.forEach(function (mth) { methRow.appendChild(el('button', { type: 'button', cls: 'btn sm' + (mth === method ? ' pri' : ''), text: t(mth === 'totp' ? 'login2faTotp' : 'login2faEmail'), onclick: function () { method = mth; leadEl.textContent = leadText(); [].forEach.call(methRow.children, function (b, i) { b.className = 'btn sm' + (methods[i] === method ? ' pri' : ''); }); } })); });
        c.appendChild(methRow);
      }
      var code = inp('------', 'text', ''); code.setAttribute('inputmode', 'numeric'); code.setAttribute('maxlength', '6'); code.style.cssText = 'width:100%;letter-spacing:6px;text-align:center;font-size:20px';
      c.appendChild(lbl(t('login2faCode'))); c.appendChild(code);
      var msg = el('div', { style: 'min-height:18px;margin:10px 0 2px;font-size:13px;color:var(--crit)' });
      var go = el('button', { type: 'button', cls: 'btn pri', text: t('loginBtn'), style: 'width:100%;justify-content:center;margin-top:8px' });
      function submit() {
        var cc = (code.value || '').replace(/\D/g, '');
        if (cc.length !== 6) { msg.textContent = t('login2faNeed'); return; }
        go.disabled = true; msg.style.color = 'var(--muted)'; msg.textContent = '…';
        fetch('/api/login/2fa', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ticket: info.ticket, code: cc, method: method, rememberDays: rd }) })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
          .then(function (x) { if (x.ok && x.j && x.j.ok) { location.reload(); } else { go.disabled = false; msg.style.color = 'var(--crit)'; msg.textContent = (x.j && x.j.error) ? loc(x.j.error) : t('loginFail'); } })
          .catch(function () { go.disabled = false; msg.style.color = 'var(--crit)'; msg.textContent = t('loginFail'); });
      }
      go.onclick = submit;
      code.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });
      c.appendChild(msg); c.appendChild(go);
      c.appendChild(el('button', { type: 'button', cls: 'btn sm', text: t('login2faBack'), style: 'width:100%;justify-content:center;margin-top:8px', onclick: step1 }));
      host.appendChild(c); try { code.focus(); } catch (e) { }
    }

    step1();
  }
  function doLogout() { fetch('/api/logout', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-LogBok-Token': S.token || '' }, body: '{}' }).then(function () { location.reload(); }).catch(function () { location.reload(); }); }

  // info "i" badges: every descriptive paragraph (p.lead) becomes a small (i) next to its heading; text shows on hover/tap
  var TIP = null;
  function tipShow(ic) {
    if (!TIP) { TIP = el('div', { cls: 'lbtip', role: 'tooltip' }); document.body.appendChild(TIP); }
    TIP.textContent = ic._tip; TIP.className = 'lbtip on';
    var r = ic.getBoundingClientRect(), w = Math.min(380, window.innerWidth - 24);
    TIP.style.maxWidth = w + 'px';
    var tw = TIP.offsetWidth, th = TIP.offsetHeight;
    var rtl = document.documentElement.dir === 'rtl';
    var x = rtl ? (r.right - tw) : r.left; x = Math.max(12, Math.min(x, window.innerWidth - tw - 12));
    var y = r.bottom + 8; if (y + th > window.innerHeight - 8) y = Math.max(8, r.top - th - 8);
    TIP.style.left = x + 'px'; TIP.style.top = y + 'px';
  }
  function tipHide() { if (TIP) TIP.className = 'lbtip'; }
  function infoIcon(text) {
    var ic = el('span', { cls: 'info', tabindex: '0', role: 'button', 'aria-label': text, text: 'i' });
    ic._tip = text;
    ic.addEventListener('mouseenter', function () { tipShow(ic); });
    ic.addEventListener('mouseleave', tipHide);
    ic.addEventListener('focus', function () { tipShow(ic); });
    ic.addEventListener('blur', tipHide);
    ic.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); if (TIP && TIP.className === 'lbtip on') tipHide(); else tipShow(ic); });
    return ic;
  }
  function leadToInfo(p) {
    if (!p || p._lbDone || !p.parentNode) return; p._lbDone = true;
    var text = (p.textContent || '').trim(); if (!text) return;
    var h = null, n = p.previousElementSibling;
    while (n) { if (/^H[1-4]$/.test(n.tagName)) { h = n; break; } if (n.classList && (n.classList.contains('stabs') || n.classList.contains('tabs'))) { n = n.previousElementSibling; continue; } break; }
    if (!h) { var cd = p.parentNode.closest ? p.parentNode.closest('.card') : null; if (cd && cd.firstElementChild && cd.firstElementChild.tagName === 'H3') h = cd.firstElementChild; }
    if (!h) { var pv = p.previousElementSibling; if (pv && pv.classList && pv.classList.contains('seg')) { var ic2 = infoIcon(text); ic2.classList.add('aftseg'); pv.parentNode.insertBefore(ic2, p); p.parentNode.removeChild(p); return; } }
    if (!h) { var vh = document.querySelector('#view > h1'); if (vh && vh.contains && !vh.contains(p)) h = vh; }
    if (!h) { p.classList.add('leadsm'); p.textContent = ''; p.appendChild(infoIcon(text)); return; }
    if (h.querySelector(':scope > .info')) { var ex = h.querySelector(':scope > .info'); if (ex._tip.indexOf(text) < 0) ex._tip += '\n\n' + text; p.parentNode.removeChild(p); return; }
    var after = h.firstElementChild && h.tagName !== 'H1' ? h.firstElementChild : null;
    var ic = infoIcon(text);
    if (after && after.nextSibling) h.insertBefore(ic, after.nextSibling); else h.appendChild(ic);
    p.parentNode.removeChild(p);
  }
  function leadScan(root) { [].forEach.call((root || document).querySelectorAll('p.lead'), leadToInfo); }
  window.addEventListener('scroll', tipHide, true);
  document.addEventListener('click', tipHide);

  function boot() {
    initTheme();
    try { leadScan(document); new MutationObserver(function (ms) { var any = false; ms.forEach(function (m) { if (m.addedNodes.length) any = true; }); if (any) leadScan(document); }).observe(document.body, { childList: true, subtree: true }); } catch (e) { }
    $('scrim').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !$('drawer').hidden) closeDrawer(); });
    api('/api/meta').then(function (m) {
      if (m && m.authed === false) {
        S.lang = m.lang || 'fa'; document.documentElement.lang = (S.lang === 'en') ? 'en' : 'fa'; document.documentElement.dir = S.lang === 'en' ? 'ltr' : 'rtl';
        try { applyTheme(document.documentElement.getAttribute('data-theme') || 'light'); } catch (e) { }
        renderAuthScreen(m); return;
      }
      S.meta = m; S.lang = m.lang || 'fa'; S.token = m.token; S.cats = arr(m.categories);
      document.documentElement.lang = (S.lang === 'en') ? 'en' : 'fa'; document.documentElement.dir = S.lang === 'en' ? 'ltr' : 'rtl';
      $('brandSub').textContent = S.lang === 'en' ? 'Security Package' : 'لاگ‌بوک · بستهٔ امنیتی';
      var wu = String(m.user || '').replace(/^.*\\/, ''), wb = clear($('who'));
      wb.appendChild(el('span', { cls: 'av', text: (wu.charAt(0) || '?').toUpperCase() }));
      wb.appendChild(el('div', null, el('div', { cls: 'wn', text: wu || t('userLbl') }), el('div', { cls: 'wv', text: (m.host ? m.host + ' · ' : '') + 'v' + m.version })));
      if (m.loginOn) { wb.appendChild(el('button', { type: 'button', cls: 'btn sm', text: t('logout'), title: t('logout'), style: 'margin-inline-start:auto', onclick: doLogout })); }
      applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
      $('liveTxt').textContent = t('updated') + ' ' + new Date().toTimeString().slice(0, 5);
      window.addEventListener('hashchange', route);
      route();
      setInterval(function () { $('liveTxt').textContent = t('updated') + ' ' + new Date().toTimeString().slice(0, 5); if (S.view === 'overview' && $('drawer').hidden) vOverview(); }, 120000);
    }).catch(function (e) { var v = clear($('view')); v.appendChild(el('div', { cls: 'flash err', text: (e && e.message ? e.message : String(e)) + ' — ' + t('reload') })); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
