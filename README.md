# VEGA Server — Test v1.2

این بسته نسخه آزمایشی API سرور VEGA است. فایل migration اولیه با نسخه موجود در مخزن حفظ شده و تغییرات جدید فقط در migration شماره 0002 هستند.

## محتویات
- `src/index.js`: Worker API آزمایشی
- `migrations/0001_initial.sql`: ساختار اولیه موجود؛ نباید تغییر کند
- `migrations/0002_test_api.sql`: ستون‌های نوع پیام/پاسخ، salt رمز و جدول‌های نشست و محدودسازی درخواست
- `wrangler.toml`: binding و شناسه فعلی D1 حفظ شده است
- `package.json`: فرمان‌های توسعه و migration

## اجرای محلی
1. Node.js نسخه LTS نصب باشد.
2. `npm install`
3. `npm run db:migrate:local`
4. `npm run dev`

این فرمان‌ها باید ابتدا روی دیتابیس محلی Wrangler اجرا شوند. برای دیتابیس Remote از فرمان migration راه دور استفاده نکنید تا وقتی نسخه migrationهای اعمال‌شده و پشتیبان D1 بررسی نشده باشد.

## APIهای موجود
- `GET /health`
- `GET /api/v1/health`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/me`
- `PATCH /api/v1/me`
- `GET /api/v1/users/search?q=...`
- `GET /api/v1/conversations`
- `POST /api/v1/conversations` (فقط private و group)
- `GET /api/v1/conversations/{id}/messages`
- `POST /api/v1/conversations/{id}/messages`
- `PATCH /api/v1/messages/{id}`
- `DELETE /api/v1/messages/{id}`
- `GET /api/v1/sync?since=ISO_TIMESTAMP`

برای APIهای محافظت‌شده هدر `Authorization: Bearer <token>` لازم است.

## تغییرات اصلاحی v1.2
- ذخیره `content_type` و `reply_to` در دیتابیس؛ در نسخه قبلی فقط در پاسخ API ظاهر می‌شدند.
- بررسی تعلق پیام پاسخ به همان گفتگو.
- برگرداندن `content_type` و `reply_to` در همگام‌سازی.
- محدودسازی درخواست با یک UPSERT اتمیک به‌جای پاک‌سازی و چند کوئری در هر درخواست؛ پاک‌سازی ردیف‌های منقضی‌شده به‌صورت فرصت‌طلبانه انجام می‌شود.
- ساخت گفتگو و اعضا با `D1.batch` تا درج‌های مرتبط با هم اجرا شوند.
- شناسه عضو نامعتبر دیگر بی‌صدا نادیده گرفته نمی‌شود.
- نام کاربری جدید به حروف کوچک تبدیل می‌شود و حداقل ۵ نویسه دارد؛ نام نمایشی حداکثر ۲۰ نویسه است.
- CORS دیگر Origin ورودی را به‌صورت خودکار بازتاب نمی‌دهد؛ در صورت نیاز `ALLOWED_ORIGIN` را برای دامنه وب مشخص کنید. برای کلاینت Native معمولاً CORS مرورگر مطرح نیست.

## نتایج تست محلی این بسته
- `node --check src/index.js`: موفق
- اجرای هر دو migration روی SQLite: موفق
- درج و خواندن پیام متنی و پیام رمزگذاری‌شده دارای reply: موفق
- آزمون UPSERT محدودسازی درخواست (افزایش شمارنده و reset پس از انقضا): موفق

این تست‌ها تست واحد/محلی هستند؛ به معنی تست روی Cloudflare Worker واقعی، D1 زنده یا سازگاری قطعی با کلاینت Flutter نیستند.

## محدودیت‌ها و هشدارها
این بسته برای تست داخلی است و نسخه آماده انتشار عمومی نیست. رمزهای جدید با PBKDF2-HMAC-SHA256 و salt تصادفی ذخیره می‌شوند. کاربران قدیمی که `password_salt` ندارند، با endpoint ورود این نسخه وارد نمی‌شوند؛ رمزهای قدیمی به‌صورت خودکار تغییر داده نمی‌شوند.

رمزنگاری سرتاسری واقعی، مدیریت کلید و دستگاه، انتقال رسانه، اعلان push، WebSocket، کانال‌ها، مجوزهای کامل گروه، دعوت‌نامه‌ها، گزارش/مسدودسازی و پنل مدیریت کامل در این بسته پیاده‌سازی نشده‌اند. مقدار `content_type: encrypted` به‌تنهایی E2EE ایجاد نمی‌کند.

قبل از هر migration یا deploy راه دور، از D1 پشتیبان بگیرید و وضعیت migrationهای اعمال‌شده را بررسی کنید. هرگز این ZIP را مستقیماً روی Worker زنده deploy نکنید بدون تست سازگاری کلاینت و محیط.
