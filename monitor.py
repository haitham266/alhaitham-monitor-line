# -*- coding: utf-8 -*-
"""
مراقب خطوط شبكة الهيثم - سوبرنت ADSL (يمن نت)

الاستخدام:
    python monitor.py check    # فحص كل الخطوط وتحديث اللوحة (كل ساعة)
    python monitor.py report   # فحص + إرسال التقرير اليومي على تيليجرام

المتغيرات (GitHub Secrets):
    LINES_JSON        قائمة الخطوط: [{"name":"الخط الأول","user":"...","pass":"..."}]
    DASH_PASSWORD     كلمة سر لوحة المراقبة (تُستخدم للتشفير)
    TELEGRAM_TOKEN    توكن البوت
    TELEGRAM_CHAT_ID  رقم المحادثة/القروب
    LOW_LIMIT_GB      حد التحذير (اختياري، الافتراضي 100)
"""
import base64
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import requests
from bs4 import BeautifulSoup

# استخدام مخزن شهادات النظام (ويندوز) مثل كروم، لأنه يكمل سلسلة الشهادات الناقصة
try:
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE = "https://adsl.yemen.net.ye"
TZ = ZoneInfo("Asia/Aden")
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.enc")
NETWORK_NAME = "شبكة الهيثم"
LOW_LIMIT = float(os.environ.get("LOW_LIMIT_GB", "100"))
MAX_CAPTCHA_TRIES = 10
KEEP_DAYS = 60
PBKDF2_ITER = 200_000

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")

AR_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩٫٬", "0123456789.,")

_ocr = None


def log(*a):
    print(datetime.now(TZ).strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------------ OCR
def read_captcha(img_bytes: bytes) -> str:
    global _ocr
    if _ocr is None:
        import ddddocr
        try:
            _ocr = ddddocr.DdddOcr(show_ad=False)
        except TypeError:
            _ocr = ddddocr.DdddOcr()
    text = _ocr.classification(img_bytes) or ""
    fix = {"o": "0", "O": "0", "D": "0", "l": "1", "I": "1", "i": "1", "|": "1",
           "z": "2", "Z": "2", "s": "5", "S": "5", "b": "6", "G": "6", "q": "9",
           "g": "9", "B": "8", "T": "7", "A": "4"}
    return "".join(fix.get(c, c) for c in text if c.isdigit() or c in fix)


# ------------------------------------------------------------------ Scraping
def parse_number(s: str):
    s = s.translate(AR_DIGITS)
    m = re.search(r"\d+(?:[.,]\d+)?", s.replace(" ", ""))
    if not m:
        return None
    val = float(m.group(0).replace(",", "."))
    if "ميجا" in s or "MB" in s.upper() and "GB" not in s.upper():
        val = val / 1024
    elif "تيرا" in s or "TB" in s.upper():
        val = val * 1024
    return round(val, 2)


def parse_info(html: str) -> dict:
    """يقرأ جدول (بيانات الاشتراك الرئيسية)."""
    soup = BeautifulSoup(html, "html.parser")
    fields = {}
    for row in soup.find_all("tr"):
        cells = [c.get_text(" ", strip=True) for c in row.find_all(["td", "th"])]
        cells = [c for c in cells if c]
        if len(cells) >= 2:
            fields[cells[0]] = cells[1]
    # احتياط: لو كانت البيانات في div بدل جدول
    if not any("الرصيد" in k for k in fields):
        text = soup.get_text("\n", strip=True).split("\n")
        for i, t in enumerate(text[:-1]):
            if t in ("الرصيد الحالي", "باقة الاشتراك", "حالة الاشتراك",
                     "تاريخ انتهاء الصلاحية", "رقم الهاتف"):
                fields[t] = text[i + 1]

    def get(*keys):
        for k in fields:
            if any(key in k for key in keys):
                return fields[k]
        return None

    balance_txt = get("الرصيد", "Balance")
    if balance_txt is None:
        raise RuntimeError("لم أجد الرصيد في الصفحة")
    return {
        "balance": parse_number(balance_txt),
        "balance_text": balance_txt,
        "package": get("الباقة", "باقة", "Package"),
        "status": get("حالة", "Status"),
        "expiry": get("انتهاء", "Expir"),
    }


def fetch_line(user: str, password: str) -> dict:
    last_err = "?"
    for attempt in range(1, MAX_CAPTCHA_TRIES + 1):
        s = requests.Session()
        s.headers.update({"User-Agent": UA, "Accept-Language": "ar,en;q=0.8"})
        r = s.get(f"{BASE}/login", timeout=30)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        form = None
        for f in soup.find_all("form"):
            if f.find("input", {"name": "Username"}):
                form = f
                break
        if form is None:
            raise RuntimeError("نموذج الدخول غير موجود (تغيّر شكل الموقع؟)")
        token_el = form.find("input", {"name": "__RequestVerificationToken"})
        token = token_el["value"] if token_el else ""

        img = s.get(f"{BASE}/captcha?{int(time.time() * 1000)}", timeout=30,
                    headers={"Referer": f"{BASE}/login"}).content
        code = read_captcha(img)
        if not (3 <= len(code) <= 6):
            last_err = f"قراءة كابتشا غير صالحة ({code!r})"
            continue

        payload = {
            "UId": uuid.uuid5(uuid.NAMESPACE_DNS, f"alhaitham-{user}").hex,
            "Username": user,
            "Password": password,
            "CapatchInput": code,
            "Remember": "false",
            "__RequestVerificationToken": token,
        }
        r = s.post(f"{BASE}/login", data=payload, timeout=30,
                   headers={"Referer": f"{BASE}/login", "Origin": BASE})
        html = r.text
        if 'name="CapatchInput"' in html:
            err = BeautifulSoup(html, "html.parser").select(".field-validation-error, .validation-summary-errors, .text-danger")
            msg = " ".join(e.get_text(" ", strip=True) for e in err if e.get_text(strip=True))
            last_err = msg or "فشل الدخول"
            if msg and ("كلمة" in msg or "المستخدم" in msg) and "التحقق" not in msg:
                raise RuntimeError(f"بيانات الدخول خاطئة: {msg}")
            log(f"  محاولة {attempt}: الكابتشا {code} مرفوضة")
            time.sleep(1.5)
            continue

        if "الرصيد" not in html:
            for path in ("/", "/Home/Index", "/info"):
                html = s.get(f"{BASE}{path}", timeout=30).text
                if "الرصيد" in html:
                    break
        info = parse_info(html)
        info["tries"] = attempt
        return info
    raise RuntimeError(f"فشل الدخول بعد {MAX_CAPTCHA_TRIES} محاولات: {last_err}")


# ------------------------------------------------------------------ Encrypted state
def _key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=PBKDF2_ITER).derive(password.encode())


def load_state(password: str) -> dict:
    if not os.path.exists(DATA_FILE):
        return {"lines": {}, "daily": []}
    with open(DATA_FILE, encoding="utf-8") as f:
        blob = json.load(f)
    salt, iv, ct = (base64.b64decode(blob[k]) for k in ("salt", "iv", "ct"))
    data = AESGCM(_key(password, salt)).decrypt(iv, ct, None)
    return json.loads(data)


def save_state(state: dict, password: str):
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(password, salt)).encrypt(
        iv, json.dumps(state, ensure_ascii=False).encode(), None)
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump({"v": 1, "iter": PBKDF2_ITER,
                   "salt": base64.b64encode(salt).decode(),
                   "iv": base64.b64encode(iv).decode(),
                   "ct": base64.b64encode(ct).decode()}, f)


# ------------------------------------------------------------------ Telegram
def tg_send(text: str):
    token, chat = os.environ.get("TELEGRAM_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        log("تيليجرام غير مضبوط، تم التخطي")
        return
    r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", timeout=30,
                      data={"chat_id": chat, "text": text, "parse_mode": "HTML",
                            "disable_web_page_preview": "true"})
    if not r.ok:
        log("خطأ تيليجرام:", r.text)


def gb(x):
    return "—" if x is None else f"{x:,.2f}"


# ------------------------------------------------------------------ Logic
def usage_between(snaps, start_ts, end_ts):
    """الاستهلاك والشحن بين وقتين من سلسلة القراءات."""
    before = [s for s in snaps if s[0] < start_ts]
    inside = [s for s in snaps if start_ts <= s[0] <= end_ts]
    seq = ([before[-1]] if before else []) + inside
    used = recharged = 0.0
    for (_, a), (_, b) in zip(seq, seq[1:]):
        if a is None or b is None:
            continue
        if b < a:
            used += a - b
        else:
            recharged += b - a
    return round(used, 2), round(recharged, 2)


def run_check(state, lines):
    now = datetime.now(TZ)
    ts = int(now.timestamp())
    alerts = []
    active_names = []
    for ln in lines:
        name, user = ln["name"], str(ln["user"])
        active_names.append(name)
        rec = state["lines"].setdefault(name, {"snaps": []})
        rec["phone"] = user
        log(f"فحص {name} ...")
        try:
            info = fetch_line(user, ln["pass"])
            prev_bal = rec.get("balance")
            rec.update({k: info[k] for k in ("balance", "package", "status", "expiry")})
            rec["ok"] = True
            rec["error"] = None
            rec["checked"] = ts
            rec["snaps"].append([ts, info["balance"]])
            log(f"  ✓ {gb(info['balance'])} GB (محاولات الكابتشا: {info['tries']})")
            if info["balance"] is not None and info["balance"] < LOW_LIMIT and \
                    (prev_bal is None or prev_bal >= LOW_LIMIT):
                alerts.append(f"🔴 <b>{name}</b> نزل تحت {LOW_LIMIT:g} جيجا — المتبقي <b>{gb(info['balance'])}</b> جيجا")
            if prev_bal is not None and info["balance"] is not None and info["balance"] - prev_bal > 1:
                alerts.append(f"✅ تم شحن <b>{name}</b> (+{gb(info['balance'] - prev_bal)} جيجا)")
        except Exception as e:  # noqa
            rec["ok"] = False
            rec["error"] = str(e)[:200]
            rec["checked"] = ts
            log(f"  ✗ {e}")
        cutoff = ts - KEEP_DAYS * 86400
        rec["snaps"] = [s for s in rec["snaps"] if s[0] >= cutoff]

    # إزالة الخطوط المحذوفة من الإعدادات
    for n in list(state["lines"]):
        if n not in active_names:
            del state["lines"][n]
    state["order"] = active_names
    state["updated"] = ts
    state["low_limit"] = LOW_LIMIT
    state["network"] = NETWORK_NAME
    fails = [n for n in active_names if not state["lines"][n].get("ok")]
    return alerts, fails


def build_report(state):
    now = datetime.now(TZ)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    t0, t1 = int(day_start.timestamp()), int(now.timestamp())
    rows, total_used, total_left = [], 0.0, 0.0
    day = {"date": day_start.strftime("%Y-%m-%d"), "lines": {}}
    for name in state.get("order", []):
        rec = state["lines"][name]
        used, rech = usage_between(rec["snaps"], t0, t1)
        bal = rec.get("balance")
        total_used += used
        total_left += bal or 0
        day["lines"][name] = {"used": used, "recharged": rech, "balance": bal}
        flag = "🔴" if bal is not None and bal < LOW_LIMIT else "🟢"
        line = (f"{flag} <b>{name}</b>\n"
                f"   📉 الاستهلاك اليوم: <b>{gb(used)}</b> جيجا\n"
                f"   💾 المتبقي: <b>{gb(bal)}</b> جيجا")
        if rech > 0:
            line += f"\n   ➕ شحن: {gb(rech)} جيجا"
        if rec.get("expiry"):
            line += f"\n   📅 الانتهاء: {rec['expiry']}"
        if not rec.get("ok"):
            line += "\n   ⚠️ آخر فحص فشل"
        rows.append(line)
    day["total_used"] = round(total_used, 2)
    day["total_left"] = round(total_left, 2)

    days_ar = ["الإثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت", "الأحد"]
    low = [n for n in state.get("order", []) if (state["lines"][n].get("balance") or 1e9) < LOW_LIMIT]
    msg = (f"📊 <b>التقرير اليومي — {NETWORK_NAME}</b>\n"
           f"🗓 {days_ar[now.weekday()]} {now:%Y/%m/%d}\n"
           f"━━━━━━━━━━━━━━\n\n" + "\n\n".join(rows) +
           f"\n\n━━━━━━━━━━━━━━\n"
           f"📉 <b>إجمالي استهلاك اليوم:</b> {gb(total_used)} جيجا\n"
           f"💾 <b>إجمالي المتبقي:</b> {gb(total_left)} جيجا")
    if low:
        msg += f"\n\n⚠️ <b>تحتاج شحن:</b> " + "، ".join(low)
    return msg, day


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    password = os.environ.get("DASH_PASSWORD")
    lines_json = os.environ.get("LINES_JSON")
    if not password or not lines_json:
        sys.exit("ضع DASH_PASSWORD و LINES_JSON في الأسرار (Secrets)")
    lines = json.loads(lines_json)

    state = load_state(password)
    alerts, fails = run_check(state, lines)

    if mode == "report":
        msg, day = build_report(state)
        state["daily"] = [d for d in state.get("daily", []) if d["date"] != day["date"]] + [day]
        state["daily"] = state["daily"][-KEEP_DAYS:]
        tg_send(msg)
    else:
        if alerts:
            tg_send("\n".join(alerts))
        # تنبيه إذا فشلت كل الخطوط 3 مرات متتالية (حجب أو تغيّر الموقع)
        state["fail_streak"] = state.get("fail_streak", 0) + 1 if len(fails) == len(lines) else 0
        if state["fail_streak"] == 3:
            err = state["lines"][fails[0]].get("error", "")
            tg_send(f"⚠️ <b>{NETWORK_NAME}</b>: فشل فحص كل الخطوط 3 مرات متتالية\n<code>{err}</code>")

    save_state(state, password)
    log("تم.")


if __name__ == "__main__":
    main()
