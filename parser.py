#!/usr/bin/env python3
"""
ВАРТА — Супер-розумний парсер для GitHub Actions
Режим: polling (не streaming) — запускається кожні 10 хв через cron
Геокодування: Nominatim (OpenStreetMap) — будь-який населений пункт
Класифікація: дрон / крилата ракета / балістика / РСЗО / КАБ / С-300 / артилерія
"""

import asyncio
import json
import re
import os
import time
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import quote
from urllib.error import URLError

from telethon import TelegramClient
from telethon.errors import FloodWaitError

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФІГ
# ══════════════════════════════════════════════════════════════════════════════

API_ID   = int(os.getenv("TG_API_ID",  "25635427"))
API_HASH = os.getenv("TG_API_HASH",    "e2f99fb35400e6628c88ffd388308598")
SESSION  = "varta_session"   # розпаковується з секрету в workflow

CHANNELS: list = [
    "monitor1654",
    # "hueviyharkiv",
    # "kharkiv_online",
    # "ua_alert",
    # -1001234567890,   # числовий ID приватного каналу
]

DATA_FILE     = Path(os.getenv("DATA_FILE",  "data.json"))
STATE_FILE    = Path(os.getenv("STATE_FILE", "state.json"))
GEOCACHE_FILE = Path(os.getenv("GEOCACHE",   "geocache.json"))

MAX_EVENTS     = int(os.getenv("MAX_EVENTS",    "500"))
MESSAGES_LIMIT = int(os.getenv("MSG_LIMIT",     "100"))
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK","12"))

NOM_URL     = "https://nominatim.openstreetmap.org/search"
NOM_UA      = "VARTA-Monitor/2.0 (github.com/your-org/your-repo)"
NOM_DELAY   = 1.15   # Nominatim: ≤1 req/sec

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
    datefmt= "%H:%M:%S",
)
log = logging.getLogger("varta")


# ══════════════════════════════════════════════════════════════════════════════
#  КЛАСИФІКАТОР ЗАГРОЗ
#  (pattern, threat_type, subtype/model, confidence_score 1-10)
# ══════════════════════════════════════════════════════════════════════════════

THREAT_RULES: list[tuple[str, str, str, int]] = [

    # ── ДРОНИ ─────────────────────────────────────────────────────────────────
    (r"shahed[\s\-]?13[169]",              "drone",      "Shahed-136/131/139", 10),
    (r"shahed[\s\-]?\d+",                  "drone",      "Shahed",              9),
    (r"shaheed",                           "drone",      "Shaheed",             9),
    (r"герань[\s\-]?2?",                   "drone",      "Герань-2",           10),
    (r"geran",                             "drone",      "Герань-2",           10),
    (r"ланцет[\s\-]?\d*",                  "drone",      "Ланцет",              9),
    (r"lancet",                            "drone",      "Ланцет",              9),
    (r"орлан[\s\-]?\d*",                   "drone",      "Орлан",               9),
    (r"куб[\s\-]бла",                      "drone",      "КУБ-БЛА",             9),
    (r"zala[\s\-]?\d*",                    "drone",      "Zala",                9),
    (r"supercam",                          "drone",      "SuperCam",            9),
    (r"бпла[\s\-]камікадзе",              "drone",      "Дрон-камікадзе",      9),
    (r"дрон[\s\-]камікадзе",              "drone",      "Дрон-камікадзе",      9),
    (r"ударн\w+\s+бпла",                   "drone",      "Ударний БПЛА",        9),
    (r"\bбпла\b",                          "drone",      "БПЛА",                7),
    (r"безпілотник",                       "drone",      "БПЛА",                7),
    (r"\bдрон\w*\b",                       "drone",      "Дрон",                6),

    # ── КРИЛАТІ РАКЕТИ ────────────────────────────────────────────────────────
    (r"х[\s\-]?101",                       "missile",    "Х-101",              10),
    (r"х[\s\-]?555",                       "missile",    "Х-555",              10),
    (r"х[\s\-]?22",                        "missile",    "Х-22",               10),
    (r"х[\s\-]?59м?",                      "missile",    "Х-59М",              10),
    (r"х[\s\-]?35",                        "missile",    "Х-35",               10),
    (r"х[\s\-]?32",                        "missile",    "Х-32",               10),
    (r"калібр",                            "missile",    "Калібр",             10),
    (r"kaliber|kalibr",                    "missile",    "Калібр",             10),
    (r"р[\s\-]?360",                       "missile",    "Р-360 Нептун",       10),
    (r"нептун",                            "missile",    "Р-360 Нептун",       10),
    (r"крилат\w+\s+ракет",                "missile",    "Крилата ракета",      9),
    (r"cruise\s+missile",                  "missile",    "Крилата ракета",      9),
    (r"\bракет\w+\b",                      "missile",    "Ракета",              5),

    # ── БАЛІСТИКА ─────────────────────────────────────────────────────────────
    (r"іскандер[\s\-]?[мкe]?",            "ballistic",  "Іскандер-М/К",       10),
    (r"iskander",                          "ballistic",  "Іскандер",           10),
    (r"х[\s\-]?47[\s\-]?м2?",             "ballistic",  "Х-47М2 Кінжал",      10),
    (r"кінжал",                            "ballistic",  "Х-47М2 Кінжал",      10),
    (r"kinzhal|kindzhal",                  "ballistic",  "Кінжал",             10),
    (r"балістич\w+\s+ракет",              "ballistic",  "Балістична ракета",   10),
    (r"оперативно.?тактич\w+\s+ракет",   "ballistic",  "ОТР",                  9),
    (r"\bотр\b",                           "ballistic",  "ОТР",                  9),
    (r"точка[\s\-]?у",                     "ballistic",  "Точка-У",              9),
    (r"р[\s\-]?17",                        "ballistic",  "Р-17 Ельбрус",         9),

    # ── РСЗО ──────────────────────────────────────────────────────────────────
    (r"\bрсзо\b",                          "mlrs",       "РСЗО",               10),
    (r"смерч",                             "mlrs",       "Смерч",              10),
    (r"торнадо[\s\-]?[гс]?",              "mlrs",       "Торнадо-Г/С",        10),
    (r"ураган",                            "mlrs",       "Ураган",              9),
    (r"\bград\b",                          "mlrs",       "Град",                9),
    (r"\bbm[\s\-]?21\b",                   "mlrs",       "БМ-21 Град",         10),
    (r"himars",                            "mlrs",       "HIMARS",             10),
    (r"реактивн\w+\s+залп",              "mlrs",       "РСЗО залп",            9),
    (r"нурс",                              "mlrs",       "НУРС",                 8),

    # ── КАБ / ФАБ ─────────────────────────────────────────────────────────────
    (r"каб[\s\-]?\d{3,4}",                "kab",        "КАБ",                10),
    (r"фаб[\s\-]?\d{3,4}",               "kab",        "ФАБ",                10),
    (r"\bумпк\b",                          "kab",        "ФАБ+УМПК",           10),
    (r"керован\w+\s+авіабомб",           "kab",        "КАБ",                10),
    (r"планеруюч\w+\s+авіабомб",        "kab",        "КАБ планеруюча",       9),
    (r"авіабомб",                          "kab",        "Авіабомба",            7),
    (r"jdam",                              "kab",        "JDAM",               10),

    # ── С-300 / С-400 ──────────────────────────────────────────────────────────
    (r"с[\s\-]?300",                       "s300",       "С-300",              10),
    (r"с[\s\-]?400",                       "s300",       "С-400",              10),
    (r"s[\s\-]?300",                       "s300",       "С-300",              10),

    # ── АРТИЛЕРІЯ ──────────────────────────────────────────────────────────────
    (r"артилерій\w+\s+обстріл",           "artillery",  "Артилерія",            9),
    (r"мінометн\w+\s+обстріл",            "artillery",  "Міномет",              9),
    (r"танков\w+\s+обстріл",              "artillery",  "Танк",                 8),
    (r"обстріл",                           "artillery",  "Обстріл",              6),
    (r"прильот",                           "artillery",  "Прильот",              7),
    (r"вибух",                             "artillery",  "Вибух",                4),
]

# Паттерни вилучення цільової локації
LOCATION_PATTERNS = [
    r"(?:над|в районі|у районі|біля|поблизу)\s+([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)(?=[,\.!\n\)\u2014]|$|\s+(?:виявлено|фіксуємо|помічено|зафіксовано|летить|рухається|пролетів|впав|вибух))",
    r"(?:в|у)\s+([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)\s+(?:виявлено|помічено|зафіксовано|фіксуємо)",
    r"([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)\s+(?:під|в)\s+загрозою",
    r"(?:виявлено|помічено|зафіксовано|фіксуємо)\s+(?:над|в|у|біля)?\s*([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)(?=[,\.!\n]|$)",
    r"(?:летить|рухається|прямує)\s+(?:на|в|у|до)\s+([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)(?=[,\.!\n]|$)",
    r"удар\s+(?:по|в|у)\s+([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)(?=[,\.!\n]|$)",
    r"пуск\w*\s+(?:по|в|у|на)\s+([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)(?=[,\.!\n]|$)",
]

# Паттерни точки пуску
LAUNCH_PATTERNS = [
    r"(?:з|із)\s+(?:напрямку|боку|районі)\s+([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)(?=[,\.!\n]|$)",
    r"(?:запущен\w+|пущен\w+|стартував)\s+(?:з|із)\s+([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)(?=[,\.!\n]|$)",
    r"пуск\s+(?:з|із)\s+([А-ЯҐЄІЇа-яґєії'ʼ][А-ЯҐЄІЇа-яґєії'ʼ\s\-]{1,35}?)(?=[,\.!\n]|$)",
    r"(?:з|із)\s+([А-ЯҐЄІЇа-яґєії'ʼ][а-яґєії'ʼ]{2,20}(?:ської|ськ[оа]|ського)?\s*(?:обл|регіону|районн?у)?)(?=[,\.\s]|$)",
]

QUANTITY_PATTERNS = [
    r"(\d+)\s+(?:дрон\w*|бпла|ракет\w*|шахед\w*|балістич\w*|снаряд\w*)",
    r"(?:дрон\w*|ракет\w*|шахед\w*)\s+(?:у кількості|кількістю)\s+(\d+)",
    r"пакет\s+(?:із|з)?\s*(\d+)",
    r"(?:залп|серія)\s+(?:із|з)?\s*(\d+)",
    r"(\d+)\s+(?:об'єктів|цілей|одиниць)",
]

STOP_WORDS = {
    "загрозою","бпла","дрон","ракет","шахед","обстріл","вибух","прильот",
    "виявлено","фіксуємо","помічено","зафіксовано","районі","напрямку",
    "боку","поблизу","над","запущено","летить","рухається","прямує",
    "стартував","ukraine","росія","рф","оос","зсу","поранен","загинув",
    "жертв","тривога","відбій","загрозою","повітряна","ціль",
    "ворог","противник","атака","небезпека","сирена",
}


def classify_threat(text: str) -> tuple[str, str, int]:
    """Повертає (type, model, confidence)."""
    low = text.lower()
    best_type, best_model, best_score = "unknown", "", 0

    for pattern, ttype, model, score in THREAT_RULES:
        if re.search(pattern, low, re.IGNORECASE):
            if score > best_score:
                best_type, best_model, best_score = ttype, model, score

    return best_type, best_model, best_score


def extract_locations(text: str) -> list[str]:
    found = []
    for pat in LOCATION_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE | re.MULTILINE):
            loc = m.group(1).strip().rstrip(" .,!:-–")
            loc = re.sub(r"^(?:над|в|у|біля|поблизу)\s+", "", loc, flags=re.I).strip()
            if 2 < len(loc) < 40 and loc.lower() not in STOP_WORDS:
                found.append(loc)
    return list(dict.fromkeys(found))


def extract_launch(text: str) -> str | None:
    for pat in LAUNCH_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            loc = m.group(1).strip().rstrip(" .,!")
            if 2 < len(loc) < 40 and loc.lower() not in STOP_WORDS:
                return loc
    return None


def extract_quantity(text: str) -> int:
    for pat in QUANTITY_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                return min(int(m.group(1)), 999)
            except (ValueError, IndexError):
                pass
    return 1


# ══════════════════════════════════════════════════════════════════════════════
#  NOMINATIM ГЕОКОДЕР
# ══════════════════════════════════════════════════════════════════════════════

_geocache: dict = {}
_last_request  = 0.0


def _load_geocache() -> None:
    global _geocache
    if GEOCACHE_FILE.exists():
        try:
            _geocache = json.loads(GEOCACHE_FILE.read_text(encoding="utf-8"))
            log.info("🗄️  Геокеш: %d записів", len(_geocache))
        except Exception:
            _geocache = {}


def _save_geocache() -> None:
    GEOCACHE_FILE.write_text(
        json.dumps(_geocache, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _nominatim(name: str) -> dict | None:
    global _last_request
    wait = NOM_DELAY - (time.time() - _last_request)
    if wait > 0:
        time.sleep(wait)

    # Спробуємо спочатку Україну, потім весь світ
    for extra in ["&countrycodes=ua", ""]:
        try:
            url = f"{NOM_URL}?q={quote(name)}&format=json&limit=5&addressdetails=1&accept-language=uk{extra}"
            req  = Request(url, headers={"User-Agent": NOM_UA})
            data = json.loads(urlopen(req, timeout=10).read())
            _last_request = time.time()

            if not data:
                continue

            priority = ("city","town","village","hamlet","suburb","municipality","county","district")
            for item in data:
                addr = item.get("address", {})
                for key in priority:
                    if key in addr:
                        return {
                            "lat":     float(item["lat"]),
                            "lon":     float(item["lon"]),
                            "display": item.get("display_name", name),
                            "country": addr.get("country_code", ""),
                            "type":    key,
                        }
            # Перший результат як запасний
            f = data[0]
            return {
                "lat":     float(f["lat"]),
                "lon":     float(f["lon"]),
                "display": f.get("display_name", name),
                "country": f.get("address", {}).get("country_code", ""),
                "type":    f.get("type", ""),
            }

        except URLError as e:
            log.warning("Nominatim недоступний: %s", e)
            return None
        except Exception as e:
            log.debug("Nominatim '%s': %s", name, e)

    return None


def geocode(name: str) -> dict | None:
    key = name.lower().strip()
    if key in _geocache:
        return _geocache[key]

    log.info("🌍 Геокодую: «%s»", name)
    result = _nominatim(name)
    _geocache[key] = result

    if result:
        log.info("   ✅ → %.4f, %.4f (%s)", result["lat"], result["lon"], result["display"][:60])
    else:
        log.warning("   ❌ Не знайдено: %s", name)
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  STATE / DATA
# ══════════════════════════════════════════════════════════════════════════════

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def load_data() -> list[dict]:
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def save_data(events: list[dict]) -> None:
    seen: dict[str, dict] = {}
    for e in events:
        seen[e["id"]] = e
    out = sorted(seen.values(), key=lambda e: e.get("timestamp", ""), reverse=True)[:MAX_EVENTS]
    DATA_FILE.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("💾 data.json → %d подій", len(out))


# ══════════════════════════════════════════════════════════════════════════════
#  ПАРСИНГ
# ══════════════════════════════════════════════════════════════════════════════

def parse_message(msg_id: int, text: str, source: str) -> list[dict]:
    threat_type, model, confidence = classify_threat(text)
    if confidence < 4:
        return []

    locations = extract_locations(text)
    if not locations:
        return []

    quantity   = extract_quantity(text)
    launch_raw = extract_launch(text)
    now        = datetime.now(timezone.utc).isoformat()
    results    = []

    for loc in locations:
        uid = hashlib.md5(f"{source}:{msg_id}:{loc.lower()}".encode()).hexdigest()[:12]
        geo = geocode(loc)

        event: dict = {
            "id":           uid,
            "type":         threat_type,
            "model":        model,
            "confidence":   confidence,
            "location_name": loc.strip().capitalize(),
            "quantity":     quantity,
            "source":       source,
            "timestamp":    now,
            "msg_id":       msg_id,
            "text_preview": text[:250].replace("\n", " "),
        }

        if geo:
            event["lat"]     = geo["lat"]
            event["lon"]     = geo["lon"]
            event["display"] = geo["display"]
            event["country"] = geo.get("country", "")

        if launch_raw:
            lg = geocode(launch_raw)
            event["launch_from"] = launch_raw
            if lg:
                event["launch_lat"] = lg["lat"]
                event["launch_lon"] = lg["lon"]

        results.append(event)
        log.info("📌 [%s #%d] %s | %s | %s (qty=%d, conf=%d)",
                 source, msg_id, threat_type.upper(), model, loc, quantity, confidence)

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  TELETHON POLLING
# ══════════════════════════════════════════════════════════════════════════════

async def fetch_channel(client, ch, last_id: int) -> tuple[list[dict], int]:
    all_events = []
    new_last   = last_id

    try:
        entity = await client.get_entity(ch)
        name   = getattr(entity, "username", None) or str(getattr(entity, "id", ch))

        kw: dict = {"limit": MESSAGES_LIMIT}
        if last_id > 0:
            kw["min_id"] = last_id
        else:
            kw["offset_date"] = datetime.now(timezone.utc) - timedelta(hours=HOURS_LOOKBACK)

        async for msg in client.iter_messages(entity, **kw):
            text = msg.message or ""
            if text.strip():
                all_events.extend(parse_message(msg.id, text, name))
            if msg.id > new_last:
                new_last = msg.id

    except FloodWaitError as e:
        log.warning("FloodWait %ds для %s", e.seconds, ch)
        await asyncio.sleep(min(e.seconds, 60))
    except Exception as e:
        log.error("Канал %s: %s", ch, e)

    return all_events, new_last


async def run_once():
    if not API_ID or not API_HASH:
        log.error("Потрібні TG_API_ID та TG_API_HASH!")
        return

    _load_geocache()
    state    = load_state()
    existing = load_data()

    client = TelegramClient(SESSION, API_ID, API_HASH)
    await client.start()
    log.info("✅ Telegram підключено. Каналів: %d", len(CHANNELS))

    all_new: list[dict] = []
    for ch in CHANNELS:
        key     = str(ch)
        last_id = state.get(key, 0)
        log.info("📥 %s (last_id=%d)", ch, last_id)
        events, new_last = await fetch_channel(client, ch, last_id)
        all_new.extend(events)
        state[key] = new_last

    await client.disconnect()

    if all_new:
        log.info("🆕 Нових подій: %d", len(all_new))
        save_data(existing + all_new)
    else:
        log.info("ℹ️  Нічого нового")

    save_state(state)
    _save_geocache()
    log.info("✅ Запуск завершено")


if __name__ == "__main__":
    asyncio.run(run_once())
