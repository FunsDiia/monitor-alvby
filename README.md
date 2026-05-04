# ВАРТА — GitHub Actions: розгортання 24/7

## Архітектура

```
GitHub Actions (cron */10 * * * *)
        │
        ▼  Telethon polling
  Telegram-канали
        │
        ▼  parse_message()
  Класифікатор загроз
  (drone/missile/ballistic/mlrs/kab/s300/artillery)
        │
        ▼  geocode()
  Nominatim OpenStreetMap API
  (будь-який населений пункт у світі)
        │
        ▼  git commit --push
  data.json  ──►  GitHub Pages PWA  ──►  Карта
```

## Типи загроз

| Тип          | Що визначає |
|-------------|-------------|
| drone       | БПЛА, Shahed-136/131, Герань-2, Ланцет, Орлан |
| missile     | Крилаті: Калібр, Х-101/555/22/59, Нептун |
| ballistic   | Іскандер-М/К, Кінжал (Х-47М2), ОТР |
| mlrs        | РСЗО: Смерч, Ураган, Град, Торнадо |
| kab         | КАБ-500/1500, ФАБ+УМПК |
| s300        | С-300/400 як ударна зброя |
| artillery   | Артилерія, прильоти, обстріли |

## Крок 1 — Telegram API ключі
1. https://my.telegram.org → API development tools
2. Скопіювати api_id та api_hash

## Крок 2 — Авторизація (один раз локально)
```bash
pip install telethon
python setup_session.py
# Після → з'явиться session.b64
```

## Крок 3 — GitHub Secrets
Settings → Secrets → Actions → New secret:
- TG_API_ID      → число
- TG_API_HASH    → рядок  
- TG_SESSION_B64 → вміст session.b64

## Крок 4 — Канали в parser.py
```python
CHANNELS: list = [
    "monitor1654",
    "kharkiv_online",
    -1001234567890,   # числовий ID приватного каналу
]
```

## Крок 5 — GitHub Pages
Settings → Pages → Branch: main → / (root)

## Структура data.json
```json
{
  "id": "a3f9c12b8e1d",
  "type": "drone",
  "model": "Shahed-136/131",
  "confidence": 10,
  "location_name": "Харків",
  "quantity": 3,
  "lat": 49.9935, "lon": 36.2304,
  "launch_from": "Бєлгород",
  "launch_lat": 50.5977, "launch_lon": 36.5882,
  "source": "monitor1654",
  "timestamp": "2026-05-03T16:25:04Z",
  "text_preview": "3 Shahed-136 над Харковом..."
}
```
