import asyncio
from telethon import TelegramClient
import base64
from pathlib import Path

# Вказуємо значення за замовчуванням
DEFAULT_ID = "25635427"
DEFAULT_HASH = "e2f99fb35400e6628c88ffd388308598"

# Якщо ввід порожній (просто Enter), використовуємо DEFAULT
api_id_input = input(f"API_ID [{DEFAULT_ID}]: ").strip()
API_ID = api_id_input if api_id_input else DEFAULT_ID

api_hash_input = input(f"API_HASH [{DEFAULT_HASH}]: ").strip()
API_HASH = api_hash_input if api_hash_input else DEFAULT_HASH

async def main():
    try:
        client = TelegramClient("varta_session", int(API_ID), API_HASH)
        await client.start()
        
        me = await client.get_me()
        print(f"\n✅ Авторизовано як: {me.first_name} (@{me.username})")
        await client.disconnect()

        session_path = Path("varta_session.session")
        if session_path.exists():
            b64 = base64.b64encode(session_path.read_bytes()).decode()
            # Виводимо повний рядок для зручності копіювання
            print(f"\n📋 Вміст для TG_SESSION_B64:")
            print(b64) 
            
            Path("session.b64").write_text(b64)
            print("\n💾 Також збережено у файл: session.b64")
            
    except ValueError:
        print("❌ Помилка: API_ID має бути числом!")
    except Exception as e:
        print(f"❌ Виникла помилка: {e}")

if __name__ == "__main__":
    asyncio.run(main())