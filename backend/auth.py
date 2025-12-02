import hashlib
import hmac
import urllib.parse
from dotenv import load_dotenv
import os

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

def check_telegram_auth(init_data: str) -> dict | None:
    try:
        parsed = urllib.parse.parse_qs(init_data)
        auth_hash = parsed.pop("hash")[0]

        data_check_string = "\n".join(
            f"{k}={v[0]}" for k, v in sorted(parsed.items())
        )

        secret_key = hmac.new(
            key="WebAppData".encode(),
            msg=BOT_TOKEN.encode(),
            digestmod=hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            key=secret_key,
            msg=data_check_string.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()

        if calculated_hash != auth_hash:
            return None

        return {k: v[0] for k, v in parsed.items()}

    except Exception:
        return None

