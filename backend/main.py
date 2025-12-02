from fastapi import FastAPI, Form
import hmac
import hashlib
import urllib.parse
from fastapi.responses import JSONResponse

app = FastAPI()

BOT_TOKEN = "TOKEN_HERE"  # 👈 این را بعداً با توکن واقعی رباتت جایگزین می‌کنیم

def validate_telegram_init_data(init_data: str) -> dict:
    """
    Validate Telegram WebApp initData according to Telegram documentation.
    """

    data_dict = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))

    if "hash" not in data_dict:
        return None

    received_hash = data_dict.pop("hash")
    sorted_data = sorted([f"{k}={v}" for k, v in data_dict.items()])
    data_check_string = "\n".join(sorted_data)

    secret_key = hashlib.sha256(("WebAppData" + BOT_TOKEN).encode()).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    if calculated_hash != received_hash:
        return None

    return data_dict


@app.post("/auth")
async def auth(initData: str = Form(...)):
    """
    Validate MiniApp user and return user_id on success.
    """
    result = validate_telegram_init_data(initData)

    if not result:
        return JSONResponse({"ok": False, "error": "Invalid data"}, status_code=400)

    user = urllib.parse.parse_qs(result["user"])
    user_id = user["id"][0]

    return {"ok": True, "user_id": user_id}


@app.get("/")
def root():
    return {"message": "Backend for Shahhosseini MiniApp is working."}
