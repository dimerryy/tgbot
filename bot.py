#!/usr/bin/env python3
from __future__ import annotations
import os, asyncio, logging
from threading import Thread
from flask import Flask, request, jsonify
from telegram import Update as TGUpdate
from telegram.ext import Application, ApplicationBuilder, CommandHandler, ContextTypes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("minibot")

# ---------- Config (env) ----------
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "whsec").strip()
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")  # e.g. https://your-app.onrender.com

# ---------- Flask app (exported for gunicorn) ----------
app = Flask(__name__)

# PTB application + background loop
tg_app: Application | None = None
_loop: asyncio.AbstractEventLoop | None = None

# ---------- Handlers ----------
async def start_cmd(update: TGUpdate, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Bot is live!")

def _start_loop() -> asyncio.AbstractEventLoop:
    """Start a dedicated asyncio loop in a background thread (for PTB)."""
    loop = asyncio.new_event_loop()
    def runner():
        asyncio.set_event_loop(loop)
        loop.run_forever()
    Thread(target=runner, daemon=True).start()
    return loop

def _build_ptb() -> Application:
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    return app

# ---------- Webhook route ----------
@app.post(f"/webhook/{WEBHOOK_SECRET}")
def telegram_webhook():
    # Verify Telegram secret header
    hdr = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if hdr != WEBHOOK_SECRET:
        return "forbidden", 403

    if not (tg_app and _loop):
        return "bot not ready", 503

    data = request.get_json(force=True, silent=True)
    if not data:
        return "no json", 400

    try:
        upd = TGUpdate.de_json(data, tg_app.bot)
    except Exception as e:
        log.exception("Bad update JSON: %s", e)
        return "bad request", 400

    # Hand off to PTB on background loop (non-blocking)
    asyncio.run_coroutine_threadsafe(tg_app.process_update(upd), _loop)
    return "ok", 200

@app.get("/")
def index():
    return "OK", 200

@app.get("/healthz")
def healthz():
    return jsonify(ok=True), 200

# ---------- Boot when imported by gunicorn ----------
if __name__ != "__main__":
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN not set")
    _loop = _start_loop()
    tg_app = _build_ptb()

    async def _boot():
        await tg_app.initialize()
        await tg_app.start()
        # Set webhook so Telegram sends updates here (optional if you set it via curl)
        if PUBLIC_BASE_URL:
            await tg_app.bot.set_webhook(
                url=f"{PUBLIC_BASE_URL}/webhook/{WEBHOOK_SECRET}",
                secret_token=WEBHOOK_SECRET,
                drop_pending_updates=True,
            )
            log.info("Webhook set to %s/webhook/%s", PUBLIC_BASE_URL, WEBHOOK_SECRET)
        else:
            log.warning("PUBLIC_BASE_URL not set — not calling setWebhook.")

    asyncio.run_coroutine_threadsafe(_boot(), _loop)

# ---------- Local dev (polling) ----------
if __name__ == "__main__":
    # For running locally: python bot.py (polling mode)
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN not set")
    app_local = _build_ptb()
    app_local.run_polling()
