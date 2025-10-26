#!/usr/bin/env python3
from __future__ import annotations

# =====================
# Imports & setup
# =====================
import os, re, sqlite3, logging, random, string, pickle, asyncio, math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from telegram import (
    Update,
    InlineKeyboardMarkup, InlineKeyboardButton,
)
from telegram.ext import (
    Application, ApplicationBuilder, ContextTypes,
    ConversationHandler, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters
)

# Flask for webhook mode
from flask import Flask, request

# =====================
# Config (env overrides at boot)
# =====================
global DB_PATH, ADMIN_ID, PAYMENT_PHONE

RATE_PER_HOUR = 200
CURRENCY = "KZT"
MIN_DURATION_MIN = 15
MAX_DURATION_HOURS = 24
TIMEZONE = timezone(timedelta(hours=5))  # Asia/Almaty (+05:00)

# Tiered pricing: apply the highest matching tier to billed hours (30-min blocks)
PRICING_TIERS = [
    (12, 0.25),
    (8,  0.20),
    (4,  0.10),
    (2,  0.05),
    (1,  0.00),
]

ASK_DURATION, CONFIRM, WAIT_BILL, CONTACT = range(4)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("timed_access_bot")

DB_PATH = os.environ.get("DB_PATH", "bot.db")
ADMIN_ID = os.environ.get("ADMIN_USER_ID", "").strip()
PAYMENT_PHONE = os.environ.get("PAYMENT_PHONE", "+7XXXXXXXXXX").strip()

# Optional Gmail token path (Render Secret File or local file)
GMAIL_TOKEN_PATH = os.environ.get("GMAIL_TOKEN_PATH", "/etc/secrets/token.pickle")

# =====================
# DB schema & helpers
# =====================
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label TEXT NOT NULL,
  token TEXT NOT NULL,
  is_allocated INTEGER NOT NULL DEFAULT 0,          -- legacy flag
  max_concurrent INTEGER NOT NULL DEFAULT 1,        -- available seats
  allocated_count INTEGER NOT NULL DEFAULT 0        -- seats used
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id INTEGER NOT NULL,
  account_id INTEGER NOT NULL,
  start_ts INTEGER NOT NULL,
  end_ts INTEGER NOT NULL,
  price_cents INTEGER NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL,                             -- active | expired | cancelled
  FOREIGN KEY(account_id) REFERENCES accounts(id)
);
"""

def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.executescript(SCHEMA_SQL)

def ensure_seat_columns():
    with db() as con:
        cols = {row[1] for row in con.execute("PRAGMA table_info(accounts)")}
        if "max_concurrent" not in cols:
            con.execute("ALTER TABLE accounts ADD COLUMN max_concurrent INTEGER NOT NULL DEFAULT 1")
        if "allocated_count" not in cols:
            con.execute("ALTER TABLE accounts ADD COLUMN allocated_count INTEGER NOT NULL DEFAULT 0")

def cleanup_expired_now():
    now = int(datetime.now(tz=TIMEZONE).timestamp())
    with db() as con:
        con.execute("UPDATE sessions SET status='expired' WHERE status='active' AND end_ts < ?", (now,))
        con.execute("UPDATE accounts SET allocated_count = 0")
        con.execute("""
        WITH active AS (
          SELECT account_id, COUNT(*) AS c
          FROM sessions
          WHERE status='active'
          GROUP BY account_id
        )
        UPDATE accounts
        SET allocated_count = COALESCE((SELECT c FROM active WHERE active.account_id = accounts.id), 0)
        """)

def recompute_allocated_counts():
    with db() as con:
        con.execute("UPDATE accounts SET allocated_count = 0")
        con.execute("""
        WITH active AS (
          SELECT account_id, COUNT(*) AS c
          FROM sessions
          WHERE status='active'
          GROUP BY account_id
        )
        UPDATE accounts
        SET allocated_count = COALESCE((SELECT c FROM active WHERE active.account_id = accounts.id), 0)
        """)

# =====================
# Pricing & parsing
# =====================
@dataclass
class Quote:
    minutes: int
    price: int

def parse_duration(text: str) -> int | None:
    t = (text or "").strip().lower()
    if re.fullmatch(r"\d+", t): return int(t)
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*h(?:ours?)?", t)
    if m: return int(round(float(m.group(1)) * 60))
    m = re.fullmatch(r"(\d+)\s*h(?:ours?)?\s*(\d+)\s*m(?:in(?:utes?)?)?", t)
    if m: return int(m.group(1))*60 + int(m.group(2))
    m = re.fullmatch(r"(\d+)\s*h(?:hours?)?", t)
    if m: return int(m.group(1))*60
    m = re.fullmatch(r"(\d+)\s*m(?:in(?:utes?)?)?", t)
    if m: return int(m.group(1))
    m = re.fullmatch(r"(\d+)\s*h\s*(\d+)\s*m", t)
    if m: return int(m.group(1))*60 + int(m.group(2))
    return None

def quote_price(minutes: int) -> Quote:
    if minutes <= 0:
        return Quote(minutes=0, price=0)
    blocks = (minutes + 29) // 30
    billed_hours = blocks * 0.5
    discount = 0.0
    for h, d in PRICING_TIERS:
        if billed_hours >= h:
            discount = d
            break
    price = RATE_PER_HOUR * billed_hours * (1.0 - discount)
    return Quote(minutes=minutes, price=int(round(price)))

def fmt_dt(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=TIMEZONE).strftime("%Y-%m-%d %H:%M")

# =====================
# Seat allocation
# =====================
def allocate_account() -> sqlite3.Row | None:
    with db() as con:
        latest = con.execute("SELECT * FROM accounts ORDER BY id DESC LIMIT 1").fetchone()
        if not latest:
            return None
        if latest["allocated_count"] >= latest["max_concurrent"]:
            return None
        con.execute("UPDATE accounts SET allocated_count = allocated_count + 1 WHERE id = ?", (latest["id"],))
        return con.execute("SELECT * FROM accounts WHERE id = ?", (latest["id"],)).fetchone()

def release_seat(account_id: int):
    with db() as con:
        con.execute(
            "UPDATE accounts SET allocated_count = CASE WHEN allocated_count>0 THEN allocated_count-1 ELSE 0 END "
            "WHERE id = ?",
            (account_id,)
        )

def get_seat_availability():
    now_ts = int(datetime.now(tz=TIMEZONE).timestamp())
    with db() as con:
        latest = con.execute("SELECT id, max_concurrent, allocated_count FROM accounts ORDER BY id DESC LIMIT 1").fetchone()
        if not latest:
            return 0, None
        free = int(latest["max_concurrent"] - latest["allocated_count"])
        eta_row = con.execute(
            "SELECT MIN(end_ts) FROM sessions WHERE status='active' AND account_id = ? AND end_ts > ?",
            (latest["id"], now_ts)
        ).fetchone()
        eta_minutes = None
        if eta_row and eta_row[0]:
            eta_sec = eta_row[0] - now_ts
            if eta_sec > 0:
                eta_minutes = eta_sec // 60
    return max(0, free), eta_minutes

# =====================
# Gmail (optional, subject-only)
# =====================
gmail_service = None
def _headers_map(payload):
    return {h['name']: h['value'] for h in payload.get('headers', [])}

def _init_gmail():
    global gmail_service
    try:
        with open(GMAIL_TOKEN_PATH, "rb") as token:
            creds = pickle.load(token)
        from googleapiclient.discovery import build as gbuild
        gmail_service = gbuild('gmail', 'v1', credentials=creds)
        log.info("Gmail monitor enabled.")
    except Exception as e:
        gmail_service = None
        log.warning("Failed to init Gmail service: %s — Gmail monitor disabled.", e)

async def monitor_gmail(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if gmail_service is None:
        await context.bot.send_message(update.effective_chat.id, "Verification auto-forward is unavailable.")
        return

    chat_id = update.effective_chat.id
    await context.bot.send_message(chat_id, "Log in, and I will send you a verification code…")

    res = gmail_service.users().messages().list(userId='me', maxResults=1).execute()
    latest_id = res['messages'][0]['id'] if 'messages' in res else None

    while True:
        await asyncio.sleep(5)
        res = gmail_service.users().messages().list(userId='me', maxResults=1).execute()
        if 'messages' not in res:
            continue
        new_id = res['messages'][0]['id']
        if latest_id and new_id == latest_id:
            continue

        msg = gmail_service.users().messages().get(
            userId='me',
            id=new_id,
            format='metadata',
            metadataHeaders=['Subject'],
            fields='id,payload/headers'
        ).execute()

        payload = msg.get('payload', {}) or {}
        headers = _headers_map(payload)
        subject = headers.get('Subject', '(no subject)')

        await context.bot.send_message(chat_id, subject)
        break

# =====================
# UI bits
# =====================
kb_copy = InlineKeyboardMarkup([[
    InlineKeyboardButton("📋 Copy phone", callback_data="copy_phone"),
    InlineKeyboardButton("📋 Copy ref",   callback_data="copy_ref"),
]])

def _user_tag(u) -> str:
    return f"@{u.username}" if getattr(u, "username", None) else str(u.id)

# =====================
# Handlers
# =====================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    free, eta = get_seat_availability()
    if free <= 0:
        msg = "No seats are available right now."
        if eta is not None and eta > 0:
            msg += f" Earliest estimated availability in ~{eta} minutes."
        msg += "\nPlease try again later."
        await update.message.reply_text(msg)
        return ConversationHandler.END

    await update.message.reply_text(
        "Welcome!\n\n"
        "This bot issues a temporary login (email/username) + password.\n"
        f"Base rate: {RATE_PER_HOUR} {CURRENCY}/hour (billed in 30-min blocks).\n"
        "Long-duration discounts:\n"
        "• 1h: 0%   • 2h: 5%   • 4h: 10%   • 8h: 20%   • 12h: 25%\n\n"
        "How long do you need access?\n"
        "Examples: 90m, 2h, 2h30m, 1h 20m, 45 minutes"
    )
    return ASK_DURATION

async def ask_duration(update: Update, context: ContextTypes.DEFAULT_TYPE):
    m = parse_duration(update.message.text)
    if m is None:
        await update.message.reply_text("Please enter duration like '2h', '90m', or '1h 20m'."); return ASK_DURATION
    if m < MIN_DURATION_MIN:
        await update.message.reply_text(f"Minimum duration is {MIN_DURATION_MIN} minutes."); return ASK_DURATION
    if m > MAX_DURATION_HOURS * 60:
        await update.message.reply_text(f"Maximum duration is {MAX_DURATION_HOURS} hours."); return ASK_DURATION

    q = quote_price(m)
    context.user_data["minutes"] = m
    context.user_data["quote_price"] = q.price

    billed_blocks = (m + 29) // 30
    billed_hours = billed_blocks * 0.5
    base = RATE_PER_HOUR * billed_hours
    discount_pct = int(round((1 - (q.price / base)) * 100)) if base > 0 else 0

    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton(text=f"Confirm — {q.price} {CURRENCY}", callback_data="confirm"),
        InlineKeyboardButton(text="Cancel", callback_data="cancel"),
    ]])
    await update.message.reply_text(
        (
            f"Duration: {m} minutes\n"
            f"Billed time: {billed_hours:.1f}h (30-min blocks)\n"
            f"Price: {q.price} {CURRENCY}  (discount: {discount_pct}%)\n\n"
            "Confirm?"
        ),
        reply_markup=kb,
    )
    return CONFIRM

async def confirm_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if q.data == "cancel":
        await q.edit_message_text("Cancelled."); return ConversationHandler.END

    minutes = int(context.user_data["minutes"])
    price = int(context.user_data["quote_price"])
    pay_ref = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    context.user_data["pay_ref"] = pay_ref

    await q.edit_message_text(
        (
            "Payment required.\n\n"
            f"Amount: *{price} {CURRENCY}*\n"
            f"Reference: *{pay_ref}*\n\n"
            "Pay via *Jusan Bank* or *Kaspi.kz* to the phone number below, then send the receipt here.\n"
            f"Phone: `{PAYMENT_PHONE}`\n\n"
            "Please send a payment receipt *photo* or *PDF file* in this chat.\n"
            "Tip: add the reference in the transfer comment if possible."
        ),
        parse_mode="Markdown",
        reply_markup=kb_copy,
        disable_web_page_preview=True,
    )
    return WAIT_BILL

async def copy_phone_cb(update, context):
    q = update.callback_query
    await q.answer("Phone sent below — long-press to copy.", show_alert=False)
    await context.bot.send_message(chat_id=q.message.chat_id, text=f"`{os.environ.get('PAYMENT_PHONE', PAYMENT_PHONE)}`", parse_mode="Markdown")

async def copy_ref_cb(update, context):
    q = update.callback_query
    await q.answer("Reference sent below — long-press to copy.", show_alert=False)
    await context.bot.send_message(chat_id=q.message.chat_id, text=f"`{context.user_data.get('pay_ref','N/A')}`", parse_mode="Markdown")

async def receive_bill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    is_photo = bool(update.message.photo)
    is_pdf = bool(update.message.document and update.message.document.mime_type == "application/pdf")
    if not (is_photo or is_pdf):
        await update.message.reply_text("Please send a photo or a PDF receipt file.")
        return WAIT_BILL

    minutes = int(context.user_data.get("minutes", 0))
    price = int(context.user_data.get("quote_price", 0))
    pay_ref = context.user_data.get("pay_ref", "N/A")
    user_tag = f"@{update.effective_user.username}" if update.effective_user.username else str(update.effective_user.id)

    if ADMIN_ID:
        caption = f"Payment receipt from {user_tag}\nRef: {pay_ref} | Amount: {price} {CURRENCY} | Minutes: {minutes}"
        try:
            await context.bot.copy_message(
                chat_id=int(ADMIN_ID),
                from_chat_id=update.message.chat_id,
                message_id=update.message.message_id,
                caption=caption
            )
        except Exception as e:
            log.warning("Failed to send receipt to admin: %s", e)

    acct = allocate_account()
    if not acct:
        await update.message.reply_text("Thanks! Receipt received. However, no seats are available at the moment. Please try again later or contact support.")
        return ConversationHandler.END

    now = datetime.now(tz=TIMEZONE); end = now + timedelta(minutes=minutes)
    with db() as con:
        cur = con.execute(
            "INSERT INTO sessions (telegram_id, account_id, start_ts, end_ts, price_cents, currency, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'active')",
            (update.effective_user.id, acct["id"], int(now.timestamp()), int(end.timestamp()), price, CURRENCY),
        )
        session_id = cur.lastrowid

    delay = (end - now).total_seconds()
    context.application.job_queue.run_once(
        expire_session_job,
        when=delay,
        data={"session_id": session_id, "account_id": acct["id"], "chat_id": update.message.chat_id},
        name=f"expire:{session_id}",
    )

    kb_creds = InlineKeyboardMarkup([[
        InlineKeyboardButton("📋 Copy login",    switch_inline_query_current_chat=acct['label']),
        InlineKeyboardButton("📋 Copy password", switch_inline_query_current_chat=acct['token']),
    ]])

    await update.message.reply_text(
        (
            "Approved. Your access is active until {until}.\n\n"
            "Login (email/username): {login}\n"
            "Temporary password: {password}\n"
        ).format(until=fmt_dt(int(end.timestamp())), login=acct['label'], password=acct['token']),
        reply_markup=kb_creds,
    )

    try:
        await monitor_gmail(update, context)
    except Exception as e:
        log.warning("Failed to send verification code: %s", e)
        await update.message.reply_text("Could not send verification at this time.")

    if ADMIN_ID:
        try:
            await context.bot.send_message(
                chat_id=int(ADMIN_ID),
                text=(f"Approved session #{session_id}\n"
                      f"User: {user_tag}\n"
                      f"Ref: {pay_ref} | Amount: {price} {CURRENCY} | Minutes: {minutes}\n"
                      f"Account: {acct['label']} | Ends: {fmt_dt(int(end.timestamp()))}")
            )
        except Exception as e:
            log.warning("Failed to send approval summary to admin: %s", e)

    return ConversationHandler.END

async def expire_session_job(context: ContextTypes.DEFAULT_TYPE):
    d = context.job.data
    session_id, account_id, chat_id = d["session_id"], d["account_id"], d["chat_id"]
    with db() as con:
        row = con.execute("SELECT status FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row or row["status"] != "active":
            return
        con.execute("UPDATE sessions SET status='expired' WHERE id = ?", (session_id,))
    release_seat(account_id)
    await context.bot.send_message(
        chat_id=chat_id,
        text=("Your session has ended.\n"
              "Please log out from the account now so it doesn't slow down other users' workflow.")
    )

async def my_session(update: Update, context: ContextTypes.DEFAULT_TYPE):
    with db() as con:
        row = con.execute(
            "SELECT s.id, s.start_ts, s.end_ts, s.status, a.label, a.allocated_count, a.max_concurrent "
            "FROM sessions s JOIN accounts a ON a.id = s.account_id "
            "WHERE s.telegram_id = ? ORDER BY s.id DESC LIMIT 1",
            (update.effective_user.id,),
        ).fetchone()
    if not row:
        await update.message.reply_text("You have no sessions."); return
    now_ts = int(datetime.now(tz=TIMEZONE).timestamp())
    mins = max(0, row["end_ts"] - now_ts)//60
    await update.message.reply_text(
        f"Last session: {row['status']}, account={row['label']}\n"
        f"Start: {fmt_dt(row['start_ts'])}\nEnd: {fmt_dt(row['end_ts'])}\n"
        f"Remaining: {mins} minutes\n"
        f"Seats in use: {row['allocated_count']}/{row['max_concurrent']}"
    )

def _is_admin(update: Update) -> bool:
    return bool(ADMIN_ID) and str(update.effective_user.id) == str(ADMIN_ID)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "/start — begin a new request\n"
        "/my_session — see your latest session\n"
        "/contact — write a message to the admin\n"
        "/help — this help\n\n"
        "Admin:\n"
        "/admin_add <email> <password> [seats]\n"
        "/admin_set_seats <email> <seats>\n"
        "/admin_list — accounts & seats\n"
        "/admin_list_seats — active sessions\n"
        "/admin_purge — purge all | <login> | #<id>"
    )

async def admin_add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Not authorized."); return
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /admin_add <email_or_username> <temporary_password> [max_concurrent]")
        return
    email_or_user = context.args[0]
    password = context.args[1]
    max_cc = int(context.args[2]) if len(context.args) >= 3 and context.args[2].isdigit() else 1
    with db() as con:
        con.execute(
            "INSERT INTO accounts(label, token, is_allocated, max_concurrent, allocated_count) VALUES (?, ?, 0, ?, 0)",
            (email_or_user, password, max_cc),
        )
    with db() as con:
        latest = con.execute("SELECT id FROM accounts ORDER BY id DESC LIMIT 1").fetchone()
    await update.message.reply_text(
        f"Added new account: {email_or_user} (seats: {max_cc}). "
        f"This account will be used for NEW allocations (id={latest['id']}). "
        f"Existing sessions on older accounts continue unaffected."
    )

async def admin_set_seats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Not authorized."); return
    if len(context.args) < 2 or not context.args[1].isdigit():
        await update.message.reply_text("Usage: /admin_set_seats <email_or_username> <max_concurrent>"); return
    email_or_user = context.args[0]; max_cc = int(context.args[1])
    with db() as con:
        con.execute("UPDATE accounts SET max_concurrent=? WHERE label=?", (max_cc, email_or_user))
    await update.message.reply_text(f"Updated seats: {email_or_user} -> {max_cc}")

async def admin_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Not authorized."); return
    with db() as con:
        rows = con.execute("SELECT id,label,max_concurrent,allocated_count FROM accounts ORDER BY id").fetchall()
    if not rows:
        await update.message.reply_text("No accounts in pool."); return
    lines = [f"{r['id']}: {r['label']} seats {r['allocated_count']}/{r['max_concurrent']}" for r in rows]
    await update.message.reply_text("\n".join(lines))

async def admin_list_seats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Not authorized."); return
    with db() as con:
        rows = con.execute(
            """
            SELECT s.id, s.telegram_id, s.start_ts, s.end_ts, a.label AS account_label
            FROM sessions s
            JOIN accounts a ON a.id = s.account_id
            WHERE s.status = 'active'
            ORDER BY s.end_ts ASC
            """
        ).fetchall()
    if not rows:
        await update.message.reply_text("No active sessions."); return
    now_ts = int(datetime.now(tz=TIMEZONE).timestamp())
    lines = []
    for r in rows:
        try:
            chat = await context.bot.get_chat(r["telegram_id"])
            user_tag = f"@{chat.username}" if chat and chat.username else str(r["telegram_id"])
        except Exception:
            user_tag = str(r["telegram_id"])
        remaining_min = max(0, (r["end_ts"] - now_ts) // 60)
        lines.append(
            f"#{r['id']} • {user_tag} • {r['account_label']}\n"
            f"   Start: {fmt_dt(r['start_ts'])} | End: {fmt_dt(r['end_ts'])} | Remaining: {remaining_min} min"
        )
    buf, count = [], 0
    for line in lines:
        if count + len(line) > 3500:
            await update.message.reply_text("\n".join(buf)); buf, count = [], 0
        buf.append(line); count += len(line)
    if buf: await update.message.reply_text("\n".join(buf))

def cancel_expiry_job(session_id: int, application: Application):
    name = f"expire:{session_id}"
    for job in application.job_queue.get_jobs_by_name(name):
        job.schedule_removal()

async def notify_users(context, user_ids, text: str):
    for uid in set(user_ids or []):
        try:
            await context.bot.send_message(chat_id=uid, text=text)
        except Exception:
            pass

def users_on_accounts(account_ids):
    if not account_ids: return []
    q = ",".join("?" for _ in account_ids)
    with db() as con:
        rows = con.execute(
            f"SELECT id, telegram_id FROM sessions WHERE status='active' AND account_id IN ({q})",
            account_ids
        ).fetchall()
    return [(r["id"], r["telegram_id"]) for r in rows]

def all_active_sessions():
    with db() as con:
        rows = con.execute("SELECT id, telegram_id FROM sessions WHERE status='active'").fetchall()
    return [(r["id"], r["telegram_id"]) for r in rows]

async def admin_purge(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Not authorized."); return

    if not context.args:
        active = all_active_sessions()
        with db() as con:
            con.execute("UPDATE sessions SET status='expired' WHERE status='active'")
            con.execute("DELETE FROM accounts")
            con.execute("UPDATE accounts SET allocated_count = 0")
        for sid, _ in active:
            cancel_expiry_job(sid, context.application)
        await notify_users(
            context, [uid for _, uid in active],
            "Your session has ended because the admin purged all accounts.\n"
            "Please log out from the account now so it doesn't slow down other users' workflow."
        )
        await update.message.reply_text(f"Purged all accounts and ended {len(active)} active session(s).")
        return

    arg = context.args[0].strip()
    if arg.startswith("#") or arg.isdigit():
        sid = int(arg[1:] if arg.startswith("#") else arg)
        with db() as con:
            s = con.execute("SELECT id, telegram_id, account_id, status FROM sessions WHERE id = ?", (sid,)).fetchone()
        if not s:
            await update.message.reply_text(f"Session #{sid} not found."); return
        if s["status"] != "active":
            await update.message.reply_text(f"Session #{sid} is not active (status={s['status']})."); return
        with db() as con:
            con.execute("UPDATE sessions SET status='expired' WHERE id = ?", (sid,))
        release_seat(s["account_id"])
        cancel_expiry_job(sid, context.application)
        try:
            await context.bot.send_message(
                chat_id=s["telegram_id"],
                text=("Your session was ended by the admin.\n"
                      "Please log out from the account now so it doesn't slow down other users' workflow.")
            )
        except Exception:
            pass
        await update.message.reply_text(f"Ended session #{sid} and freed its seat.")
        return

    target_label = arg
    with db() as con:
        accs = con.execute("SELECT id FROM accounts WHERE label = ?", (target_label,)).fetchall()
    account_ids = [r["id"] for r in accs]
    if not account_ids:
        await update.message.reply_text(f"No accounts found for: {target_label}"); return

    affected = users_on_accounts(account_ids)
    q = ",".join("?" for _ in account_ids)
    with db() as con:
        con.execute(f"UPDATE sessions SET status='expired' WHERE status='active' AND account_id IN ({q})", account_ids)
        con.execute(f"DELETE FROM accounts WHERE id IN ({q})", account_ids)
        con.execute("UPDATE accounts SET allocated_count = 0")
        con.execute("""
        WITH active AS (SELECT account_id, COUNT(*) AS c FROM sessions WHERE status='active' GROUP BY account_id)
        UPDATE accounts
        SET allocated_count = COALESCE((SELECT c FROM active WHERE active.account_id = accounts.id), 0)
        """)
    for sid, _ in affected:
        cancel_expiry_job(sid, context.application)
    await notify_users(
        context, [uid for _, uid in affected],
        f"Your session was ended because the admin purged the account: {target_label}.\n"
        "Please log out from the account now so it doesn't slow down other users' workflow."
    )
    await update.message.reply_text(f"Purged login: {target_label}. Ended {len(affected)} active session(s).")

async def contact_start(update, context):
    if not ADMIN_ID:
        await update.message.reply_text("Admin is not configured. Please try again later.")
        return ConversationHandler.END
    await update.message.reply_text("Send your message for the admin (text, photo, or PDF). When you’re done, you can /cancel.")
    return CONTACT

async def contact_receive(update, context):
    if not ADMIN_ID:
        await update.message.reply_text("Admin is not configured. Please try again later.")
        return ConversationHandler.END
    user = update.effective_user; tag = _user_tag(user)
    try:
        if update.message.photo or (update.message.document and update.message.document.mime_type == "application/pdf"):
            await context.bot.copy_message(
                chat_id=int(ADMIN_ID),
                from_chat_id=update.message.chat_id,
                message_id=update.message.message_id,
                caption=(update.message.caption or "")
            )
            await context.bot.send_message(chat_id=int(ADMIN_ID), text=f"From {tag} (user id {user.id}) via /contact")
        else:
            text = update.message.text or "(non-text message)"
            await context.bot.send_message(chat_id=int(ADMIN_ID), text=f"Message from {tag} (user id {user.id}) via /contact:\n\n{text}")
        await update.message.reply_text("Sent to admin. Thanks!")
    except Exception as e:
        await update.message.reply_text("Could not deliver your message to admin. Please try again later.")
        log.warning("contact forward failed: %s", e)
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Cancelled.")
    return ConversationHandler.END

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.exception("Exception while handling an update: %s", context.error)

# =====================
# Handler registration
# =====================
def register_handlers(tgapp: Application):
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            ASK_DURATION: [MessageHandler(filters.TEXT & ~filters.COMMAND, ask_duration)],
            CONFIRM: [CallbackQueryHandler(confirm_cb, pattern="^(confirm|cancel)$")],
            WAIT_BILL: [MessageHandler((filters.PHOTO | filters.Document.PDF) & ~filters.COMMAND, receive_bill)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    contact_conv = ConversationHandler(
        entry_points=[CommandHandler("contact", contact_start)],
        states={CONTACT: [MessageHandler((filters.TEXT | filters.PHOTO | filters.Document.PDF) & ~filters.COMMAND, contact_receive)]},
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    tgapp.add_handler(contact_conv)
    tgapp.add_handler(conv)
    tgapp.add_handler(CommandHandler("my_session", my_session))
    tgapp.add_handler(CommandHandler("help", help_cmd))
    tgapp.add_handler(CommandHandler("admin_add", admin_add))
    tgapp.add_handler(CommandHandler("admin_set_seats", admin_set_seats))
    tgapp.add_handler(CommandHandler("admin_list", admin_list))
    tgapp.add_handler(CommandHandler("admin_list_seats", admin_list_seats))
    tgapp.add_handler(CommandHandler("admin_purge", admin_purge))
    tgapp.add_handler(CallbackQueryHandler(copy_phone_cb, pattern="^copy_phone$"))
    tgapp.add_handler(CallbackQueryHandler(copy_ref_cb,   pattern="^copy_ref$"))
    tgapp.add_error_handler(error_handler)

# =====================
# Webhook server (Render)
# =====================
BOT_TOKEN = os.environ.get("BOT_TOKEN")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "whsec")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")

# Flask app exposed as `app` for gunicorn
app = Flask(__name__)

# Global PTB app for server mode
tg_app_server: Application | None = None

@app.get("/")
def index():
    return "Bot is running. See /healthz", 200

@app.get("/healthz")
def healthz():
    return "ok", 200

@app.post(f"/webhook/{WEBHOOK_SECRET}")
def telegram_webhook():
    # Only accept Telegram’s signed calls
    if request.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
        return "forbidden", 403
    if tg_app_server is None:
        return "bot not ready", 503
    data = request.get_json(force=True, silent=True) or {}
    update = Update.de_json(data, tg_app_server.bot)
    # Hand off to PTB loop and return immediately
    tg_app_server.create_task(tg_app_server.process_update(update))
    return "ok", 200
if __name__ != "__main__":
    load_dotenv()
    # env overrides
    # env overrides
    DB_PATH = os.environ.get("DB_PATH", DB_PATH)
    ADMIN_ID = os.environ.get("ADMIN_USER_ID", ADMIN_ID).strip()
    PAYMENT_PHONE = os.environ.get("PAYMENT_PHONE", PAYMENT_PHONE).strip()

    init_db(); ensure_seat_columns(); cleanup_expired_now()
    _init_gmail()

    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN not set")

    tg_app_server = ApplicationBuilder().token(BOT_TOKEN).build()
    register_handlers(tg_app_server)

    # Start PTB and set webhook
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tg_app_server.initialize())
    loop.run_until_complete(tg_app_server.start())
    if PUBLIC_BASE_URL:
        try:
            loop.run_until_complete(
                tg_app_server.bot.set_webhook(
                    url=f"{PUBLIC_BASE_URL}/webhook/{WEBHOOK_SECRET}",
                    secret_token=WEBHOOK_SECRET
                )
            )
            log.info("Webhook set to %s/webhook/%s", PUBLIC_BASE_URL, WEBHOOK_SECRET)
        except Exception as e:
            log.error("Failed to set webhook: %s", e)
    else:
        log.warning("PUBLIC_BASE_URL not set — webhook not registered yet.")

# =====================
# Local entry (polling)
# =====================
if __name__ == "__main__":
    load_dotenv()
    token = os.environ.get("BOT_TOKEN")
    if not token:
        raise SystemExit("BOT_TOKEN not set")

    # env overrides
    DB_PATH = os.environ.get("DB_PATH", DB_PATH)
    ADMIN_ID = os.environ.get("ADMIN_USER_ID", ADMIN_ID).strip()
    PAYMENT_PHONE = os.environ.get("PAYMENT_PHONE", PAYMENT_PHONE).strip()

    init_db(); ensure_seat_columns(); cleanup_expired_now()
    _init_gmail()

    app_local = ApplicationBuilder().token(token).build()
    register_handlers(app_local)
    log.info("Bot starting (polling)…")
    app_local.run_polling(allowed_updates=Update.ALL_TYPES)
