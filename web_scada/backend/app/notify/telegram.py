"""Optional Telegram push for ERROR-severity / ATTACK_* events, plus 2-way
"Xác nhận" (ack) from an inline button on the notification itself.

No-op unless TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set, matching the
project's explicit-placeholder convention (see history/service.py,
scenarios/store.py) instead of failing silently or faking a delivery.

Long-polling (getUpdates), not a webhook: this app has no public HTTPS
endpoint (LAN-only lab), so Telegram has no way to call back to us — we
call out to it instead, repeatedly asking "anything new?" with a long
server-side wait so it isn't a busy-loop. See poll_telegram_updates().

Scope, deliberately narrow: the button only ever does a plain "Xác nhận"
(disposition=None) — never the admin-only "confirmed_new_pattern", and never
a note. Escalation (main.py) only re-nags an ACTIVE event with no acked_by
at all, so a bare ack is the one action that actually matters from a phone;
the fuller triage (đang xử lý / báo động giả / ghi chú / giao vụ) stays a
web-only workflow where there's room to actually do it properly. Every ack
from Telegram is attributed to the fixed username "telegram-bot", never a
real person — Telegram's user ID isn't mapped to any Web-SCADA IDS account,
so pretending otherwise would be a fake attribution in the audit trail.
"""

from __future__ import annotations

import logging
import os
from typing import Awaitable, Callable

import httpx

logger = logging.getLogger("telegram_notify")

TELEGRAM_API_BASE = "https://api.telegram.org"
TELEGRAM_ACK_USERNAME = "telegram-bot"

# event_id -> [(chat_id, message_id), ...] — every message that ever
# announced this event (the first push, plus any escalation re-nags each
# send a fresh message), so acking from any one of them can go back and
# clean up the button on all the others too. In-memory only: worst case
# after a backend restart is that an old button stops updating its own
# message visually on tap — the ack itself still goes through fine, since
# callback_data carries the event_id, not a reference into this dict.
_sent_messages: dict[str, list[tuple[str, int]]] = {}
_update_offset = 0


def telegram_configured() -> bool:
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))


async def notify_event(event: dict) -> None:
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    if not bot_token or not chat_id:
        return

    text = (
        "\U0001F6A8 Web-SCADA alert\n"
        f"Type: {event.get('event_type')}\n"
        f"Severity: {event.get('severity')}\n"
        f"Message: {event.get('message')}\n"
        f"Time: {event.get('timestamp')}"
    )

    event_id = event.get("id")
    payload: dict = {"chat_id": chat_id, "text": text}
    if event_id:
        payload["reply_markup"] = {
            "inline_keyboard": [[{"text": "✅ Xác nhận", "callback_data": f"ack:{event_id}"}]]
        }

    url = f"{TELEGRAM_API_BASE}/bot{bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code >= 400:
                logger.warning(f"Telegram notify failed: {resp.status_code} {resp.text}")
            elif event_id:
                msg = resp.json().get("result", {})
                sent_chat_id = str(msg.get("chat", {}).get("id", chat_id))
                message_id = msg.get("message_id")
                if message_id is not None:
                    _sent_messages.setdefault(event_id, []).append((sent_chat_id, message_id))
    except Exception as e:
        logger.warning(f"Telegram notify error: {e}")


async def poll_telegram_updates(on_ack: Callable[[str], Awaitable[None]]) -> None:
    """One long-poll cycle: ask Telegram for new updates (waits up to 30s
    server-side for one to arrive, so calling this in a tight `while True`
    loop is fine — it's not busy-waiting), handle any "ack:<event_id>"
    button taps found, then return. `on_ack` is the caller's own
    event_service.ack() + WebSocket broadcast — kept out of this module on
    purpose, so this file stays Telegram-protocol-only and never imports
    the events/websocket internals.
    """
    global _update_offset
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not bot_token:
        return

    url = f"{TELEGRAM_API_BASE}/bot{bot_token}/getUpdates"
    async with httpx.AsyncClient(timeout=35) as client:
        resp = await client.get(url, params={
            "offset": _update_offset,
            "timeout": 30,
            "allowed_updates": '["callback_query"]',
        })
        if resp.status_code != 200:
            logger.warning(f"Telegram getUpdates failed: {resp.status_code} {resp.text}")
            return

        for update in resp.json().get("result", []):
            _update_offset = update["update_id"] + 1
            cq = update.get("callback_query")
            if not cq or not str(cq.get("data", "")).startswith("ack:"):
                continue

            event_id = cq["data"][len("ack:"):]
            await _answer_callback(client, cq["id"], "Đã xác nhận")
            await on_ack(event_id)
            await _clear_buttons(client, event_id)


async def _answer_callback(client: httpx.AsyncClient, callback_query_id: str, text: str) -> None:
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    try:
        await client.post(
            f"{TELEGRAM_API_BASE}/bot{bot_token}/answerCallbackQuery",
            json={"callback_query_id": callback_query_id, "text": text},
        )
    except Exception:
        pass  # cosmetic (stops the tap's loading spinner) — ack itself already went through


async def _clear_buttons(client: httpx.AsyncClient, event_id: str) -> None:
    """Remove the "Xác nhận" button from every message that ever announced
    this event, so a since-acked alert doesn't keep inviting a second tap.
    Best-effort per message — one already-edited/deleted message failing
    must not stop the others from being cleaned up.
    """
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    for chat_id, message_id in _sent_messages.pop(event_id, []):
        try:
            await client.post(
                f"{TELEGRAM_API_BASE}/bot{bot_token}/editMessageReplyMarkup",
                json={"chat_id": chat_id, "message_id": message_id, "reply_markup": {"inline_keyboard": []}},
            )
        except Exception:
            pass
