"""Optional Telegram push for ERROR-severity / ATTACK_* events.

No-op unless TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set, matching the
project's explicit-placeholder convention (see history/service.py,
scenarios/store.py) instead of failing silently or faking a delivery.
"""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger("telegram_notify")

TELEGRAM_API_BASE = "https://api.telegram.org"


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

    url = f"{TELEGRAM_API_BASE}/bot{bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(url, json={"chat_id": chat_id, "text": text})
            if resp.status_code >= 400:
                logger.warning(f"Telegram notify failed: {resp.status_code} {resp.text}")
    except Exception as e:
        logger.warning(f"Telegram notify error: {e}")
