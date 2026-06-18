"""Formats hunter engine events into Telegram messages and builds the
notifier callback the Hunter calls into (kept free of any hunter/storage
imports beyond what it needs to format text, to avoid a circular import)."""
from __future__ import annotations

import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application

logger = logging.getLogger(__name__)


def _hit_keyboard(service_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("✅ оставить", callback_data=f"keep:{service_id}"),
        InlineKeyboardButton("🔁 искать ещё", callback_data=f"continue:{service_id}"),
        InlineKeyboardButton("🗑 освободить", callback_data=f"release:{service_id}"),
    ]])


async def broadcast(app: Application, chat_ids: set[int], text: str, reply_markup=None) -> None:
    for chat_id in chat_ids:
        try:
            await app.bot.send_message(chat_id=chat_id, text=text, reply_markup=reply_markup)
        except Exception:
            logger.exception("failed to notify chat_id=%s", chat_id)


def make_notifier(app: Application, chat_ids: set[int]):
    async def notifier(event_type: str, payload: dict) -> None:
        if event_type == "hit":
            text = (
                f"🎯 Найден целевой IP!\n"
                f"IP: {payload['ip']}\n"
                f"ASN: {payload.get('asn')}\n"
                f"Префикс: {payload.get('prefix')}\n"
                f"AS: {payload.get('as_name')}"
            )
            await broadcast(app, chat_ids, text, _hit_keyboard(payload["service_id"]))
        elif event_type == "stop":
            stats = payload["stats"]
            text = (
                f"⏹ Перебор остановлен ({payload['reason']})\n"
                f"Попыток: {stats.attempts}, уникальных: {stats.unique}, "
                f"повторов: {stats.rerolls}, найдено: {stats.found}"
            )
            await broadcast(app, chat_ids, text)
        elif event_type == "error":
            kind = payload.get("kind", "")
            await broadcast(app, chat_ids, f"⚠️ Ошибка ({kind}): {payload['message']}")
        elif event_type == "progress":
            stats = payload["stats"]
            text = (
                f"⏳ Прогресс: попыток {stats.attempts}, уникальных {stats.unique}, "
                f"повторов {stats.rerolls}, найдено {stats.found}, "
                f"прошло {stats.elapsed_min():.1f} мин"
            )
            await broadcast(app, chat_ids, text)
        else:
            logger.warning("unknown notifier event type: %s", event_type)

    return notifier
