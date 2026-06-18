"""Telegram command handlers. All access is gated to whitelisted chat_ids
from .env (TELEGRAM_ALLOWED_CHAT_IDS) -- everyone else is silently ignored."""
from __future__ import annotations

import functools
import logging

import aiohttp
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, Update
from telegram.ext import CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

from app.calibrate import run as run_calibration
from app.context import AppContext
from app.hunter import STRATEGY_HOLD_WINDOW, STRATEGY_RELEASE_IMMEDIATELY, AlreadyRunning
from app.matcher import TargetConfig
from app.proxy import ProxyConfig, build_connector

logger = logging.getLogger(__name__)

MENU_LAYOUT = [
    ["▶️ /hunt", "⏹ /stop"],
    ["📊 /status", "📋 /list"],
    ["🎯 /found", "🧪 /calibrate"],
    ["🔀 /strategy", "🌐 /target"],
    ["🧦 /proxy", "⚙️ /limits"],
]


def build_main_menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(MENU_LAYOUT, resize_keyboard=True)


def _ctx(context: ContextTypes.DEFAULT_TYPE) -> AppContext:
    return context.application.bot_data["ctx"]


def restricted(handler):
    @functools.wraps(handler)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id if update.effective_chat else None
        ctx = _ctx(context)
        if chat_id not in ctx.settings.telegram_allowed_chat_ids:
            logger.warning("ignored update from non-whitelisted chat_id=%s", chat_id)
            return
        return await handler(update, context)
    return wrapper


@restricted
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    status = "запущен" if ctx.hunter.running else "остановлен"
    await update.message.reply_text(
        "MWS IP-Hunter\n"
        f"Статус перебора: {status}\n\n"
        "/hunt — запустить\n/stop — остановить\n/status — статистика\n"
        "/target — цель (CIDR/AS)\n/strategy — стратегия\n/calibrate — калибровка\n"
        "/proxy — SOCKS5 прокси\n/list — текущие резервации\n/release — освободить\n"
        "/found — найденные IP\n/limits — стоп-условия\n/logs — логи",
        reply_markup=build_main_menu(),
    )


@restricted
async def cmd_hunt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    try:
        await ctx.hunter.start()
    except AlreadyRunning:
        await update.message.reply_text("Перебор уже запущен.")
        return
    await update.message.reply_text("Перебор запущен.")


@restricted
async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    if not ctx.hunter.running:
        await update.message.reply_text("Перебор не запущен.")
        return
    await update.message.reply_text("Останавливаю...")
    await ctx.hunter.stop()


@restricted
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    stats = ctx.hunter.stats
    reserved_now = await ctx.storage.count_reserved()
    hit_rate = (stats.found / stats.unique * 100) if stats.unique else 0.0
    text = (
        f"Запущен: {ctx.hunter.running}\n"
        f"Попыток: {stats.attempts}\n"
        f"Уникальных: {stats.unique}\n"
        f"Повторов: {stats.rerolls}\n"
        f"Найдено: {stats.found}\n"
        f"Зарезервировано сейчас: {reserved_now}\n"
        f"Hit-rate: {hit_rate:.2f}%\n"
        f"Прошло: {stats.elapsed_min():.1f} мин\n"
        f"Оценка стоимости: {ctx.hunter.estimated_cost():.2f}"
    )
    await update.message.reply_text(text)


@restricted
async def cmd_target(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    args = context.args
    target = ctx.hunter.limits.target
    if not args:
        await update.message.reply_text(
            f"CIDR: {', '.join(target.cidrs) or '(пусто)'}\nASN: {', '.join(map(str, sorted(target.asns))) or '(пусто)'}"
        )
        return
    sub = args[0].lower()
    if sub == "clear":
        ctx.hunter.limits.target = TargetConfig()
    elif sub == "cidr" and len(args) > 1:
        target.cidrs = [c.strip() for c in args[1].split(",") if c.strip()]
    elif sub == "asn" and len(args) > 1:
        target.asns = {int(a.strip().lstrip("ASas")) for a in args[1].split(",") if a.strip()}
    else:
        await update.message.reply_text("Использование: /target cidr <list> | /target asn <list> | /target clear")
        return
    await ctx.storage.set_config_json("target", ctx.hunter.limits.target.to_dict())
    await update.message.reply_text("Цель обновлена.")


def _strategy_keyboard(current: str) -> InlineKeyboardMarkup:
    def label(value: str) -> str:
        return f"✅ {value}" if value == current else value

    return InlineKeyboardMarkup([
        [InlineKeyboardButton(label(STRATEGY_RELEASE_IMMEDIATELY), callback_data=f"strategy:{STRATEGY_RELEASE_IMMEDIATELY}")],
        [InlineKeyboardButton(label(STRATEGY_HOLD_WINDOW), callback_data=f"strategy:{STRATEGY_HOLD_WINDOW}")],
    ])


@restricted
async def cmd_strategy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    args = context.args
    if not args:
        current = ctx.hunter.limits.strategy
        await update.message.reply_text(
            f"Текущая стратегия: {current}", reply_markup=_strategy_keyboard(current)
        )
        return
    value = args[0].strip()
    if value not in (STRATEGY_RELEASE_IMMEDIATELY, STRATEGY_HOLD_WINDOW):
        await update.message.reply_text(f"Допустимо: {STRATEGY_RELEASE_IMMEDIATELY} | {STRATEGY_HOLD_WINDOW}")
        return
    ctx.hunter.limits.strategy = value
    await ctx.storage.set_config("strategy", value)
    await update.message.reply_text(f"Стратегия установлена: {value}")


@restricted
async def on_strategy_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    query = update.callback_query
    _, _, value = query.data.partition(":")
    await query.answer()
    if value not in (STRATEGY_RELEASE_IMMEDIATELY, STRATEGY_HOLD_WINDOW):
        return
    ctx.hunter.limits.strategy = value
    await ctx.storage.set_config("strategy", value)
    await query.edit_message_text(f"Текущая стратегия: {value}", reply_markup=_strategy_keyboard(value))


@restricted
async def cmd_calibrate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    if ctx.hunter.running:
        await update.message.reply_text("Сначала остановите перебор (/stop).")
        return
    n = int(context.args[0]) if context.args else ctx.hunter.limits.quota
    await update.message.reply_text(f"Калибровка: резервирую {n} адресов...")
    result = await run_calibration(ctx.mws, ctx.storage, ctx.hunter.limits.target, ctx.hunter.limits.quota, n)
    await update.message.reply_text(
        f"Вердикт: {result.verdict}\nРекомендация: {result.recommendation}\n"
        f"Медианная дельта: {result.median_delta:.0f}\nРазличных /24: {result.distinct_slash24}\n"
        f"IP: {', '.join(result.ips)}"
    )


@restricted
async def cmd_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    args = context.args
    if not args:
        masked = ProxyConfig.parse(ctx.proxy_raw).masked() if ctx.proxy_raw else "(не задан)"
        await update.message.reply_text(f"Текущий прокси: {masked}")
        return
    if args[0] == "test":
        await update.message.reply_text("Проверяю прокси...")
        try:
            ip = await _test_proxy(ctx.proxy_raw)
            await update.message.reply_text(f"OK, внешний IP через прокси: {ip}")
        except Exception as exc:
            await update.message.reply_text(f"Ошибка проверки прокси: {exc}")
        return
    raw = args[0]
    try:
        ProxyConfig.parse(raw)
    except ValueError as exc:
        await update.message.reply_text(f"Не удалось разобрать прокси: {exc}")
        return
    await ctx.rebuild_mws_client(raw)
    await ctx.storage.set_config("proxy", raw)
    await update.message.reply_text(f"Прокси обновлён: {ProxyConfig.parse(raw).masked()}")


async def _test_proxy(proxy_raw: str) -> str:
    proxy_cfg = ProxyConfig.parse(proxy_raw) if proxy_raw else None
    connector = build_connector(proxy_cfg)
    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.get("https://api.ipify.org?format=json", timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.json()
            return data["ip"]


def _release_keyboard(rows) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f"🗑 {r.ip or r.service_id[:8]}", callback_data=f"release:{r.service_id}")]
        for r in rows
    ])


@restricted
async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    rows = await ctx.storage.list_reserved()
    if not rows:
        await update.message.reply_text("Нет активных резерваций.")
        return
    lines = [f"{r.service_id[:8]} {r.ip} [{r.status}]" for r in rows]
    await update.message.reply_text("\n".join(lines), reply_markup=_release_keyboard(rows))


@restricted
async def cmd_release(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    args = context.args
    if not args:
        await update.message.reply_text("Использование: /release <id|all|misses>")
        return
    target_arg = args[0]
    rows = await ctx.storage.list_reserved()
    if target_arg == "all":
        for r in rows:
            await ctx.hunter.release(r.service_id)
        await update.message.reply_text(f"Освобождено: {len(rows)}")
        return
    if target_arg == "misses":
        misses = [r for r in rows if r.status in ("pending", "held")]
        for r in misses:
            await ctx.hunter.release(r.service_id)
        await update.message.reply_text(f"Освобождено промахов: {len(misses)}")
        return
    matched = [r for r in rows if r.service_id.startswith(target_arg)]
    if not matched:
        await update.message.reply_text("Не найдено резервации с таким id.")
        return
    await ctx.hunter.release(matched[0].service_id)
    await update.message.reply_text(f"Освобождён: {matched[0].service_id}")


@restricted
async def cmd_found(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    rows = await ctx.storage.list_reserved(status="kept")
    if not rows:
        await update.message.reply_text("Пока ничего не найдено.")
        return
    await update.message.reply_text(
        "\n".join(f"{r.ip} ({r.service_id[:8]})" for r in rows),
        reply_markup=_release_keyboard(rows),
    )


@restricted
async def cmd_limits(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    limits = ctx.hunter.limits
    args = context.args
    if not args or len(args) < 2:
        await update.message.reply_text(
            f"target_count: {limits.target_count}\nmax_attempts: {limits.max_attempts}\n"
            f"max_runtime_min: {limits.max_runtime_min}\nmax_budget: {limits.max_budget}\n\n"
            "Изменить: /limits <поле> <значение>"
        )
        return
    field, value = args[0], args[1]
    int_fields = {"target_count", "max_attempts", "max_runtime_min"}
    float_fields = {"max_budget"}
    if field in int_fields:
        setattr(limits, field, int(value))
    elif field in float_fields:
        setattr(limits, field, float(value))
    else:
        await update.message.reply_text("Неизвестное поле.")
        return
    await ctx.storage.set_config(field, value)
    await update.message.reply_text(f"{field} = {value}")


@restricted
async def cmd_logs(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    n = int(context.args[0]) if context.args else 30
    log_path = ctx.settings.db_path.parent / "app.log"
    if not log_path.exists():
        await update.message.reply_text("Лог-файл пока пуст.")
        return
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
    text = "\n".join(lines) or "(пусто)"
    await update.message.reply_text(text[-3500:])


@restricted
async def on_action_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ctx = _ctx(context)
    query = update.callback_query
    action, _, service_id = query.data.partition(":")
    await query.answer()
    if action == "keep":
        await query.edit_message_text(query.message.text + "\n\n✅ оставлен")
    elif action == "continue":
        ctx.hunter.limits.target_count += 1
        await query.edit_message_text(query.message.text + "\n\n🔁 ищем ещё один")
    elif action == "release":
        record = await ctx.storage.get_reserved(service_id)
        await ctx.hunter.release(service_id)
        if record is not None and record.status == "kept":
            ctx.hunter.stats.found = max(0, ctx.hunter.stats.found - 1)
        await query.edit_message_text(query.message.text + "\n\n🗑 освобождён")


_MENU_DISPATCH = {
    "▶️ /hunt": cmd_hunt,
    "⏹ /stop": cmd_stop,
    "📊 /status": cmd_status,
    "📋 /list": cmd_list,
    "🎯 /found": cmd_found,
    "🧪 /calibrate": cmd_calibrate,
    "🔀 /strategy": cmd_strategy,
    "🌐 /target": cmd_target,
    "🧦 /proxy": cmd_proxy,
    "⚙️ /limits": cmd_limits,
}


@restricted
async def on_menu_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text.strip() if update.message and update.message.text else ""
    handler = _MENU_DISPATCH.get(text)
    if handler is None:
        return
    context.args = []
    await handler(update, context)


def register_handlers(application) -> None:
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("hunt", cmd_hunt))
    application.add_handler(CommandHandler("stop", cmd_stop))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("target", cmd_target))
    application.add_handler(CommandHandler("strategy", cmd_strategy))
    application.add_handler(CommandHandler("calibrate", cmd_calibrate))
    application.add_handler(CommandHandler("proxy", cmd_proxy))
    application.add_handler(CommandHandler("list", cmd_list))
    application.add_handler(CommandHandler("release", cmd_release))
    application.add_handler(CommandHandler("found", cmd_found))
    application.add_handler(CommandHandler("limits", cmd_limits))
    application.add_handler(CommandHandler("logs", cmd_logs))
    application.add_handler(CallbackQueryHandler(on_strategy_button, pattern=r"^strategy:"))
    application.add_handler(CallbackQueryHandler(on_action_button, pattern=r"^(keep|continue|release):"))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_menu_button))
