"""
Оповещения об инцидентах в Telegram и Slack.

Настройки берутся из переменных окружения (файл .env не коммитим):
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID — бот Telegram и чат/канал дежурных;
  SLACK_WEBHOOK_URL                    — входящий вебхук Slack.
Если ничего не задано, оповещения выводятся в консоль (режим dry-run),
поэтому проект запускается без токенов.

Чтобы не завалить дежурных однотипными сообщениями, одинаковые оповещения
(тот же тип и источник) повторно отправляются не чаще, чем раз в dedup_seconds.
"""

from __future__ import annotations

import os
import time
from typing import Iterable

import requests

LEVELS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ICONS = {"LOW": "[i]", "MEDIUM": "[!]", "HIGH": "[!!]", "CRITICAL": "[!!!]"}


def format_alert(alert: dict, company: str = "ТехноПрофи") -> str:
    sev = alert.get("severity", "MEDIUM")
    ts = alert.get("timestamp")
    ts = ts.strftime("%d.%m.%Y %H:%M:%S") if hasattr(ts, "strftime") else str(ts or "")
    return (f"{ICONS.get(sev, '[!]')} {sev}: {alert.get('type', 'EVENT')}\n"
            f"Компания: {company}\n"
            f"Источник: {alert.get('source', '-')}\n"
            f"Время: {ts}\n"
            f"Описание: {alert.get('details', '')}")


class Notifier:
    name = "base"

    def send(self, text: str) -> bool:  # pragma: no cover - интерфейс
        raise NotImplementedError


class ConsoleNotifier(Notifier):
    name = "console"

    def __init__(self):
        self.sent: list[str] = []

    def send(self, text: str) -> bool:
        self.sent.append(text)
        print("\n[ОПОВЕЩЕНИЕ, dry-run]\n" + text)
        return True


class TelegramNotifier(Notifier):
    """Отправка через Telegram Bot API, метод sendMessage."""
    name = "telegram"

    def __init__(self, token: str, chat_id: str, session: requests.Session | None = None, timeout: int = 10):
        self.url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.session = session or requests.Session()
        self.timeout = timeout

    def send(self, text: str) -> bool:
        r = self.session.post(self.url, json={"chat_id": self.chat_id, "text": text,
                                              "disable_web_page_preview": True}, timeout=self.timeout)
        return r.status_code == 200 and r.json().get("ok", False)


class SlackNotifier(Notifier):
    """Отправка через входящий вебхук Slack (Incoming Webhooks)."""
    name = "slack"

    def __init__(self, webhook_url: str, session: requests.Session | None = None, timeout: int = 10):
        self.webhook_url = webhook_url
        self.session = session or requests.Session()
        self.timeout = timeout

    def send(self, text: str) -> bool:
        r = self.session.post(self.webhook_url, json={"text": text}, timeout=self.timeout)
        return r.status_code == 200


class AlertManager:
    def __init__(self, notifiers: Iterable[Notifier], min_severity: str = "HIGH", dedup_seconds: int = 300,
                 audit=None, company: str = "ТехноПрофи"):
        self.notifiers = list(notifiers)
        self.min_level = LEVELS[min_severity]
        self.dedup_seconds = dedup_seconds
        self.audit = audit
        self.company = company
        self._last_sent: dict[tuple, float] = {}
        self.history: list[dict] = []

    @classmethod
    def from_env(cls, **kwargs) -> "AlertManager":
        notifiers: list[Notifier] = []
        if os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"):
            notifiers.append(TelegramNotifier(os.environ["TELEGRAM_BOT_TOKEN"], os.environ["TELEGRAM_CHAT_ID"]))
        if os.getenv("SLACK_WEBHOOK_URL"):
            notifiers.append(SlackNotifier(os.environ["SLACK_WEBHOOK_URL"]))
        if not notifiers:
            notifiers.append(ConsoleNotifier())
        return cls(notifiers, **kwargs)

    def notify(self, alert: dict) -> bool:
        if LEVELS.get(alert.get("severity", "MEDIUM"), 2) < self.min_level:
            return False
        key = (alert.get("type"), str(alert.get("source")))
        now = time.monotonic()
        if key in self._last_sent and now - self._last_sent[key] < self.dedup_seconds:
            return False
        self._last_sent[key] = now
        text = format_alert(alert, self.company)
        delivered = False
        for n in self.notifiers:
            try:
                ok = n.send(text)
            except requests.RequestException as e:
                ok = False
                print(f"Не удалось отправить оповещение через {n.name}: {e}")
            delivered = delivered or ok
            self.history.append({"channel": n.name, "ok": ok, "type": alert.get("type")})
            if self.audit is not None:
                self.audit.log("ALERT_SENT", {"channel": n.name, "alert_type": alert.get("type")},
                               alert.get("severity", "MEDIUM"), str(alert.get("source")),
                               outcome="success" if ok else "failure")
        return delivered
