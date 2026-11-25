"""
Журнал аудита событий безопасности.

Требования, на которые ориентирован журнал:
- ГОСТ Р ИСО/МЭК 27001-2021 / ISO/IEC 27001:2022, мера A.8.15 «Протоколирование»:
  события должны записываться, храниться и быть защищены от изменения;
- Приказ ФСТЭК России № 21, группа мер РСБ «Регистрация событий безопасности»
  (состав и содержание записей, сроки хранения, защита журнала);
- 152-ФЗ: в журнале не храним лишних персональных данных, только IP и учётные имена.

Реализация:
- формат JSON Lines: одна строка — одно событие, легко загружается в SIEM;
- у каждой записи есть порядковый номер, время в UTC, тип, критичность, кто и что сделал;
- записи связаны в цепочку хешей SHA-256: hash = SHA256(prev_hash + содержимое записи).
  Если кто-то изменит или удалит строку в середине файла, verify() это покажет.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _default(o):
    """Сериализация pandas/numpy/datetime-значений в JSON."""
    if hasattr(o, "isoformat"):
        return o.isoformat()
    if hasattr(o, "item"):
        return o.item()
    return str(o)


def _digest(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, ensure_ascii=False, sort_keys=True, default=_default)
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, path: str | os.PathLike = "logs/audit.jsonl", actor: str | None = None,
                 system: str = "network-traffic-monitor"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.actor = actor or getpass.getuser()
        self.system = system
        self._seq, self._last_hash = self._tail()

    def _tail(self) -> tuple[int, str]:
        """Продолжаем цепочку, если журнал уже существует."""
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS
        rec = json.loads(last)
        return rec["seq"], rec["hash"]

    def log(self, event_type: str, details=None, severity: str = "INFO", source: str = "",
            outcome: str = "success") -> dict:
        severity = severity.upper()
        if severity not in SEVERITIES:
            severity = "INFO"
        record = {
            "seq": self._seq + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "system": self.system,
            "actor": self.actor,
            "event_type": event_type,
            "severity": severity,
            "source": str(source),
            "outcome": outcome,
            "details": details,
            "prev_hash": self._last_hash,
        }
        record["hash"] = _digest(self._last_hash, record)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=_default) + "\n")
        self._seq, self._last_hash = record["seq"], record["hash"]
        return record

    @staticmethod
    def verify(path: str | os.PathLike) -> tuple[bool, int | None]:
        """Проверяет целостность журнала. Возвращает (True, None) или (False, номер испорченной строки)."""
        prev = GENESIS
        with Path(path).open(encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                stored = rec.pop("hash", None)
                if rec.get("prev_hash") != prev or _digest(prev, rec) != stored or rec.get("seq") != n:
                    return False, n
                prev = stored
        return True, None

    @staticmethod
    def read(path: str | os.PathLike, event_type: str | None = None) -> list[dict]:
        with Path(path).open(encoding="utf-8") as f:
            rows = [json.loads(x) for x in f if x.strip()]
        return [r for r in rows if event_type is None or r["event_type"] == event_type]
