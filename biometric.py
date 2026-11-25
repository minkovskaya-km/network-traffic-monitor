"""
Интеграция с системой биометрической аутентификации.

Зачем она системе мониторинга: критичные действия администратора — снять блокировку
с IP-адреса, изменить политики, очистить журнал — подтверждаются биометрией
(второй фактор поверх пароля). Каждая попытка пишется в журнал аудита.

Устройство модуля:
- BiometricProvider — интерфейс поставщика (сканер, внешний сервис, Единая биометрическая система);
- LocalTemplateProvider — учебная реализация: шаблон — вектор признаков (например,
  эмбеддинг лица), сравнение по косинусной близости с порогом;
- RestBiometricProvider — адаптер к внешнему сервису по REST (POST /verify);
- BiometricAuthenticator — бизнес-логика: проверка «живости» (liveness), блокировка
  после N неудачных попыток, запись в аудит; декоратор require_biometric.

Биометрические персональные данные по ст. 11 152-ФЗ обрабатываются только с письменного
согласия, поэтому в журнале хранится только результат проверки и оценка сходства,
сами шаблоны в журнал не попадают.
"""

from __future__ import annotations

import functools
import math
from typing import Callable

import requests


class BiometricProvider:
    name = "base"

    def enroll(self, user_id: str, sample: list[float]) -> None:  # pragma: no cover
        raise NotImplementedError

    def match(self, user_id: str, sample: list[float]) -> float:  # pragma: no cover
        """Возвращает оценку сходства 0..1."""
        raise NotImplementedError


class LocalTemplateProvider(BiometricProvider):
    name = "local"

    def __init__(self):
        self._templates: dict[str, list[float]] = {}

    def enroll(self, user_id: str, sample: list[float]) -> None:
        self._templates[user_id] = list(sample)

    def match(self, user_id: str, sample: list[float]) -> float:
        tpl = self._templates.get(user_id)
        if tpl is None or len(tpl) != len(sample):
            return 0.0
        dot = sum(a * b for a, b in zip(tpl, sample))
        norm = math.sqrt(sum(a * a for a in tpl)) * math.sqrt(sum(b * b for b in sample))
        return max(0.0, dot / norm) if norm else 0.0


class RestBiometricProvider(BiometricProvider):
    """Адаптер к внешнему сервису биометрии. Ожидаемый ответ: {"score": 0.93}."""
    name = "rest"

    def __init__(self, base_url: str, api_key: str, session: requests.Session | None = None, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key}"})
        self.timeout = timeout

    def enroll(self, user_id: str, sample: list[float]) -> None:
        self.session.post(f"{self.base_url}/enroll", json={"user_id": user_id, "sample": sample},
                          timeout=self.timeout).raise_for_status()

    def match(self, user_id: str, sample: list[float]) -> float:
        try:
            r = self.session.post(f"{self.base_url}/verify", json={"user_id": user_id, "sample": sample},
                                  timeout=self.timeout)
            r.raise_for_status()
            return float(r.json().get("score", 0.0))
        except (requests.RequestException, ValueError):
            return 0.0


class BiometricAuthenticator:
    def __init__(self, provider: BiometricProvider, threshold: float = 0.90, max_attempts: int = 3, audit=None):
        self.provider = provider
        self.threshold = threshold
        self.max_attempts = max_attempts
        self.audit = audit
        self._fails: dict[str, int] = {}

    def enroll(self, user_id: str, sample: list[float]) -> None:
        self.provider.enroll(user_id, sample)
        self._log("BIOMETRIC_ENROLL", user_id, "INFO", {"provider": self.provider.name})

    def is_locked(self, user_id: str) -> bool:
        return self._fails.get(user_id, 0) >= self.max_attempts

    def verify(self, user_id: str, sample: list[float], liveness: bool = True) -> bool:
        if self.is_locked(user_id):
            self._log("AUTH_FAILURE", user_id, "HIGH", {"reason": "учётная запись заблокирована"}, "failure")
            return False
        if not liveness:
            # предъявлены фото/видео/маска — атака подменой (presentation attack)
            self._fails[user_id] = self._fails.get(user_id, 0) + 1
            self._log("AUTH_FAILURE", user_id, "HIGH", {"reason": "не пройдена проверка живости"}, "failure")
            return False
        score = self.provider.match(user_id, sample)
        ok = score >= self.threshold
        if ok:
            self._fails[user_id] = 0
            self._log("AUTH_SUCCESS", user_id, "INFO", {"score": round(score, 3)})
        else:
            self._fails[user_id] = self._fails.get(user_id, 0) + 1
            self._log("AUTH_FAILURE", user_id, "MEDIUM",
                      {"score": round(score, 3), "attempt": self._fails[user_id]}, "failure")
        return ok

    def _log(self, event, user, severity, details, outcome="success"):
        if self.audit is not None:
            self.audit.log(event, details=details, severity=severity, source=user, outcome=outcome)


class BiometricRequired(PermissionError):
    pass


def require_biometric(auth: BiometricAuthenticator) -> Callable:
    """Декоратор: функция выполняется только после успешной биометрической проверки.

    Вызывающий передаёт user_id и sample именованными аргументами:
        unblock_ip("1.2.3.4", user_id="admin", sample=[...])
    """
    def deco(func):
        @functools.wraps(func)
        def wrapper(*args, user_id: str, sample: list[float], liveness: bool = True, **kwargs):
            if not auth.verify(user_id, sample, liveness):
                raise BiometricRequired(f"Действие «{func.__name__}» не подтверждено биометрией")
            return func(*args, **kwargs)
        return wrapper
    return deco
