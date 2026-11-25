"""
Интеграция с базами данных угроз (Threat Intelligence): MISP и AlienVault OTX.

- MISP — платформа обмена индикаторами компрометации. Поиск атрибутов через REST:
  POST {MISP_URL}/attributes/restSearch, заголовок Authorization: <API-ключ>.
- OTX (Open Threat Exchange) — открытая база AlienVault/LevelBlue. Репутация IP:
  GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general,
  заголовок X-OTX-API-KEY. Признак угрозы — число «пульсов» (pulse_info.count) > 0.
- LocalFeed — локальный файл с индикаторами (data/threat_feed_sample.json). Нужен
  для работы без интернета и для тестов; так же можно подгружать выгрузки из ГосСОПКА/НКЦКИ.

ThreatIntelAggregator опрашивает все подключённые источники и кэширует ответы,
чтобы не упираться в лимиты API при проверке тысяч адресов.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import requests


class ThreatSource:
    name = "base"

    def lookup(self, ip: str) -> dict | None:  # pragma: no cover - интерфейс
        """Возвращает {'malicious': bool, 'info': ...} или None, если источник недоступен."""
        raise NotImplementedError


class LocalFeed(ThreatSource):
    name = "local_feed"

    def __init__(self, path: str | os.PathLike):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.indicators = {i["value"]: i for i in data["indicators"]}

    def lookup(self, ip: str) -> dict | None:
        hit = self.indicators.get(ip)
        return {"malicious": hit is not None, "info": hit}


class MISPClient(ThreatSource):
    name = "misp"

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True,
                 session: requests.Session | None = None, timeout: int = 10):
        self.url = url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": api_key, "Accept": "application/json",
                                     "Content-Type": "application/json"})
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def lookup(self, ip: str) -> dict | None:
        try:
            r = self.session.post(f"{self.url}/attributes/restSearch",
                                  json={"returnFormat": "json", "value": ip, "type": ["ip-src", "ip-dst"]},
                                  verify=self.verify_ssl, timeout=self.timeout)
            r.raise_for_status()
        except requests.RequestException:
            return None
        attrs = r.json().get("response", {}).get("Attribute", [])
        return {"malicious": bool(attrs),
                "info": [{"event_id": a.get("event_id"), "category": a.get("category"),
                          "comment": a.get("comment")} for a in attrs[:5]]}


class OTXClient(ThreatSource):
    name = "otx"
    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str, session: requests.Session | None = None, timeout: int = 10):
        self.session = session or requests.Session()
        self.session.headers.update({"X-OTX-API-KEY": api_key})
        self.timeout = timeout

    def lookup(self, ip: str) -> dict | None:
        try:
            r = self.session.get(f"{self.BASE}/indicators/IPv4/{ip}/general", timeout=self.timeout)
            r.raise_for_status()
        except requests.RequestException:
            return None
        pulses = r.json().get("pulse_info", {})
        return {"malicious": pulses.get("count", 0) > 0,
                "info": [p.get("name") for p in pulses.get("pulses", [])[:5]]}


class ThreatIntelAggregator:
    def __init__(self, sources: list[ThreatSource]):
        self.sources = sources
        self._cache: dict[str, dict] = {}

    @classmethod
    def from_env(cls, local_feed: str | None = "data/threat_feed_sample.json") -> "ThreatIntelAggregator":
        sources: list[ThreatSource] = []
        if local_feed and Path(local_feed).exists():
            sources.append(LocalFeed(local_feed))
        if os.getenv("MISP_URL") and os.getenv("MISP_API_KEY"):
            sources.append(MISPClient(os.environ["MISP_URL"], os.environ["MISP_API_KEY"],
                                      verify_ssl=os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"))
        if os.getenv("OTX_API_KEY"):
            sources.append(OTXClient(os.environ["OTX_API_KEY"]))
        return cls(sources)

    def check_ip(self, ip: str) -> dict:
        if ip in self._cache:
            return self._cache[ip]
        found, details = [], {}
        for s in self.sources:
            res = s.lookup(ip)
            if res and res["malicious"]:
                found.append(s.name)
                details[s.name] = res["info"]
        verdict = {"ip": ip, "malicious": bool(found), "sources": found, "details": details}
        self._cache[ip] = verdict
        return verdict
