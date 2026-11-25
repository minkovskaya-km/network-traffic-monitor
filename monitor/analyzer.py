"""
Система мониторинга сетевого трафика предприятия.

Базовый класс взят из лекции 7 (кейс «ТехноПрофи») и доработан:
- исправлены мелкие ошибки исходного кода (устаревший шаг '5T' в pandas и др.);
- добавлена генерация DDoS-всплеска для проверки детектора;
- нарушения пишутся в журнал аудита и передаются в модуль оповещений;
- добавлено обнаружение DDoS по числу пакетов в секунду (модуль ddos.py);
- добавлена сверка адресов с базами угроз (integrations/threat_intel.py).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import numpy as np
import pandas as pd

from .ddos import DDoSDetector

if TYPE_CHECKING:  # импорт только для подсказок типов
    from .alerts import AlertManager
    from .audit import AuditLogger


class NetworkTrafficAnalyzer:
    """Анализ сетевого трафика предприятия."""

    def __init__(self, company_name: str = "ТехноПрофи",
                 audit: "AuditLogger | None" = None,
                 alerts: "AlertManager | None" = None,
                 ddos_detector: DDoSDetector | None = None,
                 verbose: bool = True):
        self.company_name = company_name
        self.audit = audit
        self.alerts = alerts
        self.ddos_detector = ddos_detector or DDoSDetector()
        self.verbose = verbose
        self.traffic_df: pd.DataFrame | None = None
        self.policy_violations: list[dict] = []
        self.ddos_incidents: list[dict] = []

        # Политики безопасности предприятия (из лекции)
        self.security_policies = {
            "max_daily_external_traffic": 10 * 1024 ** 3,       # 10 ГБ
            "blocked_ports": [21, 23, 135, 139, 445],           # опасные порты
            "suspicious_ips": ["192.168.1.100", "10.0.0.15"],
            "work_hours": {"start": 9, "end": 18},
            "allowed_protocols": ["HTTP", "HTTPS", "SSH", "SMTP", "DNS"],
        }
        self.anomaly_patterns = {
            "port_scan": {"threshold": 100, "window_minutes": 5},
            "ddos_attack": {"threshold": 1000, "window_minutes": 1},
            "data_exfiltration": {"threshold": 500 * 1024 ** 2, "window_minutes": 60},
        }
        self._log("SYSTEM_START", f"Запуск анализатора трафика для {company_name}", "INFO")
        self._say(f"Инициализирован анализатор трафика для: {company_name}")

    # ------------------------------------------------------------------ служебное
    def _say(self, text: str) -> None:
        if self.verbose:
            print(text)

    def _log(self, event_type: str, details, severity: str = "INFO", source: str = "analyzer") -> None:
        if self.audit is not None:
            self.audit.log(event_type, details=details, severity=severity, source=source)

    def _register_violation(self, violation: dict) -> None:
        """Сохраняет нарушение, пишет его в журнал аудита и отправляет оповещение."""
        self.policy_violations.append(violation)
        self._log("POLICY_VIOLATION", violation, violation.get("severity", "MEDIUM"), violation.get("source", ""))
        if self.alerts is not None:
            self.alerts.notify(violation)

    # ------------------------------------------------------------------ данные
    def simulate_traffic_data(self, hours: int = 24, users: int = 50, records: int = 10_000,
                              inject_ddos: bool = False, ddos_seconds: int = 90,
                              ddos_pps: int = 400, ddos_sources: int = 250,
                              threat_ips: list[str] | None = None,
                              seed: int = 42) -> pd.DataFrame:
        """Генерирует имитационный трафик. При inject_ddos=True добавляет всплеск атаки на веб-сервер."""
        rng = np.random.default_rng(seed)
        departments_list = ["Финансы", "IT", "Маркетинг", "HR", "Продажи", "Руководство"]
        protocols_list = ["HTTP", "HTTPS", "SSH", "SMTP", "FTP", "DNS", "RDP"]
        port_map = {"HTTP": 80, "HTTPS": 443, "SSH": 22, "SMTP": 25, "FTP": 21, "DNS": 53, "RDP": 3389}
        start_time = datetime.now().replace(microsecond=0) - timedelta(hours=hours)

        offsets = rng.integers(0, hours * 3600, size=records)
        user_ids = rng.integers(1, users + 1, size=records)
        depts = rng.choice(departments_list, size=records, p=[0.1, 0.2, 0.15, 0.1, 0.3, 0.15])
        protos = rng.choice(protocols_list, size=records, p=[0.3, 0.4, 0.05, 0.05, 0.05, 0.1, 0.05])
        external = rng.random(records) > 0.7          # 30 % внешнего трафика
        ext_ips = [".".join(map(str, rng.integers(1, 255, size=4))) for _ in range(records)]
        int_ips = [f"192.168.1.{i}" for i in rng.integers(1, users + 1, size=records)]
        sizes = np.minimum(rng.lognormal(mean=10, sigma=2, size=records).astype(int), 65535)

        df = pd.DataFrame({
            "timestamp": [start_time + timedelta(seconds=int(o)) for o in offsets],
            "source_ip": [f"192.168.1.{u}" for u in user_ids],
            "destination_ip": [e if x else i for x, e, i in zip(external, ext_ips, int_ips)],
            "protocol": protos,
            "port": [port_map[p] for p in protos],
            "size_bytes": sizes,
            "department": depts,
        })

        if inject_ddos:
            df = pd.concat([df, self._make_ddos_burst(start_time, hours, ddos_seconds, ddos_pps, ddos_sources, rng)],
                           ignore_index=True)
        if threat_ips:
            # заражённый компьютер в финансовом отделе обращается к адресам из баз угроз
            n = 5 * len(threat_ips)
            df = pd.concat([df, pd.DataFrame({
                "timestamp": [start_time + timedelta(seconds=int(o)) for o in rng.integers(0, hours * 3600, size=n)],
                "source_ip": "192.168.1.17",
                "destination_ip": list(threat_ips) * 5,
                "protocol": "HTTPS", "port": 443,
                "size_bytes": rng.integers(500, 60000, size=n),
                "department": "Финансы",
            })], ignore_index=True)

        self.traffic_df = df.sort_values("timestamp").reset_index(drop=True)
        self._say(f"Сгенерировано {len(self.traffic_df)} записей трафика"
                  + (" (включая имитацию DDoS-атаки)" if inject_ddos else ""))
        return self.traffic_df

    @staticmethod
    def _make_ddos_burst(start_time, hours, seconds, pps, n_sources, rng) -> pd.DataFrame:
        """Всплеск запросов к веб-серверу 192.168.1.10:443 с множества внешних адресов."""
        attack_start = start_time + timedelta(hours=hours * 0.6)
        n = seconds * pps
        attackers = [".".join(map(str, rng.integers(1, 255, size=4))) for _ in range(n_sources)]
        return pd.DataFrame({
            "timestamp": [attack_start + timedelta(seconds=int(s)) for s in rng.integers(0, seconds, size=n)],
            "source_ip": rng.choice(attackers, size=n),
            "destination_ip": "192.168.1.10",
            "protocol": "HTTPS",
            "port": 443,
            "size_bytes": rng.integers(60, 600, size=n),
            "department": "Внешний",
        })

    def load_traffic(self, df: pd.DataFrame) -> pd.DataFrame:
        """Загрузка реальных данных (например, выгрузки NetFlow/CSV) с теми же колонками."""
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        self.traffic_df = df.sort_values("timestamp").reset_index(drop=True)
        return self.traffic_df

    # ------------------------------------------------------------------ анализ
    def analyze_traffic_patterns(self) -> dict:
        df = self.traffic_df
        self._say("\n" + "=" * 60 + "\nАНАЛИЗ ПАТТЕРНОВ ТРАФИКА\n" + "=" * 60)
        res = {}
        proto = df["protocol"].value_counts()
        for p, c in proto.items():
            self._say(f"  {p}: {c} ({c / len(df) * 100:.1f}%)")
        res["protocol_distribution"] = proto

        dept = df.groupby("department").agg(size_bytes=("size_bytes", "sum"), users=("source_ip", "nunique"))
        dept["size_mb"] = dept["size_bytes"] / 1024 ** 2
        res["department_traffic"] = dept.sort_values("size_bytes", ascending=False)

        df["is_external"] = ~df["destination_ip"].str.startswith("192.168.1.")
        ext = int(df["is_external"].sum())
        self._say(f"Внешний трафик: {ext} событий ({ext / len(df) * 100:.1f}%)")
        total_mb = df["size_bytes"].sum() / 1024 ** 2
        self._say(f"Общий объём трафика: {total_mb:.1f} МБ")
        res["external_events"], res["total_mb"] = ext, total_mb
        self._log("ANALYSIS_RUN", {"records": len(df), "external_events": ext, "total_mb": round(total_mb, 1)})
        return res

    def detect_policy_violations(self) -> list[dict]:
        df = self.traffic_df
        self._say("\n" + "=" * 60 + "\nАНАЛИЗ НАРУШЕНИЙ ПОЛИТИК БЕЗОПАСНОСТИ\n" + "=" * 60)
        self.policy_violations = []

        # 1. Заблокированные порты
        blocked = df[df["port"].isin(self.security_policies["blocked_ports"])]
        if not blocked.empty:
            self._say(f"[!] Использование заблокированных портов: {len(blocked)} случаев")
            for _, row in blocked.head().iterrows():
                self._register_violation({"type": "BLOCKED_PORT", "timestamp": row["timestamp"],
                                          "source": row["source_ip"],
                                          "details": f"Использование порта {row['port']}", "severity": "HIGH"})

        # 2. Активность в нерабочее время
        wh = self.security_policies["work_hours"]
        df["hour"] = df["timestamp"].dt.hour
        after = df[(df["hour"] < wh["start"]) | (df["hour"] >= wh["end"])]
        after = after[after["department"] != "Внешний"]
        if len(after) > 100:
            for dept, cnt in after.groupby("department").size().items():
                if cnt > 50:
                    self._register_violation({"type": "AFTER_HOURS_ACTIVITY", "timestamp": datetime.now(),
                                              "source": f"Отдел {dept}",
                                              "details": f"{cnt} сетевых событий в нерабочее время",
                                              "severity": "MEDIUM"})

        # 3. Сканирование портов (5-минутные окна)
        df["time_window"] = df["timestamp"].dt.floor("5min")
        scans = df.groupby(["source_ip", "time_window"]).agg(ports=("port", "nunique"),
                                                             targets=("destination_ip", "nunique")).reset_index()
        scans = scans[(scans["ports"] > 50) & (scans["targets"] > 10)]
        for _, row in scans.iterrows():
            self._register_violation({"type": "PORT_SCAN", "timestamp": row["time_window"], "source": row["source_ip"],
                                      "details": f"Обращение к {row['ports']} портам за 5 минут", "severity": "HIGH"})
        return self.policy_violations

    def detect_ddos(self) -> list[dict]:
        """Задание 1.1: обнаружение DDoS по анализу пакетов в секунду."""
        self._say("\n" + "=" * 60 + "\nОБНАРУЖЕНИЕ DDoS-АТАК (пакеты в секунду)\n" + "=" * 60)
        self.ddos_incidents = self.ddos_detector.detect(self.traffic_df)
        if not self.ddos_incidents:
            self._say("Признаков DDoS не обнаружено")
        for inc in self.ddos_incidents:
            self._say(f"[!!] {inc['attack_type']} на {inc['target']}: {inc['start']:%H:%M:%S}–{inc['end']:%H:%M:%S}, "
                      f"пик {inc['peak_pps']} пак/с при пороге {inc['threshold_pps']:.0f}, "
                      f"источников: {inc['unique_sources']}")
            self._register_violation({"type": "DDOS_ATTACK", "timestamp": inc["start"], "source": inc["target"],
                                      "details": (f"{inc['attack_type']}: пик {inc['peak_pps']} пак/с, "
                                                  f"длительность {inc['duration_s']} с, "
                                                  f"источников {inc['unique_sources']}"),
                                      "severity": inc["severity"]})
        return self.ddos_incidents

    def check_threat_intel(self, intel) -> list[dict]:
        """Сверка внешних адресов с базами угроз (MISP, OTX или локальный фид)."""
        ext = self.traffic_df.loc[~self.traffic_df["destination_ip"].str.startswith("192.168."), "destination_ip"]
        hits = []
        for ip in ext.unique():
            verdict = intel.check_ip(ip)
            if verdict["malicious"]:
                hits.append(verdict)
                self._register_violation({"type": "THREAT_INTEL_MATCH", "timestamp": datetime.now(), "source": ip,
                                          "details": f"Адрес найден в базе угроз: {', '.join(verdict['sources'])}",
                                          "severity": "HIGH"})
        self._say(f"Проверено внешних адресов: {ext.nunique()}, совпадений с базами угроз: {len(hits)}")
        return hits

    # ------------------------------------------------------------------ отчёт
    def generate_security_report(self) -> list[str]:
        df = self.traffic_df
        self._say("\n" + "=" * 60 + "\nОТЧЕТ ПО БЕЗОПАСНОСТИ СЕТЕВОГО ТРАФИКА\n" + "=" * 60)
        self._say(f"Предприятие: {self.company_name}")
        self._say(f"Период анализа: {df['timestamp'].min()} – {df['timestamp'].max()}; событий: {len(df)}")
        counts = defaultdict(int)
        for v in self.policy_violations:
            counts[v["type"]] += 1
        for t, c in counts.items():
            self._say(f"  - {t}: {c}")

        recs = []
        if (df["protocol"] == "HTTP").sum() > (df["protocol"] == "HTTPS").sum() * 0.5:
            recs.append("Перевести внутренние сервисы с HTTP на HTTPS")
        if counts.get("AFTER_HOURS_ACTIVITY"):
            recs.append("Ограничить доступ к сети в нерабочее время")
        if counts.get("PORT_SCAN"):
            recs.append("Настроить IDS/IPS на блокировку сканирования портов")
        if counts.get("DDOS_ATTACK"):
            recs.append("Подключить защиту от DDoS у провайдера и ограничение частоты запросов на веб-сервере")
        if counts.get("THREAT_INTEL_MATCH"):
            recs.append("Заблокировать на межсетевом экране адреса из баз угроз")
        for i, r in enumerate(recs, 1):
            self._say(f"{i}. {r}")
        self._log("REPORT_GENERATED", {"violations": dict(counts), "recommendations": len(recs)})
        return recs

    def visualize_traffic(self, path: str = "network_traffic_analysis.png") -> str:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        df = self.traffic_df
        fig, ax = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle(f"Анализ сетевого трафика: {self.company_name}", fontsize=15)
        hourly = df.groupby(df["timestamp"].dt.hour).size()
        ax[0, 0].bar(hourly.index, hourly.values, color="#4C72B0")
        ax[0, 0].axvspan(-0.5, 8.5, alpha=0.15, color="red", label="Нерабочее время")
        ax[0, 0].axvspan(17.5, 23.5, alpha=0.15, color="red")
        ax[0, 0].set(title="События по часам", xlabel="Час", ylabel="События")
        ax[0, 0].legend()

        pps = self.ddos_detector.packets_per_second(df)
        ax[0, 1].plot(pps.index, pps.values, lw=0.6, color="#555")
        if self.ddos_incidents:
            ax[0, 1].axhline(self.ddos_incidents[0]["threshold_pps"], color="red", ls="--", label="Порог DDoS")
            ax[0, 1].legend()
        ax[0, 1].set(title="Пакеты в секунду", ylabel="пак/с")
        ax[0, 1].tick_params(axis="x", rotation=30)

        dept = df.groupby("department")["size_bytes"].sum() / 1024 ** 2
        ax[1, 0].bar(dept.index, dept.values, color="#55A868")
        ax[1, 0].set(title="Объём трафика по отделам, МБ")
        ax[1, 0].tick_params(axis="x", rotation=45)

        counts = pd.Series([v["type"] for v in self.policy_violations]).value_counts()
        ax[1, 1].barh(counts.index, counts.values, color="#C44E52")
        ax[1, 1].set(title="Нарушения по типам")
        plt.tight_layout()
        plt.savefig(path, dpi=130, bbox_inches="tight")
        plt.close(fig)
        self._say(f"Графики сохранены в {path}")
        return path
