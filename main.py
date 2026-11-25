"""
Демонстрация системы мониторинга сетевого трафика «ТехноПрофи».

Запуск:  python main.py
Без токенов и облачных ключей всё работает в режиме dry-run: оповещения печатаются
в консоль, данные для облака складываются в память, базы угроз берутся из локального файла.
"""

from pathlib import Path

from integrations.biometric import (BiometricAuthenticator, BiometricRequired, LocalTemplateProvider,
                                    require_biometric)
from integrations.cloud import AWSExporter, AzureExporter, summary_metrics
from integrations.threat_intel import ThreatIntelAggregator
from monitor import AlertManager, AuditLogger, NetworkTrafficAnalyzer
from monitor import roi

OUT = Path("output")


def load_env(path: str = ".env") -> None:
    """Простейшая загрузка .env без сторонних библиотек."""
    import os
    if Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def main() -> None:
    load_env()
    OUT.mkdir(exist_ok=True)
    print("=" * 70 + "\nСИСТЕМА МОНИТОРИНГА СЕТЕВОГО ТРАФИКА ПРЕДПРИЯТИЯ «ТехноПрофи»\n" + "=" * 70)

    # ---------- Задание 1: аудит + оповещения + DDoS
    audit = AuditLogger(OUT / "audit.jsonl", actor="soc-analyst")
    alerts = AlertManager.from_env(min_severity="HIGH", audit=audit)
    analyzer = NetworkTrafficAnalyzer("ТехноПрофи", audit=audit, alerts=alerts)

    analyzer.simulate_traffic_data(hours=24, users=50, inject_ddos=True,
                                   threat_ips=["203.0.113.66", "198.51.100.23"])
    analyzer.analyze_traffic_patterns()
    analyzer.detect_policy_violations()
    analyzer.detect_ddos()

    # ---------- Задание 3: базы угроз (MISP / OTX / локальный фид)
    print("\n" + "=" * 60 + "\nСВЕРКА С БАЗАМИ УГРОЗ (MISP, OTX)\n" + "=" * 60)
    intel = ThreatIntelAggregator.from_env()
    print("Подключённые источники:", ", ".join(s.name for s in intel.sources) or "нет")
    analyzer.check_threat_intel(intel)

    analyzer.generate_security_report()
    chart = analyzer.visualize_traffic(str(OUT / "network_traffic_analysis.png"))

    ok, bad_line = AuditLogger.verify(OUT / "audit.jsonl")
    print(f"\nЖурнал аудита: {OUT / 'audit.jsonl'}, записей: {len(AuditLogger.read(OUT / 'audit.jsonl'))}, "
          f"целостность: {'подтверждена' if ok else f'НАРУШЕНА в строке {bad_line}'}")

    # ---------- Задание 3: облака
    print("\n" + "=" * 60 + "\nЭКСПОРТ В ОБЛАКО (AWS, Azure)\n" + "=" * 60)
    metrics = summary_metrics(analyzer)
    events = [dict(v) for v in analyzer.policy_violations if v["severity"] in ("HIGH", "CRITICAL")]
    for exp in (AWSExporter(bucket=None), AzureExporter()):
        exp.export_metrics(metrics)
        exp.export_events(events)
        exp.upload_file(chart, "reports/network_traffic_analysis.png")
        mode = "dry-run (нет SDK или ключей)" if exp.dry_run else "отправлено"
        print(f"{exp.name}: метрик {len(metrics)}, событий {len(events)} — {mode}")
        audit.log("CLOUD_EXPORT", {"provider": exp.name, "metrics": len(metrics), "events": len(events),
                                   "dry_run": exp.dry_run})

    # ---------- Задание 3: биометрия для критичных действий
    print("\n" + "=" * 60 + "\nБИОМЕТРИЧЕСКОЕ ПОДТВЕРЖДЕНИЕ КРИТИЧНЫХ ДЕЙСТВИЙ\n" + "=" * 60)
    bio = BiometricAuthenticator(LocalTemplateProvider(), threshold=0.9, audit=audit)
    admin_template = [0.12, 0.85, 0.33, 0.41, 0.07, 0.66]
    bio.enroll("admin", admin_template)

    @require_biometric(bio)
    def unblock_ip(ip: str) -> str:
        audit.log("CONFIG_CHANGE", {"action": "unblock_ip", "ip": ip}, "HIGH", "admin")
        return f"Адрес {ip} разблокирован"

    print(unblock_ip("192.168.1.17", user_id="admin", sample=[0.13, 0.84, 0.31, 0.42, 0.08, 0.65]))
    try:
        unblock_ip("192.168.1.17", user_id="admin", sample=[0.9, 0.1, 0.0, 0.2, 0.7, 0.1])
    except BiometricRequired as e:
        print("Отказ:", e)

    # ---------- Задание 2: бизнес-кейс
    print()
    r = roi.calculate()
    roi.print_report(r)
    roi.plot(r, str(OUT / "roi.png"))

    print("\nФайлы результатов: " + ", ".join(str(p) for p in sorted(OUT.iterdir())))


if __name__ == "__main__":
    main()
