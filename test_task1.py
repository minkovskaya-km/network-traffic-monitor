"""Тесты задания 1: DDoS по PPS, журнал аудита, оповещения."""
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pandas as pd
import pytest

from monitor import AlertManager, AuditLogger, DDoSDetector, NetworkTrafficAnalyzer
from monitor.alerts import ConsoleNotifier, SlackNotifier, TelegramNotifier


def make_traffic(attack: bool, pps: int = 300, seconds: int = 30, sources: int = 100) -> pd.DataFrame:
    t0 = datetime(2026, 11, 17, 12, 0, 0)
    rows = [{"timestamp": t0 + timedelta(seconds=i), "destination_ip": "192.168.1.10",
             "source_ip": f"192.168.1.{i % 50 + 1}", "size_bytes": 500} for i in range(3600)]
    if attack:
        for s in range(seconds):
            for k in range(pps):
                rows.append({"timestamp": t0 + timedelta(seconds=200 + s, milliseconds=k),
                             "destination_ip": "192.168.1.10", "source_ip": f"10.9.{k % sources}.1",
                             "size_bytes": 100})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- DDoS
def test_no_ddos_on_normal_traffic():
    assert DDoSDetector().detect(make_traffic(attack=False)) == []


def test_ddos_detected_with_timing_and_sources():
    inc = DDoSDetector().detect(make_traffic(attack=True))
    assert len(inc) == 1
    i = inc[0]
    assert i["attack_type"] == "DDoS" and i["severity"] == "CRITICAL"
    assert i["duration_s"] == 30
    assert i["peak_pps"] >= 300
    assert i["unique_sources"] >= 100


def test_single_source_flood_is_dos():
    inc = DDoSDetector().detect(make_traffic(attack=True, sources=1))
    assert inc[0]["attack_type"] == "DoS"


def test_short_spike_is_ignored():
    assert DDoSDetector(min_duration_s=3).detect(make_traffic(attack=True, seconds=2)) == []


def test_threshold_not_inflated_by_attack():
    # длинная атака не должна поднимать порог выше собственной интенсивности
    inc = DDoSDetector().detect(make_traffic(attack=True, seconds=300, pps=150))
    assert inc and inc[0]["threshold_pps"] < 150


def test_analyzer_finds_simulated_ddos(tmp_path):
    a = NetworkTrafficAnalyzer(audit=AuditLogger(tmp_path / "a.jsonl"), verbose=False)
    a.simulate_traffic_data(records=2000, inject_ddos=True)
    assert len(a.detect_ddos()) == 1
    assert any(v["type"] == "DDOS_ATTACK" for v in a.policy_violations)


# ---------------------------------------------------------------- аудит
def test_audit_chain_valid_and_tamper_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLogger(p, actor="tester")
    log.log("SYSTEM_START")
    log.log("POLICY_VIOLATION", {"port": 445, "ts": datetime(2026, 1, 1)}, "HIGH", "192.168.1.5")
    log.log("ALERT_SENT", {"channel": "telegram"}, "HIGH")
    assert AuditLogger.verify(p) == (True, None)

    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["details"]["port"] = 80                      # подделываем запись
    lines[1] = json.dumps(rec, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert AuditLogger.verify(p) == (False, 2)


def test_audit_deleted_line_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLogger(p)
    for i in range(4):
        log.log("EVENT", {"i": i})
    lines = p.read_text(encoding="utf-8").splitlines()
    del lines[1]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert AuditLogger.verify(p)[0] is False


def test_audit_continues_chain_after_restart(tmp_path):
    p = tmp_path / "audit.jsonl"
    AuditLogger(p).log("A")
    AuditLogger(p).log("B")
    assert AuditLogger.verify(p) == (True, None)
    assert [r["seq"] for r in AuditLogger.read(p)] == [1, 2]


def test_audit_record_has_required_fields(tmp_path):
    rec = AuditLogger(tmp_path / "a.jsonl", actor="admin").log("CONFIG_CHANGE", {"x": 1}, "high", "fw")
    for f in ("seq", "timestamp", "actor", "event_type", "severity", "source", "outcome", "hash", "prev_hash"):
        assert f in rec
    assert rec["severity"] == "HIGH" and rec["actor"] == "admin"


# ---------------------------------------------------------------- оповещения
ALERT = {"type": "DDOS_ATTACK", "source": "192.168.1.10", "severity": "CRITICAL",
         "timestamp": datetime(2026, 11, 17, 12, 0), "details": "пик 459 пак/с"}


def fake_session(status=200, payload=None):
    s = MagicMock()
    s.post.return_value.status_code = status
    s.post.return_value.json.return_value = payload or {"ok": True}
    return s


def test_telegram_sends_correct_request():
    s = fake_session()
    assert TelegramNotifier("TOKEN", "-100123", session=s).send("тест")
    url = s.post.call_args.args[0]
    assert url == "https://api.telegram.org/botTOKEN/sendMessage"
    assert s.post.call_args.kwargs["json"]["chat_id"] == "-100123"


def test_slack_sends_webhook():
    s = fake_session()
    assert SlackNotifier("https://hooks.slack.com/services/X", session=s).send("тест")
    assert s.post.call_args.kwargs["json"] == {"text": "тест"}


def test_alert_filter_and_dedup(tmp_path):
    c = ConsoleNotifier()
    m = AlertManager([c], min_severity="HIGH", audit=AuditLogger(tmp_path / "a.jsonl"))
    assert m.notify(ALERT) is True
    assert m.notify(ALERT) is False                         # повтор подавлен
    assert m.notify({**ALERT, "severity": "MEDIUM", "type": "X"}) is False   # ниже порога
    assert len(c.sent) == 1
    assert "DDOS_ATTACK" in c.sent[0]


def test_from_env_without_tokens_uses_console(monkeypatch):
    for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SLACK_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)
    assert isinstance(AlertManager.from_env().notifiers[0], ConsoleNotifier)


def test_from_env_with_tokens(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "1")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
    names = [n.name for n in AlertManager.from_env().notifiers]
    assert names == ["telegram", "slack"]


@pytest.mark.parametrize("sev,expected", [("CRITICAL", True), ("HIGH", True), ("LOW", False)])
def test_severity_threshold(sev, expected):
    m = AlertManager([ConsoleNotifier()], min_severity="HIGH")
    assert m.notify({**ALERT, "severity": sev}) is expected
