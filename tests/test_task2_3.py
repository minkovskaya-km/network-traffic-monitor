"""Тесты заданий 2 (ROI) и 3 (интеграции)."""
from unittest.mock import MagicMock

import pytest
import requests

from integrations.biometric import (BiometricAuthenticator, BiometricRequired, LocalTemplateProvider,
                                    RestBiometricProvider, require_biometric)
from integrations.cloud import AWSExporter, AzureExporter
from integrations.threat_intel import LocalFeed, MISPClient, OTXClient, ThreatIntelAggregator
from monitor import AuditLogger
from monitor.roi import ROIInputs, calculate


# ---------------------------------------------------------------- ROI
def test_roi_formulas():
    r = calculate(ROIInputs())
    assert r["sle_before"] == pytest.approx(4_440_000 * 0.05)
    assert r["ale_breach_before"] == pytest.approx(222_000 * 0.30)
    assert r["downtime_cost_per_hour"] == pytest.approx(8_851 * 60 * 0.05)
    expected = (r["annual_benefit"] * 3 - (60_000 + 35_000 * 3)) / (60_000 + 35_000 * 3)
    assert r["roi"] == pytest.approx(expected)
    assert r["roi"] > 0 and r["payback_months"] < 12


def test_roi_negative_when_no_effect():
    r = calculate(ROIInputs(breach_aro_after=0.30, breach_cost_reduction=0, downtime_hours_after=10))
    assert r["annual_benefit"] == 0 and r["roi"] == pytest.approx(-1)


# ---------------------------------------------------------------- базы угроз
def test_local_feed(tmp_path):
    p = tmp_path / "feed.json"
    p.write_text('{"indicators": [{"value": "203.0.113.66", "type": "ip-dst"}]}', encoding="utf-8")
    agg = ThreatIntelAggregator([LocalFeed(p)])
    assert agg.check_ip("203.0.113.66")["malicious"]
    assert not agg.check_ip("8.8.8.8")["malicious"]


def test_misp_request_and_parse():
    s = MagicMock()
    s.headers = {}
    s.post.return_value.json.return_value = {"response": {"Attribute": [{"event_id": "42", "category": "Network activity"}]}}
    res = MISPClient("https://misp.local/", "KEY", session=s).lookup("203.0.113.66")
    assert res["malicious"] and res["info"][0]["event_id"] == "42"
    assert s.post.call_args.args[0] == "https://misp.local/attributes/restSearch"
    assert s.headers["Authorization"] == "KEY"


def test_otx_request_and_parse():
    s = MagicMock()
    s.headers = {}
    s.get.return_value.json.return_value = {"pulse_info": {"count": 2, "pulses": [{"name": "Botnet C2"}]}}
    res = OTXClient("KEY", session=s).lookup("203.0.113.66")
    assert res["malicious"] and res["info"] == ["Botnet C2"]
    assert s.get.call_args.args[0].endswith("/indicators/IPv4/203.0.113.66/general")
    assert s.headers["X-OTX-API-KEY"] == "KEY"


def test_source_unavailable_returns_none():
    s = MagicMock()
    s.headers = {}
    s.get.side_effect = requests.ConnectionError("нет сети")
    assert OTXClient("KEY", session=s).lookup("1.2.3.4") is None


def test_aggregator_caches():
    src = MagicMock()
    src.name = "x"
    src.lookup.return_value = {"malicious": True, "info": None}
    agg = ThreatIntelAggregator([src])
    agg.check_ip("1.2.3.4")
    agg.check_ip("1.2.3.4")
    assert src.lookup.call_count == 1


# ---------------------------------------------------------------- облака
def test_aws_uses_clients():
    cw, logs, s3 = MagicMock(), MagicMock(), MagicMock()
    e = AWSExporter(bucket="reports", cloudwatch=cw, logs=logs, s3=s3)
    e.export_metrics({"DDoSIncidents": 1})
    e.export_events([{"type": "DDOS_ATTACK"}])
    e.upload_file("r.png", "reports/r.png")
    md = cw.put_metric_data.call_args.kwargs["MetricData"][0]
    assert md["MetricName"] == "DDoSIncidents" and md["Value"] == 1.0
    assert logs.put_log_events.call_args.kwargs["logGroupName"] == "/security/network-monitor"
    s3.upload_file.assert_called_once_with("r.png", "reports", "reports/r.png")


def test_azure_uses_ingestion_client():
    client = MagicMock()
    e = AzureExporter(rule_id="dcr-123", logs_client=client)
    e.export_events([{"type": "PORT_SCAN"}])
    kw = client.upload.call_args.kwargs
    assert kw["rule_id"] == "dcr-123" and kw["stream_name"] == "Custom-NetworkMonitor_CL"
    assert '"PORT_SCAN"' in kw["logs"][0]["Payload"]


def test_azure_dry_run_without_config():
    e = AzureExporter()
    e.export_metrics({"A": 1})
    assert e.dry_run and e.outbox[0][0] == "logs"


# ---------------------------------------------------------------- биометрия
TPL = [0.12, 0.85, 0.33, 0.41, 0.07, 0.66]


def make_auth(tmp_path):
    a = BiometricAuthenticator(LocalTemplateProvider(), threshold=0.9, max_attempts=3,
                               audit=AuditLogger(tmp_path / "a.jsonl"))
    a.enroll("admin", TPL)
    return a


def test_biometric_match_and_mismatch(tmp_path):
    a = make_auth(tmp_path)
    assert a.verify("admin", [0.13, 0.84, 0.31, 0.42, 0.08, 0.65])
    assert not a.verify("admin", [0.9, 0.1, 0.0, 0.2, 0.7, 0.1])


def test_biometric_liveness_and_lockout(tmp_path):
    a = make_auth(tmp_path)
    assert not a.verify("admin", TPL, liveness=False)
    a.verify("admin", [1, 0, 0, 0, 0, 0])
    a.verify("admin", [1, 0, 0, 0, 0, 0])
    assert a.is_locked("admin")
    assert not a.verify("admin", TPL)                 # заблокирован даже с верным шаблоном
    events = [r["event_type"] for r in AuditLogger.read(tmp_path / "a.jsonl")]
    assert events.count("AUTH_FAILURE") == 4


def test_require_biometric_decorator(tmp_path):
    a = make_auth(tmp_path)

    @require_biometric(a)
    def unblock(ip):
        return f"ok {ip}"

    assert unblock("1.2.3.4", user_id="admin", sample=TPL) == "ok 1.2.3.4"
    with pytest.raises(BiometricRequired):
        unblock("1.2.3.4", user_id="admin", sample=[0, 0, 1, 0, 0, 0])


def test_rest_provider():
    s = MagicMock()
    s.headers = {}
    s.post.return_value.json.return_value = {"score": 0.95}
    p = RestBiometricProvider("https://bio.local", "KEY", session=s)
    assert p.match("admin", TPL) == 0.95
    assert s.headers["Authorization"] == "Bearer KEY"
