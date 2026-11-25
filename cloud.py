"""
Интеграция с облачными сервисами: AWS и Microsoft Azure.

Что отправляем в облако:
- метрики (число событий, нарушений, пик пакетов в секунду) — для дашбордов и алармов;
- события безопасности (нарушения, DDoS-инциденты) — в облачное хранилище логов / SIEM;
- итоговый отчёт (PNG/JSON) — в объектное хранилище.

AWS:   CloudWatch (put_metric_data), CloudWatch Logs (put_log_events), S3 (upload_file); библиотека boto3.
Azure: Azure Monitor Logs Ingestion API (LogsIngestionClient.upload) и Blob Storage;
       библиотеки azure-monitor-ingestion, azure-identity, azure-storage-blob.

Облачные SDK не обязательны: если библиотека не установлена или не заданы учётные данные,
экспортёр работает в режиме dry-run и складывает данные в self.outbox. Клиенты можно
передать в конструктор — так модуль тестируется без доступа к облаку.

Важно для российских компаний: персональные данные граждан РФ по ч. 5 ст. 18 152-ФЗ
должны первично записываться в базы на территории России. Поэтому в облако уходят
только агрегированные метрики и технические события без ПДн (IP-адреса узлов
корпоративной сети, типы нарушений).
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone


def _jsonable(o):
    return o.isoformat() if hasattr(o, "isoformat") else (o.item() if hasattr(o, "item") else str(o))


class CloudExporter:
    name = "base"

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.outbox: list[tuple[str, object]] = []

    def export_metrics(self, metrics: dict[str, float]) -> None:  # pragma: no cover
        raise NotImplementedError

    def export_events(self, events: list[dict]) -> None:  # pragma: no cover
        raise NotImplementedError

    def upload_file(self, path: str, key: str) -> None:  # pragma: no cover
        raise NotImplementedError


class AWSExporter(CloudExporter):
    name = "aws"

    def __init__(self, namespace: str = "TechnoProfi/NetworkMonitor", log_group: str = "/security/network-monitor",
                 log_stream: str = "events", bucket: str | None = None, region: str | None = None,
                 cloudwatch=None, logs=None, s3=None):
        super().__init__()
        self.namespace, self.log_group, self.log_stream, self.bucket = namespace, log_group, log_stream, bucket
        if cloudwatch is None and logs is None and s3 is None:
            try:
                import boto3  # type: ignore
                cloudwatch = boto3.client("cloudwatch", region_name=region)
                logs = boto3.client("logs", region_name=region)
                s3 = boto3.client("s3", region_name=region)
            except Exception:           # нет boto3 или учётных данных
                self.dry_run = True
        self.cloudwatch, self.logs, self.s3 = cloudwatch, logs, s3

    def export_metrics(self, metrics: dict[str, float]) -> None:
        data = [{"MetricName": k, "Value": float(v), "Unit": "Count", "Timestamp": datetime.now(timezone.utc)}
                for k, v in metrics.items()]
        if self.dry_run:
            self.outbox.append(("metrics", data))
            return
        self.cloudwatch.put_metric_data(Namespace=self.namespace, MetricData=data)

    def export_events(self, events: list[dict]) -> None:
        ts = int(time.time() * 1000)
        log_events = [{"timestamp": ts, "message": json.dumps(e, ensure_ascii=False, default=_jsonable)}
                      for e in events]
        if self.dry_run:
            self.outbox.append(("events", log_events))
            return
        self.logs.put_log_events(logGroupName=self.log_group, logStreamName=self.log_stream, logEvents=log_events)

    def upload_file(self, path: str, key: str) -> None:
        if self.dry_run or not self.bucket:
            self.outbox.append(("file", {"path": path, "key": key}))
            return
        self.s3.upload_file(path, self.bucket, key)


class AzureExporter(CloudExporter):
    name = "azure"

    def __init__(self, endpoint: str | None = None, rule_id: str | None = None,
                 stream_name: str = "Custom-NetworkMonitor_CL", container: str | None = None,
                 blob_conn_str: str | None = None, logs_client=None, blob_client=None):
        super().__init__()
        self.rule_id, self.stream_name, self.container = rule_id, stream_name, container
        if logs_client is None and endpoint and rule_id:
            try:
                from azure.identity import DefaultAzureCredential  # type: ignore
                from azure.monitor.ingestion import LogsIngestionClient  # type: ignore
                logs_client = LogsIngestionClient(endpoint=endpoint, credential=DefaultAzureCredential())
            except Exception:
                logs_client = None
        if blob_client is None and blob_conn_str:
            try:
                from azure.storage.blob import BlobServiceClient  # type: ignore
                blob_client = BlobServiceClient.from_connection_string(blob_conn_str)
            except Exception:
                blob_client = None
        self.logs_client, self.blob_client = logs_client, blob_client
        self.dry_run = logs_client is None

    def _upload(self, rows: list[dict]) -> None:
        if self.dry_run:
            self.outbox.append(("logs", rows))
            return
        self.logs_client.upload(rule_id=self.rule_id, stream_name=self.stream_name, logs=rows)

    def export_metrics(self, metrics: dict[str, float]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._upload([{"TimeGenerated": now, "Kind": "metric", "Name": k, "Value": float(v)}
                      for k, v in metrics.items()])

    def export_events(self, events: list[dict]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._upload([{"TimeGenerated": now, "Kind": "event",
                       "Payload": json.dumps(e, ensure_ascii=False, default=_jsonable)} for e in events])

    def upload_file(self, path: str, key: str) -> None:
        if self.blob_client is None or not self.container:
            self.outbox.append(("file", {"path": path, "key": key}))
            return
        with open(path, "rb") as f:
            self.blob_client.get_blob_client(container=self.container, blob=key).upload_blob(f, overwrite=True)


def summary_metrics(analyzer) -> dict[str, float]:
    """Набор метрик для облака по результатам анализа."""
    df = analyzer.traffic_df
    return {
        "TrafficEvents": len(df),
        "PolicyViolations": len(analyzer.policy_violations),
        "DDoSIncidents": len(analyzer.ddos_incidents),
        "PeakPPS": max([i["peak_pps"] for i in analyzer.ddos_incidents], default=0),
    }
