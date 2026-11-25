"""
Обнаружение DDoS-атак по анализу пакетов в секунду (packets per second, PPS).

Идея: для каждого адреса назначения считаем число пакетов в каждую секунду.
Порог берётся как максимум из двух значений:
  - абсолютный порог (по умолчанию 100 пак/с на один узел);
  - статистический: среднее + k * стандартное отклонение «обычного» PPS.
Секунды с превышением порога, идущие подряд (с разрывом не больше max_gap_s),
объединяются в один инцидент. Если 80 % пакетов пришли от многих источников
(не меньше distributed_min_sources), это DDoS, от одного–нескольких — DoS.

Базовая линия считается по всему анализируемому периоду, поэтому период должен быть
заметно длиннее атаки (сутки трафика против минут атаки), как в реальном мониторинге.
"""

from __future__ import annotations

import pandas as pd


class DDoSDetector:
    def __init__(self, pps_threshold: float = 100, sigma: float = 6.0, min_duration_s: int = 3,
                 max_gap_s: int = 2, distributed_min_sources: int = 20):
        self.pps_threshold = pps_threshold
        self.sigma = sigma
        self.min_duration_s = min_duration_s
        self.max_gap_s = max_gap_s
        self.distributed_min_sources = distributed_min_sources

    @staticmethod
    def packets_per_second(df: pd.DataFrame) -> pd.Series:
        """Общее число пакетов в каждую секунду (для графика и базовой линии)."""
        s = df.set_index("timestamp").sort_index()["destination_ip"].resample("1s").count()
        return s

    def threshold(self, per_target_pps: pd.Series) -> float:
        """Порог: не ниже абсолютного и не ниже медиана + k·σ.

        σ оценивается через медианное абсолютное отклонение (MAD · 1,4826), а не через
        обычное стандартное отклонение: сама атака раздувает среднее и σ и могла бы
        «спрятаться» под собственным порогом.
        """
        base = per_target_pps[per_target_pps > 0]
        if base.empty:
            return float(self.pps_threshold)
        med = base.median()
        robust_sigma = 1.4826 * (base - med).abs().median()
        stat = med + self.sigma * robust_sigma
        return float(max(self.pps_threshold, stat))

    def detect(self, df: pd.DataFrame) -> list[dict]:
        if df is None or df.empty:
            return []
        d = df[["timestamp", "destination_ip", "source_ip", "size_bytes"]].copy()
        d["second"] = d["timestamp"].dt.floor("1s")
        per = d.groupby(["destination_ip", "second"]).size().rename("pps").reset_index()
        thr = self.threshold(per["pps"])
        hot = per[per["pps"] > thr].sort_values(["destination_ip", "second"])

        incidents = []
        for target, grp in hot.groupby("destination_ip"):
            # разбиваем на эпизоды: новая серия, если разрыв больше max_gap_s
            gaps = grp["second"].diff().dt.total_seconds().fillna(0) > self.max_gap_s
            for _, ep in grp.groupby(gaps.cumsum()):
                start, end = ep["second"].min(), ep["second"].max()
                duration = int((end - start).total_seconds()) + 1
                if duration < self.min_duration_s:
                    continue
                window = d[(d["destination_ip"] == target) & (d["second"] >= start) & (d["second"] <= end)]
                sources = window["source_ip"].nunique()
                # «основные» источники — те, что дали 80 % пакетов; фоновые легитимные запросы не в счёт
                share = window["source_ip"].value_counts(normalize=True).cumsum()
                core_sources = int((share < 0.8).sum()) + 1
                distributed = core_sources >= self.distributed_min_sources
                incidents.append({
                    "target": target,
                    "start": start,
                    "end": end,
                    "duration_s": duration,
                    "peak_pps": int(ep["pps"].max()),
                    "avg_pps": round(float(ep["pps"].mean()), 1),
                    "threshold_pps": thr,
                    "total_packets": int(len(window)),
                    "total_mb": round(window["size_bytes"].sum() / 1024 ** 2, 2),
                    "unique_sources": int(sources),
                    "core_sources": core_sources,
                    "attack_type": "DDoS" if distributed else "DoS",
                    "severity": "CRITICAL" if distributed else "HIGH",
                    "top_sources": window["source_ip"].value_counts().head(5).index.tolist(),
                })
        return sorted(incidents, key=lambda x: x["start"])
