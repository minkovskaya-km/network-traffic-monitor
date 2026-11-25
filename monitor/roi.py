"""
Задание 2. Расчёт ROI от внедрения системы мониторинга сетевого трафика.

Метод: сравниваем ожидаемые годовые потери (ALE = SLE × ARO) до и после
внедрения системы и вычитаем затраты на систему.

  ROI = (выгоды за период − затраты за период) / затраты за период × 100 %

Источники исходных данных (подробнее — docs/roi.md):
  [1] IBM, Ponemon Institute. Cost of a Data Breach Report 2025: средняя стоимость
      утечки в мире — 4,44 млн долл.; среднее время выявления и сдерживания — 241 день.
  [2] Ponemon Institute, Emerson Network Power. Cost of Data Center Outages, 2016:
      средняя стоимость минуты незапланированного простоя — 8 851 долл.,
      средняя стоимость одного инцидента — 740 357 долл.

Все значения в долларах США, как в исследованиях Ponemon. Перевод в рубли — параметр usd_rub.
Коэффициент масштаба переводит средние значения по крупным компаниям из выборки Ponemon
к предприятию «ТехноПрофи» (200 сотрудников). Это допущение, его можно менять.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class ROIInputs:
    # --- исходные данные Ponemon
    breach_cost_ponemon: float = 4_440_000      # [1] средняя стоимость утечки, долл.
    downtime_cost_per_min_ponemon: float = 8_851  # [2] стоимость минуты простоя, долл.
    scale: float = 0.05                         # масштаб: среднее предприятие (200 чел.)

    # --- утечки данных
    breach_aro_before: float = 0.30             # частота утечек в год до внедрения (у компании они уже были)
    breach_aro_after: float = 0.15              # мониторинг выявляет вывод данных до того, как он завершится
    breach_cost_reduction: float = 0.25         # ущерб ниже за счёт раннего обнаружения (меньше 241 дня)

    # --- простои (доступность)
    downtime_hours_before: float = 10.0         # часов простоя в год из-за сетевых инцидентов (DDoS, вирусы)
    downtime_hours_after: float = 4.0           # раннее обнаружение и оповещение сокращают простой

    # --- затраты на систему
    capex: float = 60_000                       # разработка, сервер, интеграция, обучение (разово)
    opex_per_year: float = 35_000               # 0,5 ставки аналитика, облако, поддержка
    years: int = 3
    discount_rate: float = 0.15                 # ставка дисконтирования для NPV
    usd_rub: float | None = None                # курс для перевода в рубли (если нужен)


def calculate(p: ROIInputs = ROIInputs()) -> dict:
    sle_before = p.breach_cost_ponemon * p.scale
    sle_after = sle_before * (1 - p.breach_cost_reduction)
    ale_breach_before = sle_before * p.breach_aro_before
    ale_breach_after = sle_after * p.breach_aro_after

    cost_per_hour = p.downtime_cost_per_min_ponemon * 60 * p.scale
    downtime_before = cost_per_hour * p.downtime_hours_before
    downtime_after = cost_per_hour * p.downtime_hours_after

    breach_saving = ale_breach_before - ale_breach_after
    downtime_saving = downtime_before - downtime_after
    annual_benefit = breach_saving + downtime_saving

    total_cost = p.capex + p.opex_per_year * p.years
    total_benefit = annual_benefit * p.years
    roi = (total_benefit - total_cost) / total_cost

    cash_flows = [-p.capex] + [annual_benefit - p.opex_per_year] * p.years
    npv = sum(cf / (1 + p.discount_rate) ** t for t, cf in enumerate(cash_flows))
    monthly_net = (annual_benefit - p.opex_per_year) / 12
    payback_months = p.capex / monthly_net if monthly_net > 0 else float("inf")

    by_year, cum = [], -p.capex
    for y in range(1, p.years + 1):
        cum += annual_benefit - p.opex_per_year
        by_year.append({"year": y, "benefit": annual_benefit, "cost": p.opex_per_year + (p.capex if y == 1 else 0),
                        "cumulative_net": cum})

    return {
        "inputs": asdict(p),
        "sle_before": sle_before, "sle_after": sle_after,
        "ale_breach_before": ale_breach_before, "ale_breach_after": ale_breach_after,
        "downtime_cost_per_hour": cost_per_hour,
        "downtime_loss_before": downtime_before, "downtime_loss_after": downtime_after,
        "breach_saving": breach_saving, "downtime_saving": downtime_saving,
        "annual_benefit": annual_benefit,
        "total_benefit": total_benefit, "total_cost": total_cost,
        "roi": roi, "npv": npv, "payback_months": payback_months,
        "by_year": by_year,
    }


def _m(x: float, rate: float | None) -> str:
    s = f"{x:,.0f} $".replace(",", " ")
    if rate:
        s += f" ({x * rate / 1e6:,.1f} млн ₽)".replace(",", " ").replace(".", ",")
    return s


def print_report(r: dict) -> None:
    p = r["inputs"]
    rate = p["usd_rub"]
    print("=" * 66 + "\nБИЗНЕС-КЕЙС: ROI СИСТЕМЫ МОНИТОРИНГА СЕТЕВОГО ТРАФИКА\n" + "=" * 66)
    print(f"Ущерб от одной утечки (SLE):        {_m(r['sle_before'], rate)} -> {_m(r['sle_after'], rate)}")
    print(f"Ожидаемые потери от утечек (ALE):   {_m(r['ale_breach_before'], rate)} -> {_m(r['ale_breach_after'], rate)}")
    print(f"Стоимость часа простоя:             {_m(r['downtime_cost_per_hour'], rate)}")
    print(f"Потери от простоев в год:           {_m(r['downtime_loss_before'], rate)} -> {_m(r['downtime_loss_after'], rate)}")
    print("-" * 66)
    print(f"Экономия на утечках в год:          {_m(r['breach_saving'], rate)}")
    print(f"Экономия на простоях в год:         {_m(r['downtime_saving'], rate)}")
    print(f"Итого выгода в год:                 {_m(r['annual_benefit'], rate)}")
    print(f"Затраты за {p['years']} года:                 {_m(r['total_cost'], rate)}")
    print(f"Выгода за {p['years']} года:                  {_m(r['total_benefit'], rate)}")
    print("-" * 66)
    print(f"ROI за {p['years']} года:                     {r['roi'] * 100:.0f} %")
    print(f"NPV (ставка {p['discount_rate'] * 100:.0f} %):                {_m(r['npv'], rate)}")
    print(f"Срок окупаемости:                   {r['payback_months']:.1f} мес.")


def sensitivity(base: ROIInputs = ROIInputs(), field: str = "scale", values=(0.02, 0.05, 0.1)) -> list[tuple]:
    """Чувствительность ROI к одному параметру (по умолчанию — к масштабу компании)."""
    out = []
    for v in values:
        r = calculate(ROIInputs(**{**asdict(base), field: v}))
        out.append((v, r["roi"], r["payback_months"]))
    return out


def plot(r: dict, path: str = "roi.png") -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(1, 2, figsize=(13, 5))
    labels = ["Утечки данных", "Простои"]
    before = [r["ale_breach_before"] / 1e3, r["downtime_loss_before"] / 1e3]
    after = [r["ale_breach_after"] / 1e3, r["downtime_loss_after"] / 1e3]
    x = range(len(labels))
    ax[0].bar([i - 0.2 for i in x], before, 0.4, label="До внедрения", color="#C44E52")
    ax[0].bar([i + 0.2 for i in x], after, 0.4, label="После внедрения", color="#55A868")
    ax[0].set_xticks(list(x), labels)
    ax[0].set(title="Ожидаемые годовые потери, тыс. $")
    ax[0].legend()

    years = [0] + [y["year"] for y in r["by_year"]]
    cum = [-r["inputs"]["capex"] / 1e3] + [y["cumulative_net"] / 1e3 for y in r["by_year"]]
    ax[1].plot(years, cum, marker="o", color="#4C72B0")
    ax[1].axhline(0, color="grey", lw=0.8)
    ax[1].set(title=f"Накопленный чистый эффект, тыс. $ (ROI {r['roi'] * 100:.0f} %)", xlabel="Год")
    plt.tight_layout()
    plt.savefig(path, dpi=130)
    plt.close(fig)
    return path


if __name__ == "__main__":
    res = calculate()
    print_report(res)
    print("\nЧувствительность ROI к масштабу компании:")
    for v, roi, pb in sensitivity():
        print(f"  scale = {v:.2f}: ROI {roi * 100:.0f} %, окупаемость {pb:.1f} мес.")
    print("График:", plot(res))
