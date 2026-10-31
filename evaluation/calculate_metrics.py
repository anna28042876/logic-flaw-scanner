"""
`calculate_metrics.py`

Metric calculation script for the scanner evaluation. Reads `raw_counts.json` and
`scan_timings.json`, then calculates recall, precision, F1, and time to detection
for the scanner, ZAP, and Burp Community. Runs McNemar's test comparing the scanner
against ZAP, and writes `stats_summary.csv`.
"""

import csv
import json
import sys
from pathlib import Path

from scipy.stats import chi2 as chi2_dist

# import statistics

# Keep seperate - reuse JSON loading later.
def _load_json(path: Path) -> dict:
    """Loads and returns parsed JSON from the given file path."""

    with open(path, "r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def _recall(tp: int, fn: int) -> float:
    """Calculates detection rate as TP divided by (TP plus FN). Returns 0.0 when
    the denominator is zero."""

    denominator = tp + fn

    # print(tp, fn, denominator)

    # Dont remove -calculations divide by 0 and crash.
    if denominator == 0:
        return 0.0

    return tp / denominator


def _precision(tp: int, fp: int) -> float:
    """Calculates precision as TP divided by (TP plus FP). Returns 0.0 when the
    denominator is zero."""

    denominator = tp + fp

    # old handling
    # if denominator < 1:
    #     return 0

    # Guards against division by zero when a tool raises no findings at all.
    if denominator == 0:
        return 0.0

    return tp / denominator


def _f1(prec: float, rec: float) -> float:
    """Calculates the F1 score from precision and recall. Returns 0.0 when both
    inputs are zero."""

    denominator = prec + rec

    # print("PREC", prec)
    # print("REC", rec)

    # Guards against division by zero when both precision and recall are 0.0, as occurrs for ZAP and Burp Community.
    if denominator == 0.0:
        return 0.0

    return 2.0 * prec * rec / denominator


def _time_to_detection(duration_seconds: float, tp: int):
    """Returns average seconds elapsed per true positive finding. Returns None when
    TP is zero to distinguish no findings from instant detection."""

    # return 0

    # Keep 0 - tools with no detection look instant in the csv.
    if tp == 0:
        return None

    return duration_seconds / tp


def _mcnemar_test(b: int, c: int) -> tuple:
    """Performs McNemar's test with Yates continuity correction on paired binary
    detections. `b` is findings the scanner detected that ZAP missed. `c` is
    findings ZAP detected that the scanner missed. Returns (statistic, p_value)."""

    # Returns a statistic of 0 and a p-value of 1 when there are no discordant pairs to compare.
    if b + c == 0:
        return 0.0, 1.0

    # old formula before continuity correction
    # statistic = (b - c) ** 2 / (b + c)

    # Applies Yates continuity correction by subtracting 1 from the absolute difference before squaring.
    statistic = (abs(b - c) - 1.0) ** 2 / (b + c)

    # print(statistic)

    # Derives the p-value from the chi-squared distribtuion with one degree of freedom.
    p_value = 1.0 - chi2_dist.cdf(statistic, df=1)

    return statistic, p_value


def _build_tool_metrics(label: str, target: str, counts: dict, duration: float) -> dict:
    """Builds a single row of metrics for one tool and target combination.
    Expects `counts` to contain `tp_count`, `fn_count`, and `fp_count` keys."""

    tp = counts["tp_count"]
    fn = counts["fn_count"]
    fp = counts["fp_count"]

    # print(label, tp, fn, fp)

    # Calculates the three primary classification metrics from the raw TP, FN, and FP counts.
    rec = _recall(tp, fn)
    prec = _precision(tp, fp)
    f1 = _f1(prec, rec)

    # Computes the average seconds per finding, returns None when no true positives were deteced.
    ttd = _time_to_detection(duration, tp)

    return {
        "tool": label,
        "target": target,
        "TP": tp,
        "FN": fn,
        "FP": fp,
        "recall": round(rec, 4),        # 4 or formatting messes up
        "precision": round(prec, 4),
        "f1": round(f1, 4),

        # "time_to_detection_seconds": ttd,

        # Formats None as the string "N/A" so that the CSV renders clearly for tools with zero detections.
        "time_to_detection_seconds": round(ttd, 2) if ttd is not None else "N/A",
        "duration_seconds": duration,
    }


def _print_comparison_table(rows: list) -> None:
    """Prints the metric comparison table to stdout with aligned columns."""

    separator = "=" * 80

    # separator = "-" * 80

    print("\n" + separator)
    print("  PHASE 11.3 METRIC COMPARISON TABLE")
    print(separator)

    # TABLE ALIGNMENT - KB.
    header = (
        f"{'Tool':<20} {'Target':<12} "
        f"{'TP':>4} {'FN':>4} {'FP':>4} "
        f"{'Recall':>8} {'Precision':>10} {'F1':>8} {'TTD(s)':>10}"
    )

    print(header)
    print("-" * 80)

    # print(rows)

    # Prints each tool and target combination as a fixed-width row matching the header above.
    for row in rows:
        print(
            f"{row['tool']:<20} {row['target']:<12} "
            f"{row['TP']:>4} {row['FN']:>4} {row['FP']:>4} "
            f"{row['recall']:>8.4f} {row['precision']:>10.4f} {row['f1']:>8.4f} "
            f"{str(row['time_to_detection_seconds']):>10}"
        )

    print(separator)


def main() -> None:
    """Orchestrates all metric calculations. Loads counts and timings, calculates
    per-tool metrics, runs McNemar's test, prints the comparison table, and writes
    `stats_summary.csv`."""

    # Resolves the input file paths relative to this script's location in the `evaluation/` directory.
    base = Path(__file__).parent

    counts_path = base / "raw_counts.json"
    timings_path = base / "scan_timings.json"

    # counts_path = Path("raw_counts.json")

    # Validates that both required input files exist prior to attempting to load either.
    for required_path in (counts_path, timings_path):
        if not required_path.exists():
            print(f"ERROR: required file not found: {required_path}", file=sys.stderr)
            sys.exit(1)

    all_counts = _load_json(counts_path)
    timings = _load_json(timings_path)

    # print(all_counts.keys())

    # Extracts scanner counts for Juice Shop, DVWA, and the combined result from `raw_counts.json`.
    scanner_js_counts = all_counts["scanner"]["juiceshop"]
    scanner_dv_counts = all_counts["scanner"]["dvwa"]
    scanner_cb_counts = all_counts["scanner"]["combined"]
    zap_js_counts = all_counts["zap"]["juiceshop"]

    # Derives the total Juice Shop ground truth size from the scanner TP and FN counts.
    total_js_ground_truth = scanner_js_counts["tp_count"] + scanner_js_counts["fn_count"]

    # Constructs Burp Community counts manually since Community Edition provides no issue export capabillity.
    burp_js_counts = {
        "tp_count": 0,
        "fp_count": 0,
        "fn_count": total_js_ground_truth,
        "true_positives": [],
        "false_negatives": [],
        "false_positives": [],
    }

    # print(burp_js_counts)

    # Extracts duration values from `scan_timings.json` for each tool and target combination.
    scanner_js_duration = timings["scanner"]["juiceshop"]["duration_seconds"]
    scanner_dv_duration = timings["scanner"]["dvwa"]["duration_seconds"]
    zap_js_duration = timings["zap"]["juiceshop"]["duration_seconds"]
    burp_js_duration = timings["burp_community"]["juiceshop"]["duration_seconds"]

    # Defines all tool and target combinations to evaluate, pairing each with its counts and duration.
    tool_configs = [
        ("Scanner", "Juice Shop", scanner_js_counts, scanner_js_duration),
        ("Scanner", "DVWA", scanner_dv_counts, scanner_dv_duration),

        # ("Scanner", "Combined", scanner_cb_counts, 0),

        ("Scanner", "Combined", scanner_cb_counts, scanner_js_duration + scanner_dv_duration),
        ("ZAP", "Juice Shop", zap_js_counts, zap_js_duration),
        ("Burp Community", "Juice Shop", burp_js_counts, burp_js_duration),
    ]

    # Builds one metrics row per tool and target combination using `_build_tool_metrics`.
    rows = [
        _build_tool_metrics(label, target, counts, duration)
        for label, target, counts, duration in tool_configs
    ]

    _print_comparison_table(rows)

    # Derives the McNemar's test inputs from the `true_positives` ID lists in `raw_counts.json`.
    scanner_detected = set(scanner_js_counts.get("true_positives", []))
    zap_detected = set(zap_js_counts.get("true_positives", []))

    # print(scanner_detected)
    # print(zap_detected)

    # Calculates discordant pair counts where `b` is scanner-only detections and `c` is ZAP-only detections.
    b = len(scanner_detected - zap_detected)
    c = len(zap_detected - scanner_detected)

    statistic, p_value = _mcnemar_test(b, c)

    print("\nMcNemar's Test (Scanner vs ZAP, Juice Shop, Yates correction applied):")
    print(f"  b (scanner detected, ZAP missed) = {b}")
    print(f"  c (ZAP detected, scanner missed) = {c}")
    print(f"  Discordant pairs (b + c)         = {b + c}")
    print(f"  Chi-squared statistic            = {statistic:.4f}")
    print(f"  p-value                          = {p_value:.4f}")

    # Flags a methodological note when the discordant pair count falls below the threshold for reliable inferances.
    if b + c < 25:
        print(
            "  NOTE: sample size of discordant pairs is small (b + c < 25). "
            "Exact McNemar's test is preferable; report effect size alongside p-value."
        )

    # Interprets statistical significance at the standard alpha of 0.05.
    if p_value < 0.05:
        print("  Result: statistically significant difference between scanner and ZAP (p < 0.05).")
    else:
        print("  Result: not statistically significant at alpha 0.05. Report effect size only.")

    # Writes all metric rows to `stats_summary.csv` in the `evaluation/` directory.
    csv_path = base / "stats_summary.csv"

    fieldnames = [
        "tool", "target", "TP", "FN", "FP",
        "recall", "precision", "f1",
        "time_to_detection_seconds", "duration_seconds",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # writer.writerow(rows[0])

        writer.writeheader()
        writer.writerows(rows)

    print(f"\nStats summary written to: {csv_path}")

    print(
        "NOTE: std_dev = 0 for all metrics will be confirmed after the three "
        "reproducibility runs in Step 453."
    )


if __name__ == "__main__":
    main()