#!/usr/bin/env python3
"""Experiments and statistics of thesis Chapter 3 (Section 3.5).

* ``run_configuration_trials`` – the Table 8 configurations (C0 baseline, C1
  buffer sizing only, C2 batching only, C3 threading only, C4 full optimized,
  R1 MD5, R2 SHA-256) on one set of evidence files, through the same engine
  data stream as the Autopsy module, with rotated order per trial block.
* ``analyze_autopsy_trials`` – the same analysis for the trials CSV written by
  the Autopsy ingest module.

Every execution must reproduce the reference digest, otherwise the run aborts.
``FORMULAS`` (thesis Equations 1–19) and ``STATISTICAL_PLAN`` are defined here
so the documented methodology and the code cannot disagree.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import blake3 as _blake3

from dataset_tool import classify_format, size_tier
from optimized_blake3 import (
    MIB,
    OperationCancelled,
    SMALL_FILE_LIMIT,
    TABLE8_BY_CODE,
    TABLE8_CONFIGURATIONS,
    EngineSession,
    detected_simd_tier,
    logical_cpu_count,
    physical_cpu_count,
    system_summary,
)

# ─────────────────────────────────────────────────────────────────────────────
# Formula registry: Equations 1–19 of thesis Chapter 3 (Section 3.5), in the
# same numbering. Rendered by the app's Methodology view and exported to
# Markdown, so the documented methodology and the code cannot disagree.
# ─────────────────────────────────────────────────────────────────────────────

FORMULAS: List[Dict[str, str]] = [
    {"id": "Eq. 1", "name": "Throughput",
     "expression": "T = S / t",
     "symbols": "S: data hashed in mebibytes (1 MiB = 1,048,576 bytes); t: time in seconds.",
     "function": "throughput_mib_s"},
    {"id": "Eq. 2", "name": "Execution time",
     "expression": "t = t_end − t_start",
     "symbols": "Monotonic high-resolution clock (time.perf_counter_ns in the engine, "
                "System.nanoTime in the Autopsy module).",
     "function": "optimized_blake3._MetricSampler"},
    {"id": "Eq. 3", "name": "Speedup",
     "expression": "Speedup = t_C0 / t_Ck",
     "symbols": "t: mean execution time of the trials (Eq. 7); > 1 means Ck is faster than C0.",
     "function": "speedup"},
    {"id": "Eq. 4", "name": "Percent reduction in execution time",
     "expression": "%Δ = (t_C0 − t_Ck) / t_C0 × 100",
     "symbols": "> 0 means Ck takes less time than C0.",
     "function": "percent_time_reduction"},
    {"id": "Eq. 5", "name": "CPU utilization",
     "expression": "Ū = (1/n) Σ u_i",
     "symbols": "u_i: psutil sample i, the CPU use over its 10 ms interval normalized by the "
                "number of logical processors (0–100 %); n: samples in the run.",
     "function": "optimized_blake3._MetricSampler"},
    {"id": "Eq. 6", "name": "Peak memory usage",
     "expression": "M_peak = max_i (RSS_i)",
     "symbols": "RSS_i: resident set size of psutil sample i, in MiB.",
     "function": "optimized_blake3._MetricSampler"},
    {"id": "Eq. 7", "name": "Mean",
     "expression": "x̄ = Σ x_i / n",
     "symbols": "x_i: the measurement of trial i; n: number of trials (30).",
     "function": "describe"},
    {"id": "Eq. 8", "name": "Sample standard deviation",
     "expression": "s = √( Σ (x_i − x̄)² / (n − 1) )",
     "symbols": "x̄: mean of the trials (Eq. 7); n − 1: degrees of freedom.", "function": "describe"},
    {"id": "Eq. 9", "name": "95 % confidence interval",
     "expression": "CI_95% = x̄ ± t_0.975,n−1 · s / √n",
     "symbols": "t_0.975,n−1: critical value of the t distribution with n − 1 degrees of freedom.",
     "function": "describe, t_ppf"},
    {"id": "Eq. 10", "name": "Coefficient of variation",
     "expression": "CV = s / x̄ × 100",
     "symbols": "s: Eq. 8; x̄: Eq. 7. CV above 10 % flags an unstable measurement.", "function": "describe"},
    {"id": "Eq. 11", "name": "Digest agreement",
     "expression": "A = digests matching baseline BLAKE3 / files hashed × 100",
     "symbols": "Each digest of the evaluated configuration is compared with the digest of an "
                "independent baseline BLAKE3 pass over the same file.", "function": "digest_agreement"},
    {"id": "Eq. 12", "name": "Report completeness",
     "expression": "C = files reported / readable files × 100",
     "symbols": "Readable files: files of the data source in the case database, excluding "
                "directories and unallocated/unused space blocks.", "function": "report_completeness"},
    {"id": "Eq. 13", "name": "Avalanche effect",
     "expression": "AE = HD(H(m), H(m′)) / 256 × 100",
     "symbols": "HD: Hamming distance; m′: m with one bit flipped.",
     "function": "blake3_validation.avalanche_test"},
    {"id": "Eq. 14", "name": "Chi-square statistic",
     "expression": "χ² = Σ_{i=1}^{256} (O_i − E_i)² / E_i",
     "symbols": "O_i, E_i: observed and expected frequency of digest byte value i − 1.",
     "function": "blake3_validation.distribution_test, chi_square_sf"},
    {"id": "Eq. 15", "name": "Collision rate",
     "expression": "CR = collisions found / (N (N − 1) / 2)",
     "symbols": "N: number of digests compared.",
     "function": "blake3_validation.collision_test"},
    {"id": "Eq. 16", "name": "Deterministic output",
     "expression": "D = identical repeated digests / repetitions × 100",
     "symbols": "Each input is hashed ten times; a repetition is identical when it equals the "
                "first digest of that input.", "function": "blake3_validation.deterministic_test"},
    {"id": "Eq. 17", "name": "Amdahl's Law",
     "expression": "S(p) = 1 / ((1 − P) + P / p)",
     "symbols": "P: portion of the work that can run in parallel; p: number of threads. "
                "Solved for P from an observed speedup: P = (1 − 1/S) / (1 − 1/p).",
     "function": "amdahl_speedup, amdahl_parallel_fraction"},
    {"id": "Eq. 18", "name": "Effect size (paired)",
     "expression": "d = d̄ / s_d",
     "symbols": "d_i = t_C0,i − t_Ck,i for trial block i; d̄, s_d: mean and standard deviation "
                "of the paired differences.",
     "function": "cohens_d_paired"},
    {"id": "Eq. 19", "name": "Weighted mean (expert survey)",
     "expression": "WM = Σ f_i x_i / N",
     "symbols": "f_i: number of experts who chose rating x_i; N: total responses. Interpreted "
                "with Table 3.",
     "function": "weighted_mean, interpret_weighted_mean"},
]

STATISTICAL_PLAN = """\
Statistical analysis plan (thesis Section 3.5)
==============================================

Design. Each configuration is run for thirty (30) measured trials; the order of
the configurations is rotated in every trial block so that no configuration
always runs first. Trials of different configurations are paired by trial block.

Summary. The trials of each configuration are summarized by the mean (Eq. 7),
sample standard deviation (Eq. 8), 95 % confidence interval with the t critical
value (Eq. 9) and coefficient of variation (Eq. 10).

Comparison with C0. For each configuration Ck the paired differences
d_i = t_C0,i − t_Ck,i in execution time are tested for normality with the
Shapiro–Wilk test. When the differences are normal (p ≥ 0.05) a paired t-test is
used, otherwise the Wilcoxon signed-rank test. The Holm correction is applied
across the comparisons with C0 at the 0.05 level of significance. Effect size is
d = d̄ / s_d (Eq. 18). Improvement is expressed as speedup (Eq. 3) and percent
reduction (Eq. 4) of the mean execution times.

Decision rule. Ck is reported as significantly faster (slower) than C0 when the
Holm-adjusted p < 0.05 and the mean paired difference is positive (negative).

Multithreading. Speedups of multithreaded configurations are interpreted with
Amdahl's Law (Eq. 17).

Stability. A configuration whose CV exceeds 10 %, or whose mean time is below
10 ms, is flagged for re-measurement.

Correctness gate. Every measured execution must reproduce the expected digest;
any disagreement aborts the benchmark instead of producing timing results.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Performance indicators (Eq. 1, 3, 4, 17)
# ─────────────────────────────────────────────────────────────────────────────

def throughput_mib_s(byte_count: float, seconds: float) -> float:
    """Eq. 1."""
    return (float(byte_count) / MIB) / float(seconds) if seconds > 0 else 0.0


def speedup(baseline_time: float, configuration_time: float) -> Optional[float]:
    """Eq. 3."""
    if baseline_time <= 0 or configuration_time <= 0:
        return None
    return float(baseline_time) / float(configuration_time)


def percent_time_reduction(baseline_time: float, configuration_time: float) -> Optional[float]:
    """Eq. 4."""
    if baseline_time <= 0 or configuration_time < 0:
        return None
    return (float(baseline_time) - float(configuration_time)) / float(baseline_time) * 100.0


def amdahl_speedup(parallel_fraction: float, threads: int) -> float:
    """Eq. 17."""
    return 1.0 / ((1.0 - parallel_fraction) + parallel_fraction / float(threads))


def amdahl_parallel_fraction(observed_speedup: Optional[float], threads: int) -> Optional[float]:
    """Eq. 17 solved for P: the parallel portion implied by an observed speedup."""
    if not observed_speedup or observed_speedup <= 0 or threads <= 1:
        return None
    return (1.0 - 1.0 / observed_speedup) / (1.0 - 1.0 / float(threads))


def digest_agreement(matching: int, hashed: int) -> Optional[float]:
    """Eq. 11."""
    return 100.0 * matching / hashed if hashed else None


def report_completeness(reported: int, readable: int) -> Optional[float]:
    """Eq. 12."""
    return 100.0 * reported / readable if readable else None


# ─────────────────────────────────────────────────────────────────────────────
# Distributions (normal, Student t) — no SciPy dependency
# ─────────────────────────────────────────────────────────────────────────────

def normal_cdf(z: float) -> float:
    return 0.5 * math.erfc(-z / math.sqrt(2.0))


def normal_ppf(p: float) -> float:
    """Inverse standard normal CDF (Acklam's algorithm + one Halley refinement)."""
    if not 0.0 < p < 1.0:
        raise ValueError("p must be in (0, 1)")
    a = (-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00)
    b = (-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01)
    c = (-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00)
    d = (7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00)
    low = 0.02425
    if p < low:
        q = math.sqrt(-2.0 * math.log(p))
        x = (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
            ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    elif p > 1.0 - low:
        q = math.sqrt(-2.0 * math.log(1.0 - p))
        x = -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
            ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    else:
        q = p - 0.5
        r = q * q
        x = (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / \
            (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
    error = normal_cdf(x) - p
    u = error * math.sqrt(2.0 * math.pi) * math.exp(x * x / 2.0)
    return x - u / (1.0 + x * u / 2.0)


def _beta_continued_fraction(a: float, b: float, x: float) -> float:
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 10000):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return h


def regularized_beta(x: float, a: float, b: float) -> float:
    """I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_front = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                 + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(log_front) * _beta_continued_fraction(a, b, x) / a
    return 1.0 - math.exp(log_front) * _beta_continued_fraction(b, a, 1.0 - x) / b


def t_cdf(t: float, df: float) -> float:
    tail = 0.5 * regularized_beta(df / (df + t * t), df / 2.0, 0.5)
    return 1.0 - tail if t > 0 else tail


def t_ppf(p: float, df: float) -> float:
    """Inverse Student t CDF by bisection on t_cdf (accurate to ~1e-10)."""
    if not 0.0 < p < 1.0:
        raise ValueError("p must be in (0, 1)")
    low, high = -1e3, 1e3
    for _ in range(200):
        middle = (low + high) / 2.0
        if t_cdf(middle, df) < p:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


# ─────────────────────────────────────────────────────────────────────────────
# Descriptive statistics (Eq. 7–10)
# ─────────────────────────────────────────────────────────────────────────────

def describe(values: Sequence[float]) -> Dict[str, Any]:
    """Eq. 7 (mean), Eq. 8 (SD), Eq. 9 (95 % CI with t critical value), Eq. 10 (CV)."""
    data = [float(v) for v in values]
    keys = ("n", "mean", "stdev", "ci95", "cv_percent", "median", "minimum", "maximum")
    if not data:
        return {key: None for key in keys}
    n = len(data)
    mean = statistics.fmean(data)
    stdev = statistics.stdev(data) if n > 1 else 0.0
    ci95 = None
    if n > 1:
        margin = t_ppf(0.975, n - 1) * stdev / math.sqrt(n)
        ci95 = [mean - margin, mean + margin]
    return {
        "n": n,
        "mean": mean,
        "stdev": stdev,
        "ci95": ci95,
        "cv_percent": (stdev / mean * 100.0) if mean else None,
        "median": statistics.median(data),
        "minimum": min(data),
        "maximum": max(data),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Inferential statistics (Shapiro–Wilk, paired t, Wilcoxon, Holm, Eq. 18)
# ─────────────────────────────────────────────────────────────────────────────

def _poly(coefficients: Sequence[float], x: float) -> float:
    return sum(c * x ** i for i, c in enumerate(coefficients))


def shapiro_wilk(values: Sequence[float]) -> Dict[str, Any]:
    """Shapiro–Wilk W test (Royston 1995, algorithm AS R94; 3 ≤ n ≤ 5000)."""
    x = sorted(float(v) for v in values)
    n = len(x)
    if n < 3:
        return {"n": n, "w": None, "p_value": None, "method": "needs at least 3 values"}
    if x[-1] - x[0] < 1e-19 * max(1.0, abs(x[0])):
        return {"n": n, "w": None, "p_value": None, "method": "all values identical"}
    half = n // 2
    a = [0.0] * (half + 1)  # 1-based, as in AS R94
    if n == 3:
        a[1] = math.sqrt(0.5)
    else:
        m = [0.0] + [normal_ppf((i - 0.375) / (n + 0.25)) for i in range(1, half + 1)]
        summ2 = 2.0 * sum(value * value for value in m[1:])
        ssumm2 = math.sqrt(summ2)
        rsn = 1.0 / math.sqrt(n)
        c1 = (0.0, 0.221157, -0.147981, -2.07119, 4.434685, -2.706056)
        c2 = (0.0, 0.042981, -0.293762, -1.752461, 5.682633, -3.582633)
        a1 = _poly(c1, rsn) - m[1] / ssumm2
        if n > 5:
            first = 3
            a2 = -m[2] / ssumm2 + _poly(c2, rsn)
            fac = math.sqrt((summ2 - 2.0 * m[1] ** 2 - 2.0 * m[2] ** 2)
                            / (1.0 - 2.0 * a1 ** 2 - 2.0 * a2 ** 2))
            a[2] = a2
        else:
            first = 2
            fac = math.sqrt((summ2 - 2.0 * m[1] ** 2) / (1.0 - 2.0 * a1 ** 2))
        a[1] = a1
        for i in range(first, half + 1):
            a[i] = -m[i] / fac
    mean = statistics.fmean(x)
    ss = sum((v - mean) ** 2 for v in x)
    numerator = sum(a[i + 1] * (x[n - 1 - i] - x[i]) for i in range(half))
    w = min(1.0, numerator * numerator / ss)
    if n == 3:
        p = max(0.0, 6.0 / math.pi * (math.asin(math.sqrt(w)) - math.pi / 3.0))
        return {"n": n, "w": w, "p_value": min(1.0, p), "method": "exact (n = 3)"}
    y = math.log(1.0 - w) if w < 1.0 else -math.inf
    if n <= 11:
        gamma = _poly((-2.273, 0.459), n)
        if y >= gamma:
            return {"n": n, "w": w, "p_value": 1e-99, "method": "Royston (1995)"}
        y = -math.log(gamma - y)
        mu = _poly((0.544, -0.39978, 0.025054, -6.714e-4), n)
        sigma = math.exp(_poly((1.3822, -0.77857, 0.062767, -0.0020322), n))
    else:
        log_n = math.log(n)
        mu = _poly((-1.5861, -0.31082, -0.083751, 0.0038915), log_n)
        sigma = math.exp(_poly((-0.4803, -0.082676, 0.0030302), log_n))
    p = 1.0 if y == -math.inf else 1.0 - normal_cdf((y - mu) / sigma)
    return {"n": n, "w": w, "p_value": p, "method": "Royston (1995) AS R94"}


def paired_t_test(baseline: Sequence[float], configuration: Sequence[float]) -> Dict[str, Any]:
    """Two-sided paired t-test on d_i = baseline_i − configuration_i."""
    if len(baseline) != len(configuration):
        raise ValueError("paired samples must have equal length")
    differences = [float(a) - float(b) for a, b in zip(baseline, configuration)]
    n = len(differences)
    if n < 2:
        return {"n": n, "t": None, "df": None, "p_value": None}
    mean = statistics.fmean(differences)
    sd = statistics.stdev(differences)
    if sd == 0.0:
        return {"n": n, "t": None, "df": n - 1, "p_value": 1.0 if mean == 0 else 0.0}
    t = mean / (sd / math.sqrt(n))
    p = 2.0 * (1.0 - t_cdf(abs(t), n - 1))
    return {"n": n, "t": t, "df": n - 1, "p_value": min(1.0, max(0.0, p))}


def _average_ranks(values: Sequence[float]) -> List[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        average = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = average
        i = j + 1
    return ranks


def _normal_two_sided_p(z: float) -> float:
    return math.erfc(abs(z) / math.sqrt(2.0))


def _wilcoxon_exact_cdf(n: int, w: int) -> float:
    """P(W+ ≤ w) under H0 for n untied, non-zero differences (ranks 1..n)."""
    max_sum = n * (n + 1) // 2
    counts = [0] * (max_sum + 1)
    counts[0] = 1
    for rank in range(1, n + 1):
        for total in range(max_sum, rank - 1, -1):
            counts[total] += counts[total - rank]
    return sum(counts[: w + 1]) / float(2 ** n)


def wilcoxon_signed_rank(
    baseline: Sequence[float], configuration: Sequence[float]
) -> Dict[str, Any]:
    """Paired two-sided Wilcoxon signed-rank test (zero differences dropped).

    Exact null distribution for n ≤ 50 without ties; otherwise the normal
    approximation with tie and continuity correction.
    """
    if len(baseline) != len(configuration):
        raise ValueError("paired samples must have equal length")
    differences = [float(a) - float(b) for a, b in zip(baseline, configuration)]
    nonzero = [d for d in differences if d != 0.0]
    n = len(nonzero)
    if n == 0:
        return {"n": 0, "w_plus": 0.0, "w_minus": 0.0, "z": 0.0, "p_value": 1.0,
                "method": "all differences are zero"}
    ranks = _average_ranks([abs(d) for d in nonzero])
    w_plus = sum(r for r, d in zip(ranks, nonzero) if d > 0)
    w_minus = sum(r for r, d in zip(ranks, nonzero) if d < 0)

    tie_groups: Dict[float, int] = {}
    for value in (abs(d) for d in nonzero):
        tie_groups[value] = tie_groups.get(value, 0) + 1
    tie_term = sum(t ** 3 - t for t in tie_groups.values() if t > 1)

    mean = n * (n + 1) / 4.0
    variance = n * (n + 1) * (2 * n + 1) / 24.0 - tie_term / 48.0
    if variance > 0:
        correction = 0.5 if w_plus > mean else (-0.5 if w_plus < mean else 0.0)
        z = (w_plus - mean - correction) / math.sqrt(variance)
    else:
        z = 0.0
    if tie_term == 0 and n <= 50:
        w_small = int(round(min(w_plus, w_minus)))
        p_value = min(1.0, 2.0 * _wilcoxon_exact_cdf(n, w_small))
        method = "exact"
    else:
        p_value = _normal_two_sided_p(z)
        method = "normal approximation (tie + continuity corrected)"
    return {"n": n, "w_plus": w_plus, "w_minus": w_minus, "z": z,
            "p_value": p_value, "method": method}


def cohens_d_paired(baseline: Sequence[float], configuration: Sequence[float]) -> Dict[str, Any]:
    """Eq. 18: d = d̄ / s_d with conventional magnitude labels (Cohen, 1988)."""
    differences = [float(a) - float(b) for a, b in zip(baseline, configuration)]
    if len(differences) < 2:
        return {"d": None, "magnitude": "n/a"}
    sd = statistics.stdev(differences)
    mean = statistics.fmean(differences)
    if sd == 0.0:
        return {"d": None if mean == 0 else math.copysign(math.inf, mean),
                "magnitude": "n/a" if mean == 0 else "large"}
    d = mean / sd
    size = abs(d)
    magnitude = ("negligible" if size < 0.2 else "small" if size < 0.5
                 else "medium" if size < 0.8 else "large")
    return {"d": d, "magnitude": magnitude}


def holm_adjust(p_values: Sequence[Optional[float]]) -> List[Optional[float]]:
    """Holm correction. ``None`` entries are passed through and not counted."""
    indexed = [(p, i) for i, p in enumerate(p_values) if p is not None]
    m = len(indexed)
    adjusted: List[Optional[float]] = [None] * len(p_values)
    running = 0.0
    for rank, (p, index) in enumerate(sorted(indexed)):
        running = max(running, min(1.0, (m - rank) * p))
        adjusted[index] = running
    return adjusted


NORMALITY_ALPHA = 0.05


def compare_to_baseline(
    baseline_times: Sequence[float],
    configuration_times: Sequence[float],
    *,
    seed: int = 0,  # kept for call compatibility; the analysis is deterministic
) -> Dict[str, Any]:
    """Everything Section 3.5 reports for one configuration Ck against C0.

    Trials are paired by trial block (index i of both sequences).
    """
    if len(baseline_times) != len(configuration_times):
        raise ValueError("paired samples must have equal length")
    base = describe(baseline_times)
    config = describe(configuration_times)
    differences = [float(a) - float(b) for a, b in zip(baseline_times, configuration_times)]
    difference_stats = describe(differences)
    normality = shapiro_wilk(differences)
    normal = normality["p_value"] is not None and normality["p_value"] >= NORMALITY_ALPHA
    if normal:
        test = paired_t_test(baseline_times, configuration_times)
        test_name = "paired t-test"
    else:
        test = wilcoxon_signed_rank(baseline_times, configuration_times)
        test_name = "Wilcoxon signed-rank"
    effect = cohens_d_paired(baseline_times, configuration_times)
    speed = speedup(base["mean"], config["mean"]) if base["mean"] and config["mean"] else None
    # Speedup range implied by the 95 % CI of the mean paired difference (Eq. 9 on d_i).
    speedup_ci = None
    if difference_stats["ci95"] and base["mean"]:
        low_d, high_d = difference_stats["ci95"]
        slow, fast = base["mean"] - low_d, base["mean"] - high_d
        if slow > 0 and fast > 0:
            speedup_ci = [base["mean"] / slow, base["mean"] / fast]
    return {
        "speedup": speed,
        "speedup_ci95": speedup_ci,
        "percent_time_reduction": (percent_time_reduction(base["mean"], config["mean"])
                                   if base["mean"] else None),
        "mean_difference": difference_stats["mean"],
        "mean_difference_ci95": difference_stats["ci95"],
        "shapiro_w": normality["w"],
        "shapiro_p": normality["p_value"],
        "differences_normal": normal,
        "test": test_name,
        "test_details": test,
        "p_value": test["p_value"],
        "cohens_d": effect["d"],
        "effect_magnitude": effect["magnitude"],
    }


def verdict(comparison: Dict[str, Any], alpha: float = 0.05) -> str:
    """Plain-language outcome per the decision rule of the plan."""
    p_adj = comparison.get("p_holm")
    difference = comparison.get("mean_difference")
    if p_adj is None or difference is None:
        return "insufficient data"
    if p_adj < alpha and difference > 0:
        return "significantly faster"
    if p_adj < alpha and difference < 0:
        return "significantly slower"
    return "no significant difference"


# ─────────────────────────────────────────────────────────────────────────────
# Expert survey (Eq. 19, Table 3)
# ─────────────────────────────────────────────────────────────────────────────

def weighted_mean(ratings: Sequence[int]) -> Optional[float]:
    """Eq. 19 over individual 1–5 ratings (equivalent to Σ f_i x_i / N)."""
    values = [int(r) for r in ratings]
    if any(r < 1 or r > 5 for r in values):
        raise ValueError("ratings must be on the 1–5 scale")
    return statistics.fmean(values) if values else None


def interpret_weighted_mean(value: float) -> str:
    """Table 3 verbal interpretation."""
    if value >= 4.21:
        return "Strongly Agree"
    if value >= 3.41:
        return "Agree"
    if value >= 2.61:
        return "Neutral"
    if value >= 1.81:
        return "Disagree"
    return "Strongly Disagree"


# ─────────────────────────────────────────────────────────────────────────────
# Chi-square distribution (Eq. 14)
# ─────────────────────────────────────────────────────────────────────────────

def _lower_gamma_series(a: float, x: float) -> float:
    term = 1.0 / a
    total = term
    ap = a
    for _ in range(10000):
        ap += 1.0
        term *= x / ap
        total += term
        if abs(term) < abs(total) * 1e-15:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _upper_gamma_continued_fraction(a: float, x: float) -> float:
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi_square_sf(statistic: float, degrees_of_freedom: int) -> float:
    """Upper-tail probability P(χ²_df ≥ statistic) via the regularized gamma Q."""
    if statistic <= 0:
        return 1.0
    a = degrees_of_freedom / 2.0
    x = statistic / 2.0
    if x < a + 1.0:
        return max(0.0, 1.0 - _lower_gamma_series(a, x))
    return min(1.0, _upper_gamma_continued_fraction(a, x))


# ─────────────────────────────────────────────────────────────────────────────
# Experiment settings
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TRIALS = 30
DEFAULT_WARMUPS = 1
CV_LIMIT_PERCENT = 10.0
SHORT_MEASUREMENT_MS = 10.0

ProgressCallback = Optional[Callable[[str, float], None]]

# Backward-compatible names.
optimization_percent = percent_time_reduction


class BenchmarkCancelled(OperationCancelled):
    """Raised when the caller's cancel event is set between executions."""


def host_information() -> Dict[str, Any]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "processor": system_summary()["cpu_model"],
        "memory_gib": system_summary()["memory_gib"],
        "logical_cpu_count": logical_cpu_count(),
        "physical_cpu_count": physical_cpu_count(),
        "blake3_package_version": str(getattr(_blake3, "__version__", "unknown")),
        "simd_tier": detected_simd_tier(),
        "simd_note": "Native SIMD dispatch is identical in every BLAKE3 configuration "
                     "(held constant; not a studied technique).",
    }


def _check_cancel(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise BenchmarkCancelled("benchmark cancelled by user")


class _Progress:
    """Progress fractions plus a simple remaining-time estimate."""

    def __init__(self, callback: ProgressCallback, total_steps: int):
        self.callback = callback
        self.total = max(1, total_steps)
        self.done = 0
        self.started = time.perf_counter()

    def step(self, message: str) -> None:
        self.done += 1
        if self.callback is None:
            return
        fraction = min(1.0, self.done / self.total)
        elapsed = time.perf_counter() - self.started
        if 0 < fraction < 1:
            remaining = elapsed / fraction - elapsed
            message += "  ·  about %s left" % _format_duration(remaining)
        self.callback(message, fraction)


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%d s" % seconds
    if seconds < 3600:
        return "%d min %d s" % divmod(seconds, 60)
    hours, rest = divmod(seconds, 3600)
    return "%d h %d min" % (hours, rest // 60)


def _summarize_condition(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    elapsed = [run["elapsed_ms"] for run in runs]
    throughput = [run["throughput_mib_s"] for run in runs]
    cpu = [run["cpu_percent"] for run in runs if run.get("cpu_percent") is not None]
    rss = [run["peak_rss_mib"] for run in runs if run.get("peak_rss_mib") is not None]
    time_stats = describe(elapsed)  # Eq. 7-10
    return {
        "elapsed_ms": time_stats,
        "throughput_mib_s": describe(throughput),
        "cpu_percent": describe(cpu),
        "peak_rss_mib": describe(rss),
        "stable": (time_stats["cv_percent"] or 0.0) <= CV_LIMIT_PERCENT
        and (time_stats["mean"] or 0.0) >= SHORT_MEASUREMENT_MS,
    }


def _comparisons(
    by_condition: Dict[str, List[float]],
    pairs: Sequence[Tuple[str, str, str]],
    seed: int,
) -> List[Dict[str, Any]]:
    """``pairs``: (family, slower/reference key, faster/candidate key)."""
    results: List[Dict[str, Any]] = []
    for family, reference, candidate in pairs:
        if reference not in by_condition or candidate not in by_condition:
            continue
        comparison = compare_to_baseline(
            by_condition[reference], by_condition[candidate], seed=seed
        )
        comparison.update({"family": family, "reference": reference, "candidate": candidate})
        results.append(comparison)
    for family in {item["family"] for item in results}:
        members = [item for item in results if item["family"] == family]
        for item, adjusted in zip(members, holm_adjust([m["p_value"] for m in members])):
            item["p_holm"] = adjusted
    for item in results:
        item["verdict"] = verdict(item)
    return results


def _paired_times(runs: List[Dict[str, Any]], keys: Sequence[str]) -> Dict[str, List[float]]:
    """Elapsed times per condition ordered by round, so index i pairs block i."""
    table: Dict[str, Dict[int, float]] = {key: {} for key in keys}
    for run in runs:
        if run["condition"] in table:
            table[run["condition"]][run.get("trial_block", run.get("round"))] = run["elapsed_ms"]
    rounds = sorted(set.intersection(*(set(v) for v in table.values()))) if table else []
    return {key: [table[key][r] for r in rounds] for key in keys}


def _warnings_for(summary: Dict[str, Dict[str, Any]], labels: Dict[str, str]) -> List[str]:
    warnings = []
    for key, item in summary.items():
        stats = item["elapsed_ms"]
        if stats["mean"] is not None and stats["mean"] < SHORT_MEASUREMENT_MS:
            warnings.append("%s: mean below %.0f ms; timer and sampling noise dominate — "
                            "use a larger input." % (labels[key], SHORT_MEASUREMENT_MS))
        if stats["cv_percent"] is not None and stats["cv_percent"] > CV_LIMIT_PERCENT:
            warnings.append("%s: CV %.1f %% exceeds %.0f %%; re-run on a quieter system."
                            % (labels[key], stats["cv_percent"], CV_LIMIT_PERCENT))
    return warnings


# ─────────────────────────────────────────────────────────────────────────────
# Technique evaluation: the Table 8 configurations on a set of evidence files
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CONFIGURATION_CODES = tuple(c["code"] for c in TABLE8_CONFIGURATIONS)


def _expected_digests(paths: Sequence[str]) -> Dict[str, List[str]]:
    """Reference digests computed outside the timer with the plain libraries."""
    expected: Dict[str, List[str]] = {"BLAKE3": [], "MD5": [], "SHA-256": []}
    for path in paths:
        hashers = {"BLAKE3": _blake3.blake3(), "MD5": hashlib.md5(), "SHA-256": hashlib.sha256()}
        with open(path, "rb") as source:
            for block in iter(lambda: source.read(8 * MIB), b""):
                for hasher in hashers.values():
                    hasher.update(block)
        for name, hasher in hashers.items():
            expected[name].append(hasher.hexdigest())
    return expected


def run_configuration_trials(
    paths: Sequence[os.PathLike[str] | str],
    *,
    configurations: Sequence[str] = DEFAULT_CONFIGURATION_CODES,
    trials: int = DEFAULT_TRIALS,
    warmups: int = 1,
    progress: ProgressCallback = None,
    cancel: Optional[threading.Event] = None,
    engine_command: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Run each Table 8 configuration on the whole file set, ``trials`` times.

    Every configuration sends the files through the same persistent engine data
    stream the Autopsy module uses (EngineSession), so batching (C2, C4) has its
    real meaning: fewer requests between the client and the engine. The order of
    the configurations is rotated in each trial block so no configuration always
    runs first (Section 3.5). One untimed warm-up block loads the files into the
    file cache. Every digest must equal the reference digest, or the run aborts.

    The execution time of a run is the wall time from the first request to the
    last response for the whole file set (Eq. 2); throughput is Eq. 1; CPU is the
    mean of every psutil sample of every request (Eq. 5); memory is the largest
    engine RSS sample (Eq. 6).
    """
    files = [str(Path(p).resolve()) for p in paths]
    files = [p for p in dict.fromkeys(files) if os.path.isfile(p)]
    if not files:
        raise ValueError("select at least one file")
    if trials < 1 or warmups < 0:
        raise ValueError("trials must be at least 1 and warm-ups at least 0")
    codes = [code for code in DEFAULT_CONFIGURATION_CODES if code in set(configurations)]
    if "C0" not in codes:
        raise ValueError("C0 (baseline) is required: every configuration is compared with it")
    chosen = [TABLE8_BY_CODE[code] for code in codes]
    sizes = [os.path.getsize(p) for p in files]
    total_bytes = sum(sizes)
    snapshot = {p: os.stat(p).st_mtime_ns for p in files}
    tracker = _Progress(progress, len(codes) * (trials + warmups) + 1)
    expected = _expected_digests(files)
    tracker.step("Computed reference digests for %d files (not timed)" % len(files))

    runs: List[Dict[str, Any]] = []
    per_file: List[Dict[str, Any]] = []
    with EngineSession(engine_command) as session:
        def execute(configuration: Dict[str, Any], block: int, position: int, warmup: bool) -> None:
            _check_cancel(cancel)
            started = time.perf_counter_ns()
            results = session.hash_set(files, configuration)
            elapsed_s = max(1e-9, (time.perf_counter_ns() - started) / 1e9)
            reference = expected[configuration["algorithm"]]
            for path, result, digest in zip(files, results, reference):
                if result.get("status") != "ok" or result.get("digest") != digest:
                    raise RuntimeError("%s produced a wrong or missing digest for %s (%s); results "
                                       "discarded" % (configuration["label"], os.path.basename(path),
                                                      result.get("message") or result.get("digest")))
            cpu_total = cpu_count = 0.0
            for result in results:
                if result.get("cpu_utilization_percent") is not None:
                    samples = max(1, int(result.get("cpu_samples") or 1))
                    cpu_total += float(result["cpu_utilization_percent"]) * samples
                    cpu_count += samples
            rss = [r["peak_rss_mb"] for r in results if r.get("peak_rss_mb") is not None]
            tracker.step("%s · %s %d" % (configuration["label"], "warm-up" if warmup else "trial", block))
            if warmup:
                return
            runs.append({
                "trial_block": block, "position": position, "condition": configuration["code"],
                "label": configuration["label"], "files": len(files), "total_bytes": total_bytes,
                "elapsed_ms": round(elapsed_s * 1000.0, 3),
                "throughput_mib_s": round(throughput_mib_s(total_bytes, elapsed_s), 3),
                "cpu_percent": round(cpu_total / cpu_count, 3) if cpu_count else None,
                "cpu_samples": int(cpu_count),
                "peak_rss_mib": max(rss) if rss else None,
                "requests": len(files) if not configuration["batching"] else None,
            })
            for path, size, result in zip(files, sizes, results):
                per_file.append({"trial_block": block, "condition": configuration["code"],
                                 "size_bytes": size, "size_tier": size_tier(size),
                                 "engine_ms": result.get("elapsed_ms"),
                                 "threads": result.get("threads_used"),
                                 "buffer_bytes": result.get("chunk_size")})

        for block in range(1, warmups + 1):
            for position, configuration in enumerate(chosen, 1):
                execute(configuration, block, position, True)
        for block in range(1, trials + 1):
            shift = (block - 1) % len(chosen)
            order = chosen[shift:] + chosen[:shift]  # rotated per trial block
            for position, configuration in enumerate(order, 1):
                execute(configuration, block, position, False)

    for path, mtime in snapshot.items():
        if os.stat(path).st_mtime_ns != mtime:
            raise RuntimeError("file changed during the evaluation: %s" % path)

    labels = {c["code"]: c["label"] for c in chosen}
    summary = {code: _summarize_condition([r for r in runs if r["condition"] == code])
               for code in codes}
    for code in codes:
        summary[code]["label"] = labels[code]
        summary[code]["kind"] = "reference" if code.startswith("R") else "blake3"
        summary[code]["configuration"] = TABLE8_BY_CODE[code]
    paired = _paired_times(runs, codes)
    technique = [code for code in ("C1", "C2", "C3", "C4") if code in codes]
    comparisons = _comparisons(paired, [("technique", "C0", code) for code in technique], seed=0)
    references = []
    for code in (c for c in codes if c.startswith("R")):
        base = summary["C0"]["elapsed_ms"]["mean"]
        mean = summary[code]["elapsed_ms"]["mean"]
        references.append({"reference": code, "speedup_vs_c0": speedup(base, mean),
                           "note": "reference point; not tested (Section 1.5)"})
    cores = physical_cpu_count()
    has_large = any(size >= SMALL_FILE_LIMIT for size in sizes)
    amdahl = {}
    for comparison in comparisons:
        if comparison["candidate"] in ("C3", "C4") and has_large:
            amdahl[comparison["candidate"]] = {
                "threads": cores, "observed_speedup": comparison["speedup"],
                "parallel_fraction": amdahl_parallel_fraction(comparison["speedup"], cores)}
    warnings = _warnings_for(summary, labels)
    if trials < DEFAULT_TRIALS:
        warnings.append("%d trials per configuration; the thesis protocol uses %d."
                        % (trials, DEFAULT_TRIALS))
    if not has_large:
        warnings.append("No file is %s or larger, so multithreading (C3, C4) cannot apply."
                        % _mib(SMALL_FILE_LIMIT))
    if sum(1 for s in sizes if s < SMALL_FILE_LIMIT) < 2:
        warnings.append("Fewer than two files below %s, so batching (C2, C4) has nothing to group."
                        % _mib(SMALL_FILE_LIMIT))
    return {
        "schema_version": 4,
        "experiment": "Table 8 configurations on one evidence file set (Section 3.5)",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": host_information(),
        "design": {
            "trials_per_configuration": trials, "warmup_blocks": warmups,
            "order": "rotated in each trial block", "pairing": "by trial block",
            "timing_scope": "first request to last response for the whole file set, through the "
                            "engine data stream (Eq. 2)",
            "tests": "Shapiro-Wilk on paired differences, then paired t-test or Wilcoxon signed-rank; "
                     "Holm over the comparisons with C0; d = mean(d)/s_d (Eq. 18)",
            "simd": detected_simd_tier() + " — identical in every configuration (not a technique)",
        },
        "workload": {
            "files": len(files), "total_bytes": total_bytes,
            "small_files": sum(1 for s in sizes if s < SMALL_FILE_LIMIT),
            "large_files": sum(1 for s in sizes if s >= SMALL_FILE_LIMIT),
            "smallest_bytes": min(sizes), "largest_bytes": max(sizes),
            "categories": sorted({classify_format(p) for p in files}),
        },
        "configurations": [TABLE8_BY_CODE[code] for code in codes],
        "summary": summary,
        "comparisons": comparisons,
        "references": references,
        "amdahl": amdahl,
        "size_tiers": _size_tier_table(per_file, codes),
        "warnings": warnings,
        "runs": runs,
        "file_paths": files,
    }


def _size_tier_table(per_file: List[Dict[str, Any]], codes: Sequence[str]) -> List[Dict[str, Any]]:
    """Mean engine throughput by size tier and configuration (execution time vs file size)."""
    rows = []
    for tier in sorted({record["size_tier"] for record in per_file}):
        row: Dict[str, Any] = {"size_tier": tier}
        for code in codes:
            items = [r for r in per_file if r["size_tier"] == tier and r["condition"] == code
                     and r["engine_ms"]]
            if items:
                mib = sum(r["size_bytes"] for r in items) / MIB
                seconds = sum(float(r["engine_ms"]) for r in items) / 1000.0
                row[code] = round(mib / seconds, 1) if seconds > 0 else None
        rows.append(row)
    return rows


def planned_read_bytes(sizes: Sequence[int], trials: int, warmups: int,
                       configurations: int = len(DEFAULT_CONFIGURATION_CODES)) -> int:
    """Total bytes an evaluation reads (to warn before very large runs)."""
    return int(sum(sizes)) * int(configurations) * (int(trials) + int(warmups))


def _mib(value: int) -> str:
    return "%d MiB" % (value // MIB)


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────

def summary_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One row per configuration, for spreadsheets."""
    comparisons = {c["candidate"]: c for c in report["comparisons"]}
    references = {r["reference"]: r for r in report.get("references", [])}
    rows = []
    for code, item in report["summary"].items():
        stats = item["elapsed_ms"]
        ci = stats["ci95"] or [None, None]
        comparison = comparisons.get(code, {})
        rows.append({
            "configuration": code, "label": item["label"], "trials": stats["n"],
            "mean_ms": stats["mean"], "sd_ms": stats["stdev"],
            "ci95_low_ms": ci[0], "ci95_high_ms": ci[1], "cv_percent": stats["cv_percent"],
            "mean_throughput_mib_s": item["throughput_mib_s"]["mean"],
            "mean_cpu_percent": item["cpu_percent"]["mean"],
            "mean_peak_rss_mib": item["peak_rss_mib"]["mean"],
            "speedup_vs_c0": comparison.get("speedup", references.get(code, {}).get("speedup_vs_c0")),
            "percent_reduction": comparison.get("percent_time_reduction"),
            "shapiro_p": comparison.get("shapiro_p"), "test": comparison.get("test"),
            "p_value": comparison.get("p_value"), "p_holm": comparison.get("p_holm"),
            "cohens_d": comparison.get("cohens_d"),
            "verdict": comparison.get("verdict", "baseline" if code == "C0" else "reference point"),
        })
    return rows


def _write_csv(path: os.PathLike[str] | str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def export_report(report: Dict[str, Any], folder: os.PathLike[str] | str, stem: str) -> Dict[str, str]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": str(folder / (stem + ".json")),
        "runs_csv": str(folder / (stem + "_runs.csv")),
        "summary_csv": str(folder / (stem + "_summary.csv")),
    }
    Path(paths["json"]).write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_csv(paths["runs_csv"], report["runs"])
    _write_csv(paths["summary_csv"], summary_rows(report))
    return paths


# ─────────────────────────────────────────────────────────────────────────────
# Autopsy trials (thesis Table 8, Section 3.5)
# ─────────────────────────────────────────────────────────────────────────────
# The Autopsy module appends one row per ingest run to a trials CSV (see
# AUTOPSY_TRIAL_COLUMNS in blake3_ingest_module.py). Each row is one
# configuration × disk image × trial block.

AUTOPSY_CONFIGURATIONS = ("C0", "C1", "C2", "C3", "C4", "R1", "R2")
AUTOPSY_SCOPES = (
    ("file_hashing_ms", "Readable files (end-to-end, batch round trips counted once)"),
    ("evidence_ms", "Complete evidence source (timed pass after the warm-up)"),
)
_AUTOPSY_SECONDARY = (
    ("throughput_mib_s", "evidence_throughput_mib_s"),
    ("cpu_mean_percent", "evidence_cpu_percent"),
    ("peak_rss_mib", "evidence_peak_rss_mib"),
)


def _float_or_none(value: Any) -> Optional[float]:
    try:
        return float(value) if value not in (None, "", "N/A") else None
    except (TypeError, ValueError):
        return None


def analyze_autopsy_trials(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Section 3.5 analysis of Autopsy trial rows, per disk image and timing scope.

    For every disk image: Eq. 7–10 summaries for each configuration; C1–C4 are
    compared with C0 on trials paired by trial block (Shapiro–Wilk → paired t
    or Wilcoxon; Holm over the four comparisons; Eq. 3, 4, 18); R1/R2 are
    summarized as reference points. When a configuration has more than one row
    for the same trial block, the most recent row is used and a warning is added.
    """
    images: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        images.setdefault(str(row.get("data_source", "")), []).append(row)
    results: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for image, image_rows in sorted(images.items()):
        image_result: Dict[str, Any] = {"data_source": image, "scopes": []}
        bad_agreement = [r for r in image_rows
                         if _float_or_none(r.get("digest_agreement_percent")) not in (None, 100.0)]
        if bad_agreement:
            warnings.append("%s: %d run(s) with digest agreement below 100 %%."
                            % (image, len(bad_agreement)))
        for metric, scope_label in AUTOPSY_SCOPES:
            by_config: Dict[str, Dict[int, Dict[str, Any]]] = {}
            for row in image_rows:
                code = str(row.get("configuration", "")).upper()
                block = row.get("trial_block")
                # Trial block 0 marks a run that is not a measured trial.
                if code not in AUTOPSY_CONFIGURATIONS or block in (None, "") or int(block) <= 0:
                    continue
                if _float_or_none(row.get(metric)) is None:
                    continue
                slot = by_config.setdefault(code, {})
                if int(block) in slot:
                    warnings.append("%s %s: trial block %s recorded more than once; latest kept."
                                    % (image, code, block))
                slot[int(block)] = row
            if not by_config:
                continue
            secondary = dict(_AUTOPSY_SECONDARY)
            summary = {}
            for code, blocks in sorted(by_config.items()):
                ordered = [blocks[b] for b in sorted(blocks)]
                entry = {"trials": len(ordered),
                         "execution_time_ms": describe([float(r[metric]) for r in ordered])}
                for file_key, evidence_key in secondary.items():
                    key = file_key if metric == "file_hashing_ms" else evidence_key
                    values = [v for v in (_float_or_none(r.get(key)) for r in ordered) if v is not None]
                    entry[file_key] = describe(values)
                summary[code] = entry
            comparisons = []
            if "C0" in by_config:
                for code in ("C1", "C2", "C3", "C4"):
                    if code not in by_config:
                        continue
                    blocks = sorted(set(by_config["C0"]) & set(by_config[code]))
                    if len(blocks) < 3:
                        warnings.append("%s %s: fewer than 3 trial blocks paired with C0." % (image, code))
                        continue
                    base = [float(by_config["C0"][b][metric]) for b in blocks]
                    candidate = [float(by_config[code][b][metric]) for b in blocks]
                    comparison = compare_to_baseline(base, candidate)
                    comparison.update({"candidate": code, "reference": "C0",
                                       "paired_trial_blocks": len(blocks)})
                    comparisons.append(comparison)
                for comparison, adjusted in zip(
                        comparisons, holm_adjust([c["p_value"] for c in comparisons])):
                    comparison["p_holm"] = adjusted
                    comparison["verdict"] = verdict(comparison)
                    threads = _float_or_none(next(iter(by_config[comparison["candidate"]].values()))
                                             .get("physical_cores"))
                    if comparison["candidate"] in ("C3", "C4") and threads and threads > 1:
                        comparison["amdahl_parallel_fraction"] = amdahl_parallel_fraction(
                            comparison["speedup"], int(threads))
            for code, entry in summary.items():
                if entry["trials"] < DEFAULT_TRIALS:
                    warnings.append("%s %s (%s): %d trials, fewer than the %d planned."
                                    % (image, code, metric, entry["trials"], DEFAULT_TRIALS))
            image_result["scopes"].append({"metric": metric, "label": scope_label,
                                           "configurations": summary, "comparisons": comparisons})
        results.append(image_result)
    return {
        "analysis": "thesis Section 3.5 (Autopsy trials)",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "plan": STATISTICAL_PLAN,
        "data_sources": results,
        "warnings": sorted(set(warnings)),
    }


def read_autopsy_trials(path: os.PathLike[str] | str) -> List[Dict[str, Any]]:
    with open(path, newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def autopsy_summary_rows(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for image in analysis["data_sources"]:
        for scope in image["scopes"]:
            comparisons = {c["candidate"]: c for c in scope["comparisons"]}
            for code, entry in scope["configurations"].items():
                stats_ = entry["execution_time_ms"]
                ci = stats_["ci95"] or [None, None]
                comparison = comparisons.get(code, {})
                rows.append({
                    "data_source": image["data_source"], "scope": scope["metric"],
                    "configuration": code, "trials": entry["trials"],
                    "mean_ms": stats_["mean"], "sd_ms": stats_["stdev"],
                    "ci95_low_ms": ci[0], "ci95_high_ms": ci[1], "cv_percent": stats_["cv_percent"],
                    "mean_throughput_mib_s": entry["throughput_mib_s"]["mean"],
                    "mean_cpu_percent": entry["cpu_mean_percent"]["mean"],
                    "mean_peak_rss_mib": entry["peak_rss_mib"]["mean"],
                    "speedup": comparison.get("speedup"),
                    "percent_reduction": comparison.get("percent_time_reduction"),
                    "shapiro_w": comparison.get("shapiro_w"), "shapiro_p": comparison.get("shapiro_p"),
                    "test": comparison.get("test"), "p_value": comparison.get("p_value"),
                    "p_holm": comparison.get("p_holm"), "cohens_d": comparison.get("cohens_d"),
                    "verdict": comparison.get("verdict",
                                              "reference" if code in ("C0", "R1", "R2") else ""),
                })
    return rows


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="experiment", required=True)
    trials = sub.add_parser("trials", help="run the Table 8 configurations on files or a folder")
    trials.add_argument("paths", nargs="+", help="evidence files and/or folders (searched recursively)")
    trials.add_argument("--configurations", nargs="+", default=list(DEFAULT_CONFIGURATION_CODES),
                        choices=list(DEFAULT_CONFIGURATION_CODES))
    trials.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    trials.add_argument("--warmups", type=int, default=1)
    trials.add_argument("--output", default=".", help="folder for JSON/CSV results")
    autopsy = sub.add_parser("autopsy", help="analyze the trials CSV written by the Autopsy module")
    autopsy.add_argument("trials_csv")
    autopsy.add_argument("--output", default=".", help="folder for JSON/CSV results")
    args = parser.parse_args(argv)
    if args.experiment == "autopsy":
        analysis = analyze_autopsy_trials(read_autopsy_trials(args.trials_csv))
        folder = Path(args.output)
        folder.mkdir(parents=True, exist_ok=True)
        stem = "autopsy_trials_analysis_" + time.strftime("%Y%m%d_%H%M%S")
        (folder / (stem + ".json")).write_text(json.dumps(analysis, indent=2), encoding="utf-8")
        rows = autopsy_summary_rows(analysis)
        if rows:
            with open(folder / (stem + ".csv"), "w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
        for warning in analysis["warnings"]:
            print("WARNING:", warning, file=sys.stderr)
        print(json.dumps({"json": str(folder / (stem + ".json")),
                          "csv": str(folder / (stem + ".csv")) if rows else None}, indent=2))
        return 0
    printer = lambda message, fraction: print("[%5.1f%%] %s" % (fraction * 100, message), file=sys.stderr)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    paths: List[str] = []
    for path in args.paths:
        if os.path.isdir(path):
            paths.extend(str(p) for p in sorted(Path(path).rglob("*")) if p.is_file())
        else:
            paths.append(path)
    report = run_configuration_trials(paths, configurations=args.configurations, trials=args.trials,
                                      warmups=args.warmups, progress=printer)
    written = export_report(report, args.output, "technique_evaluation_" + stamp)
    print(json.dumps(written, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
