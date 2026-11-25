import itertools
import math
import os
import statistics
import tempfile
import unittest
from pathlib import Path

import blake3

import benchmark_blake3 as bench

metrics = bench  # formulas and statistics live in benchmark_blake3
from optimized_blake3 import SMALL_FILE_LIMIT


class ConfigurationTrialsTests(unittest.TestCase):
    """Technique evaluation of thesis Table 8 through the engine data stream."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        cls.paths = []
        for index in range(40):
            path = root / ("doc%02d.txt" % index)
            path.write_bytes(os.urandom(500 + index * 301))
            cls.paths.append(path)
        large = root / "video.mp4"
        large.write_bytes(os.urandom(SMALL_FILE_LIMIT + 1234))
        cls.paths.append(large)
        cls.report = bench.run_configuration_trials(cls.paths, trials=4, warmups=1)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_all_seven_configurations_run(self):
        self.assertEqual(list(self.report["summary"]), ["C0", "C1", "C2", "C3", "C4", "R1", "R2"])
        self.assertEqual([c["candidate"] for c in self.report["comparisons"]], ["C1", "C2", "C3", "C4"])
        for comparison in self.report["comparisons"]:
            self.assertIn(comparison["test"], ("paired t-test", "Wilcoxon signed-rank"))
            self.assertIn("p_holm", comparison)
        self.assertEqual({r["reference"] for r in self.report["references"]}, {"R1", "R2"})

    def test_order_is_rotated_per_trial_block(self):
        firsts = [r["condition"] for r in self.report["runs"] if r["position"] == 1]
        self.assertEqual(firsts, ["C0", "C1", "C2", "C3"])
        for block in range(1, 5):
            self.assertEqual(sorted(r["condition"] for r in self.report["runs"] if r["trial_block"] == block),
                             ["C0", "C1", "C2", "C3", "C4", "R1", "R2"])

    def test_threading_applies_and_amdahl_reported(self):
        self.assertIn("C4", self.report["amdahl"])
        self.assertEqual(self.report["workload"]["large_files"], 1)
        self.assertEqual(self.report["workload"]["small_files"], 40)

    def test_size_tier_table_and_export(self):
        tiers = {row["size_tier"] for row in self.report["size_tiers"]}
        self.assertTrue(any(t.startswith("T4") for t in tiers))
        with tempfile.TemporaryDirectory() as out:
            paths = bench.export_report(self.report, out, "test")
            for path in paths.values():
                self.assertTrue(Path(path).stat().st_size > 0)

    def test_c0_is_required_and_subsets_work(self):
        with self.assertRaises(ValueError):
            bench.run_configuration_trials(self.paths[:3], configurations=["C1"], trials=1)
        report = bench.run_configuration_trials(self.paths[:3], configurations=["C0", "C2"], trials=3,
                                                warmups=0)
        self.assertEqual(list(report["summary"]), ["C0", "C2"])
        self.assertTrue(any("Multithreading" in w or "multithreading" in w for w in report["warnings"]))

    def test_cancellation(self):
        import threading
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(bench.BenchmarkCancelled):
            bench.run_configuration_trials(self.paths[:2], trials=2, warmups=0, cancel=cancel)


class IndicatorTests(unittest.TestCase):
    def test_indicators(self):
        self.assertAlmostEqual(metrics.throughput_mib_s(2 * metrics.MIB, 0.5), 4.0)
        self.assertEqual(metrics.speedup(10.0, 4.0), 2.5)
        self.assertEqual(metrics.percent_time_reduction(10.0, 7.5), 25.0)
        self.assertEqual(metrics.percent_time_reduction(10.0, 12.0), -20.0)
        self.assertIsNone(metrics.speedup(0.0, 1.0))
        self.assertEqual(metrics.digest_agreement(99, 100), 99.0)
        self.assertEqual(metrics.report_completeness(50, 50), 100.0)
        self.assertIsNone(metrics.report_completeness(0, 0))

    def test_amdahl(self):
        self.assertAlmostEqual(metrics.amdahl_speedup(1.0, 6), 6.0)
        self.assertAlmostEqual(metrics.amdahl_speedup(0.0, 6), 1.0)
        fraction = metrics.amdahl_parallel_fraction(metrics.amdahl_speedup(0.9, 6), 6)
        self.assertAlmostEqual(fraction, 0.9)

    def test_describe_matches_equations_7_to_10(self):
        data = [1, 2, 3, 4, 100]
        stats = metrics.describe(data)
        self.assertEqual(stats["mean"], 22)
        self.assertAlmostEqual(stats["stdev"], statistics.stdev(data))
        margin = 2.7764451051977934 * stats["stdev"] / math.sqrt(5)  # t(0.975, 4), SciPy
        self.assertAlmostEqual(stats["ci95"][0], 22 - margin, places=8)
        self.assertAlmostEqual(stats["ci95"][1], 22 + margin, places=8)
        self.assertAlmostEqual(stats["cv_percent"], stats["stdev"] / 22 * 100)

    def test_survey_weighted_mean_and_table3(self):
        self.assertAlmostEqual(metrics.weighted_mean([5, 5, 4, 4, 3]), 4.2)
        self.assertEqual(metrics.interpret_weighted_mean(4.2), "Agree")
        self.assertEqual(metrics.interpret_weighted_mean(4.21), "Strongly Agree")
        self.assertEqual(metrics.interpret_weighted_mean(2.61), "Neutral")
        self.assertEqual(metrics.interpret_weighted_mean(1.8), "Strongly Disagree")

    def test_every_formula_is_documented(self):
        ids = [f["id"] for f in metrics.FORMULAS]
        self.assertEqual(ids, ["Eq. %d" % i for i in range(1, 20)])
        for formula in metrics.FORMULAS:
            for key in ("name", "expression", "symbols", "function"):
                self.assertTrue(formula[key])


class WilcoxonTests(unittest.TestCase):
    def test_exact_distribution_matches_enumeration(self):
        for n in range(1, 11):
            sums = [sum(r for r, s in zip(range(1, n + 1), signs) if s)
                    for signs in itertools.product((0, 1), repeat=n)]
            for w in range(0, n * (n + 1) // 2 + 1):
                brute = sum(1 for s in sums if s <= w) / 2 ** n
                self.assertAlmostEqual(metrics._wilcoxon_exact_cdf(n, w), brute)

    def test_clear_difference_is_significant(self):
        baseline = [10.0 + i * 0.1 for i in range(30)]
        faster = [b * 0.8 for b in baseline]
        result = metrics.wilcoxon_signed_rank(baseline, faster)
        self.assertEqual(result["method"], "exact")
        self.assertLess(result["p_value"], 1e-6)
        self.assertEqual(result["w_minus"], 0.0)

    def test_known_small_sample(self):
        # Differences 1..8 all positive except rank 1: W- = 1 → two-sided exact p = 4/256.
        baseline = [i + 1.0 for i in range(1, 9)]
        configuration = [1.0] * 8
        configuration[0] = 3.0  # difference -1 (rank 1)
        result = metrics.wilcoxon_signed_rank(baseline, configuration)
        self.assertAlmostEqual(result["p_value"], 2 * 2 / 256)

    def test_ties_use_normal_approximation(self):
        result = metrics.wilcoxon_signed_rank([2, 2, 2, 3, 3, 5], [1, 1, 1, 1, 1, 1])
        self.assertIn("normal", result["method"])
        self.assertLess(result["p_value"], 0.05)

    def test_no_difference(self):
        self.assertEqual(metrics.wilcoxon_signed_rank([1, 2], [1, 2])["p_value"], 1.0)


class ReferenceValueTests(unittest.TestCase):
    """Values computed with SciPy 1.18.1 (scipy.stats), used only to verify."""

    def test_t_critical_values(self):
        self.assertAlmostEqual(metrics.t_ppf(0.975, 29), 2.045229642132704, places=9)
        self.assertAlmostEqual(metrics.t_ppf(0.975, 4), 2.7764451051977934, places=9)

    def test_shapiro_wilk(self):
        result = metrics.shapiro_wilk([2.1, 3.4, 1.9, 5.6, 4.4, 3.3, 2.8, 4.9, 3.1, 2.2])
        self.assertAlmostEqual(result["w"], 0.9294789098437634, places=10)
        self.assertAlmostEqual(result["p_value"], 0.44278629029381383, places=10)
        result = metrics.shapiro_wilk([148, 154, 158, 160, 161, 162, 166, 170, 182, 195, 236])
        self.assertAlmostEqual(result["w"], 0.7888146948353875, places=10)
        self.assertAlmostEqual(result["p_value"], 0.006703814056502984, places=10)
        result = metrics.shapiro_wilk([1, 2, 4])
        self.assertAlmostEqual(result["p_value"], 0.6368868450289701, places=10)

    def test_paired_t(self):
        x = [10.2, 11.1, 9.8, 10.5, 10.9, 11.3, 10.0, 10.7]
        y = [9.1, 10.4, 9.9, 9.6, 10.1, 10.2, 9.3, 9.8]
        result = metrics.paired_t_test(x, y)
        self.assertAlmostEqual(result["t"], 5.653274201951819, places=9)
        self.assertAlmostEqual(result["p_value"], 0.0007718484065882959, places=10)
        self.assertEqual(result["df"], 7)


class EffectSizeAndAdjustmentTests(unittest.TestCase):
    def test_cohens_d_is_mean_over_sd_of_differences(self):
        baseline, configuration = [10, 12, 11, 13], [8, 9, 10, 9]
        differences = [2, 3, 1, 4]
        expected = statistics.fmean(differences) / statistics.stdev(differences)
        self.assertAlmostEqual(metrics.cohens_d_paired(baseline, configuration)["d"], expected)

    def test_holm(self):
        adjusted = metrics.holm_adjust([0.01, 0.04, 0.03, None])
        self.assertAlmostEqual(adjusted[0], 0.03)
        self.assertAlmostEqual(adjusted[2], 0.06)
        self.assertAlmostEqual(adjusted[1], 0.06)
        self.assertIsNone(adjusted[3])

    def test_test_selection_follows_normality(self):
        baseline = [10.0 + 0.37 * math.sin(i) for i in range(30)]
        normal_like = [b - 1.0 - 0.05 * ((i * 7919) % 11 - 5) for i, b in enumerate(baseline)]
        comparison = metrics.compare_to_baseline(baseline, normal_like)
        self.assertEqual(comparison["test"],
                         "paired t-test" if comparison["shapiro_p"] >= 0.05 else "Wilcoxon signed-rank")
        skewed = [b - (5.0 if i == 0 else 0.01 * i) for i, b in enumerate(baseline)]
        comparison = metrics.compare_to_baseline(baseline, skewed)
        self.assertLess(comparison["shapiro_p"], 0.05)
        self.assertEqual(comparison["test"], "Wilcoxon signed-rank")

    def test_speedup_uses_means(self):
        comparison = metrics.compare_to_baseline([10.0, 12.0, 11.0], [5.0, 6.0, 5.5])
        self.assertAlmostEqual(comparison["speedup"], 2.0)
        self.assertAlmostEqual(comparison["percent_time_reduction"], 50.0)

    def test_verdict_rule(self):
        self.assertEqual(metrics.verdict({"p_holm": 0.01, "mean_difference": 2.0}),
                         "significantly faster")
        self.assertEqual(metrics.verdict({"p_holm": 0.01, "mean_difference": -2.0}),
                         "significantly slower")
        self.assertEqual(metrics.verdict({"p_holm": 0.20, "mean_difference": 2.0}),
                         "no significant difference")


class DistributionTests(unittest.TestCase):
    def test_chi_square_known_values(self):
        self.assertAlmostEqual(metrics.chi_square_sf(3.841458820694124, 1), 0.05, places=6)
        self.assertAlmostEqual(metrics.chi_square_sf(18.307038053275146, 10), 0.05, places=6)
        for x in (0.5, 2.0, 7.0, 30.0):
            self.assertAlmostEqual(metrics.chi_square_sf(x, 2), math.exp(-x / 2), places=10)



class AutopsyTrialAnalysisTests(unittest.TestCase):
    def rows(self):
        import random
        rng = random.Random(5)
        rows = []
        for block in range(1, 31):
            for code, mean in (("C0", 100.0), ("C1", 99.5), ("C2", 70.0), ("C3", 98.0), ("C4", 60.0),
                               ("R1", 90.0), ("R2", 120.0)):
                rows.append({"data_source": "image1.dd", "configuration": code, "trial_block": block,
                             "file_hashing_ms": mean + rng.gauss(0, 1.5),
                             "evidence_ms": 40 + rng.gauss(0, 0.5),
                             "throughput_mib_s": 10, "cpu_mean_percent": 20, "peak_rss_mib": 30,
                             "physical_cores": 6, "digest_agreement_percent": 100.0})
        rows.append({"data_source": "image1.dd", "configuration": "C4", "trial_block": 0,
                     "file_hashing_ms": 1.0, "evidence_ms": 1.0})
        return rows

    def test_four_comparisons_with_holm_and_paper_statistics(self):
        analysis = bench.analyze_autopsy_trials(self.rows())
        scope = analysis["data_sources"][0]["scopes"][0]
        self.assertEqual(scope["metric"], "file_hashing_ms")
        self.assertEqual([c["candidate"] for c in scope["comparisons"]], ["C1", "C2", "C3", "C4"])
        self.assertEqual(scope["configurations"]["C4"]["trials"], 30)  # block 0 excluded
        c4 = next(c for c in scope["comparisons"] if c["candidate"] == "C4")
        self.assertEqual(c4["verdict"], "significantly faster")
        self.assertAlmostEqual(c4["speedup"], 100.0 / 60.0, delta=0.05)
        self.assertIn(c4["test"], ("paired t-test", "Wilcoxon signed-rank"))
        self.assertIsNotNone(c4["amdahl_parallel_fraction"])
        ps = [c["p_value"] for c in scope["comparisons"]]
        self.assertEqual([c["p_holm"] for c in scope["comparisons"]], metrics.holm_adjust(ps))
        evidence = analysis["data_sources"][0]["scopes"][1]
        self.assertEqual(evidence["metric"], "evidence_ms")
        rows = bench.autopsy_summary_rows(analysis)
        self.assertEqual(len(rows), 14)


if __name__ == "__main__":
    unittest.main()
