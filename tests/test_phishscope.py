"""Unit tests for PhishScope (run:  python -m unittest discover -s tests -v   from the project root, with src on the path)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import engine as E          # noqa: E402
import evalkit as K         # noqa: E402
import features as F        # noqa: E402
import rules_engine as R    # noqa: E402


class TestParsing(unittest.TestCase):
    def test_plain_domain(self):
        t = E.parse_target("example.com")
        self.assertEqual((t["host"], t["reg"], t["subdomain"]), ("example.com", "example.com", ""))

    def test_defanged_url_is_accepted(self):
        t = E.parse_target("hxxps://login[.]secure[.]example[.]co[.]uk/verify?id=1")
        self.assertEqual(t["host"], "login.secure.example.co.uk")
        self.assertEqual(t["reg"], "example.co.uk")
        self.assertEqual(t["subdomain"], "login.secure")
        self.assertIn("verify", t["path"])

    def test_shared_platform_is_detected(self):
        t = E.parse_target("my-shop.pages.dev")
        self.assertTrue(t["shared_platform"])
        self.assertEqual(t["reg"], "my-shop.pages.dev")

    def test_ip_and_garbage_rejected(self):
        for bad in ("http://192.168.0.1/login", "not a url", ""):
            with self.assertRaises(ValueError):
                E.parse_target(bad)


class TestRules(unittest.TestCase):
    def row(self, **kw):
        base = {"brand_typosquat": 0, "brand_contained": 0, "brand_in_subdomain": 0, "n_suspicious_words": 0, "n_hyphens": 0, "digit_ratio": 0.0,
                "entropy": 2.0, "longest_consonant_run": 2, "is_punycode": 0, "suffix": "com", "shared_platform": 0, "age_days": 4000, "dns_ok": 1,
                "mx_count": 1, "has_spf": 1, "has_dmarc": 1, "txt_count": 3, "ttl": 3600, "has_www": 1, "n_vulns": 0,
                "shared_ip_known_phish": 0, "shared_ns_known_phish": 0, "status_hold_or_lock": 0}
        base.update(kw)
        return base

    def test_clean_established_site_scores_zero(self):
        score, fired, level = R.evaluate(self.row())
        self.assertEqual((score, fired, level), (0, [], "LOW"))

    def test_new_domain_with_scam_words_is_high(self):
        score, fired, level = R.evaluate(self.row(age_days=5, n_suspicious_words=2, suffix="top", mx_count=0, has_spf=0, has_dmarc=0, txt_count=0))
        ids = {f[0] for f in fired}
        self.assertTrue({"R1", "N4", "N5", "N9", "D1", "D2"} <= ids)
        self.assertEqual(level, "HIGH")

    def test_score_is_capped_at_100(self):
        score, _, _ = R.evaluate(self.row(age_days=1, brand_typosquat=1, brand_contained=1, brand_in_subdomain=1, n_suspicious_words=3, n_hyphens=4,
                                          digit_ratio=.5, is_punycode=1, suffix="tk", shared_platform=1, shared_ip_known_phish=2, shared_ns_known_phish=1,
                                          mx_count=0, has_spf=0, has_dmarc=0, txt_count=0))
        self.assertEqual(score, 100)

    def test_age_rules_are_mutually_exclusive(self):
        for age, expect in ((10, "R1"), (60, "R2"), (200, "R3")):
            ids = {f[0] for f in R.evaluate(self.row(age_days=age))[1]}
            self.assertIn(expect, ids)
            self.assertEqual(len(ids & {"R1", "R2", "R3"}), 1)

    def test_level_boundaries(self):
        self.assertEqual(dict(R.LEVELS)[50], "HIGH")
        self.assertEqual(dict(R.LEVELS)[25], "MEDIUM")
        self.assertEqual(R.evaluate(self.row(age_days=10))[2], "MEDIUM")     # 30 points

    def test_every_rule_has_unique_id_and_positive_points(self):
        ids = [r.id for r in R.RULES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(r.points > 0 for r in R.RULES))


class TestFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.brands = F.load_brands()

    def test_typosquat_of_a_top_brand_is_flagged(self):
        X = F.lexical_frame(["gooogle.com", "totally-unrelated-name.com"], self.brands)
        self.assertEqual(int(X.loc[0, "brand_typosquat"]), 1)
        self.assertEqual(int(X.loc[1, "brand_typosquat"]), 0)

    def test_entropy(self):
        self.assertEqual(F.entropy("aaaa"), 0.0)
        self.assertAlmostEqual(F.entropy("abab"), 1.0)

    def test_suspicious_words_counted(self):
        X = F.lexical_frame(["secure-login-verify.com"], self.brands)
        self.assertGreaterEqual(int(X.loc[0, "n_suspicious_words"]), 3)


class TestEvalKit(unittest.TestCase):
    def test_wilson_interval_contains_estimate(self):
        lo, hi = K.wilson(30, 100)
        self.assertLess(lo, 0.30)
        self.assertGreater(hi, 0.30)

    def test_precision_falls_with_prevalence(self):
        hi = K.precision_at_prevalence(0.5, 0.01, 0.5)
        lo = K.precision_at_prevalence(0.5, 0.01, 0.01)
        self.assertGreater(hi, 0.9)
        self.assertLess(lo, 0.4)

    def test_threshold_at_fpr(self):
        import numpy as np
        y = np.array([0] * 100 + [1] * 10)
        p = np.concatenate([np.linspace(0, 0.5, 100), np.linspace(0.6, 1, 10)])
        thr = K.threshold_at_fpr(y, p, 0.01)
        self.assertLess((p[y == 0] >= thr).mean(), 0.02)


if __name__ == "__main__":
    unittest.main(verbosity=2)
