"""Configuration and rule-file tests."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cagesight.config import Context, load_config, load_rules, merge_rules  # noqa: E402


class RulesMergeTest(unittest.TestCase):
    def test_partial_override_keeps_builtins(self):
        builtin = load_rules()
        payload = {"rules": [{"id": "CS-DNS-002", "enabled": False}]}
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "rules.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            merged = load_rules(path)

        self.assertEqual(len(merged["rules"]), len(builtin["rules"]))
        ctx = Context(load_config(), merged)
        self.assertFalse(ctx.enabled("CS-DNS-002"))
        self.assertTrue(ctx.enabled("CS-DNS-001"))

    def test_severity_override(self):
        merged = merge_rules(load_rules(), {"rules": [{"id": "CS-NET-001", "severity": "medium"}]})
        ctx = Context(load_config(), merged)
        self.assertEqual(ctx.severity("CS-NET-001"), "medium")

    def test_unknown_rule_is_appended(self):
        merged = merge_rules(
            load_rules(),
            {"rules": [{"id": "CS-X-001", "title": "custom", "severity": "low", "enabled": True}]},
        )
        ids = [rule["id"] for rule in merged["rules"]]
        self.assertIn("CS-X-001", ids)
        self.assertEqual(len(ids), len(load_rules()["rules"]) + 1)


class ConfigValidationTest(unittest.TestCase):
    def test_valid_config(self):
        Context(load_config(), load_rules())

    def test_wrong_threshold_type_raises(self):
        config = load_config()
        config["thresholds"]["dns"]["min_queries"] = "twenty"
        with self.assertRaises(ValueError):
            Context(config, load_rules())

    def test_wrong_list_type_raises(self):
        config = load_config()
        config["thresholds"]["net"]["common_ports"] = "80"
        with self.assertRaises(ValueError):
            Context(config, load_rules())


if __name__ == "__main__":
    unittest.main()
