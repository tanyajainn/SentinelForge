"""Regression coverage for the audited campus isolation issue SF-26."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from sentinelforge.campus import render, safe_endpoint


class CampusHardeningTests(unittest.TestCase):
    def test_malformed_timestamp_does_not_break_other_endpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for alias, stamp in (("bad", 123), ("good", "2026-11-16T10:00:00+00:00")):
                folder = root / alias
                folder.mkdir()
                (folder / "batch-00000000000000000001.json").write_text(
                    json.dumps([[1, stamp, "high", "event-4625"]]), encoding="utf-8")
            html = render(root, ["bad", "good"])
            self.assertIn("Alert history unreadable", html)
            self.assertIn("good", html)
            self.assertIn("2026-11-16T10:00:00+00:00", html)

    def test_oversized_batch_rejected_without_global_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "over"
            folder.mkdir()
            (folder / "batch-00000000000000000001.json").write_text(
                "x" * 300000, encoding="utf-8")
            self.assertIn("Alert history unreadable", render(root, ["over"]))

    def test_direct_render_validates_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertRaises(ValueError, safe_endpoint, Path(temp), "../escape")
            self.assertRaises(ValueError, safe_endpoint, Path(temp), "CON")
            html = render(Path(temp), ["../escape"])
            self.assertIn("Alert history unreadable", html)

    def test_csp_present_and_html_escaped(self):
        with tempfile.TemporaryDirectory() as temp:
            html = render(Path(temp), ["<script>"])
            self.assertIn("Content-Security-Policy", html)
            self.assertNotIn("<script>", html)


if __name__ == "__main__":
    unittest.main()
