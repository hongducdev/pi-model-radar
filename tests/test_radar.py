#!/usr/bin/env python3
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location(
    'radar', Path(__file__).resolve().parents[1] / 'scripts' / 'radar.py'
)
assert spec is not None and spec.loader is not None
radar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(radar)


class TableParsingTests(unittest.TestCase):
    SAMPLE_TABLE = (
        "provider     model                         context  max-out  thinking  images\n"
        "antigravity  claude-opus-4-6               250K     64K      yes       yes\n"
        "antigravity  gemini-2.5-flash              1.0M     65.5K    yes       yes\n"
        "antigravity  gpt-oss-120b                  131.1K   32.8K    yes       no\n"
        "deepseek     deepseek-flash                1M       384K     yes       yes\n"
        "opencode-go  minimax-m2.7                  204.8K   131.1K   no        no\n"
    )

    def test_parse_models_table(self):
        models = radar.parse_models_table(self.SAMPLE_TABLE)
        self.assertEqual(len(models), 5)

        m0 = models[0]
        self.assertEqual(m0["id"], "antigravity/claude-opus-4-6")
        self.assertEqual(m0["provider"], "antigravity")
        self.assertEqual(m0["model"], "claude-opus-4-6")
        self.assertEqual(m0["context"], "250K")
        self.assertEqual(m0["context_tokens"], 250000)
        self.assertEqual(m0["max_out"], "64K")
        self.assertTrue(m0["thinking"])
        self.assertTrue(m0["images"])

        m1 = models[1]
        self.assertEqual(m1["id"], "antigravity/gemini-2.5-flash")
        self.assertEqual(m1["context_tokens"], 1000000)

        m2 = models[2]
        self.assertEqual(m2["id"], "antigravity/gpt-oss-120b")
        self.assertEqual(m2["context_tokens"], 131100)
        self.assertFalse(m2["images"])

        m3 = models[3]
        self.assertEqual(m3["id"], "deepseek/deepseek-flash")
        self.assertEqual(m3["context_tokens"], 1000000)

        m4 = models[4]
        self.assertEqual(m4["id"], "opencode-go/minimax-m2.7")
        self.assertEqual(m4["context_tokens"], 204800)
        self.assertFalse(m4["thinking"])
        self.assertFalse(m4["images"])

    def test_context_tokens_parsing(self):
        self.assertEqual(radar.parse_context_tokens("1.0M"), 1000000)
        self.assertEqual(radar.parse_context_tokens("1M"), 1000000)
        self.assertEqual(radar.parse_context_tokens("1.1M"), 1100000)
        self.assertEqual(radar.parse_context_tokens("131.1K"), 131100)
        self.assertEqual(radar.parse_context_tokens("250K"), 250000)
        self.assertEqual(radar.parse_context_tokens("262.1K"), 262100)
        self.assertEqual(radar.parse_context_tokens("32.8K"), 32800)
        self.assertEqual(radar.parse_context_tokens("8192"), 8192)
        self.assertEqual(radar.parse_context_tokens("-"), 0)
        self.assertEqual(radar.parse_context_tokens(""), 0)


class DiffTests(unittest.TestCase):
    def test_diff_initial_scan(self):
        models = [{"id": "p/m1"}, {"id": "p/m2"}]
        probes, diff = radar.calculate_diff(None, models, "p/m1")
        self.assertEqual(probes, {})
        self.assertEqual(diff["added"], ["p/m1", "p/m2"])
        self.assertEqual(diff["removed"], [])
        self.assertIsNone(diff["default_changed"])

    def test_diff_added_removed_and_default_changed(self):
        old_report = {
            "models": [{"id": "p/m1"}, {"id": "p/m2"}],
            "default": "p/m1",
            "probes": {
                "p/m1": {"ok": True},
                "p/m2": {"ok": False},
            },
        }
        current_models = [{"id": "p/m2"}, {"id": "p/m3"}]
        current_default = "p/m3"

        probes, diff = radar.calculate_diff(old_report, current_models, current_default)
        self.assertEqual(diff["added"], ["p/m3"])
        self.assertEqual(diff["removed"], ["p/m1"])
        self.assertEqual(diff["default_changed"], {"from": "p/m1", "to": "p/m3"})
        self.assertEqual(probes, {"p/m2": {"ok": False}})

    def test_diff_default_unchanged(self):
        old_report = {
            "models": [{"id": "p/m1"}],
            "default": "p/m1",
            "probes": {},
        }
        current_models = [{"id": "p/m1"}]
        current_default = "p/m1"

        _, diff = radar.calculate_diff(old_report, current_models, current_default)
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertIsNone(diff["default_changed"])


class MaskingTests(unittest.TestCase):
    def test_mask_sk_token(self):
        res = radar.mask_secrets("Failed with key sk-proj-1234567890abcdef")
        self.assertEqual(res, "Failed with key sk-p***")

    def test_mask_bearer_token(self):
        res = radar.mask_secrets("Authorization: Bearer mysecrettoken12345")
        self.assertEqual(res, "Authorization: Bearer myse***")

    def test_mask_long_string(self):
        token = "a" * 32
        res = radar.mask_secrets(f"secret token is {token}")
        self.assertEqual(res, "secret token is aaaa***")

    def test_mask_key_value(self):
        res1 = radar.mask_secrets("key=supersecretpass123")
        self.assertEqual(res1, "key=supe***")

        res2 = radar.mask_secrets('"api_key": "mysecretapikey999"')
        self.assertEqual(res2, '"api_key": "myse***"')

    def test_safe_strings_not_masked(self):
        text = "status ok, model response received in 0.45s"
        self.assertEqual(radar.mask_secrets(text), text)

    def test_already_masked_not_corrupted(self):
        self.assertEqual(radar.mask_secrets("Bearer abcd***"), "Bearer abcd***")
        self.assertEqual(radar.mask_secrets("sk-1***"), "sk-1***")
        self.assertEqual(radar.mask_secrets("key=myse***"), "key=myse***")


class ProbeRefusalTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.report_path = Path(self.td.name) / "pi-model-radar.json"
        self.orig_env = os.environ.get("PI_RADAR_REPORT")
        os.environ["PI_RADAR_REPORT"] = str(self.report_path)

    def tearDown(self):
        if self.orig_env is not None:
            os.environ["PI_RADAR_REPORT"] = self.orig_env
        else:
            os.environ.pop("PI_RADAR_REPORT", None)
        self.td.cleanup()

    @patch("subprocess.run")
    def test_probe_refuses_unknown_id_without_subprocess(self, mock_run):
        report = {
            "scanned_at": "2026-03-30T00:00:00+00:00",
            "default": "p/m1",
            "models": [{"id": "p/m1"}],
            "probes": {},
            "diff": {"added": [], "removed": [], "default_changed": None},
        }
        self.report_path.write_text(json.dumps(report), encoding="utf-8")

        code = radar.probe("p/unknown-model")
        self.assertEqual(code, 2)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_probe_refuses_when_no_report_without_subprocess(self, mock_run):
        code = radar.probe("p/m1")
        self.assertEqual(code, 2)
        mock_run.assert_not_called()


class ProbeOkPathTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.report_path = Path(self.td.name) / "pi-model-radar.json"
        self.orig_env = os.environ.get("PI_RADAR_REPORT")
        os.environ["PI_RADAR_REPORT"] = str(self.report_path)

        report = {
            "scanned_at": "2026-03-30T00:00:00+00:00",
            "default": "provider/test-model",
            "models": [{"id": "provider/test-model"}],
            "probes": {},
            "diff": {"added": ["provider/test-model"], "removed": [], "default_changed": None},
        }
        self.report_path.write_text(json.dumps(report), encoding="utf-8")

    def tearDown(self):
        if self.orig_env is not None:
            os.environ["PI_RADAR_REPORT"] = self.orig_env
        else:
            os.environ.pop("PI_RADAR_REPORT", None)
        self.td.cleanup()

    @patch("subprocess.run")
    def test_probe_ok_path(self, mock_run):
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "Reply: pong\n"
        proc.stderr = ""
        mock_run.return_value = proc

        code = radar.probe("provider/test-model", timeout=30)
        self.assertEqual(code, 0)
        mock_run.assert_called_once()
        cmd_called = mock_run.call_args[0][0]
        self.assertEqual(
            cmd_called[1:],
            ["-p", "reply with exactly: pong", "--model", "provider/test-model"],
        )

        saved = json.loads(self.report_path.read_text(encoding="utf-8"))
        probe_rec = saved["probes"]["provider/test-model"]
        self.assertTrue(probe_rec["ok"])
        self.assertIsNone(probe_rec["error"])
        self.assertIn("latency_s", probe_rec)
        self.assertIn("at", probe_rec)


class RecommendOrderingTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.report_path = Path(self.td.name) / "pi-model-radar.json"
        self.orig_env = os.environ.get("PI_RADAR_REPORT")
        os.environ["PI_RADAR_REPORT"] = str(self.report_path)

    def tearDown(self):
        if self.orig_env is not None:
            os.environ["PI_RADAR_REPORT"] = self.orig_env
        else:
            os.environ.pop("PI_RADAR_REPORT", None)
        self.td.cleanup()

    def test_recommend_ordering_default_first_then_context_desc(self):
        report = {
            "scanned_at": "2026-03-30T00:00:00+00:00",
            "default": "p/default-model",
            "models": [
                {"id": "p/small", "context": "128K", "context_tokens": 128000},
                {"id": "p/default-model", "context": "256K", "context_tokens": 256000},
                {"id": "p/huge", "context": "1.0M", "context_tokens": 1000000},
                {"id": "p/failed", "context": "2.0M", "context_tokens": 2000000},
            ],
            "probes": {
                "p/small": {"ok": True, "latency_s": 0.5},
                "p/default-model": {"ok": True, "latency_s": 0.8},
                "p/huge": {"ok": True, "latency_s": 1.2},
                "p/failed": {"ok": False, "latency_s": 2.0, "error": "timeout"},
            },
            "diff": {"added": [], "removed": [], "default_changed": None},
        }
        self.report_path.write_text(json.dumps(report), encoding="utf-8")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = radar.recommend()
        self.assertEqual(code, 0)
        output = buf.getvalue()

        pos_default = output.find("p/default-model")
        pos_huge = output.find("p/huge")
        pos_small = output.find("p/small")

        self.assertNotEqual(pos_default, -1)
        self.assertNotEqual(pos_huge, -1)
        self.assertNotEqual(pos_small, -1)
        self.assertIn("DEFAULT", output)
        self.assertNotIn("p/failed", output)

        self.assertLess(pos_default, pos_huge)
        self.assertLess(pos_huge, pos_small)

    def test_recommend_none_probed_ok(self):
        report = {
            "scanned_at": "2026-03-30T00:00:00+00:00",
            "default": "p/def",
            "models": [{"id": "p/def", "context": "128K", "context_tokens": 128000}],
            "probes": {"p/def": {"ok": False, "error": "failed"}},
            "diff": {"added": [], "removed": [], "default_changed": None},
        }
        self.report_path.write_text(json.dumps(report), encoding="utf-8")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = radar.recommend()
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("No models have been verified", output)
        self.assertIn("Suggest probing the default", output)


class ScanAndStatusIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.report_path = Path(self.td.name) / "pi-model-radar.json"
        self.settings_path = Path(self.td.name) / "settings.json"
        self.orig_report = os.environ.get("PI_RADAR_REPORT")
        self.orig_settings = os.environ.get("PI_SETTINGS_PATH")
        os.environ["PI_RADAR_REPORT"] = str(self.report_path)
        os.environ["PI_SETTINGS_PATH"] = str(self.settings_path)

    def tearDown(self):
        if self.orig_report is not None:
            os.environ["PI_RADAR_REPORT"] = self.orig_report
        else:
            os.environ.pop("PI_RADAR_REPORT", None)

        if self.orig_settings is not None:
            os.environ["PI_SETTINGS_PATH"] = self.orig_settings
        else:
            os.environ.pop("PI_SETTINGS_PATH", None)
        self.td.cleanup()

    @patch("subprocess.run")
    def test_scan_and_status(self, mock_run):
        self.settings_path.write_text(
            json.dumps({"defaultProvider": "antigravity", "defaultModel": "gemini-flash"}),
            encoding="utf-8",
        )
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = (
            "provider     model                         context  max-out  thinking  images\n"
            "antigravity  gemini-flash                  1.0M     64K      yes       yes\n"
            "deepseek     deepseek-v4                   1M       128K     yes       no\n"
        )
        mock_run.return_value = proc

        code = radar.scan()
        self.assertEqual(code, 0)
        self.assertTrue(self.report_path.is_file())

        saved = json.loads(self.report_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["default"], "antigravity/gemini-flash")
        self.assertEqual(len(saved["models"]), 2)
        self.assertEqual(saved["diff"]["added"], ["antigravity/gemini-flash", "deepseek/deepseek-v4"])

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code_st = radar.status()
        self.assertEqual(code_st, 0)
        output = buf.getvalue()
        self.assertIn("Models: 2 total", output)
        self.assertIn("Default: antigravity/gemini-flash", output)
        self.assertIn("Probes: 0 ok, 0 failed", output)


if __name__ == '__main__':
    unittest.main()
