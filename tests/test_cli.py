import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args, data=None):
    return subprocess.run(
        [sys.executable, "-m", "hostgrant_diff", *map(str, args)],
        input=data,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=15,
    )


class CliTests(unittest.TestCase):
    def test_complete_report_flow(self):
        before, after = [ROOT / f"examples/{name}.json" for name in ["before", "after"]]
        original = (before.read_bytes(), after.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            result = run(before, after, "-o", report)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, "")
            saved = report.read_bytes()
            self.assertEqual(json.loads(saved)["status"], "host-expansion")
            self.assertEqual(run(before, after, "-o", report).returncode, 2)
            self.assertEqual(report.read_bytes(), saved)
        self.assertEqual((before.read_bytes(), after.read_bytes()), original)

    def test_equivalent_exit_zero(self):
        result = run(
            ROOT / "examples/equivalent-before.json", ROOT / "examples/equivalent-after.json"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "no-host-expansion")

    def test_stdin_and_non_echoing_errors(self):
        before = ROOT / "examples/before.json"
        after = ROOT / "examples/after.json"
        self.assertEqual(run("-", after, data=before.read_text()).returncode, 1)
        self.assertEqual(run("-", "-", data="{}").returncode, 2)
        secret = "SYNTHETIC_PRIVATE_MARKER"
        for result in [
            run("-", after, data="{" + secret),
            run(secret, after),
            run("-", after, data=json.dumps({"manifest_version": 3, "host_permissions": [secret]})),
        ]:
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(secret, result.stdout + result.stderr)

    def test_input_overwrite_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "manifest.json"
            source.write_text('{"manifest_version":3}')
            before = source.read_bytes()
            self.assertEqual(run(source, source, "-o", source).returncode, 2)
            self.assertEqual(source.read_bytes(), before)

    def test_help_and_version(self):
        self.assertEqual(run("--help").returncode, 0)
        self.assertEqual(run("--version").stdout.strip(), "0.1.0")


if __name__ == "__main__":
    unittest.main()
