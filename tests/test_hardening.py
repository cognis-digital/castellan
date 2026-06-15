"""Hardening tests — edge cases, bad input, and error-handling paths."""
from __future__ import annotations

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatmodeler import parse_spec, SpecError  # noqa: E402
from threatmodeler.cli import main  # noqa: E402
from threatmodeler.mcp_server import _analyze  # noqa: E402


# ---------------------------------------------------------------------------
# Helper for capturing CLI output
# ---------------------------------------------------------------------------

def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = main(argv)
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# parse_spec edge cases
# ---------------------------------------------------------------------------

class ParseSpecEdgeCasesTest(unittest.TestCase):
    def test_empty_string_raises(self):
        """Empty string must raise SpecError, not hang or produce garbage."""
        with self.assertRaises(SpecError) as ctx:
            parse_spec("")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_whitespace_only_raises(self):
        """Whitespace-only input must raise SpecError."""
        with self.assertRaises(SpecError):
            parse_spec("   \n\t  ")

    def test_non_string_input_raises(self):
        """Passing bytes or None must raise SpecError, not TypeError."""
        with self.assertRaises(SpecError):
            parse_spec(None)  # type: ignore[arg-type]

    def test_blank_element_name_raises(self):
        """An element whose name is whitespace-only must be rejected."""
        spec_text = (
            "name: X\n"
            "elements:\n"
            "  - name: ' '\n"
            "    type: process\n"
        )
        with self.assertRaises(SpecError) as ctx:
            parse_spec(spec_text)
        self.assertIn("blank", str(ctx.exception).lower())

    def test_no_elements_raises(self):
        """A spec without any elements must raise SpecError."""
        with self.assertRaises(SpecError):
            parse_spec("name: X\n")

    def test_empty_elements_list_raises(self):
        """An empty elements list must raise SpecError."""
        with self.assertRaises(SpecError):
            parse_spec("name: X\nelements: []\n")


# ---------------------------------------------------------------------------
# CLI error-path tests (exit codes)
# ---------------------------------------------------------------------------

class CliErrorPathsTest(unittest.TestCase):

    def test_missing_file_returns_exit_2(self):
        """Analyzing a non-existent file must exit with code 2, not crash."""
        code, _, err = _run(["analyze", "/no/such/file/spec.yml"])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err.lower())

    def test_missing_file_validate_returns_exit_2(self):
        """Validating a non-existent file must exit with code 2."""
        code, _, err = _run(["validate", "/no/such/file/spec.yml"])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err.lower())

    def test_empty_stdin_validate_returns_nonzero(self):
        """Passing empty stdin to validate must exit non-zero with a clear error."""
        old = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            code, _, err = _run(["validate", "-"])
        finally:
            sys.stdin = old
        self.assertNotEqual(code, 0)

    def test_empty_stdin_analyze_returns_nonzero(self):
        """Passing empty stdin to analyze must exit non-zero with a clear error."""
        old = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            code, _, err = _run(["analyze", "-"])
        finally:
            sys.stdin = old
        self.assertNotEqual(code, 0)

    def test_malformed_spec_via_stdin_returns_exit_2(self):
        """A malformed spec via stdin must yield exit code 2 (parse error)."""
        old = sys.stdin
        sys.stdin = io.StringIO("name: Bad\nelements:\n  - name: a\n    type: wormhole\n")
        try:
            code, _, err = _run(["analyze", "-"])
        finally:
            sys.stdin = old
        self.assertEqual(code, 2)
        self.assertIn("spec error", err.lower())

    def test_validate_json_bad_spec_returns_json_error(self):
        """validate --format json on bad input must return JSON with valid=false."""
        old = sys.stdin
        sys.stdin = io.StringIO("elements: []\n")
        try:
            code, out, _ = _run(["--format", "json", "validate", "-"])
        finally:
            sys.stdin = old
        self.assertNotEqual(code, 0)
        data = json.loads(out)
        self.assertFalse(data["valid"])
        self.assertIn("error", data)


# ---------------------------------------------------------------------------
# MCP server _analyze helper
# ---------------------------------------------------------------------------

class McpAnalyzeHelperTest(unittest.TestCase):
    def test_empty_spec_returns_json_error(self):
        """_analyze('') must return JSON with an 'error' key, not raise."""
        result = json.loads(_analyze(""))
        self.assertIn("error", result)

    def test_whitespace_only_returns_json_error(self):
        result = json.loads(_analyze("   "))
        self.assertIn("error", result)

    def test_invalid_spec_returns_json_error(self):
        result = json.loads(_analyze("name: X\nelements: []\n"))
        self.assertIn("error", result)

    def test_valid_spec_returns_threats(self):
        spec = (
            "name: MCPTest\n"
            "elements:\n"
            "  - name: svc\n"
            "    type: process\n"
        )
        result = json.loads(_analyze(spec))
        self.assertNotIn("error", result)
        self.assertIn("threats", result)
        self.assertGreater(len(result["threats"]), 0)


if __name__ == "__main__":
    unittest.main()
