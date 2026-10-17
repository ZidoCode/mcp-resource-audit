"""Tests for mcp-resource-audit."""

import io
import json
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, "/home/agentuser/mcp-resource-audit")

from mcp_resource_audit import audit, main, report  # noqa: E402


def run_main(lines):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["mcp-resource-audit", "-"])
    return rc, buf.getvalue()


def write(tmp, lines):
    p = tmp / "session.jsonl"
    p.write_text("\n".join(json.dumps(l) for l in lines) + "\n")
    return str(p)


def invoke_main(tmp, lines):
    path = write(tmp, lines)
    return main(["mcp-resource-audit", path])


def init_result(caps):
    return {"protocolVersion": "2025-06-18", "capabilities": caps,
            "serverInfo": {"name": "srv", "version": "1.0"}}


class TemplateLeak(unittest.TestCase):
    def test_template_in_resources_list(self):
        lines = [
            {"direction": "request", "id": 1, "method": "resources/list"},
            {"direction": "response", "id": 1, "result": {"resources": [
                {"uri": "file:///static.txt", "name": "static"},
                {"uri": "user://{userId}", "name": "profile"},
            ]}},
        ]
        findings = audit(lines)
        kinds = [f["kind"] for f in findings]
        self.assertIn("template-in-resources-list", kinds)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("java-sdk #319", findings[0]["ref"])

    def test_templates_in_template_list_ok(self):
        lines = [
            {"direction": "request", "id": 1, "method": "resources/templates/list"},
            {"direction": "response", "id": 1, "result": {"resourceTemplates": [
                {"uriTemplate": "user://{userId}", "name": "profile"}]}},
        ]
        self.assertEqual(substantive(audit(lines)), [])

    def test_clean_resources_list(self):
        lines = [
            {"direction": "request", "id": 1, "method": "resources/list"},
            {"direction": "response", "id": 1, "result": {"resources": [
                {"uri": "file:///a.txt"}, {"uri": "file:///b.txt"}]}},
        ]
        self.assertEqual(substantive(audit(lines)), [])

    def test_duplicate_resource_uri(self):
        lines = [
            {"direction": "request", "id": 1, "method": "resources/list"},
            {"direction": "response", "id": 1, "result": {"resources": [
                {"uri": "file:///a.txt"}, {"uri": "file:///a.txt"}]}},
        ]
        kinds = [f["kind"] for f in audit(lines)]
        self.assertIn("duplicate-resource-uri", kinds)


class MimeMismatch(unittest.TestCase):
    def test_blob_labeled_text(self):
        lines = [
            {"direction": "request", "id": 2, "method": "resources/read",
             "params": {"uri": "img://logo"}},
            {"direction": "response", "id": 2, "result": {"contents": [
                {"uri": "img://logo", "mimeType": "text/plain",
                 "blob": "aVZCT1J3"}]}},
        ]
        kinds = [f["kind"] for f in audit(lines)]
        self.assertIn("mime-mismatch", kinds)
        self.assertIn("python-sdk #152", findings_ref(audit(lines), "mime-mismatch"))

    def test_blob_with_image_mime_ok(self):
        lines = [
            {"direction": "request", "id": 2, "method": "resources/read"},
            {"direction": "response", "id": 2, "result": {"contents": [
                {"mimeType": "image/png", "blob": "aVZCT1J3"}]}},
        ]
        self.assertEqual(substantive(audit(lines)), [])


def substantive(findings):
    return [f for f in findings if f["severity"] != "INFO"]


def findings_ref(findings, kind):
    for f in findings:
        if f["kind"] == kind:
            return f["ref"]
    return ""


class NeverAnswered(unittest.TestCase):
    def test_resource_read_dropped(self):
        lines = [
            {"direction": "request", "id": 5, "method": "resources/read",
             "params": {"uri": "file:///x"}},
        ]
        findings = audit(lines)
        self.assertEqual(findings[0]["kind"], "request-never-answered")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("codex #20194", findings[0]["ref"])

    def test_prompts_get_dropped(self):
        lines = [{"direction": "request", "id": 7, "method": "prompts/get"}]
        self.assertEqual(audit(lines)[0]["kind"], "request-never-answered")

    def test_answered_ok(self):
        lines = [
            {"direction": "request", "id": 5, "method": "resources/read"},
            {"direction": "response", "id": 5, "result": {"contents": []}},
        ]
        self.assertEqual(substantive(audit(lines)), [])


class CapabilityIntegrity(unittest.TestCase):
    def test_method_not_found_on_advertised(self):
        lines = [
            {"direction": "request", "id": 0, "method": "initialize"},
            {"direction": "response", "id": 0, "result": init_result(
                {"prompts": {}})},
            {"direction": "request", "id": 1, "method": "prompts/list"},
            {"direction": "response", "id": 1,
             "error": {"code": -32601, "message": "Method not found"}},
        ]
        findings = audit(lines)
        self.assertEqual(findings[0]["kind"], "method-not-found-on-advertised")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_unadvertised_call(self):
        lines = [
            {"direction": "request", "id": 0, "method": "initialize"},
            {"direction": "response", "id": 0, "result": init_result({})},
            {"direction": "request", "id": 1, "method": "resources/list"},
            {"direction": "response", "id": 1, "result": {"resources": []}},
        ]
        kinds = [f["kind"] for f in audit(lines)]
        self.assertIn("unadvertised-call", kinds)
        self.assertEqual(
            [f["severity"] for f in findings_by_kind(audit(lines), "unadvertised-call")],
            ["CRITICAL"])

    def test_capability_lost(self):
        lines = [
            {"direction": "request", "id": 0, "method": "initialize"},
            {"direction": "response", "id": 0, "result": init_result(
                {"prompts": {}})},
        ]
        findings = audit(lines)
        kinds = [f["kind"] for f in findings]
        self.assertIn("capability-lost", kinds)
        self.assertEqual(findings_by_kind(audit(lines), "capability-lost")[0]["severity"],
                         "WARNING")
        self.assertIn("jcode #698", findings_ref(audit(lines), "capability-lost"))

    def test_advertised_and_used_clean(self):
        lines = [
            {"direction": "request", "id": 0, "method": "initialize"},
            {"direction": "response", "id": 0, "result": init_result(
                {"prompts": {}, "resources": {}})},
            {"direction": "request", "id": 1, "method": "prompts/list"},
            {"direction": "response", "id": 1, "result": {"prompts": []}},
            {"direction": "request", "id": 2, "method": "resources/list"},
            {"direction": "response", "id": 2, "result": {"resources": []}},
        ]
        self.assertEqual(substantive(audit(lines)), [])

    def test_no_initialize_info(self):
        findings = audit([])
        self.assertEqual(findings[0]["kind"], "no-initialize")
        self.assertEqual(findings[0]["severity"], "INFO")


def findings_by_kind(findings, kind):
    return [f for f in findings if f["kind"] == kind]


class PromptsShape(unittest.TestCase):
    def test_duplicate_prompt_name(self):
        lines = [
            {"direction": "request", "id": 1, "method": "prompts/list"},
            {"direction": "response", "id": 1, "result": {"prompts": [
                {"name": "review"}, {"name": "review"}]}},
        ]
        kinds = [f["kind"] for f in audit(lines)]
        self.assertIn("duplicate-prompt-name", kinds)


class Tolerance(unittest.TestCase):
    def test_junk_lines_never_crash(self):
        lines = [{"junk": "x"}, None, [1, 2], "string",
                 {"direction": "request", "id": 1, "method": "resources/list"},
                 {"direction": "response", "id": 1,
                  "error": {"code": -32603, "message": "boom"}}]
        # internal error is not -32601; nothing surfaced for pairing
        kinds = [f["kind"] for f in audit(lines)]
        self.assertNotIn("request-never-answered", kinds)

    def test_unicode(self):
        lines = [
            {"direction": "request", "id": 1, "method": "prompts/list"},
            {"direction": "response", "id": 1, "result": {"prompts": [
                {"name": "résumé-中文"}]}},
        ]
        self.assertEqual(substantive(audit(lines)), [])

    def test_missing_id_requests_tolerated(self):
        lines = [{"method": "resources/list", "result": None}]
        audit(lines)  # must not raise

    def test_empty(self):
        self.assertEqual(
            [f["kind"] for f in audit([])], ["no-initialize"])


class Cli(unittest.TestCase):
    def test_clean_exit_0(self, tmp=None):
        lines = [
            {"direction": "request", "id": 1, "method": "prompts/list"},
            {"direction": "response", "id": 1, "result": {"prompts": []}},
        ]
        self.assertEqual(invoke_main(self.tmp_dir(), lines), 0)

    def tmp_dir(self):
        import tempfile, os
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        import pathlib
        return pathlib.Path(d)

    def test_critical_exit_2(self):
        lines = [{"direction": "request", "id": 9, "method": "resources/read"}]
        self.assertEqual(invoke_main(self.tmp_dir(), lines), 2)

    def test_warning_exit_1(self):
        lines = [
            {"direction": "request", "id": 0, "method": "initialize"},
            {"direction": "response", "id": 0, "result": init_result(
                {"prompts": {}})},
        ]
        self.assertEqual(invoke_main(self.tmp_dir(), lines), 1)

    def test_missing_file_exit_2(self):
        self.assertEqual(main(["mcp-resource-audit", "/nonexistent/x.jsonl"]), 2)

    def test_no_args_exit_2(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["mcp-resource-audit"])
        self.assertEqual(rc, 2)
        self.assertIn("mcp-resource-audit", buf.getvalue())

    def test_report_format(self):
        text = report([{"severity": "CRITICAL", "kind": "k", "detail": "d",
                        "ref": "r"}], "/tmp/x.jsonl")
        self.assertIn("critical: 1", text)
        self.assertIn("[CRITICAL] k: d  (ref: r)", text)
        self.assertIn("x.jsonl", text)


if __name__ == "__main__":
    unittest.main()
