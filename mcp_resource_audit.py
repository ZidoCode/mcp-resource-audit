#!/usr/bin/env python3
"""mcp-resource-audit — audit a recorded MCP session's resource, template,
prompt, and capability-negotiation surface.

Half of MCP never touches tools/call — resources, resource templates, and
prompts — and that half fails silently in ways a tool-focused audit never
sees: URI templates leak into resources/list so clients address URIs that
can never resolve (modelcontextprotocol/java-sdk #319); a declared mimeType
is ignored and a base64 PNG arrives labeled text/plain
(modelcontextprotocol/python-sdk #152); handlers log a request and never
answer, leaving the client hung until timeout (openai/codex #20194); the
prompts capability is parsed and thrown away so prompt-gallery servers
appear empty (1jehuang/jcode #698, warpdotdev/warp #9456); clients call
methods the server never advertised and squash the resulting
method-not-found into a warning (modelcontextprotocol/python-sdk #2689).

All of these are visible in a recorded transcript — if something actually
looks.

Input: JSONL where each line is one recorded message:
  {"direction":"request","id":1,"method":"resources/list","params":{...}}
  {"direction":"response","id":1,"result":{...}}          # or "error":{...}
(direction defaults to "response" when a line has a result/error and no
method; bare JSON-RPC batches and raw client/server logs are tolerated.)

Checks (each maps to a real bug someone already shipped):
  1. template-in-resources-list — a URI containing {param} returned by
     resources/list instead of resources/templates/list (java-sdk #319)
  2. duplicate resource URI / duplicate prompt name
  3. mime-mismatch — resources/read response mimeType "text/plain" but
     content carries a "blob" (binary) field (python-sdk #152)
  4. request-never-answered — a resources/* or prompts/* request with an
     id that got no response at all (codex #20194 dropped-request hang)
  5. method-not-found-on-advertised — server advertised resources/prompts
     in initialize but answered -32601 to their list call (python-sdk
     #2689 in reverse: server lies at init)
  6. unadvertised-call — session calls a resources/* or prompts/* method
     the initialize result never advertised (spec violation, python-sdk
     #2689)
  7. capability-lost — initialize response contains the capability but the
     session never issues the corresponding list call (jcode #698, warp
     #9456: parsed and discarded)

Exit codes: 0 = clean, 1 = warnings only, 2 = any CRITICAL finding.
"""

import json
import os
import argparse
import sys

CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"

RESOURCE_METHODS = {
    "resources/list", "resources/templates/list", "resources/read",
    "resources/subscribe", "resources/unsubscribe",
}
PROMPT_METHODS = {"prompts/list", "prompts/get"}
CAPABILITY_METHODS = {
    "resources": "resources/list",
    "prompts": "prompts/list",
}


def audit(lines):
    """Audit an iterable of parsed JSON lines. Returns a list of findings."""
    findings = []

    def add(severity, kind, detail, ref):
        findings.append({"severity": severity, "kind": kind,
                         "detail": detail, "ref": ref})

    # -- pass 1: index messages ------------------------------------------
    requests = {}        # id -> {method, line}
    responses = {}       # id -> {line, result, error}
    init_result = None

    for lineno, obj in enumerate(lines, 1):
        if not isinstance(obj, dict):
            continue
        direction = obj.get("direction")
        method = obj.get("method")
        rid = obj.get("id")
        if direction == "request" or (method and rid is not None):
            requests[rid] = {"method": method, "line": lineno}
        elif direction == "response" or ("result" in obj or "error" in obj):
            responses[rid] = {"line": lineno, "result": obj.get("result"),
                              "error": obj.get("error")}
        # notifications and unknown shapes are tolerated silently

    for rid, res in sorted(
            responses.items(),
            key=lambda kv: (kv[0] is None, str(type(kv[0])), str(kv[0]))):
        result = res.get("result")
        if isinstance(result, dict) and isinstance(result.get("capabilities"), dict) \
                and ("serverInfo" in result or "protocolVersion" in result):
            init_result = result

    caps = {}
    if isinstance(init_result, dict):
        caps = init_result.get("capabilities") or {}

    # -- pass 2: request/response pairing on resource/prompt surface ------
    for rid, req in requests.items():
        method = req.get("method") or ""
        if not (method in RESOURCE_METHODS or method in PROMPT_METHODS):
            continue
        res = responses.get(rid)
        if res is None:
            add(CRITICAL, "request-never-answered",
                "line %d: %s (id %s) never received a response — client waits "
                "until timeout" % (req["line"], method, rid),
                "openai/codex #20194")
            continue
        err = res.get("error")
        if isinstance(err, dict) and err.get("code") == -32601:
            cap = method.split("/")[0]
            if cap in caps:
                add(CRITICAL, "method-not-found-on-advertised",
                    "line %d: %s answered -32601 but '%s' was advertised in "
                    "initialize — server lies at init" % (res["line"], method, cap),
                    "python-sdk #2689 (reverse direction)")
            else:
                add(WARNING, "unadvertised-call",
                    "line %d: %s called but not advertised in initialize — "
                    "spec says only negotiate capabilities you will use"
                    % (req["line"], method), "python-sdk #2689")

    # -- pass 3: resources/list shape, read mime, prompts shape -----------
    for rid, res in responses.items():
        result = res.get("result")
        if not isinstance(result, dict):
            continue
        req = requests.get(rid) or {}
        method = req.get("method") or ""

        if method == "resources/list" or (
                "resources" in result and "resourceTemplates" not in result):
            seen = set()
            for r in result.get("resources", []) or []:
                if not isinstance(r, dict):
                    continue
                uri = r.get("uri", "")
                if not isinstance(uri, str):
                    add(WARNING, "duplicate-resource-uri",
                        "line %d: resource uri is not a string (%r)"
                        % (res["line"], type(uri).__name__), "hygiene")
                    continue
                if "{" in uri and "}" in uri:
                    add(CRITICAL, "template-in-resources-list",
                        "line %d: resources/list returned templated URI '%s' — "
                        "templates belong in resources/templates/list; clients "
                        "cannot read this" % (res["line"], uri),
                        "modelcontextprotocol/java-sdk #319")
                if uri in seen:
                    add(WARNING, "duplicate-resource-uri",
                        "line %d: duplicate resource uri '%s'" % (res["line"], uri),
                        "hygiene")
                seen.add(uri)

        if method == "resources/read" and isinstance(result, dict):
            for c in result.get("contents", []) or []:
                if not isinstance(c, dict):
                    continue
                mime = c.get("mimeType", "")
                if "blob" in c and mime in ("text/plain", ""):
                    add(WARNING, "mime-mismatch",
                        "line %d: resources/read returned a blob with mimeType "
                        "'%s' — binary content labeled as text; declared type "
                        "likely ignored" % (res["line"], mime or "(none)"),
                        "modelcontextprotocol/python-sdk #152")

        if "prompts" in result and isinstance(result["prompts"], list):
            seen = set()
            for p in result["prompts"]:
                name = p.get("name") if isinstance(p, dict) else None
                if not isinstance(name, str):
                    name = repr(name) if name is not None else None
                if name in seen:
                    add(WARNING, "duplicate-prompt-name",
                        "line %d: duplicate prompt name '%s'" % (res["line"], name),
                        "hygiene")
                seen.add(name)

    # -- pass 4: capability integrity -------------------------------------
    for cap, list_method in CAPABILITY_METHODS.items():
        advertised = cap in caps
        called = any((req.get("method") or "") == list_method
                     for req in requests.values())
        if init_result is None:
            # recording starts after init (partial capture): capability
            # comparisons would be guesses, so only pairing checks run
            continue
        if advertised and not called:
            add(WARNING, "capability-lost",
                "initialize advertised '%s' but the session never called %s — "
                "clients that parse-and-drop capabilities make prompt servers "
                "invisible" % (cap, list_method),
                "1jehuang/jcode #698, warpdotdev/warp #9456")
        if called and not advertised:
            add(CRITICAL, "unadvertised-call",
                "session calls %s but initialize never advertised '%s' — "
                "spec violation" % (list_method, cap), "python-sdk #2689")

    if init_result is None:
        add(INFO, "no-initialize",
            "no initialize response found — capability checks skipped",
            "n/a")

    return findings


def report(findings, src=""):
    counts = {CRITICAL: 0, WARNING: 0, INFO: 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    name = os.path.basename(src) if src else ""
    out = ["mcp-resource-audit%s" % (" — " + name if name else ""),
           "critical: %d  warning: %d  info: %d"
           % (counts[CRITICAL], counts[WARNING], counts[INFO])]
    for f in findings:
        out.append("[%s] %s: %s  (ref: %s)"
                   % (f["severity"], f["kind"], f["detail"], f["ref"]))
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mcp-resource-audit",
        description="Audit a captured MCP session for resource/URI-handling bugs.",
    )
    parser.add_argument("path", nargs="?", help="JSONL session capture to audit")
    args = parser.parse_args(sys.argv[1:] if argv is None else list(argv)[1:])
    if not args.path:
        parser.print_help()
        return 2
    src = args.path
    try:
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        print("cannot read %s: %s" % (src, exc))
        return 2
    lines = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            lines.append(json.loads(ln))
        except ValueError:
            lines.append({"junk": ln})
    findings = audit(lines)
    print(report(findings, src))
    if any(f["severity"] == CRITICAL for f in findings):
        return 2
    if any(f["severity"] == WARNING for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
