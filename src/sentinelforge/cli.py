"""`sentinelforge` command-line tool (library). No server or database required.

    sentinelforge rules validate [PATH ...]                     # default: builtin packs
    sentinelforge rules test --rules PATH ... --tests DIR       # per-rule match / no-match tests
    sentinelforge coverage export --rules PATH ... [--check | --summary]
    sentinelforge profile inventory.json
    sentinelforge evaluate --source windows [--rules ...] [--inventory inv.json] events.ndjson
    sentinelforge forward --url http://sentinelforge:8000 --source docker [--host NAME] -
"""

import argparse
import itertools
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

from sentinelforge import __version__


def _rules(paths: list[str]):
    from sentinelforge.rules.loader import load_rule_paths

    return load_rule_paths(paths)


def _print_load_errors(errors: dict) -> None:
    for path, errs in errors.items():
        print(f"  FAIL  {path}")
        for e in errs:
            print(f"          {e}")


def cmd_validate(a) -> int:
    report = _rules(a.paths or ["builtin"])
    for r in report.rules:
        print(f"  OK    {r.definition.id:16} v{r.definition.version:6} {r.definition.name}")
    _print_load_errors(report.errors)
    print(f"{len(report.rules)} valid, {len(report.errors)} invalid")
    return 1 if report.errors else 0


def cmd_test(a) -> int:
    from sentinelforge.rules.testing import run_all

    report = _rules(a.rules)
    if report.errors:
        _print_load_errors(report.errors)
        return 1
    results, errors = run_all(report.rules, Path(a.tests), [Path(d) for d in a.inventory_dir] or None,
                              require_tests=not a.allow_untested)
    cases = 0
    for r in results:
        cases += r.cases
        print(f"  {'PASS' if r.ok else 'FAIL'}  {r.rule_id:16} {r.cases} case(s)")
        for f in r.failures:
            print(f"          {f}")
    for path, errs in errors.items():
        print(f"  ERROR {path}: {'; '.join(errs)}")
    failed = [r for r in results if not r.ok]
    print(f"{len(results) - len(failed)}/{len(results)} rules passed, {cases} test cases, {len(errors)} test-file error(s)")
    return 1 if failed or errors else 0


def cmd_coverage(a) -> int:
    from sentinelforge.rules.coverage import coverage_markdown, navigator_layer
    from sentinelforge.rules.testing import load_test_files

    report = _rules(a.rules)
    if report.errors:
        _print_load_errors(report.errors)
        return 1
    tested = set(load_test_files(Path(a.tests))[0]) if Path(a.tests).is_dir() else set()
    md = coverage_markdown(report.rules, tested)
    if a.summary:
        print(md)
        return 0
    out = Path(a.out)
    files = {out / "attack-coverage.md": md, out / "attack-navigator-layer.json": navigator_layer(report.rules)}
    stale = [p for p, text in files.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
    if a.check:
        for p in stale:
            print(f"stale: {p} (run `sentinelforge coverage export`)")
        return 1 if stale else 0
    out.mkdir(parents=True, exist_ok=True)
    for p, text in files.items():
        p.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {p}")
    return 0


def cmd_profile(a) -> int:
    from sentinelforge.inventory import load_inventory
    from sentinelforge.profiling import build_profile

    print(build_profile(load_inventory(a.inventory)).model_dump_json(indent=2))
    return 0


def _records(path: str, source: str):
    """NDJSON or a JSON array; each record is either a raw source record or {"source", "data"}."""
    stream = sys.stdin if path == "-" else open(path, encoding="utf-8-sig")
    with stream:
        first = stream.readline()
        if first.lstrip().startswith("[") or (first.strip() == "{"):  # JSON array, or a pretty-printed {"events": [...]}
            doc = json.loads(first + stream.read())
            if isinstance(doc, dict) and isinstance(doc.get("events"), list):
                doc = doc["events"]
            elif isinstance(doc, dict) and doc.get("kind") == "EventList":
                doc = doc.get("items", [])
            items = doc
            items = items if isinstance(items, list) else [items]
        else:  # NDJSON, read lazily so `docker events ... | sentinelforge forward` streams
            items = (json.loads(line) for line in itertools.chain([first], stream) if line.strip())
        for rec in items:
            yield rec if isinstance(rec, dict) and {"source", "data"} <= rec.keys() else {"source": source, "data": rec}


def cmd_evaluate(a) -> int:
    from sentinelforge.engine import Engine

    engine = Engine.from_paths(a.rules, a.inventory)
    errors: list[str] = []
    n = 0
    for det in engine.process_many(_records(a.input, a.source), errors):
        n += 1
        print(json.dumps(det, default=str))
    print(f"{n} detection(s), {len(engine.rules)} active rule(s), {len(errors)} rejected record(s)", file=sys.stderr)
    for e in errors[:20]:
        print(f"  {e}", file=sys.stderr)
    return 0


def cmd_forward(a) -> int:
    """Ship records to a SentinelForge server's /api/v1/ingest/{source}. Stdlib only (no extra dependency)."""
    url = f"{a.url.rstrip('/')}/api/v1/ingest/{a.source}" + (f"?host={a.host}" if a.host else "")
    headers = {"Content-Type": "application/json"}
    if a.api_key_env and os.environ.get(a.api_key_env):
        headers["X-API-Key"] = os.environ[a.api_key_env]
    batch: list[dict] = []

    def flush() -> None:
        if not batch:
            return
        req = urllib.request.Request(url, data=json.dumps(batch).encode(), headers=headers, method="POST")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    res = json.load(r)
                print(f"sent {len(batch)}: accepted={res.get('accepted')} detections={res.get('detections')}", file=sys.stderr)
                break
            except OSError as e:
                print(f"send failed ({e}); retry {attempt + 1}/3", file=sys.stderr)
                time.sleep(2 ** attempt)
        batch.clear()

    for rec in _records(a.input, a.source):
        batch.append(rec["data"])
        if len(batch) >= a.batch:
            flush()
    flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinelforge", description="SentinelForge detection engineering toolkit")
    p.add_argument("--version", action="version", version=f"sentinelforge {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    rules = sub.add_parser("rules", help="rule packs").add_subparsers(dest="rcmd", required=True)
    v = rules.add_parser("validate", help="validate rule files (schema, safe YAML, compile)")
    v.add_argument("paths", nargs="*", help='rule files/directories; "builtin" = shipped packs (default)')
    v.set_defaults(fn=cmd_validate)
    t = rules.add_parser("test", help="run per-rule match / no-match unit tests")
    t.add_argument("--rules", nargs="+", default=["builtin"])
    t.add_argument("--tests", default="rule-tests")
    t.add_argument("--inventory-dir", action="append", default=[], help="where `environment: <name>` inventories live")
    t.add_argument("--allow-untested", action="store_true", help="don't fail for rules without a test file")
    t.set_defaults(fn=cmd_test)

    cov = sub.add_parser("coverage", help="MITRE ATT&CK coverage").add_subparsers(dest="ccmd", required=True)
    ce = cov.add_parser("export", help="write attack-coverage.md and attack-navigator-layer.json")
    ce.add_argument("--rules", nargs="+", default=["builtin"])
    ce.add_argument("--tests", default="rule-tests")
    ce.add_argument("--out", default="docs")
    ce.add_argument("--check", action="store_true", help="exit 1 if the files in --out are stale")
    ce.add_argument("--summary", action="store_true", help="print the Markdown report to stdout instead")
    ce.set_defaults(fn=cmd_coverage)

    pr = sub.add_parser("profile", help="build an environment profile from an inventory JSON")
    pr.add_argument("inventory")
    pr.set_defaults(fn=cmd_profile)

    ev = sub.add_parser("evaluate", help="run events through the rules offline; detections as NDJSON on stdout")
    ev.add_argument("input", nargs="?", default="-", help="NDJSON or JSON array file, or - for stdin")
    ev.add_argument("--source", default="generic", help="parser for raw records: windows|linux|docker|kubernetes|generic")
    ev.add_argument("--rules", nargs="+", default=["builtin"])
    ev.add_argument("--inventory", help="inventory JSON of the host, enables environment-specific rules")
    ev.set_defaults(fn=cmd_evaluate)

    fw = sub.add_parser("forward", help="stream records (NDJSON / JSON array / stdin) to a SentinelForge server")
    fw.add_argument("input", nargs="?", default="-")
    fw.add_argument("--url", required=True, help="server base URL, e.g. http://sentinelforge:8000")
    fw.add_argument("--source", required=True)
    fw.add_argument("--host", help="host name to use when records don't carry one (e.g. Docker events)")
    fw.add_argument("--batch", type=int, default=1, help="records per request (1 = send immediately)")
    fw.add_argument("--api-key-env", default="SENTINELFORGE_API_KEY", help="environment variable holding the API key")
    fw.set_defaults(fn=cmd_forward)

    args = p.parse_args(argv)
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
