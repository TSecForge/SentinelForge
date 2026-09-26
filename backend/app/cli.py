"""SentinelForge CLI. The web UI is the primary interface; this is for scripting and CI.

    sentinelforge discovery [--local | --remote HOST | --file inventory.json] [--save]
    sentinelforge profile --file inventory.json | --template windows-web-server
    sentinelforge rules validate [PATH ...]
    sentinelforge rules test
    sentinelforge coverage export [--check]
    sentinelforge rules generate --file inventory.json | --template NAME
    sentinelforge events simulate --template NAME [--scenario NAME ...] [--benign N]
    sentinelforge demo [--template NAME] [--benign N]
    sentinelforge schemas export [--out DIR]
"""

import argparse
import json
import sys
from pathlib import Path

from app.core.config import REPO_ROOT, get_settings


def _db():
    from app.db.session import SessionLocal, init_db
    from app.plugins import load_plugins
    from app.services import normalization  # noqa: F401
    from app.services.rules import sync_rule_store
    from app.services.siem import gateway  # noqa: F401

    init_db()
    load_plugins()
    db = SessionLocal()
    sync_rule_store(db)
    return db


def _inventory(args):
    from app.services import discovery

    if getattr(args, "file", None):
        return discovery.parse_inventory(Path(args.file).read_bytes())
    if getattr(args, "template", None):
        return discovery.load_demo_inventory(args.template)
    if getattr(args, "remote", None):
        get_settings().enable_live_discovery = True  # explicit CLI invocation is consent
        return discovery.run_powershell_collector(args.remote)
    get_settings().enable_live_discovery = True
    return discovery.run_powershell_collector()


def cmd_discovery(args):
    inv = _inventory(args)
    if args.save:
        from app.services import environments

        env = environments.upsert_environment(_db(), inv, "import" if args.file else ("remote" if args.remote else "local"))
        print(f"saved environment #{env.id} {env.hostname}")
    if args.out:
        Path(args.out).write_text(inv.model_dump_json(indent=2), encoding="utf-8")
        print(f"inventory written to {args.out}")
    if not args.save and not args.out:
        print(json.dumps({"host": inv.host.model_dump(mode="json"), "services": len(inv.services), "processes": len(inv.processes),
                          "listening_ports": sorted({p.port for p in inv.network.listening_ports}), "docker": inv.containers.docker,
                          "kubernetes": inv.containers.kubernetes}, indent=2))


def cmd_profile(args):
    from app.services.profiling import build_profile

    print(build_profile(_inventory(args)).model_dump_json(indent=2))


def cmd_rules_validate(args):
    from app.services.rules.loader import load_rule_paths

    paths = args.paths or get_settings().split(get_settings().rule_paths)
    report = load_rule_paths(paths)
    for r in report.rules:
        print(f"  OK    {r.definition.id:16} v{r.definition.version:6} {r.definition.name}")
    for path, errs in report.errors.items():
        print(f"  FAIL  {path}")
        for e in errs:
            print(f"          {e}")
    print(f"{len(report.rules)} valid, {len(report.errors)} invalid")
    return 1 if report.errors else 0


def _all_rules():
    from app.services.rules.loader import load_rule_paths

    return load_rule_paths(get_settings().split(get_settings().rule_paths)).rules


def cmd_rules_test(args):
    from app.services.rules.testing import run_all

    results, errors = run_all(_all_rules())
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


def cmd_coverage_export(args):
    from app.services.rules.coverage import coverage_markdown, navigator_layer
    from app.services.rules.testing import load_test_files

    rules = _all_rules()
    tested = set(load_test_files()[0])
    out = Path(args.out)
    files = {out / "attack-coverage.md": coverage_markdown(rules, tested), out / "attack-navigator-layer.json": navigator_layer(rules)}
    stale = [p for p, text in files.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
    if args.check:
        for p in stale:
            print(f"stale: {p} (run `sentinelforge coverage export`)")
        return 1 if stale else 0
    for p, text in files.items():
        p.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {p}")
    return 0


def cmd_rules_generate(args):
    from app.services import environments, rules

    db = _db()
    env = environments.upsert_environment(db, _inventory(args), "import" if args.file else "demo")
    counts = rules.generate_rules(db, env)
    for a in environments.assignments(db, env.id):
        print(f"  {a['status']:15} {a['rule_id']:16} {a['reason'][:90]}")
    print(json.dumps(counts))


def cmd_events_simulate(args):
    from app.services import demo, rules

    db = _db()
    env = demo.create_demo_environment(db, args.template)
    rules.generate_rules(db, env)
    out = demo.simulate(db, env, args.scenario or ["all"], args.benign)
    print(json.dumps(out["result"] | {"scenarios": out["scenarios"]}, indent=2, default=str))


def cmd_demo(args):
    from app.services import demo, metrics

    db = _db()
    out = demo.run_full_demo(db, args.template, args.benign)
    print(f"environment: {out['hostname']} (#{out['environment_id']}, SIMULATED)")
    print(f"rules: {out['rules']}")
    r = out["result"]
    print(f"events: received={r['received']} matched={r['matched']} detections={r['detections']}")
    print(metrics.get_metrics(db)["statement"])


def cmd_schemas_export(args):
    from app.schemas.detection import DetectionEvent
    from app.schemas.environment import EnvironmentProfile
    from app.schemas.event import NormalizedEvent
    from app.schemas.inventory import Inventory
    from app.schemas.rule import RuleDefinition

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, model in [("inventory", Inventory), ("environment-profile", EnvironmentProfile), ("rule", RuleDefinition),
                        ("normalized-event", NormalizedEvent), ("detection-event", DetectionEvent)]:
        schema = model.model_json_schema(by_alias=True)
        schema["$id"] = f"https://sentinelforge.dev/schemas/{name}.schema.json"
        (out / f"{name}.schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out / f'{name}.schema.json'}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinelforge", description="SentinelForge - environment-aware detection engineering")
    sub = p.add_subparsers(dest="cmd", required=True)

    def src(sp, live=False):
        g = sp.add_mutually_exclusive_group(required=not live)
        g.add_argument("--file", help="inventory JSON produced by a collector")
        g.add_argument("--template", help="demo template from sample-data/environments")
        if live:
            g.add_argument("--local", action="store_true", help="run the PowerShell collector on this machine (default)")
            g.add_argument("--remote", metavar="HOST", help="run the collector over WinRM")

    d = sub.add_parser("discovery", help="run or import agentless discovery")
    src(d, live=True)
    d.add_argument("--out", help="write the inventory JSON here")
    d.add_argument("--save", action="store_true", help="store it as an environment")
    d.set_defaults(fn=cmd_discovery)

    pr = sub.add_parser("profile", help="build an environment profile from an inventory")
    src(pr)
    pr.set_defaults(fn=cmd_profile)

    r = sub.add_parser("rules", help="rule operations").add_subparsers(dest="rcmd", required=True)
    rv = r.add_parser("validate", help="validate rule packs")
    rv.add_argument("paths", nargs="*")
    rv.set_defaults(fn=cmd_rules_validate)
    rt = r.add_parser("test", help="run per-rule unit tests from rule-tests/")
    rt.set_defaults(fn=cmd_rules_test)
    rg = r.add_parser("generate", help="select/generate rules for an inventory")
    src(rg)
    rg.set_defaults(fn=cmd_rules_generate)

    e = sub.add_parser("events", help="event operations").add_subparsers(dest="ecmd", required=True)
    es = e.add_parser("simulate", help="send SIMULATED telemetry through the pipeline")
    es.add_argument("--template", default="windows-web-server")
    es.add_argument("--scenario", action="append", help="scenario name (repeatable); default: all relevant")
    es.add_argument("--benign", type=int, default=500)
    es.set_defaults(fn=cmd_events_simulate)

    dm = sub.add_parser("demo", help="run the full demo pipeline")
    dm.add_argument("--template", default="windows-web-server")
    dm.add_argument("--benign", type=int, default=1000)
    dm.set_defaults(fn=cmd_demo)

    sc = sub.add_parser("schemas", help="JSON Schema export").add_subparsers(dest="scmd", required=True)
    se = sc.add_parser("export")
    se.add_argument("--out", default=str(REPO_ROOT / "schemas"))
    se.set_defaults(fn=cmd_schemas_export)

    cv = sub.add_parser("coverage", help="MITRE ATT&CK coverage").add_subparsers(dest="ccmd", required=True)
    ce = cv.add_parser("export", help="write docs/attack-coverage.md and docs/attack-navigator-layer.json")
    ce.add_argument("--out", default=str(REPO_ROOT / "docs"))
    ce.add_argument("--check", action="store_true", help="exit 1 if the committed files are stale (CI)")
    ce.set_defaults(fn=cmd_coverage_export)

    args = p.parse_args(argv)
    from app.core.logging import setup_logging

    setup_logging("WARNING")
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
