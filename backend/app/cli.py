"""sentinelforge-server CLI: operations that need the server's database or collectors.

Rule validation, rule tests, ATT&CK coverage and offline evaluation live in the library CLI (`sentinelforge`).

    sentinelforge-server discovery [--local | --remote HOST | --file inventory.json] [--save]
    sentinelforge-server profile --file inventory.json | --template windows-web-server
    sentinelforge-server rules generate --file inventory.json | --template NAME
    sentinelforge-server events simulate --template NAME [--scenario NAME ...] [--benign N]
    sentinelforge-server demo [--template NAME] [--benign N]
    sentinelforge-server schemas export [--out DIR]
"""

import argparse
import json
import sys
from pathlib import Path

from app.core.config import REPO_ROOT, get_settings


def _db():
    from app.db.session import SessionLocal, init_db
    from app.plugins import load_plugins
    import sentinelforge.normalize  # noqa: F401  (registers built-in parsers)
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
    from sentinelforge.profiling import build_profile

    print(build_profile(_inventory(args)).model_dump_json(indent=2))


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
    from sentinelforge.schemas.detection import DetectionEvent
    from sentinelforge.schemas.profile import EnvironmentProfile
    from sentinelforge.schemas.event import NormalizedEvent
    from sentinelforge.schemas.inventory import Inventory
    from sentinelforge.schemas.rule import RuleDefinition

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, model in [("inventory", Inventory), ("environment-profile", EnvironmentProfile), ("rule", RuleDefinition),
                        ("normalized-event", NormalizedEvent), ("detection-event", DetectionEvent)]:
        schema = model.model_json_schema(by_alias=True)
        schema["$id"] = f"https://sentinelforge.dev/schemas/{name}.schema.json"
        (out / f"{name}.schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out / f'{name}.schema.json'}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinelforge-server", description="SentinelForge server operations")
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

    args = p.parse_args(argv)
    from app.core.logging import setup_logging

    setup_logging("WARNING")
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
