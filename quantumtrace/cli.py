"""Command line: `quantumtrace <command>`.

Commands:
    quantumtrace scan PATH [--out DIR] [--now YYYY-MM-DD] [--all] [--top N]
    quantumtrace validate CBOM.json
    quantumtrace benchmark [--kit PATH] [--suite DIR] [--only NAME ...] [--out DIR]
    quantumtrace dashboard [PATH] [--report DIR] [--now YYYY-MM-DD] [--port N] [--headless]
    quantumtrace classify NAME [--usage U] [--bits N] [--mode M] [--flag F] [--json]
    quantumtrace catalog
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .catalog import load_catalog
from .classify import classify
from .models import Finding, Tier, Usage
from .report import analyse
from .scan import scan_path
from .summary import QUIET_FLAGS, summarise

COLOURS = {Tier.CRITICAL: "\033[91m", Tier.MEDIUM: "\033[93m", Tier.SAFE: "\033[92m",
           Tier.PLAINTEXT: "\033[95m", Tier.UNKNOWN: "\033[90m", Tier.INFO: "\033[96m"}
RESET = "\033[0m"


def _paint(tier: Tier, text: str) -> str:
    return f"{COLOURS[tier]}{text}{RESET}" if sys.stdout.isatty() else text


def cmd_classify(args) -> int:
    f = classify(Finding(source="cli", location="command line", algorithm=args.name,
                         usage=Usage(args.usage), key_size=args.bits, mode=args.mode,
                         flags=set(args.flag)))
    c = f.classification
    if args.json:
        print(json.dumps(f.to_dict(), indent=2))
        return 0
    print(f"\n  {args.name!r}  ->  {_paint(c.tier, c.label)}\n")
    print(f"  {'component':<34}{'role':<14}{'tier':<11}{'threat':<8}{'NIST-Q':<8}{'flags'}")
    for comp in c.components:
        nq = "-" if comp.nist_quantum_level is None else comp.nist_quantum_level
        print(f"  {comp.name[:33]:<34}{comp.role.value:<14}{_paint(comp.tier, f'{comp.tier.value:<11}')}"
              f"{comp.threat:<8}{str(nq):<8}{', '.join(sorted(comp.flags)) or '-'}")
    if c.replacements:
        print("\n  migrate:")
        for r in c.replacements:
            print(f"    - {r}")
    print()
    return 0


def cmd_scan(args) -> int:
    now = datetime.fromisoformat(args.now).replace(tzinfo=timezone.utc) if args.now else None
    res = scan_path(args.path, now=now)
    assets = summarise(res.findings)

    print(f"\n  Scanned {sum(len(v) for v in res.files.values())} file(s): "
          + ", ".join(f"{len(v)} {k}" for k, v in res.files.items())
          + (f"  ({len(res.skipped)} skipped: no parser for them)" if res.skipped else ""))
    for w in res.warnings:
        print(f"  ! {w}")
    ps = res.pcap
    if ps.files:
        sess = ", ".join(f"{n} {k}" for k, n in ps.sessions.most_common())
        ready = f"{ps.pq_sessions}/{ps.sessions.get('tls', 0)} TLS sessions use a post-quantum group"
        if ps.pqc_readiness is not None:
            ready += f" ({ps.pqc_readiness:.0%})"
        print(f"  PCAP: {sum(ps.sessions.values())} sessions ({sess}); PQC readiness: {ready}")
    libs = [f.classification.flags for f in res.findings if f.usage is Usage.LIBRARY]
    if libs:
        n = lambda flag: sum(1 for x in libs if flag in x)          # noqa: E731
        print(f"  Libraries: {len(libs)} crypto libraries declared ({n('pqc-capable') + n('pqc-library')} with a "
              f"post-quantum API, {n('no-pqc-api')} pinned to a version without one, {n('deprecated-library')} deprecated)")
    print(f"  {len(res.findings)} findings on {len(assets)} assets\n")
    print(f"  {'tier':<18}{'asset':<36}{'#':>4}  notable flags")
    shown = assets if args.all else [a for a in assets if a.tier is not Tier.SAFE]
    for a in shown:
        flags = ", ".join(sorted(a.flags - QUIET_FLAGS)) or "-"
        print(f"  {_paint(a.tier, f'{a.label:<18}')}{a.asset[:35]:<36}{len(a.findings):>4}  {flags}")
    hidden = len(assets) - len(shown)
    if hidden:
        print(f"  ... and {hidden} SAFE asset(s) (use --all to show)")

    tiers = Counter(a.tier.value for a in assets)
    hndl = sum(1 for a in assets if a.tier is Tier.CRITICAL and a.hndl)
    print("\n  assets by tier: " + ", ".join(f"{t} {tiers[t]}" for t in
          ["CRITICAL", "MEDIUM", "SAFE", "PLAINTEXT", "UNKNOWN", "INFO"] if tiers[t])
          + f"   (of the CRITICAL: {hndl} HNDL)")

    target = Path(args.path).resolve().name or str(args.path)
    score, bom, report = analyse(res, target, timestamp=now, validate_cbom=bool(args.out))
    if score.score is not None:
        subs = " · ".join(f"{k} {v:.0f}" for k, v in score.by_source.items())
        print(f"\n  QUANTUM RISK SCORE: {score.score:.0f} / 100   ({subs})   0 = nothing to migrate, 100 = all exposed")
    if report["roadmap"]:
        print(f"\n  migration roadmap (top {min(args.top, len(report['roadmap']))} of {len(report['roadmap'])}):")
        for r in report["roadmap"][:args.top]:
            action = f"{r['current']} -> {r['replacement'].split(' (')[0]}"
            print(f"   P{r['priority']}  {action[:60]:<61} {r['asset_count']:>3} asset(s)  {r['standard']}")
    print()

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "findings.json").write_text(json.dumps([f.to_dict() for f in res.findings], indent=2))
        (out / "report.json").write_text(json.dumps(report, indent=2))
        (out / "cbom.json").write_text(json.dumps(bom, indent=2))
        if res.pcap.files:
            (out / "pcap_stats.json").write_text(json.dumps(res.pcap.to_dict(), indent=2))
        valid, msgs = report["cbom"]["valid"], report["cbom"]["messages"]
        status = ("valid CycloneDX 1.6 (official schema + reference check)" if valid else
                  "NOT validated: " + "; ".join(msgs) if valid is None else "INVALID: " + "; ".join(msgs[:3]))
        print(f"  wrote {out / 'findings.json'}, {out / 'report.json'}, {out / 'cbom.json'}")
        print(f"  CBOM: {len(bom['components'])} components, {len(bom.get('services', []))} services -> {status}\n")
        return 0 if valid is not False else 1
    return 0


def cmd_validate(args) -> int:
    """Check any CycloneDX 1.6 JSON file (ours or someone else's)."""
    from .cbom import validate
    bom = json.loads(Path(args.file).read_text())
    valid, msgs = validate(bom)
    print("VALID CycloneDX 1.6" if valid else ("NOT CHECKED" if valid is None else "INVALID"))
    for m in msgs:
        print(f"  - {m}")
    return 0 if valid else 1


def cmd_benchmark(args) -> int:
    """Precision / recall against the hand-labelled datasets (Phase 5)."""
    from . import benchmark as B

    repo = Path(__file__).resolve().parents[1]
    import os

    suite = Path(args.suite or os.environ.get("QT_SUITE") or repo / "tests" / "benchmarks")
    if not (suite / "holdout.yaml").is_file():
        print(f"benchmark suite not found at {suite} (it ships with the source repository): use --suite DIR")
        return 1
    kit = args.kit or os.environ.get("QT_KIT") or (suite.resolve().parents[2] / "JunctionX-QuantumTrace")
    now = datetime.fromisoformat(args.now).replace(tzinfo=timezone.utc) if args.now else B.AS_OF
    res = B.run(suite, kit=kit, only=args.only, now=now)
    print(f"\n  QuantumTrace benchmark, labels as of {res['as_of']}\n")
    for line in B.table(res["by_source"], res["all"]):
        print("  " + line)
    for name, d in res["datasets"].items():
        a = d["all"]
        extra = ""
        if d["decoys"]:
            extra += f", decoys clean {sum(x['ok'] for x in d['decoys'])}/{len(d['decoys'])}"
        if d.get("libraries"):
            extra += f", libraries P {B._pct(d['libraries']['precision'])} R {B._pct(d['libraries']['recall'])}"
        print(f"\n  {name}: {a['assets']} labelled assets, verdict {B._pct(a['verdict']['accuracy'])}, "
              f"algorithms F1 {B._pct(a['algorithms']['f1'])}{extra}")
        for line in B.problems(d)[:args.show]:
            print("    " + line)
        if len(B.problems(d)) > args.show:
            print(f"    ... {len(B.problems(d)) - args.show} more (see benchmark.md)")
    for name, why in res["skipped"].items():
        print(f"\n  {name}: skipped ({why})")
    c = res.get("classification")
    if c:
        print(f"\n  classification: {c['cases']} names, tier {B._pct(c['accuracy']['tier'])}, "
              f"threat {B._pct(c['accuracy']['threat'])}, HNDL {B._pct(c['accuracy']['hndl'])}")
        for m in c["misses"][:args.show]:
            print(f"    - {m['name']}: got {m['got']}, label {m['want']}")
    if args.out:
        paths = B.write(res, args.out)
        print("\n  wrote " + ", ".join(str(p) for p in paths))
    print()
    return 0


def cmd_catalog(args) -> int:
    cat = load_catalog()
    by_tier: dict[str, int] = {}
    for e in cat.algorithms.values():
        t = e.get("tier", "by key size")
        by_tier[t] = by_tier.get(t, 0) + 1
    print(f"{len(cat.algorithms)} algorithms, {len(cat.composites)} composite names, "
          f"{len(cat.tls_cipher_suites)} TLS suites, {len(cat.tls_groups)} TLS groups, "
          f"{len(cat.tls_signature_schemes)} TLS signature schemes, {len(cat.aws_elb_policies)} AWS ELB policies")
    for t, n in sorted(by_tier.items()):
        print(f"  {t:<12} {n}")
    return 0


def _free_port(start: int, tries: int = 30) -> int | None:
    """First port from `start` that nothing is listening on (checked by binding to it)."""
    import socket

    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("", port))
            except OSError:
                continue
            return port
    return None


def cmd_dashboard(args) -> int:
    """Start the Streamlit dashboard (needs the [dashboard] extra)."""
    import importlib.util
    import os
    import subprocess

    if importlib.util.find_spec("streamlit") is None:
        print('Streamlit is not installed. Run:  pip install -e ".[dashboard]"')
        return 1
    app = Path(__file__).with_name("dashboard") / "app.py"
    env = dict(os.environ)
    if args.path:
        env["QT_TARGET"] = str(Path(args.path).resolve())
    if args.report:
        env["QT_REPORT"] = str(Path(args.report).resolve())
    if args.now:
        env["QT_NOW"] = args.now
    port = args.port or _free_port(8501)
    if port is None:
        print("No free port between 8501 and 8530: stop the old dashboard or pass --port")
        return 1
    if args.port is None and port != 8501:
        print(f"Port 8501 is busy (another dashboard?), using {port} instead")
    cmd = [sys.executable, "-m", "streamlit", "run", str(app), "--server.port", str(port),
           "--browser.gatherUsageStats", "false"]
    if args.headless:
        cmd += ["--server.headless", "true"]
    print(f"QuantumTrace dashboard on http://localhost:{port}  (Ctrl+C to stop)")
    try:
        return subprocess.call(cmd, env=env)
    except KeyboardInterrupt:
        return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="quantumtrace", description="Post-quantum crypto readiness scanner")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a file or folder")
    s.add_argument("path", help="file or folder to scan")
    s.add_argument("--out", help="folder to write findings.json, report.json and cbom.json into")
    s.add_argument("--now", help="pretend today is YYYY-MM-DD (for expiry checks / reproducible demos)")
    s.add_argument("--all", action="store_true", help="also list SAFE assets")
    s.add_argument("--top", type=int, default=8, help="roadmap rows to print (default 8)")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("classify", help="classify one algorithm name")
    c.add_argument("name", help='e.g. "SHA1withRSA", "RSA_2048", "TLS_RSA_WITH_AES_128_CBC_SHA"')
    c.add_argument("--usage", default="unknown", choices=[u.value for u in Usage])
    c.add_argument("--bits", type=int, help="key size in bits, if known")
    c.add_argument("--mode", help="cipher mode, e.g. ecb, gcm")
    c.add_argument("--flag", action="append", default=[], help="extra fact, e.g. long-lived, redirect-to-https")
    c.add_argument("--json", action="store_true", help="print the full Finding as JSON")
    c.set_defaults(func=cmd_classify)

    d = sub.add_parser("dashboard", help="open the web dashboard (Streamlit)")
    d.add_argument("path", nargs="?", help="file or folder to offer for scanning")
    d.add_argument("--report", help="open a folder written by `scan --out` instead")
    d.add_argument("--now", help="pretend today is YYYY-MM-DD (expiry checks)")
    d.add_argument("--port", type=int, help="default: 8501, or the next free port if 8501 is busy")
    d.add_argument("--headless", action="store_true", help="do not open a browser")
    d.set_defaults(func=cmd_dashboard)

    v = sub.add_parser("validate", help="validate a CycloneDX 1.6 CBOM file")
    v.add_argument("file")
    v.set_defaults(func=cmd_validate)

    b = sub.add_parser("benchmark", help="precision / recall against the labelled benchmark datasets")
    b.add_argument("--kit", help="the organisers' starter kit folder (default: $QT_KIT or ../JunctionX-QuantumTrace)")
    b.add_argument("--suite", help="folder with holdout.yaml, sample-infra.yaml, classification.yaml "
                                   "(default: $QT_SUITE or tests/benchmarks)")
    b.add_argument("--only", nargs="+", choices=["holdout", "adversarial", "sample-infra", "kit", "classification"])
    b.add_argument("--out", help="folder to write benchmark.json and benchmark.md into")
    b.add_argument("--now", help="date the labels assume (default 2026-10-11)")
    b.add_argument("--show", type=int, default=12, help="differences to print per dataset (default 12)")
    b.set_defaults(func=cmd_benchmark)

    k = sub.add_parser("catalog", help="summarise the algorithm catalog")
    k.set_defaults(func=cmd_catalog)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:              # output piped into `head` / `less` that closed early
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
