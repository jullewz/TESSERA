"""Command-line interface.

Exit codes:
    0  success, no changes at or above the ``--fail-on`` level
    1  changes found at or above the ``--fail-on`` level
    2  usage or configuration error
    3  integrity failure (invalid seal, Merkle root or proof)
    4  internal or storage error
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

from tessera import __author__, __url__, __version__, engine, sealing
from tessera.config import CONFIG_FILENAME, Config, load_config
from tessera.errors import (
    EXIT_CHANGES,
    EXIT_INTEGRITY,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_USAGE,
    IntegrityError,
    TesseraError,
    UsageError,
)
from tessera.hooks import run_hooks
from tessera.log import setup_logging
from tessera.matcher import glob_match
from tessera.models import Report, Severity
from tessera.osinfo import PlatformName, config_dir, current_platform
from tessera.reporters import FORMATS, render
from tessera.store import BaselineStore
from tessera.templates import starter_config
from tessera.term import Progress, Style, shorten
from tessera.util import format_duration, format_size
from tessera.watch import Watcher

log = logging.getLogger("tessera.cli")

Handler = Callable[[argparse.Namespace], int]


# ------------------------------------------------------------------ helpers
class Ctx:
    """Per-invocation state: styles for stdout and stderr."""

    def __init__(self, args: argparse.Namespace) -> None:
        color = False if getattr(args, "no_color", False) else None
        self.out = Style(sys.stdout, color=color)
        self.err = Style(sys.stderr, color=color)
        self.args = args


def _ctx(args: argparse.Namespace) -> Ctx:
    ctx: Ctx = args._ctx
    return ctx


def _config(args: argparse.Namespace) -> Config:
    return load_config(args.config)


def _severity_arg(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _emit(args: argparse.Namespace, report: Report, fmt: str) -> None:
    ctx = _ctx(args)
    output: str | None = getattr(args, "output", None)
    if output:
        style = Style(sys.stdout, color=False, unicode=True)
        Path(output).write_text(render(report, fmt, style), encoding="utf-8")
        print(f"{ctx.out(ctx.out.sym['ok'], 'ok')} wrote {fmt} report to {output}", file=sys.stderr)
    else:
        sys.stdout.write(render(report, fmt, ctx.out))
        sys.stdout.flush()


def _progress(args: argparse.Namespace) -> Progress:
    quiet = getattr(args, "quiet", False)
    return Progress(sys.stderr, enabled=False if quiet else None)


def _kv(style: Style, pairs: Sequence[tuple[str, str]], stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout
    width = max(len(k) for k, _ in pairs)
    for key, value in pairs:
        print(f"  {style(key.ljust(width), 'muted')}  {value}", file=stream)


def _read_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise UsageError(f"file not found: {path}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot read {path}: {exc}") from None


def _is_under(root: str, path: str) -> bool:
    root_n, path_n = os.path.normcase(root), os.path.normcase(path)
    try:
        return os.path.commonpath([root_n, path_n]) == root_n
    except ValueError:  # different drives on Windows
        return False


def _seal_text(style: Style, status: str) -> str:
    return {
        "valid": style(f"{style.sym['ok']} valid", "ok"),
        "invalid": style.severity(Severity.CRITICAL, "INVALID"),
        "unsealed": style.severity(Severity.MEDIUM, "unsealed"),
        "no-key": style.severity(Severity.LOW, "not checked (no key)"),
    }.get(status, status)


# ----------------------------------------------------------------- commands
def cmd_init(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    platform: PlatformName = args.platform or current_platform()
    raw_target = args.path or args.config
    target = Path(raw_target).expanduser().resolve() if raw_target else config_dir() / CONFIG_FILENAME
    if target.exists() and not args.force:
        raise UsageError(f"{target} already exists", hint="pass --force to overwrite it")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(starter_config(platform), encoding="utf-8")
    print(f"{ctx.out(ctx.out.sym['ok'], 'ok')} wrote {platform} configuration to {ctx.out(str(target), 'accent')}")

    config = load_config(str(target))
    if not args.no_key:
        if config.key_file.exists():
            print(f"  sealing key already present at {config.key_file}")
        else:
            sealing.generate_key(config.key_file)
            print(
                f"{ctx.out(ctx.out.sym['ok'], 'ok')} generated sealing key at {ctx.out(str(config.key_file), 'accent')}"
            )
    print()
    print(ctx.out("  next steps", "accent_strong"))
    print(f"    1. review the watch paths and rules in {target}")
    print("    2. tessera snapshot        record the trusted baseline")
    print("    3. tessera check           compare the system against it")
    return EXIT_OK


def cmd_keygen(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    path = Path(args.path).expanduser() if args.path else _config(args).key_file
    sealing.generate_key(path, force=args.force)
    print(f"{ctx.out(ctx.out.sym['ok'], 'ok')} wrote new sealing key to {path}")
    if args.force:
        print("  baselines sealed with the old key now verify as invalid, take a new snapshot")
    return EXIT_OK


def cmd_snapshot(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    config = _config(args)
    key = engine.try_load_key(config, required=args.require_seal)
    if key is None:
        log.warning("no sealing key found at %s, the baseline will not be sealed (run `tessera keygen`)",
                    config.key_file)  # fmt: skip
    progress = _progress(args)
    snapshot = engine.scan(config, progress.update)
    progress.done()
    with BaselineStore(config.store) as store:
        result = engine.save_snapshot(config, store, snapshot, label=args.label, key=key)
    st, b = snapshot.stats, result.baseline
    print(ctx.out.rule(f"baseline #{b.id} recorded"))
    _kv(ctx.out, [
        ("entries", f"{st.entries:,}  ({st.files:,} files, {st.dirs:,} dirs, {st.symlinks:,} links)"),
        ("hashed", f"{st.hashed_files:,} files, {format_size(st.hashed_bytes)} ({b.algorithm})"),
        ("duration", format_duration(st.seconds)),
        ("merkle root", ctx.out(b.merkle_root, "accent")),
        ("seal", _seal_text(ctx.out, "valid" if result.sealed else "unsealed")),
        ("store", str(config.store)),
    ] + ([("unreadable", f"{st.errors} entries (see `tessera show {b.id} --errors`)")] if st.errors else [])
      + ([("skipped", f"{st.skipped_large} files above max_file_size, metadata only")]
         if st.skipped_large else []))  # fmt: skip
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    config = _config(args)
    key = engine.try_load_key(config)
    min_sev = args.min_severity or config.report.min_severity
    fail_on = args.fail_on or config.report.fail_on
    fmt = args.format or config.report.format
    progress = _progress(args)
    with BaselineStore(config.store) as store:
        result = engine.check(config, store, baseline_id=args.baseline, key=key,
                              progress=progress.update, min_severity=min_sev)  # fmt: skip
        progress.done()
        _emit(args, result.report, fmt)
        if not args.no_hooks and config.hooks:
            run_hooks(config.hooks, result.report)
        if args.update:
            saved = engine.save_snapshot(config, store, result.snapshot, label="check --update", key=key)
            log.warning("recorded the current state as baseline #%d", saved.baseline.id)
    if result.seal_status == "invalid" or (args.strict and result.seal_status != "valid"):
        log.error("baseline #%d failed integrity verification (seal: %s)", result.baseline.id,
                  result.seal_status)  # fmt: skip
        return EXIT_INTEGRITY
    return engine.exit_code_for(result.report.changes, fail_on)


def cmd_diff(args: argparse.Namespace) -> int:
    config = _config(args)
    with BaselineStore(config.store) as store:
        report = engine.compare_baselines(config, store, args.old, args.new)
    _emit(args, report, args.format or config.report.format)
    return engine.exit_code_for(report.changes, args.fail_on or config.report.fail_on)


def cmd_watch(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    config = _config(args)
    key = engine.try_load_key(config)
    fmt = args.format or config.report.format

    def sink(report: Report, cycle: int) -> None:
        if report.changes:
            sys.stdout.write(render(report, fmt, ctx.out))
            sys.stdout.flush()
        elif not args.quiet:
            stats = report.stats
            entries = f"{stats.entries:,} entries" if stats else ""
            print(ctx.err(f"{ctx.err.sym['dot']} cycle {cycle}: no new changes  {entries}", "muted"),
                  file=sys.stderr)  # fmt: skip

    with BaselineStore(config.store) as store:
        store.resolve(args.baseline)  # fail early when no baseline exists
        watcher = Watcher(config, store, interval=args.interval, baseline_id=args.baseline, key=key,
                          sink=sink, run_hooks=not args.no_hooks)  # fmt: skip
        print(ctx.err(f"watching {len(config.roots)} root(s) every {args.interval:g}s, Ctrl+C to stop",
                      "accent"), file=sys.stderr)  # fmt: skip
        try:
            state = watcher.run(max_cycles=args.cycles)
        except KeyboardInterrupt:
            watcher.stop()
            state = watcher.state
            print(file=sys.stderr)
    print(ctx.err(f"stopped after {state.cycles} cycle(s), {state.alerts} new change(s) reported",
                  "muted"), file=sys.stderr)  # fmt: skip
    return EXIT_CHANGES if state.alerts else EXIT_OK


def cmd_baselines(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    config = _config(args)
    with BaselineStore(config.store) as store:
        items = store.list()
    if args.json:
        print(json.dumps([b.to_dict() for b in items], indent=2))
        return EXIT_OK
    if not items:
        print("no baselines yet, create one with `tessera snapshot`")
        return EXIT_OK
    s = ctx.out
    print(s(f"  {'ID':>4}  {'CREATED (UTC)':<26} {'ENTRIES':>9}  {'SEAL':<9} {'HOST':<18} LABEL", "muted"))
    for b in items:
        seal = s("sealed", "ok") if b.seal else s("unsealed", "muted")
        print(f"  {s(f'{b.id:>4}', 'accent')}  {b.created_at:<26} {b.file_count:>9,}  "
              f"{seal}{' ' * (9 - len('sealed' if b.seal else 'unsealed'))} "
              f"{shorten(b.host, 18):<18} {b.label or ''}")  # fmt: skip
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    config = _config(args)
    with BaselineStore(config.store) as store:
        info = store.resolve(args.baseline)
        records = store.records(info.id)
    items = sorted(records.values(), key=lambda r: r.path)
    if args.pattern:
        items = [r for r in items if glob_match(args.pattern, r.path, config.scan.case_sensitive)]
    if args.errors:
        items = [r for r in items if r.error]
    if args.json:
        print(json.dumps([r.to_dict() for r in items], indent=2, ensure_ascii=False))
        return EXIT_OK
    s = ctx.out
    for r in items:
        digest = (r.digest or "-").split(":")[-1][:12]
        mode = f"{r.mode:04o}"
        extra = f"  {s(r.error, 'muted')}" if r.error else ""
        target = f" {s.sym['arrow']} {r.link_target}" if r.link_target else ""
        print(f"  {s(f'{r.kind.value:<7}', 'accent')} {mode}  {r.size:>12,}  {s(f'{digest:<12}', 'muted')}  "
              f"{r.path}{target}{extra}")  # fmt: skip
    print(s(f"  {len(items):,} of {len(records):,} records in baseline #{info.id}", "muted"))
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    config = _config(args)
    key = engine.try_load_key(config, required=args.strict)
    s = ctx.out
    if args.manifest:
        verdict = sealing.verify_manifest(_read_json(args.manifest), key)
        targets = [(f"manifest {args.manifest}", verdict)]
    else:
        with BaselineStore(config.store) as store:
            infos = store.list() if args.all else [store.resolve(args.baseline)]
            targets = [(f"baseline #{i.id}", engine.verify_baseline(store, i, key)) for i in infos]
    failed = False
    for name, v in targets:
        good = v.strict_ok if args.strict else v.ok
        failed |= not good
        mark = s(s.sym["ok"], "ok") if good else s.severity(Severity.CRITICAL, s.sym["fail"])
        root = s("ok", "ok") if v.root_ok and v.count_ok else s.severity(Severity.CRITICAL, "MISMATCH")
        print(f"  {mark} {s.bold(name)}  merkle root {root}  seal {_seal_text(s, v.seal_status)}")
    return EXIT_INTEGRITY if failed else EXIT_OK


def cmd_export(args: argparse.Namespace) -> int:
    config = _config(args)
    with BaselineStore(config.store) as store:
        info = store.resolve(args.baseline)
        manifest = sealing.build_manifest(engine.header_for(info), info.seal, store.records(info.id))
    text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote manifest for baseline #{info.id} ({info.file_count:,} records) to {args.output}",
              file=sys.stderr)  # fmt: skip
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_prove(args: argparse.Namespace) -> int:
    config = _config(args)
    path = os.path.abspath(args.path)
    with BaselineStore(config.store) as store:
        info = store.resolve(args.baseline)
        proof = sealing.build_proof(engine.header_for(info), info.seal, store.records(info.id), path)
    text = json.dumps(proof, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote inclusion proof ({len(proof['path'])} hashes) for {path} to {args.output}",
              file=sys.stderr)  # fmt: skip
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_verify_proof(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    s = ctx.out
    key: bytes | None = None
    if args.key:
        key = sealing.load_key(Path(args.key).expanduser())
    else:
        try:
            key = engine.try_load_key(_config(args))
        except TesseraError:
            key = None
    data = _read_json(args.proof)
    included, status = sealing.verify_proof(data, key)
    record = data.get("record", {})
    mark = s(s.sym["ok"], "ok") if included else s.severity(Severity.CRITICAL, s.sym["fail"])
    print(f"  {mark} {record.get('path', '?')}")
    _kv(s, [
        ("inclusion", s("proven", "ok") if included else s.severity(Severity.CRITICAL, "NOT PROVEN")),
        ("merkle root", str(data.get("header", {}).get("merkle_root", "?"))),
        ("seal", _seal_text(s, status)),
        ("digest", str(record.get("digest") or "-")),
    ])  # fmt: skip
    bad = not included or status == "invalid" or (args.strict and status != "valid")
    return EXIT_INTEGRITY if bad else EXIT_OK


def cmd_explain(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    s = ctx.out
    config = _config(args)
    for raw in args.paths:
        path = os.path.abspath(raw)
        res = config.policy.resolve(path)
        rule = res.rule.describe() if res.rule else "no rule matched, using defaults"
        roots = [r.path for r in config.roots if _is_under(r.path, path)]
        print(f"  {s.bold(path)}")
        _kv(s, [
            ("profile", s(res.profile, "accent")),
            ("tracks", ", ".join(sorted(res.attributes)) or "nothing (ignored)"),
            ("severity", s.severity(res.severity)),
            ("rule", rule if res.rule_index is None else f"#{res.rule_index + 1}  {rule}"),
            ("watched", ", ".join(roots) if roots else s("not under any [[watch]] root", "muted")),
        ])  # fmt: skip
    return EXIT_OK


def cmd_config(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    s = ctx.out
    config = _config(args)
    print(f"{s(s.sym['ok'], 'ok')} {config.source} is valid")
    _kv(s, [
        ("store", str(config.store)),
        ("key file", f"{config.key_file}" + ("" if config.key_file.exists() else s("  (missing)", "muted"))),
        ("algorithm", config.scan.algorithm),
        ("workers", str(config.scan.workers)),
        ("max file size", format_size(config.scan.max_file_size)),
        ("case sensitive", str(config.scan.case_sensitive).lower()),
        ("roots", str(len(config.roots))),
        ("rules", str(len(config.policy.rules))),
        ("hooks", str(len(config.hooks))),
        ("digest", config.digest()),
    ])  # fmt: skip
    if args.verbose:
        print()
        for root in config.roots:
            excl = f"  {s('exclude ' + ', '.join(root.exclude), 'muted')}" if root.exclude else ""
            print(f"  {s('watch', 'accent')} {root.path}{excl}")
        for i, rule in enumerate(config.policy.rules, 1):
            print(f"  {s(f'rule {i:>2}', 'accent')} {rule.describe()}")
    return EXIT_OK


def cmd_prune(args: argparse.Namespace) -> int:
    config = _config(args)
    with BaselineStore(config.store) as store:
        deleted = store.prune(args.keep)
    print(f"deleted {len(deleted)} baseline(s)" + (f": {', '.join(f'#{i}' for i in deleted)}" if deleted else ""))
    return EXIT_OK


# ------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", metavar="PATH", help="configuration file (default: auto-detect)")
    common.add_argument("-v", "--verbose", action="count", default=0, help="more output (-vv for debug)")
    common.add_argument("-q", "--quiet", action="store_true", help="only print errors and reports")
    common.add_argument("--no-color", action="store_true", help="disable coloured output")
    common.add_argument("--log-file", metavar="PATH", help="also write debug logs to this file")

    parser = argparse.ArgumentParser(
        prog="tessera",
        description="Tamper-evident filesystem integrity monitoring for Linux, macOS and Windows.",
        epilog=f"Created by {__author__}. Docs: {__url__}",
    )
    parser.add_argument("-V", "--version", action="version", version=f"tessera {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add(name: str, handler: Handler, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, parents=[common], help=help_text, description=help_text)
        p.set_defaults(handler=handler)
        return p

    def report_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("-f", "--format", choices=FORMATS, help="report format")
        p.add_argument("-o", "--output", metavar="FILE", help="write the report to a file")
        p.add_argument("--fail-on", type=_severity_arg, metavar="SEV",
                       help="exit 1 when a change reaches this severity")  # fmt: skip

    p = add("init", cmd_init, "write a starter configuration and generate a sealing key")
    p.add_argument("path", nargs="?", help="where to write tessera.toml")
    p.add_argument("--platform", choices=("linux", "macos", "windows"), help="target platform")
    p.add_argument("--force", action="store_true", help="overwrite an existing file")
    p.add_argument("--no-key", action="store_true", help="do not generate a sealing key")

    p = add("keygen", cmd_keygen, "generate a new sealing key")
    p.add_argument("path", nargs="?", help="key file (default: key_file from the config)")
    p.add_argument("--force", action="store_true", help="replace an existing key")

    p = add("snapshot", cmd_snapshot, "scan the watch roots and record a sealed baseline")
    p.add_argument("-l", "--label", help="free-text label stored with the baseline")
    p.add_argument("--require-seal", action="store_true", help="fail when no sealing key is available")

    p = add("check", cmd_check, "scan and compare against a baseline")
    report_opts(p)
    p.add_argument("-b", "--baseline", type=int, metavar="ID", help="baseline id (default: latest)")
    p.add_argument("--min-severity", type=_severity_arg, metavar="SEV", help="hide lower-severity changes")
    p.add_argument("--no-hooks", action="store_true", help="do not run configured hooks")
    p.add_argument("--update", action="store_true", help="record the current state as a new baseline")
    p.add_argument("--strict", action="store_true", help="exit 3 unless the baseline seal is valid")

    p = add("diff", cmd_diff, "compare two stored baselines")
    report_opts(p)
    p.add_argument("old", type=int, help="older baseline id")
    p.add_argument("new", type=int, help="newer baseline id")

    p = add("watch", cmd_watch, "re-check continuously and report new changes")
    p.add_argument("-i", "--interval", type=float, default=60.0, help="seconds between scans (default 60)")
    p.add_argument("-b", "--baseline", type=int, metavar="ID", help="baseline id (default: latest)")
    p.add_argument("-f", "--format", choices=FORMATS, help="report format")
    p.add_argument("--cycles", type=int, metavar="N", help="stop after N scans")
    p.add_argument("--no-hooks", action="store_true", help="do not run configured hooks")

    p = add("baselines", cmd_baselines, "list stored baselines")
    p.add_argument("--json", action="store_true", help="machine-readable output")

    p = add("show", cmd_show, "list the records of a baseline")
    p.add_argument("baseline", type=int, nargs="?", help="baseline id (default: latest)")
    p.add_argument("-p", "--pattern", help="only records matching this glob")
    p.add_argument("--errors", action="store_true", help="only records that could not be read")
    p.add_argument("--json", action="store_true", help="machine-readable output")

    p = add("verify", cmd_verify, "verify baseline seals and Merkle roots")
    p.add_argument("baseline", type=int, nargs="?", help="baseline id (default: latest)")
    p.add_argument("--all", action="store_true", help="verify every stored baseline")
    p.add_argument("--manifest", metavar="FILE", help="verify an exported manifest instead")
    p.add_argument("--strict", action="store_true", help="unsealed or unverifiable baselines fail")

    p = add("export", cmd_export, "export a baseline as a portable signed manifest")
    p.add_argument("baseline", type=int, nargs="?", help="baseline id (default: latest)")
    p.add_argument("-o", "--output", metavar="FILE", help="output file (default: stdout)")

    p = add("prove", cmd_prove, "create a Merkle inclusion proof for one file")
    p.add_argument("path", help="file whose baseline record to prove")
    p.add_argument("-b", "--baseline", type=int, metavar="ID", help="baseline id (default: latest)")
    p.add_argument("-o", "--output", metavar="FILE", help="output file (default: stdout)")

    p = add("verify-proof", cmd_verify_proof, "verify an inclusion proof")
    p.add_argument("proof", help="proof JSON file")
    p.add_argument("--key", metavar="PATH", help="sealing key used to check the seal")
    p.add_argument("--strict", action="store_true", help="fail unless the seal is verified")

    p = add("explain", cmd_explain, "show which policy rule applies to a path")
    p.add_argument("paths", nargs="+", help="paths to explain")

    add("config", cmd_config, "validate the configuration and print a summary")

    p = add("prune", cmd_prune, "delete old baselines")
    p.add_argument("--keep", type=int, default=10, help="number of newest baselines to keep (default 10)")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return EXIT_USAGE

    verbosity = -1 if args.quiet else args.verbose
    setup_logging(verbosity, log_file=args.log_file, color=False if args.no_color else None)
    args._ctx = Ctx(args)
    try:
        handler: Handler = args.handler
        return handler(args)
    except TesseraError as exc:
        log.error("%s", exc.message)
        if exc.hint:
            print(f"  hint: {exc.hint}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        with contextlib.suppress(OSError):
            sys.stdout = open(os.devnull, "w")  # noqa: SIM115 (silence further writes)
        return EXIT_OK
    except Exception:  # pragma: no cover - last-resort safety net
        log.exception("unexpected internal error, please report it at %s/issues", __url__)
        return EXIT_INTERNAL


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["EXIT_CHANGES", "EXIT_USAGE", "build_parser", "main"]
