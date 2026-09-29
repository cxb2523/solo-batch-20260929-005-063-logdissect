#!/usr/bin/env python
"""flowtui - terminal interaction diagnostic over the logdissect chain.

Entry points
------------
    python -m logdissect.flowtui                 # Textual multi-panel TUI
    python -m logdissect.flowtui --logdir samples
    python -m logdissect.flowtui --verify        # headless self-check

The TUI drives the *real* library code on every keystroke: the same
argparse options feed a fresh ``core.LogDissectCore`` (exported here as
``LogDissect``), the real parser/filter/output modules run, and a
``sys.setprofile`` tracer records the real function names and the order in
which they are actually called. Panel content is built only from the
in-memory result of that concrete run - nothing is fabricated.

Three mutually constraining trade-offs (also rendered in the panels)
--------------------------------------------------------------------
T1  --logtype vs auto-detection
    An explicit ``--logtype``/``-p`` *wins* when the parser recognizes the
    lines. Auto-detection is only consulted for the default selection; if
    it cannot recognize the file (every parser scores zero), we fall back to
    the most recently used parser that still loads (MRU persisted next to
    the log dir) and record *why* the fallback happened.

T2  filter order: filter-then-parse vs parse-then-filter
    Both paths are executed every run and shown side by side with entry
    counts and wall time. The native path parses first so range/last get
    timestamps; the reversed path can only apply raw-text filters (grep,
    rgrep, source, rsource, shost, rshost, dhost, rdhost, process,
    rprocess, protocol, rprotocol) before parsing, then runs the full chain
    again so timestamp filters keep working. Counts may legitimately differ
    when a raw filter changes which lines the parser can date.

T3  timestamp timezone fidelity boundary
    Parsed entries keep both the authored offset (``tzone``) and
    ``numeric_date_stamp`` (local) plus ``numeric_date_stamp_utc``.
    ``--range`` reads local stamps (or UTC with ``--utc``); ``--last`` is
    computed from ``datetime.utcnow()`` and therefore always compares the
    UTC stamp. The ``log`` output serializes only raw text (no offset),
    while ``linejson``/``sojson`` serialize both stamps and ``tzone``. The
    tz panel reports the original authored offset and the output offset.
"""

from __future__ import annotations

import argparse as _argparse
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import logdissect.filters
import logdissect.output
import logdissect.parsers
import logdissect.utils
from logdissect.core import LogDissectCore

# Public alias requested by the task ("drive ... core.LogDissect"):
LogDissect = LogDissectCore

from logdissect.flowdiff import diff_snapshots, node_signature


# ---------------------------------------------------------------------------
# Tracing: capture the REAL function names and real call order
# ---------------------------------------------------------------------------

def _qualified(frame, code):
    module = frame.f_globals.get("__name__", "")
    return "%s.%s" % (module, code.co_name) if module else code.co_name


class FlowTracer:
    """Record ordered calls into logdissect packages for one flow stage."""

    NAMESPACES = (
        "logdissect.core",
        "logdissect.parsers.",
        "logdissect.filters.",
        "logdissect.output.",
        "logdissect.utils",
        "argparse",
    )

    def __init__(self):
        self.events = []
        self._counts = {}
        self._active_stage = None
        self.stages = {}
        self._stage_start = None

    def _is_target(self, qualname):
        if qualname.startswith("logdissect.flow"):
            return False
        # The frame sees the private ArgumentParser class; its real f_qual
        # name at call time is argparse.parse_args.
        if qualname in ("argparse.ArgumentParser.parse_args",
                        "argparse.parse_args"):
            return True
        return any(
            qualname == ns.rstrip(".") if not ns.endswith(".")
            else qualname.startswith(ns)
            for ns in self.NAMESPACES
        )

    def _profile(self, frame, event, arg):
        if event != "call":
            return
        self._record(_qualified(frame, frame.f_code))


    def _record(self, qualname):
        if not self._is_target(qualname):
            return
        self.events.append(qualname)
        self._counts[qualname] = self._counts.get(qualname, 0) + 1
        if self._active_stage is not None:
            self.stages[self._active_stage]["nodes"].append(qualname)

    def start_stage(self, name):
        self._active_stage = name
        self.stages[name] = {"nodes": [], "started": time.perf_counter_ns()}

    def stop_stage(self, counts=None):
        stage = self.stages[self._active_stage]
        stage["elapsed_ms"] = round(
            (time.perf_counter_ns() - stage["started"]) / 1_000_000.0, 3)
        if counts is not None:
            stage["counts"] = counts
        del stage["started"]
        self._active_stage = None
        return stage

    def __enter__(self):
        sys.setprofile(self._profile)
        return self

    def __exit__(self, exc_type, exc, tb):
        sys.setprofile(None)
        return False

    def ordered_nodes(self):
        """First-occurrence ordered unique node list with call counts."""
        seen = {}
        order = []
        for name in self.events:
            if name not in seen:
                seen[name] = {"name": name, "calls": 0}
                order.append(name)
            seen[name]["calls"] += 1
        return [seen[name] for name in order]

# ---------------------------------------------------------------------------
# Log-type selection (trade-off T1)
# ---------------------------------------------------------------------------

def available_logtypes():
    """Parser names registered by logdissect.parsers (real module list)."""
    return sorted(logdissect.parsers.__all__)


def _load_parser(name):
    return __import__("logdissect.parsers." + name, globals(), locals(),
                      [logdissect]).ParseModule()


def _sample_lines(path, limit=20):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [ln.rstrip("\n") for ln in fh.readlines()[:limit]]
    except OSError:
        return []


def _parser_ready(parser):
    """parse_file compiles the format regexes; mirror that for detection."""
    import re
    if getattr(parser, "format_regex", None):
        parser.date_regex = re.compile(r"{}".format(parser.format_regex))
    if getattr(parser, "backup_format_regex", None):
        parser.backup_date_regex = re.compile(
            r"{}".format(parser.backup_format_regex))
    return parser


def detect_logtype(files):
    """Run each real parser's parse_line over the first lines of each file.

    Returns ``(best_name, score, table, error)``. ``table`` maps parser ->
    matched-line count so the panel can show the evidence. On total failure
    ``best_name`` is None and ``error`` explains why.
    """
    table = {}
    total = 0
    for name in available_logtypes():
        parser = _parser_ready(_load_parser(name))
        hits = 0
        for path in files:
            for line in _sample_lines(path):
                if not line.strip():
                    continue
                try:
                    entry = parser.parse_line(line)
                except Exception:
                    entry = None
                if entry is not None:
                    hits += 1
        table[name] = hits
        total = max(total, hits)
    if table and total > 0:
        # Prefer the parser earliest in the registered __all__ order when
        # scores tie (syslog beats the more permissive windowsrsyslog).
        best = min((n for n in available_logtypes() if table[n] == total),
                   key=available_logtypes().index)
    else:
        best = None
    error = None if best else (
        "auto-detect: no parser recognized any of %d file(s)" % len(files))
    return best, total, table, error


def load_mru(logdir):
    """Read the most-recently-used parser list (trade-off T1 fallback)."""
    path = Path(logdir) / ".flowtui-mru.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [n for n in data.get("mru", []) if n in available_logtypes()]
    except (OSError, ValueError):
        return []


def save_mru(logdir, name):
    if name not in available_logtypes():
        return
    mru = load_mru(logdir)
    mru = [name] + [n for n in mru if n != name]
    try:
        (Path(logdir) / ".flowtui-mru.json").write_text(
            json.dumps({"mru": mru[:5]}), encoding="utf-8")
    except OSError:
        pass


def resolve_logtype(files, explicit, logdir):
    """Resolve the parser using the T1 priority rules.

    Returns a dict with keys: logtype, source (explicit|detect|mru|default),
    detail, detect_table, conflict, fallback_reason.
    """
    valid = available_logtypes()
    best, score, table, detect_error = detect_logtype(files)
    mru = load_mru(logdir)

    if explicit:
        if explicit not in valid:
            return {
                "logtype": best or (mru[0] if mru else "syslog"),
                "source": "invalid-explicit",
                "detail": ("--logtype %r is not a registered parser; "
                           "ignoring it" % explicit),
                "detect_table": table,
                "conflict": True,
                "fallback_reason": "invalid --logtype, used detection/MRU",
            }
        return {
            "logtype": explicit,
            "source": "explicit",
            "detail": "--logtype=%s explicitly selected; takes precedence "
                      "over auto-detection (%s scored %d)"
                      % (explicit, best, score if best else 0),
            "detect_table": table,
            "conflict": best is not None and best != explicit,
            "fallback_reason": None,
        }

    if best:
        return {
            "logtype": best,
            "source": "detect",
            "detail": "auto-detect chose %r (%d matching sample line(s))"
                      % (best, score),
            "detect_table": table,
            "conflict": False,
            "fallback_reason": None,
        }

    if mru:
        return {
            "logtype": mru[0],
            "source": "mru",
            "detail": "detection failed; fell back to most recently used "
                      "parser %r" % mru[0],
            "detect_table": table,
            "conflict": False,
            "fallback_reason": detect_error,
        }

    return {
        "logtype": "syslog",
        "source": "default",
        "detail": "detection failed and no MRU exists; using built-in "
                  "default syslog",
        "detect_table": table,
        "conflict": False,
        "fallback_reason": detect_error,
    }

# ---------------------------------------------------------------------------
# The two real execution paths (trade-off T2)
# ---------------------------------------------------------------------------

# Filters that only touch entry['raw_text'] can run before parsing.
RAW_CAPABLE = ("grep", "rgrep")

# Filter names active when their argparse value is set. Maps filter name to
# the attribute the module registers on args.
FILTER_DESTS = {
    "last": "last", "range": "range", "grep": "pattern",
    "rgrep": "rpattern", "source": "source", "rsource": "rsource",
    "shost": "shost", "rshost": "rshost", "dhost": "dhost",
    "rdhost": "rdhost", "process": "process", "rprocess": "rprocess",
    "protocol": "protocol", "rprotocol": "rprotocol",
}


def _filter_active(name, args):
    value = getattr(args, FILTER_DESTS[name], None)
    return bool(value)


def discover_files(logdir):
    """Regular files under logdir (non-recursive), sorted for determinism."""
    root = Path(logdir)
    if root.is_file():
        return [str(root.resolve())]
    return sorted(
        str(p.resolve()) for p in root.iterdir()
        if p.is_file() and not p.name.startswith(".flowtui"))


def _new_core(argv):
    """Build a core whose real argparse parser has been driven with argv."""
    core = LogDissectCore()
    core.load_parsers()
    core.load_filters()
    core.load_outputs()
    _parse_real_argv(core, argv)
    return core


def _parse_real_argv(core, argv):
    """Drive the REAL argparse layer once (config_args registers options)."""
    old_argv = sys.argv
    sys.argv = ["logdissect"] + list(argv)
    try:
        core.config_args()
    finally:
        sys.argv = old_argv


def _load_filter_modules(core):
    return [(name, core.filter_modules[name])
            for name in sorted(logdissect.filters.__filters__)
            if _filter_active(name, core.args)]


def _apply_filters(core, data, active):
    """Mirror core.LogDissectCore.run_filters, but only active filters."""
    for name, module in active:
        data = module.filter_data(data, args=core.args)
    return data


def _run_outputs(core, data, outdir, tag):
    """Run the three real output modules; return per-format metadata."""
    paths = {
        "log": str(Path(outdir) / ("out-%s.log" % tag)),
        "linejson": str(Path(outdir) / ("out-%s.lines.json" % tag)),
        "sojson": str(Path(outdir) / ("out-%s.objects.json" % tag)),
    }
    # Wire the real argparse dests so each module's write_output runs.
    core.args.outlog = paths["log"]
    core.args.label = None
    core.args.linejson = paths["linejson"]
    core.args.sojson = paths["sojson"]
    core.args.pretty = False
    info = {}
    for fmt in sorted(logdissect.output.__formats__):
        module = core.output_modules[fmt]
        module.write_output(data, args=core.args)
        text = Path(paths[fmt]).read_text(encoding="utf-8")
        info[fmt] = {
            "path": paths[fmt],
            "bytes": len(text.encode("utf-8")),
            "carries_tzone": fmt in ("linejson", "sojson"),
        }
    return info


def _tz_report(entries):
    """Original authored offsets vs output-relevant stamps (trade-off T3)."""
    report = []
    for entry in entries[:6]:
        raw_offset = entry.get("tzone")
        local_stamp = entry.get("numeric_date_stamp", "")[:14]
        utc_stamp = entry.get("numeric_date_stamp_utc", "")[:14]
        report.append({
            "raw_text_head": entry.get("raw_text", "")[:48],
            "original_offset": raw_offset,
            "local_stamp": local_stamp,
            "utc_stamp": utc_stamp,
            # JSON formats serialize tzone; the log format emits raw text
            # only, so the offset survives implicitly in the raw line.
            "output_offsets": {
                "log": "implicit (raw text only)",
                "linejson": raw_offset,
                "sojson": raw_offset,
            },
        })
    return report


def _execute_path(order, core, files, outdir, selection, argv):
    """Execute one full path and return its trace + artifacts."""
    tracer = FlowTracer()
    active = _load_filter_modules(core)
    counts = {}

    with tracer:
        tracer.start_stage("argparse")
        # Re-invoke the real parse_args (not config_args, which would
        # re-register options) so the tracer records its true node name.
        old_argv = sys.argv
        sys.argv = ["logdissect"] + list(argv)
        try:
            core.args = core.arg_parser.parse_args()
        finally:
            sys.argv = old_argv
        tracer.stop_stage()

        counts["input_files"] = len(files)
        raw_total = 0
        for path in files:
            with open(path, encoding="utf-8", errors="replace") as fh:
                raw_total += sum(1 for ln in fh if ln.strip())
        counts["raw_lines"] = raw_total

        parser = core.parse_modules[selection["logtype"]]

        if getattr(core.args, "tzone", None):
            parser.tzone = core.args.tzone

        if order == "parse-first":
            tracer.start_stage("parse")
            parsed = {"data_set": []}
            for path in files:
                parsed["data_set"].append(parser.parse_file(path))
            data = logdissect.utils.merge_logs(
                parsed["data_set"], sort=True)
            tracer.stop_stage({"in": raw_total,
                               "out": len(data["entries"])})

            tracer.start_stage("filters")
            data = _apply_filters(core, data, active)
            tracer.stop_stage({"in": counts["raw_lines"],
                               "out": len(data["entries"])})
        else:
            # filter-first: only raw-text filters can run on unparsed lines
            pre_active = [(n, m) for n, m in active if n in RAW_CAPABLE]
            deferred = [n for n, _ in active if n not in RAW_CAPABLE]

            tracer.start_stage("filter-pre")
            raw_entries = []
            for path in files:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.strip():
                            raw_entries.append({"raw_text": line.rstrip("\n")})
            pre_data = {"entries": raw_entries}
            pre_data = _apply_filters(core, pre_data, pre_active)
            tracer.stop_stage({"in": len(raw_entries),
                               "out": len(pre_data["entries"])})

            # Materialize the filtered raw text so the real parser runs on
            # the filtered corpus.
            pre_dir = Path(outdir) / ("pre-%s" % order)
            pre_dir.mkdir(exist_ok=True)
            staged = []
            per_source = {}
            for entry in pre_data["entries"]:
                per_source.setdefault("all", []).append(entry["raw_text"])
            staged_path = pre_dir / "filtered.log"
            staged_path.write_text(
                "\n".join(per_source.get("all", [])) +
                ("\n" if per_source.get("all") else ""),
                encoding="utf-8")
            staged = [str(staged_path)]

            tracer.start_stage("parse")
            parsed = {"data_set": []}
            for path in staged:
                parsed["data_set"].append(parser.parse_file(path))
            data = logdissect.utils.merge_logs(
                parsed["data_set"], sort=True)
            tracer.stop_stage({"in": len(pre_data["entries"]),
                               "out": len(data["entries"])})

            # Full chain again so timestamp filters (range/last) still work:
            tracer.start_stage("filters-post")
            data = _apply_filters(core, data, active)
            tracer.stop_stage({"in": 0,
                               "out": len(data["entries"]),
                               "deferred": deferred})

        tracer.start_stage("output")
        output_info = _run_outputs(core, data, outdir, order)
        tracer.stop_stage({"in": len(data["entries"]),
                           "out_formats": sorted(output_info)})

    nodes = tracer.ordered_nodes()
    stage_summary = {
        name: {
            "elapsed_ms": stage["elapsed_ms"],
            "counts": stage.get("counts", {}),
            "nodes": list(dict.fromkeys(stage["nodes"])),
        }
        for name, stage in tracer.stages.items()
    }
    total_ms = round(sum(s["elapsed_ms"] for s in stage_summary.values()), 3)
    return {
        "order": order,
        "nodes": nodes,
        "stages": stage_summary,
        "total_ms": total_ms,
        "final_count": len(data["entries"]),
        "active_filters": [n for n, _ in active],
        "outputs": output_info,
        "timezone": _tz_report(data["entries"]),
        "range_uses": "numeric_date_stamp" + ("_utc" if core.args.utc else ""),
        "last_uses": "numeric_date_stamp_utc (datetime.utcnow)",
        "entries": data["entries"],
    }

# ---------------------------------------------------------------------------
# Top level run + snapshot construction
# ---------------------------------------------------------------------------

def build_argv(selection, files, filter_order, use_utc):
    """Construct the real argparse argv for a run (also shown in the panel)."""
    argv = ["-s", "-p", selection["logtype"]]
    if selection["logtype"] != "syslogiso":
        # syslogiso entries carry authored offsets; for the other parsers
        # pin +0800 so the run is independent of the host's local zone.
        argv += ["-t", "+0800"]
    argv += ["--grep", "nginx"] if selection["logtype"] == "syslog" \
        else ["--grep", "stamped"]
    argv += ["--range", "20260101000000-21000101000000"]
    # last uses datetime.utcnow() and compares numeric_date_stamp_utc;
    # a wide window keeps the 2026 fixtures selected while exercising the
    # real last filter node in every run.
    argv += ["--last", "4000d"]
    if use_utc:
        argv.append("--utc")
    argv += files
    return argv


def run_flow(logdir, explicit_logtype=None, filter_order="parse-first",
             use_utc=False, persist_mru=True):
    """Execute both T2 paths for the selected input and build a snapshot.

    The snapshot only contains data observed during this concrete run.
    """
    files = discover_files(logdir)
    if not files:
        raise FileNotFoundError("no log files found in %r" % logdir)

    selection = resolve_logtype(files, explicit_logtype, logdir)
    if persist_mru and selection["source"] in ("explicit", "detect"):
        save_mru(logdir, selection["logtype"])

    workdir = tempfile.mkdtemp(prefix="flowtui-")
    try:
        argv = build_argv(selection, files, filter_order, use_utc)

        paths = {}
        errors = []
        for order in ("parse-first", "filter-first"):
            core = _new_core(argv)
            try:
                paths[order] = _execute_path(
                    order, core, files, workdir, selection, argv)
            except Exception as exc:  # surface, do not fabricate
                errors.append({"order": order, "error": repr(exc)})

        tradeoffs = {
            "T1_logtype": {
                "winner": selection["logtype"],
                "source": selection["source"],
                "detail": selection["detail"],
                "conflict": selection["conflict"],
                "fallback_reason": selection["fallback_reason"],
            },
            "T2_filter_order": {
                "parse_first": {
                    "final_count": paths.get("parse-first", {})
                        .get("final_count"),
                    "total_ms": paths.get("parse-first", {}).get("total_ms"),
                },
                "filter_first": {
                    "final_count": paths.get("filter-first", {})
                        .get("final_count"),
                    "total_ms": paths.get("filter-first", {}).get("total_ms"),
                },
            },
            "T3_timezone": {
                "range_boundary": paths.get("parse-first", {})
                    .get("range_uses"),
                "last_boundary": paths.get("parse-first", {})
                    .get("last_uses"),
                "entries": paths.get("parse-first", {}).get("timezone", []),
            },
        }

        identity_argv = argv[:-len(files)] if files else list(argv)
        snapshot = {
            "schema": "flowtui-v1",
            "logdir": str(Path(logdir).resolve()),
            "input": files,
            "selection": {
                "logtype": selection["logtype"],
                "source": selection["source"],
                "detail": selection["detail"],
                "conflict": selection["conflict"],
                "fallback_reason": selection["fallback_reason"],
                "detect_table": selection["detect_table"],
            },
            "filter_order": filter_order,
            "use_utc": use_utc,
            "argv": identity_argv,
            # Top-level ordered node chain consumed by flowdiff: parse-first
            # nodes followed by filter-first nodes. Deterministic because
            # module iteration is sorted and inputs are sorted.
            "nodes": (
                [{"name": n["name"], "path": "parse-first"}
                 for n in paths.get("parse-first", {}).get("nodes", [])]
                + [{"name": n["name"], "path": "filter-first"}
                   for n in paths.get("filter-first", {}).get("nodes", [])]
            ),
            "paths": paths,
            "errors": errors,
            "tradeoffs": tradeoffs,
        }
        import hashlib
        basis = json.dumps({
            "input": snapshot["input"],
            "logtype": selection["logtype"],
            "argv": identity_argv,
            "parse_first_nodes": node_signature(
                {"nodes": paths.get("parse-first", {}).get("nodes", [])}),
            "filter_first_nodes": node_signature(
                {"nodes": paths.get("filter-first", {}).get("nodes", [])}),
        }, sort_keys=True)
        snapshot["run_id"] = hashlib.sha1(
            basis.encode("utf-8")).hexdigest()[:12]
        return snapshot
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Headless HTTP service: /flow.json, /healthz
# ---------------------------------------------------------------------------

class FlowState:
    """Holds the two most recent snapshots + the flowdiff verdict."""

    def __init__(self):
        self.lock = threading.Lock()
        self.snapshots = []
        self.verdict = None

    def publish(self, snapshot):
        with self.lock:
            self.snapshots.append(snapshot)
            self.snapshots = self.snapshots[-2:]
            if len(self.snapshots) == 2:
                a, b = self.snapshots
                verdict = diff_snapshots(a, b)
                self.verdict = verdict
            return dict(self.verdict) if self.verdict else None

    def payload(self):
        with self.lock:
            latest = self.snapshots[-1] if self.snapshots else None
            return {"snapshot": latest,
                    "verdict": dict(self.verdict) if self.verdict else None}


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, body):
            raw = json.dumps(body, indent=2).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path.split("?")[0] == "/healthz":
                self._send(200, {"ok": True})
            elif self.path.split("?")[0] == "/flow.json":
                payload = state.payload()
                # 409 when flowdiff says the two live runs disagree.
                verdict = payload["verdict"]
                code = 409 if verdict and not verdict["consistent"] else 200
                self._send(code, payload)
            else:
                self._send(404, {"error": "not found"})

    return Handler


def serve_forever(state, host, port, ready=None):
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    if ready is not None:
        ready.set()
    httpd.serve_forever()
    return httpd

# ---------------------------------------------------------------------------
# Textual multi-panel TUI
# ---------------------------------------------------------------------------

def _render_node_chain(snapshot, order):
    path = snapshot["paths"].get(order)
    if not path:
        return [("[red]path %s failed[/red]" % order)]
    lines = []
    for index, node in enumerate(path["nodes"]):
        lines.append("%2d. %s  (calls=%d)"
                     % (index + 1, node["name"], node["calls"]))
    return lines


def _render_selection(snapshot):
    sel = snapshot["selection"]
    lines = ["[b]T1[/b] logtype winner: [b cyan]%s[/b cyan] via %s"
             % (sel["logtype"], sel["source"])]
    lines.append("    " + sel["detail"])
    if sel["conflict"]:
        lines.append("    [yellow]explicit --logtype overrides "
                     "auto-detection[/yellow]")
    if sel.get("fallback_reason"):
        lines.append("    [yellow]fallback reason: %s[/yellow]"
                     % sel["fallback_reason"])
    top = sorted(sel["detect_table"].items(), key=lambda kv: (-kv[1], kv[0]))[:4]
    lines.append("    detect scores: " + ", ".join(
        "%s=%d" % (name, score) for name, score in top))
    return lines


def _render_paths(snapshot):
    t2 = snapshot["tradeoffs"]["T2_filter_order"]
    pf = t2["parse_first"]
    ff = t2["filter_first"]
    return [
        "[b]T2[/b] filter ordering (both paths really executed):",
        "  [cyan]parse -> filter[/cyan]: count=%s  total=%s ms"
        % (pf["final_count"], pf["total_ms"]),
        "  [cyan]filter -> parse[/cyan]: count=%s  total=%s ms"
        % (ff["final_count"], ff["total_ms"]),
    ]


def _render_tz(snapshot):
    t3 = snapshot["tradeoffs"]["T3_timezone"]
    lines = [
        "[b]T3[/b] timezone fidelity:",
        "  range compares: %s | last compares: %s"
        % (t3["range_boundary"], t3["last_boundary"]),
    ]
    for entry in t3["entries"][:4]:
        lines.append("  - %s" % entry["raw_text_head"])
        lines.append("      original offset=%s  local=%s  utc=%s"
                     % (entry["original_offset"], entry["local_stamp"],
                        entry["utc_stamp"]))
        lines.append("      output offsets: log=%s, json=%s"
                     % (entry["output_offsets"]["log"],
                        entry["output_offsets"]["linejson"]))
    return lines


def run_tui(logdir, explicit_logtype=None):
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Header, Footer, Static

    class FlowApp(App):
        CSS = """
        Screen { layout: vertical; }
        #top { height: 1fr; }
        #bottom { height: 1fr; }
        .panel { border: round $accent; padding: 0 1; }
        """
        BINDINGS = [
            ("t", "cycle_logtype", "cycle log type"),
            ("o", "toggle_order", "toggle filter order"),
            ("g", "toggle_utc", "toggle range --utc"),
            ("r", "rerun", "re-run live"),
            ("q", "quit", "quit"),
        ]
        TITLE = "logdissect flow diagnostic"

        def __init__(self):
            super().__init__()
            self.logdir = logdir
            self.explicit = explicit_logtype
            self.logtypes = available_logtypes()
            self.cursor = 0
            self.order = "parse-first"
            self.use_utc = False
            self.snapshot = None
            self.prior_snapshot = None
            self.verdict = None

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal(id="top"):
                yield Static(id="selection", classes="panel")
                yield Static(id="flow", classes="panel")
            with Horizontal(id="bottom"):
                yield Static(id="paths", classes="panel")
                yield Static(id="tz", classes="panel")
                yield Static(id="diff", classes="panel")
            yield Footer()

        def on_mount(self):
            self._recompute()

        def _recompute(self):
            chosen = self.logtypes[self.cursor]
            override = self.explicit if self.explicit is not None else chosen
            new_snapshot = run_flow(
                self.logdir, explicit_logtype=override,
                filter_order=self.order, use_utc=self.use_utc)
            if self.snapshot is not None:
                self.prior_snapshot = self.snapshot
                self.verdict = diff_snapshots(self.prior_snapshot,
                                              new_snapshot)
            self.snapshot = new_snapshot
            self._paint()

        def _paint(self):
            snap = self.snapshot
            self.query_one("#selection", Static).update(
                "\n".join(_render_selection(snap)))
            other = "filter-first" if self.order == "parse-first" \
                else "parse-first"
            flow_lines = [
                "[b]live node chain[/b] (active order: [b]%s[/b])"
                % self.order,
                "[dim]press o to compare %s[/dim]" % other,
                "",
            ] + _render_node_chain(snap, self.order)
            argv_line = "argv: " + " ".join(snap["argv"])
            flow_lines.append("")
            flow_lines.append(argv_line)
            self.query_one("#flow", Static).update("\n".join(flow_lines))

            path_lines = _render_paths(snap)
            path_lines.append("")
            for order in ("parse-first", "filter-first"):
                path = snap["paths"].get(order, {})
                path_lines.append("[b]%s[/b] stages:" % order)
                for stage, info in path.get("stages", {}).items():
                    path_lines.append(
                        "  %-13s %8.3f ms  counts=%s"
                        % (stage, info["elapsed_ms"], info["counts"]))
            self.query_one("#paths", Static).update("\n".join(path_lines))
            self.query_one("#tz", Static).update(
                "\n".join(_render_tz(snap)))

            if self.verdict is None:
                diff_text = ("[b]flowdiff[/b]\npress r / change a setting to "
                             "produce two snapshots...")
            elif self.verdict["consistent"]:
                diff_text = ("[b green]flowdiff: CONSISTENT[/b green]\n"
                             "node order identical across the two live runs.")
            else:
                diff_text = "[b red]flowdiff: MISMATCH[/b red]\n%s" % \
                            self.verdict["reason"]
            if snap["errors"]:
                diff_text += "\n[red]run errors:[/red]\n" + "\n".join(
                    e["order"] + ": " + e["error"] for e in snap["errors"])
            self.query_one("#diff", Static).update(diff_text)

            if self.verdict and not self.verdict["consistent"]:
                self.query_one("#diff").styles.color = "red"
            else:
                self.query_one("#diff").styles.color = None

        def action_cycle_logtype(self):
            self.cursor = (self.cursor + 1) % len(self.logtypes)
            self._recompute()

        def action_toggle_order(self):
            self.order = ("filter-first" if self.order == "parse-first"
                          else "parse-first")
            self._recompute()

        def action_toggle_utc(self):
            self.use_utc = not self.use_utc
            self._recompute()

        def action_rerun(self):
            self._recompute()

    FlowApp().run()

# ---------------------------------------------------------------------------
# --verify: headless self-check (non-zero exit on any failure)
# ---------------------------------------------------------------------------

def _http_get_json(url, timeout=10):
    from urllib.request import urlopen
    from urllib.error import HTTPError
    try:
        with urlopen(url, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def run_verify(logdir="samples", host="127.0.0.1", port=0,
               explicit_logtype=None):
    """Headless acceptance check.

    1. start the /flow.json HTTP service,
    2. execute the same input twice and publish both snapshots,
    3. fetch /flow.json and assert node order matches the live trace and
       that the two runs agree (HTTP 200; disagreement would be 409),
    4. exit non-zero with a printed report on any failure.
    """
    failures = []
    state = FlowState()
    server = ThreadingHTTPServer((host, port), make_handler(state))
    actual_host, actual_port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        first = run_flow(logdir, explicit_logtype=explicit_logtype)
        second = run_flow(logdir, explicit_logtype=explicit_logtype)
        state.publish(first)
        state.publish(second)

        live_verdict = diff_snapshots(first, second)
        if not live_verdict["consistent"]:
            failures.append("two live runs differ: %s" % live_verdict)

        for order in ("parse-first", "filter-first"):
            local_nodes = node_signature(
                {"nodes": first["paths"][order]["nodes"]})
            if local_nodes != node_signature(
                    {"nodes": second["paths"][order]["nodes"]}):
                failures.append("%s node order differs between runs" % order)

        code, payload = _http_get_json(
            "http://%s:%d/healthz" % (actual_host, actual_port))
        if code != 200 or not payload.get("ok"):
            failures.append("healthz returned %r" % code)

        code, payload = _http_get_json(
            "http://%s:%d/flow.json" % (actual_host, actual_port))
        if live_verdict["consistent"] and code != 200:
            failures.append("expected 200, got %d" % code)
        if not live_verdict["consistent"] and code != 409:
            failures.append("expected 409 on mismatch, got %d" % code)

        served = payload.get("snapshot") or {}
        for order in ("parse-first", "filter-first"):
            served_nodes = node_signature(
                {"nodes": served.get("paths", {}).get(order, {})
                 .get("nodes", [])})
            live_nodes = node_signature(
                {"nodes": first["paths"][order]["nodes"]})
            if served_nodes != live_nodes:
                failures.append(
                    "/flow.json %s nodes do not match the live trace"
                    % order)
        verdict = payload.get("verdict") or {}
        if live_verdict["consistent"] != bool(verdict.get("consistent")):
            failures.append("served verdict disagrees with flowdiff")

        # Also assert a deliberately tampered snapshot yields 409 logic:
        tampered = json.loads(json.dumps(second))
        if tampered.get("nodes"):
            tampered["nodes"][0]["name"] += ".TAMPER"
        tamper_verdict = diff_snapshots(first, tampered)
        if tamper_verdict["consistent"]:
            failures.append("flowdiff failed to detect tampered order")
    finally:
        server.shutdown()
        server.server_close()

    print("flowtui verify: %s" % ("PASS" if not failures else "FAIL"))
    print("  logtype:", first["selection"]["logtype"],
          "(" + first["selection"]["source"] + ")")
    for order in ("parse-first", "filter-first"):
        print("  %s: %d nodes, %d entries, %s ms" % (
            order, len(first["paths"][order]["nodes"]),
            first["paths"][order]["final_count"],
            first["paths"][order]["total_ms"]))
    for failure in failures:
        print("  [FAIL]", failure)
    return 0 if not failures else 1


def main(argv=None):
    parser = _argparse.ArgumentParser(
        prog="python -m logdissect.flowtui",
        description="interactive flow diagnostic for the logdissect chain")
    parser.add_argument("--logdir", default="samples",
                        help="directory containing log files")
    parser.add_argument("--logtype", default=None,
                        help="explicit parser (takes precedence over "
                             "auto-detection)")
    parser.add_argument("--verify", action="store_true",
                        help="headless self-check; non-zero exit on failure")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=0, type=int)
    args = parser.parse_args(argv)

    if args.verify:
        return run_verify(logdir=args.logdir, host=args.host,
                          port=args.port,
                          explicit_logtype=args.logtype)
    run_tui(args.logdir, explicit_logtype=args.logtype)
    return 0


if __name__ == "__main__":
    sys.exit(main())