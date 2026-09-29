"""Interactive flow diagnostics for the logdissect parse pipeline.

Entry point::

    python -m logdissect.flowtui --logdir samples
    python -m logdissect.flowtui --verify

The TUI drives the *real* logdissect machinery -- ``argparse`` (via
``core.LogDissectCore.config_args``), ``LogDissectCore``, the parser /
``filters`` chains and the three output modules -- and every panel is
populated from a live run only.  Nothing is cached or invented: node names
are captured with ``sys.setprofile`` while the genuine functions execute.

Three mutually constraining tradeoffs are surfaced (search for
``TRADEOFF``) and labelled in the panels:

1. Auto-detection vs explicit ``--logtype``: an explicit type always wins;
   when auto-detection fails we fall back to the most recently usable type
   and record why.
2. Filter-first vs parse-first: the upstream order is parse -> merge ->
   filters; the reversed intent (raw pre-filter before parsing) is run
   alongside it, and both show live counts and timings.
3. Timestamp/timezone fidelity: ``range`` honours ``--utc`` while ``last``
   always compares UTC, and the three serializers carry different offsets.
   The panel reports the original offset and the serialized offset.

Running the same input twice must yield the same node order.  Two live
snapshots are compared with :mod:`logdissect.flowdiff`; a mismatch turns
the panel red and makes ``/flow.json`` answer HTTP 409.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tempfile
import threading
import types
import warnings
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import logdissect.parsers
import logdissect.utils
import logdissect.filters
from logdissect.core import LogDissectCore
from logdissect.flowdiff import (
    FILTER_FIRST_PATH,
    PARSE_FIRST_PATH,
    STATUS_CONFLICT,
    STATUS_OK,
    diff_snapshots,
)

warnings.simplefilter("ignore")

SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# TRADEOFF #1 -- parser selection
# ---------------------------------------------------------------------------
# When both an explicit --logtype and an auto-detected type exist they can
# disagree.  We resolve that in favour of the explicit flag (the operator's
# intent must beat a heuristic) but keep the detected value visible.  If no
# explicit type was given and detection fails, we fall back to the most
# recently usable type for this log directory; if none exists we use the
# logdissect default parser ("syslog").  Every branch records its reason.
DEFAULT_PARSER = "syslog"

# Fixed specificity ladder used to break ties when several regexes match the
# same line (e.g. a classic syslog line matches both "syslog" and
# "windowsrsyslog").  Higher number wins on an equal field count.
PARSER_PRIORITY = {
    "syslogiso": 100,
    "webaccess": 95,
    "tcpdump": 90,
    "ciscoios": 85,
    "syslog": 80,
    "syslognohost": 70,
    "windowsrsyslog": 60,
    "emerge": 55,
    "dotnetDefault": 50,
}

# A parser must explain at least this fraction of the sampled lines to win.
DETECT_MIN_RATIO = 0.5
DETECT_SAMPLE_LINES = 40


class FlowTracer:
    """Capture real function names and order with ``sys.setprofile``.

    Only frames executing inside the installed ``logdissect`` package are
    recorded, so stdlib/Textual noise is ignored.  Consecutive calls to the
    same qualified name are folded into one node while preserving the
    ordered transition list and a call count.
    """

    def __init__(self, package_dir: str, collapse: bool = False):
        self._package_dir = os.path.abspath(package_dir)
        self._stack: Dict[Any, Tuple[Dict[str, Any], float]] = {}
        self._records: List[Dict[str, Any]] = []
        self._previous_name: Optional[str] = None
        # When False (default) every call is its own node so the ordered list
        # faithfully shows repeated per-line calls such as parse_line.  The
        # determinism contract compares this full sequence, not a folded one.
        self._collapse = collapse

    def start(self) -> None:
        sys.setprofile(self._on_event)

    def stop(self) -> None:
        sys.setprofile(None)

    def _is_ours(self, code_filename: str) -> bool:
        if not code_filename:
            return False
        normalized = os.path.abspath(code_filename)
        if not normalized.startswith(self._package_dir):
            return False
        # Never trace the diagnostic layer itself.  This is matched on the
        # file basename because under ``python -m`` flowtui runs as
        # __main__, so its __name__ cannot be used to exclude it.
        if os.path.basename(normalized) in ("flowtui.py", "flowdiff.py"):
            return False
        return os.path.splitext(normalized)[1] == ".py"

    def _on_event(self, frame: Any, event: str, arg: Any) -> None:
        code = frame.f_code
        filename = code.co_filename
        if not self._is_ours(filename):
            return
        module = frame.f_globals.get("__name__", "?")
        qualname = "{}.{}".format(module, code.co_name)
        if event == "call":
            record: Dict[str, Any]
            if self._collapse and qualname == self._previous_name and self._records:
                record = self._records[-1]
                record["calls"] += 1
            else:
                record = {"qualname": qualname, "calls": 1, "elapsed_ms": 0.0}
                self._records.append(record)
                self._previous_name = qualname
            self._stack[frame] = (record, time.perf_counter())
        elif event == "return":
            entry = self._stack.pop(frame, None)
            if entry is not None:
                record, started_at = entry
                record["elapsed_ms"] += (time.perf_counter() - started_at) * 1000.0

    def nodes(self) -> List[Dict[str, Any]]:
        return [dict(record) for record in self._records]


def load_parser_modules() -> Dict[str, Any]:
    """Instantiate every real parser module, mirroring ``core`` loading."""
    modules: Dict[str, Any] = {}
    for name in sorted(logdissect.parsers.__all__):
        module = __import__(
            "logdissect.parsers." + name, globals(), locals(), [logdissect]
        )
        modules[name] = module.ParseModule()
    return modules


def read_sample_lines(path: str, limit: int = DETECT_SAMPLE_LINES) -> List[str]:
    """Read up to ``limit`` non-empty lines from a log file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\n") for line in handle]
    except OSError:
        return []
    return [line for line in lines if line.strip()][:limit]


def detect_logtype(
    path: str, parser_modules: Dict[str, Any]
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """Auto-detect a parser by plurality vote over the sample lines.

    Returns ``(winning_parser, per_parser_scores)``.  JSON formats are
    detected structurally; regex formats vote on every sampled line.  A
    winner must explain at least ``DETECT_MIN_RATIO`` of the lines.
    """
    scores = [
        {
            "parser": name,
            "matched_lines": 0,
            "fields": len(getattr(module, "fields", []) or []),
            "priority": PARSER_PRIORITY.get(name, 0),
        }
        for name, module in parser_modules.items()
    ]
    score_by_name = {item["parser"]: item for item in scores}
    lines = read_sample_lines(path)
    if not lines:
        return None, scores

    # Structural JSON detection first -- linejson and sojson have no regex.
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        head = handle.read()
    try:
        json.loads(head)
        return "sojson", scores
    except (ValueError, TypeError):
        pass
    line_json_lines = 0
    for line in lines:
        try:
            json.loads(line)
            line_json_lines += 1
        except (ValueError, TypeError):
            pass
    if line_json_lines >= max(1, int(len(lines) * DETECT_MIN_RATIO)):
        return "linejson", scores

    import re

    for line in lines:
        for name, module in parser_modules.items():
            regex = getattr(module, "format_regex", None)
            if not regex:
                continue
            try:
                if re.compile(r"{}".format(regex)).findall(line):
                    score_by_name[name]["matched_lines"] += 1
            except re.error:
                continue

    candidates = [
        item for item in scores if item["matched_lines"] > 0
    ]
    if not candidates:
        return None, scores
    candidates.sort(
        key=lambda item: (
            item["matched_lines"],
            item["fields"],
            item["priority"],
            item["parser"],
        ),
        reverse=True,
    )
    winner = candidates[0]
    if winner["matched_lines"] / len(lines) < DETECT_MIN_RATIO:
        return None, scores
    return winner["parser"], scores


@dataclass
class LogtypeDecision:
    """Outcome of TRADEOFF #1 for one run."""

    selected: str
    explicit: Optional[str]
    detected: Optional[str]
    source: str
    reason: str
    conflict: bool
    fallback_from: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "selected": self.selected,
            "explicit": self.explicit,
            "detected": self.detected,
            "source": self.source,
            "reason": self.reason,
            "conflict": self.conflict,
            "fallback_from": self.fallback_from,
        }


def choose_logtype(
    path: str,
    explicit: Optional[str],
    parser_modules: Dict[str, Any],
    last_usable: Dict[str, str],
) -> Tuple[LogtypeDecision, List[Dict[str, Any]]]:
    """Resolve the explicit-vs-auto tradeoff with a documented fallback."""
    directory = os.path.dirname(os.path.abspath(path))
    detected, scores = detect_logtype(path, parser_modules)

    if explicit:
        if explicit in parser_modules:
            conflict = detected is not None and detected != explicit
            reason = (
                "explicit --logtype overrides conflicting auto-detection"
                if conflict
                else "explicit --logtype honoured"
            )
            if detected:
                last_usable[directory] = detected
            return (
                LogtypeDecision(
                    selected=explicit,
                    explicit=explicit,
                    detected=detected,
                    source="explicit",
                    reason=reason,
                    conflict=conflict,
                ),
                scores,
            )

    if detected:
        last_usable[directory] = detected
        return (
            LogtypeDecision(
                selected=detected,
                explicit=explicit,
                detected=detected,
                source="auto",
                reason="auto-detection matched >= {:.0%} of sample lines".format(
                    DETECT_MIN_RATIO
                ),
                conflict=False,
            ),
            scores,
        )

    fallback = last_usable.get(directory, DEFAULT_PARSER)
    reason = (
        "auto-detection matched no parser; fell back to most recently usable "
        "type '{}' for this directory".format(fallback)
        if directory in last_usable
        else "auto-detection matched no parser and no prior usable type; "
        "fell back to logdissect default '{}'".format(DEFAULT_PARSER)
    )
    return (
        LogtypeDecision(
            selected=fallback,
            explicit=explicit,
            detected=None,
            source="fallback",
            reason=reason,
            conflict=False,
            fallback_from=detected,
        ),
        scores,
    )


# ---------------------------------------------------------------------------
# TRADEOFF #3 -- timestamp / timezone fidelity
# ---------------------------------------------------------------------------
def representative_entry(entries: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for entry in entries:
        if isinstance(entry, dict):
            return entry
    return None


def timezone_report(
    entry: Optional[Dict[str, Any]],
    filters: Dict[str, Any],
    serialized: Dict[str, Any],
) -> Dict[str, Any]:
    """Describe the fidelity boundary for range/last and the 3 serializers.

    ``range`` compares local ``numeric_date_stamp`` unless ``--utc`` is set,
    while ``last`` always compares ``numeric_date_stamp_utc``.  The "log"
    serializer emits ``raw_text`` (no offset at all); linejson/sojson emit
    the entry dict including ``tzone`` and the UTC stamp.  We report both
    the original parsed offset and the offset that survives serialization.
    """
    entry = entry or {}
    original_offset = entry.get("tzone")

    # The upstream utils.get_local_tzone() helper can emit a malformed sign
    # pair on some hosts (observed "+-800"); surface it verbatim but flag it
    # so the fidelity boundary is honest rather than hidden.
    local_offset_warning = None
    if isinstance(original_offset, str) and original_offset[:2] in ("+-", "-+"):
        local_offset_warning = (
            "malformed local offset '{}' produced by upstream "
            "utils.get_local_tzone(); use -t to set an explicit offset"
            .format(original_offset)
        )

    def serialized_offset(fmt: str) -> Optional[str]:
        data = serialized.get(fmt)
        items = data.get("entries") if isinstance(data, dict) else None
        first = items[0] if items else None
        if isinstance(first, dict):
            return first.get("tzone")
        return None  # raw-text format carries no structured offset

    return {
        "original_offset": original_offset,
        "local_offset_warning": local_offset_warning,
        "output_offset": {
            "log": serialized_offset("log"),
            "linejson": serialized_offset("linejson"),
            "sojson": serialized_offset("sojson"),
        },
        "numeric_date_stamp_local": entry.get("numeric_date_stamp"),
        "numeric_date_stamp_utc": entry.get("numeric_date_stamp_utc"),
        "range": {
            "active": bool(filters.get("range")),
            "value": filters.get("range"),
            "compare_field": "numeric_date_stamp_utc"
            if filters.get("utc")
            else "numeric_date_stamp",
            "note": "range honours --utc: compares UTC only when --utc is set",
        },
        "last": {
            "active": bool(filters.get("last")),
            "value": filters.get("last"),
            "compare_field": "numeric_date_stamp_utc",
            "note": "last always compares UTC regardless of --utc",
        },
        "serializers": {
            "log": "raw_text only: original offset is dropped",
            "linejson": "entry dict: tzone + numeric_date_stamp(_utc) kept",
            "sojson": "single JSON object: same fields as linejson",
        },
    }


@dataclass
class FlowOptions:
    """Operator-selected state for one live run."""

    logdir: str = "samples"
    file_index: int = 0
    explicit_logtype: Optional[str] = None
    tzone: Optional[str] = None
    filters: Dict[str, Any] = field(
        default_factory=lambda: {
            "grep": None,
            "rgrep": None,
            "range": None,
            "utc": False,
            "last": None,
        }
    )


@dataclass
class PathResult:
    entries: int = 0
    elapsed_ms: float = 0.0
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    filter_counts: List[Dict[str, Any]] = field(default_factory=list)
    pre_parse_input_lines: int = 0
    pre_parse_output_lines: int = 0
    parse_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entries": self.entries,
            "elapsed_ms": round(self.elapsed_ms, 4),
            "nodes": self.nodes,
            "filter_counts": self.filter_counts,
            "pre_parse_input_lines": self.pre_parse_input_lines,
            "pre_parse_output_lines": self.pre_parse_output_lines,
            "parse_error": self.parse_error,
        }


PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

# Filters that can meaningfully run on raw text before parsing.  Everything
# else needs parsed fields and therefore cannot be part of the pre-parse leg
# of the reversed path.
RAW_CAPABLE_FILTERS = ("grep", "rgrep")

# argparse ``dest`` backing each filter, used to label active nodes.
FILTER_DEST = {
    "grep": "pattern",
    "rgrep": "rpattern",
    "last": "last",
    "range": "range",
    "source": "source",
    "rsource": "rsource",
    "shost": "shost",
    "rshost": "rshost",
    "dhost": "dhost",
    "rdhost": "rdhost",
    "process": "process",
    "rprocess": "rprocess",
    "protocol": "protocol",
    "rprotocol": "rprotocol",
}


def build_argv(options: FlowOptions, parser_name: str, input_path: str,
               out_paths: Dict[str, str]) -> List[str]:
    """Build the real argv consumed by ``LogDissectCore.config_args``."""
    argv = ["flowtui", "-s", "-p", parser_name, input_path]
    if options.tzone:
        argv.extend(["-t", options.tzone])
    filters = options.filters
    if filters.get("grep"):
        argv.extend(["--grep", filters["grep"]])
    if filters.get("rgrep"):
        argv.extend(["--rgrep", filters["rgrep"]])
    if filters.get("range"):
        argv.extend(["--range", filters["range"]])
    if filters.get("utc"):
        argv.append("--utc")
    if filters.get("last"):
        argv.extend(["--last", filters["last"]])
    argv.extend(["--outlog", out_paths["log"]])
    argv.extend(["--linejson", out_paths["linejson"]])
    argv.extend(["--sojson", out_paths["sojson"]])
    return argv


def configure_core(argv: List[str], input_path: str) -> LogDissectCore:
    """Load modules and run the real argparse configuration."""
    core = LogDissectCore()
    core.load_parsers()
    core.load_filters()
    core.load_outputs()
    old_argv = sys.argv
    sys.argv = argv
    try:
        core.config_args()
    finally:
        sys.argv = old_argv
    # The core normally resolves input files inside run_job; do the same
    # absolute-path resolution for the single live file.
    core.input_files = [os.path.abspath(input_path)]
    return core


def run_filters_with_counts(
    core: LogDissectCore, order: Sequence[str]
) -> List[Dict[str, Any]]:
    """Run the real filter modules in ``order`` and record per-filter counts.

    This is the same sorted module set and the same ``filter_data`` call as
    ``core.run_filters``; it is replicated only so each node's input/output
    count can be observed during the genuine run.
    """
    counts: List[Dict[str, Any]] = []
    for name in order:
        if name not in core.filter_modules:
            continue
        before = len(core.data_set["finalized_data"]["entries"])
        filter_module = core.filter_modules[name]
        result = filter_module.filter_data(
            core.data_set["finalized_data"], args=core.args
        )
        core.data_set["finalized_data"] = result
        after = len(result["entries"])
        counts.append(
            {
                "filter": name,
                "before": before,
                "after": after,
                "active": bool(getattr(core.args, FILTER_DEST.get(name, name), None)),
            }
        )
    return counts


def serialize_outputs(
    core: LogDissectCore, out_paths: Dict[str, str],
    tracer: Optional["FlowTracer"] = None,
) -> Dict[str, Any]:
    """Invoke each real output module and report per-format success."""
    results: Dict[str, Any] = {}
    if tracer is not None:
        tracer.start()
    try:
        for fmt in ("log", "linejson", "sojson"):
            info: Dict[str, Any] = {"path": out_paths[fmt], "ok": False,
                                    "error": None}
            try:
                core.output_modules[fmt].write_output(
                    core.data_set["finalized_data"], args=core.args
                )
                info["ok"] = True
            except Exception as exc:  # noqa: BLE001 - surface fidelity failures
                info["error"] = "{}: {}".format(type(exc).__name__, exc)
            results[fmt] = info
    finally:
        if tracer is not None:
            tracer.stop()
    return results


def load_serialized_preview(out_paths: Dict[str, str]) -> Dict[str, Any]:
    """Read the three output files back from disk (this run only)."""
    preview: Dict[str, Any] = {}

    log_entries: List[Dict[str, Any]] = []
    try:
        with open(out_paths["log"], "r", encoding="utf-8") as handle:
            log_entries = [{"raw_text": line.rstrip("\n")}
                           for line in handle if line.strip()]
    except OSError:
        log_entries = []
    preview["log"] = {"entries": log_entries}

    line_entries: List[Dict[str, Any]] = []
    try:
        with open(out_paths["linejson"], "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    line_entries.append(json.loads(line))
    except (OSError, ValueError):
        line_entries = []
    preview["linejson"] = {"entries": line_entries}

    so_entries: List[Dict[str, Any]] = []
    try:
        with open(out_paths["sojson"], "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
            if isinstance(loaded, list):
                so_entries = loaded
    except (OSError, ValueError):
        so_entries = []
    preview["sojson"] = {"entries": so_entries}
    return preview


def _write_temp(lines: Sequence[str]) -> str:
    fd, path = tempfile.mkstemp(prefix="flowtui_", suffix=".log")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        if lines:
            handle.write("\n")
    return path


def run_parse_first(
    core: LogDissectCore, order: Sequence[str],
    tracer: Optional[FlowTracer] = None,
) -> PathResult:
    """TRADEOFF #2, upstream order: parse -> merge -> filters."""
    result = PathResult()
    own_tracer = tracer is None
    if tracer is None:
        tracer = FlowTracer(PACKAGE_DIR)
    started = time.perf_counter()
    if own_tracer:
        tracer.start()
    try:
        # Genuine core methods: parse each file then merge/sort.
        try:
            core.run_parse()
        except Exception as exc:  # noqa: BLE001 - upstream parser fidelity edge
            result.parse_error = "{}: {}".format(type(exc).__name__, exc)
            core.data_set = {"data_set": [{"entries": []}]}
        core.data_set["finalized_data"] = logdissect.utils.merge_logs(
            core.data_set["data_set"], sort=True
        )
        result.filter_counts = run_filters_with_counts(core, order)
    finally:
        if own_tracer:
            tracer.stop()
    result.elapsed_ms = (time.perf_counter() - started) * 1000.0
    result.nodes = tracer.nodes()
    result.entries = len(core.data_set["finalized_data"]["entries"])
    return result


def run_filter_first(core: LogDissectCore, order: Sequence[str]) -> PathResult:
    """TRADEOFF #2, reversed intent: raw pre-filter -> parse -> filters.

    Only raw-capable filters (grep/rgrep) can precede parsing; field-based
    filters remain post-parse.  The pre-parse leg applies the *real* filter
    module to raw lines, then the genuine parser runs on the reduced file.
    """
    result = PathResult()
    source = core.input_files[0]
    raw_lines = read_sample_lines(source, limit=10 ** 9)
    result.pre_parse_input_lines = len(raw_lines)

    pre_names = [name for name in order if name in RAW_CAPABLE_FILTERS]
    post_names = [name for name in order if name not in RAW_CAPABLE_FILTERS]

    reduced_lines = list(raw_lines)
    temp_path: Optional[str] = None
    tracer = FlowTracer(PACKAGE_DIR)
    started = time.perf_counter()
    tracer.start()
    try:
        for name in pre_names:
            values = (
                getattr(core.args, "pattern", None)
                if name == "grep"
                else getattr(core.args, "rpattern", None)
            )
            if not values:
                continue
            before = len(reduced_lines)
            pseudo = {"entries": [{"raw_text": line} for line in reduced_lines]}
            # The real rgrep module dereferences args.rpattern even when a
            # values list is supplied (upstream quirk); a minimal shim keeps
            # the genuine filter_data call working on raw lines.
            shim = types.SimpleNamespace(
                pattern=values if name == "grep" else None,
                rpattern=values if name == "rgrep" else None,
            )
            filtered = core.filter_modules[name].filter_data(
                pseudo, args=shim
            )
            reduced_lines = [entry["raw_text"] for entry in filtered["entries"]]
            result.filter_counts.append(
                {"filter": name + "@raw", "before": before,
                 "after": len(reduced_lines), "active": True}
            )
        result.pre_parse_output_lines = len(reduced_lines)
        temp_path = _write_temp(reduced_lines)
        core.input_files = [temp_path]
        try:
            core.run_parse()
        except Exception as exc:  # noqa: BLE001 - upstream parser fidelity edge
            result.parse_error = "{}: {}".format(type(exc).__name__, exc)
            core.data_set = {"data_set": [{"entries": []}]}
        core.data_set["finalized_data"] = logdissect.utils.merge_logs(
            core.data_set["data_set"], sort=True
        )
        post_counts = run_filters_with_counts(core, post_names)
    finally:
        tracer.stop()
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        core.input_files = [source]
    result.elapsed_ms = (time.perf_counter() - started) * 1000.0
    result.nodes = tracer.nodes()
    result.filter_counts.extend(post_counts)
    result.entries = len(core.data_set["finalized_data"]["entries"])
    return result


def list_log_files(logdir: str) -> List[str]:
    if not os.path.isdir(logdir):
        return []
    names = sorted(
        name for name in os.listdir(logdir)
        if os.path.isfile(os.path.join(logdir, name))
    )
    return [os.path.abspath(os.path.join(logdir, name)) for name in names]


def execute_once(
    options: FlowOptions,
    input_path: str,
    parser_name: str,
    reverse_filters: bool,
    workdir: str,
    run_tag: str,
) -> Tuple[PathResult, PathResult, Dict[str, Any], Dict[str, Any]]:
    """Run both filter-order paths through the real pipeline once."""
    tag = run_tag
    out_paths = {
        fmt: os.path.join(workdir, "out_{}.{}".format(tag, ext))
        for fmt, ext in (("log", "log"), ("linejson", "jsonl"),
                         ("sojson", "json"))
    }
    argv = build_argv(options, parser_name, input_path, out_paths)

    # The active filter invocation order: alphabetical (core order) or the
    # reverse, toggled in the TUI.  Core loads filters sorted; this is the
    # same module set in the opposite order.
    filter_order = sorted(logdissect.filters.__filters__)
    if reverse_filters:
        filter_order = list(reversed(filter_order))

    # Parse-first path consumes the original input.  One tracer spans
    # parse -> merge -> filters -> outputs so the full real chain including
    # write_output appears in a single ordered node list.
    core_a = configure_core(argv, input_path)
    shared_tracer = FlowTracer(PACKAGE_DIR)
    shared_tracer.start()
    parse_first = run_parse_first(core_a, filter_order, shared_tracer)
    serialized = serialize_outputs(core_a, out_paths, shared_tracer)
    shared_tracer.stop()
    parse_first.nodes = shared_tracer.nodes()
    preview = load_serialized_preview(out_paths)

    # Filter-first path re-parses the raw-reduced file with a fresh core so
    # neither path can contaminate the other's observed counts.
    core_b = configure_core(argv, input_path)
    filter_first = run_filter_first(core_b, filter_order)

    return parse_first, filter_first, serialized, preview


def run_snapshot(
    options: FlowOptions,
    parser_modules: Dict[str, Any],
    last_usable: Dict[str, str],
    reverse_filters: bool = False,
) -> Dict[str, Any]:
    """Execute the input twice, diff node order, and assemble the snapshot."""
    files = list_log_files(options.logdir)
    if not files:
        raise RuntimeError("no input files found in logdir: {}".format(
            options.logdir))
    options.file_index = options.file_index % len(files)
    input_path = files[options.file_index]

    decision, detection_scores = choose_logtype(
        input_path, options.explicit_logtype, parser_modules, last_usable
    )
    parser_name = decision.selected

    workdir = tempfile.mkdtemp(prefix="flowtui_run_")
    run_a = execute_once(
        options, input_path, parser_name, reverse_filters, workdir, "a"
    )
    parse_first_a, filter_first_a, serialized, preview = run_a
    # The determinism check re-executes the identical input; filter toggle is
    # held constant so only genuine non-determinism can fail it.
    run_b = execute_once(
        options, input_path, parser_name, reverse_filters, workdir, "b"
    )
    parse_first_b, filter_first_b, _, _ = run_b

    snapshot_a = {
        "paths": {
            PARSE_FIRST_PATH: {"nodes": parse_first_a.nodes},
            FILTER_FIRST_PATH: {"nodes": filter_first_a.nodes},
        }
    }
    snapshot_b = {
        "paths": {
            PARSE_FIRST_PATH: {"nodes": parse_first_b.nodes},
            FILTER_FIRST_PATH: {"nodes": filter_first_b.nodes},
        }
    }
    diff = diff_snapshots(snapshot_a, snapshot_b)

    entry = representative_entry(
        preview["linejson"]["entries"] or preview["sojson"]["entries"]
    )
    tz = timezone_report(entry, options.filters, preview)

    snapshot: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "input": {
            "logdir": os.path.abspath(options.logdir),
            "file": input_path,
            "file_index": options.file_index,
            "file_count": len(files),
        },
        "argv_probe": build_argv(options, parser_name, input_path,
                                 {"log": "<log>", "linejson": "<jsonl>",
                                  "sojson": "<json>"}),
        "logtype": {
            "decision": decision.to_dict(),
            "detection_scores": detection_scores,
            "available": sorted(parser_modules),
        },
        "filter_order": {
            "reversed": reverse_filters,
            "order": list(reversed(sorted(logdissect.filters.__filters__)))
            if reverse_filters else sorted(logdissect.filters.__filters__),
        },
        "paths": {
            PARSE_FIRST_PATH: parse_first_a.to_dict(),
            FILTER_FIRST_PATH: filter_first_a.to_dict(),
        },
        "timezone": tz,
        "outputs": serialized,
        "diff": diff.to_dict(),
    }
    return snapshot


class SnapshotStore:
    """Thread-safe holder for the latest live snapshot and its HTTP status."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot: Optional[Dict[str, Any]] = None

    def set(self, snapshot: Dict[str, Any]) -> None:
        with self._lock:
            self._snapshot = snapshot

    def get(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return None if self._snapshot is None else json.loads(
                json.dumps(self._snapshot)
            )


def build_handler(store: SnapshotStore) -> type:
    class FlowHandler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence the server
            return

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            if self.path.split("?", 1)[0] != "/flow.json":
                self.send_response(404)
                self.end_headers()
                return
            snapshot = store.get()
            if snapshot is None:
                self.send_response(503)
                self.end_headers()
                return
            status = int(snapshot.get("diff", {}).get("status", STATUS_CONFLICT))
            body = json.dumps(snapshot, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return FlowHandler


def start_server(store: SnapshotStore, port: int) -> Tuple[ThreadingHTTPServer, str]:
    """Start a background loopback HTTP server exposing /flow.json."""
    server = ThreadingHTTPServer(("127.0.0.1", port), build_handler(store))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, bound_port = server.server_address
    return server, "http://{}:{}/flow.json".format(host, bound_port)


GREP_PRESETS = [None, "systemd", "service"]
RGROUP_PRESETS = [None, "CRON"]
# A deliberately wide, fixed historical range so the range filter is
# deterministic (it never depends on the wall clock), followed by a tight
# range and a "last" preset that uses the wall clock.
TIME_PRESETS = [
    {},
    {"range": "200001010000-210001010000", "utc": False, "last": None},
    {"range": "202609300800-202609301000", "utc": False, "last": None},
    {"range": "200001010000-210001010000", "utc": True, "last": None},
    {"last": "40000d", "range": None, "utc": False},
]
TZONE_PRESETS = [None, "+0500", "+0000", "-0800"]


def _node_line(index: int, node: Dict[str, Any]) -> str:
    return "{:>3}  {:<58} x{:<3} {:>8.3f}ms".format(
        index, node["qualname"], node["calls"], node["elapsed_ms"]
    )


def render_flow_app(snapshot: Dict[str, Any], options: FlowOptions,
                    url: str) -> Dict[str, str]:
    """Render every panel's body purely from this live snapshot."""
    from rich.text import Text

    panels: Dict[str, Any] = {}
    decision = snapshot["logtype"]["decision"]
    conflict = decision["conflict"]

    head = Text()
    head.append("flowtui  live pipeline diagnostics\n", style="bold cyan")
    head.append("input: ", style="dim")
    head.append(os.path.basename(snapshot["input"]["file"]) + "\n")
    head.append(url + "\n", style="blue underline")
    head.append("\n[TRADEOFF 1] logtype resolution\n", style="bold yellow")
    head.append("  selected : ", style="dim")
    head.append(decision["selected"] + "\n", style="bold green")
    head.append("  explicit : {}\n".format(decision["explicit"]))
    head.append("  detected : {}\n".format(decision["detected"]))
    head.append("  source   : {}\n".format(decision["source"]))
    if conflict:
        head.append("  CONFLICT: explicit --logtype wins over auto-detect\n",
                    style="bold red")
    if decision["source"] == "fallback":
        head.append("  FALLBACK: " + decision["reason"] + "\n",
                    style="bold yellow")
    head.append("  reason   : " + decision["reason"] + "\n", style="dim")
    panels["header"] = head

    scores = sorted(
        snapshot["logtype"]["detection_scores"],
        key=lambda s: (s["matched_lines"], s["fields"], s["priority"]),
        reverse=True,
    )[:8]
    det = Text("auto-detection vote (top 8)\n", style="bold")
    for item in scores:
        style = "green" if item["parser"] == decision["selected"] else "white"
        det.append("  {:<16} matched={:<3} fields={:<2} prio={:<3}\n".format(
            item["parser"], item["matched_lines"], item["fields"],
            item["priority"]), style=style)
    panels["detect"] = det

    order = snapshot["filter_order"]
    paths = snapshot["paths"]
    cmp_body = Text()
    cmp_body.append("[TRADEOFF 2] filter order side by side\n",
                    style="bold yellow")
    cmp_body.append("active order: {}\n\n".format(
        "REVERSED" if order["reversed"] else "upstream (core sorted)"))
    cmp_body.append("  parse-first  entries={:<4} total={:.3f}ms\n".format(
        paths[PARSE_FIRST_PATH]["entries"],
        paths[PARSE_FIRST_PATH]["elapsed_ms"]), style="cyan")
    cmp_body.append("  filter-first entries={:<4} total={:.3f}ms\n".format(
        paths[FILTER_FIRST_PATH]["entries"],
        paths[FILTER_FIRST_PATH]["elapsed_ms"]), style="magenta")
    cmp_body.append(
        "  raw leg: {} -> {} lines (grep/rgrep only)\n".format(
            paths[FILTER_FIRST_PATH]["pre_parse_input_lines"],
            paths[FILTER_FIRST_PATH]["pre_parse_output_lines"]),
        style="dim")
    cmp_body.append("\n  per-filter counts (parse-first):\n", style="bold")
    for row in paths[PARSE_FIRST_PATH]["filter_counts"]:
        mark = "*" if row["active"] else " "
        cmp_body.append("   {} {:<12} {} -> {}\n".format(
            mark, row["filter"], row["before"], row["after"]))
    cmp_body.append("\n  per-filter counts (filter-first):\n", style="bold")
    for row in paths[FILTER_FIRST_PATH]["filter_counts"]:
        mark = "*" if row["active"] else " "
        cmp_body.append("   {} {:<12} {} -> {}\n".format(
            mark, row["filter"], row["before"], row["after"]))
    panels["compare"] = cmp_body

    pf_nodes = paths[PARSE_FIRST_PATH]["nodes"]
    ff_nodes = paths[FILTER_FIRST_PATH]["nodes"]
    node_body = Text()
    node_body.append("real call order  (parse-first | filter-first)\n",
                     style="bold")
    node_body.append("captured via sys.setprofile during the live run\n\n",
                     style="dim")
    rows = max(len(pf_nodes), len(ff_nodes))
    for i in range(rows):
        left = _node_line(i, pf_nodes[i]) if i < len(pf_nodes) else ""
        right = _node_line(i, ff_nodes[i]) if i < len(ff_nodes) else ""
        node_body.append(left.ljust(72) + " | " + right + "\n")
    panels["nodes"] = node_body

    tz = snapshot["timezone"]
    tz_body = Text()
    tz_body.append("[TRADEOFF 3] timestamp / timezone fidelity\n",
                   style="bold yellow")
    tz_body.append("  original offset : {}\n".format(tz["original_offset"]))
    tz_body.append("  output offset   : log={} linejson={} sojson={}\n".format(
        tz["output_offset"]["log"], tz["output_offset"]["linejson"],
        tz["output_offset"]["sojson"]))
    tz_body.append("  local stamp     : {}\n".format(
        tz["numeric_date_stamp_local"]))
    tz_body.append("  utc stamp       : {}\n".format(
        tz["numeric_date_stamp_utc"]))
    if tz.get("local_offset_warning"):
        tz_body.append("  note            : {}\n".format(
            tz["local_offset_warning"]), style="bold red")
    tz_body.append("  range compares  : {} (active={}, value={})\n".format(
        tz["range"]["compare_field"], tz["range"]["active"],
        tz["range"]["value"]))
    tz_body.append("  last compares   : {} (active={}, value={})\n".format(
        tz["last"]["compare_field"], tz["last"]["active"],
        tz["last"]["value"]))
    tz_body.append("\n  serializer boundaries:\n", style="bold")
    for fmt, note in tz["serializers"].items():
        tz_body.append("   {:<9} {}\n".format(fmt, note), style="dim")
    for key in (PARSE_FIRST_PATH, FILTER_FIRST_PATH):
        err = paths[key].get("parse_error")
        if err:
            tz_body.append("\n  {} parse edge: {}\n".format(key, err),
                           style="bold red")
    panels["tz"] = tz_body

    out_body = Text("three real output modules (this run's files)\n",
                    style="bold")
    for fmt, info in snapshot["outputs"].items():
        style = "green" if info["ok"] else "red"
        out_body.append("  {:<9} ok={}  {}\n".format(
            fmt, info["ok"], info["path"]), style=style)
        if info["error"]:
            out_body.append("           error: {}\n".format(info["error"]),
                            style="red")
    panels["outputs"] = out_body

    diff = snapshot["diff"]
    diff_body = Text()
    status = diff["status"]
    consistent = diff["consistent"]
    style = "bold green" if consistent else "bold red"
    diff_body.append("determinism: two live runs  status {}\n".format(status),
                     style=style)
    for path in diff["paths"]:
        mark = "OK" if path["consistent"] else "MISMATCH @ {}".format(
            path["first_divergence_index"])
        diff_body.append("  {:<14} {}\n".format(path["path"], mark),
                         style="green" if path["consistent"] else "red")
    diff_body.append("\n  /flow.json -> {} on mismatch\n".format(
        STATUS_CONFLICT), style="dim")
    panels["diff"] = diff_body
    panels["_consistent"] = consistent
    return panels


from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Footer, Header, Static


class Panel(Static):
    """A titled scrollable diagnostic panel."""

    def __init__(self, title: str, panel_id: str) -> None:
        super().__init__(id=panel_id)
        self.border_title = title


class FlowTUIApp(App):  # type: ignore[misc]
    """Multi-panel Textual UI that re-drives the pipeline on every key."""

    CSS = """
    Screen { layout: vertical; }
    #top { height: 1fr; }
    #bottom { height: 1fr; }
    .column { width: 1fr; }
    Panel { height: 1fr; border: round $accent; padding: 0 1;
            overflow-x: hidden; }
    #header { border: round $success; }
    #compare { border: round $warning; }
    #tz { border: round $warning; }
    #nodes { border: round $accent; }
    #diff { border: round $success; }
    #diff.conflict { border: round red; color: red; }
    """

    BINDINGS = [
        ("p", "cycle_parser", "logtype"),
        ("n", "next_file", "next file"),
        ("o", "toggle_order", "filter order"),
        ("g", "cycle_grep", "grep"),
        ("x", "cycle_rgrep", "rgrep"),
        ("t", "cycle_time", "time filter"),
        ("z", "cycle_tzone", "tzone"),
        ("r", "rerun", "rerun"),
        ("q", "quit", "quit"),
    ]

    def __init__(self, options: FlowOptions, port: int = 0) -> None:
        super().__init__()
        self.options = options
        self.port = port
        self.parser_modules = load_parser_modules()
        self.last_usable: Dict[str, str] = {}
        self.store = SnapshotStore()
        self.server: Optional[ThreadingHTTPServer] = None
        self.url = ""
        self.snapshot: Optional[Dict[str, Any]] = None
        self._grep_index = 0
        self._rgrep_index = 0
        self._time_index = 0
        self._tzone_index = 0
        self._explicit_index: Optional[int] = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            with Horizontal(id="top"):
                with Vertical(classes="column"):
                    yield Panel("control / logtype [1]", "header")
                    yield Panel("auto-detection", "detect")
                with Vertical(classes="column"):
                    yield Panel("filter order tradeoff [2]", "compare")
                with Vertical(classes="column"):
                    yield Panel("timezone fidelity [3]", "tz")
            with Horizontal(id="bottom"):
                with VerticalScroll(classes="column"):
                    yield Panel("real node order (live)", "nodes")
                with Vertical(classes="column"):
                    yield Panel("outputs", "outputs")
                    yield Panel("determinism / flow.json", "diff")
        yield Footer()

    def on_mount(self) -> None:
        self.server, self.url = start_server(self.store, self.port)
        self.title = "logdissect flowtui"
        self.sub_title = self.url
        self.rerun()

    def rerun(self) -> None:
        """Re-execute the real pipeline twice and refresh every panel."""
        try:
            self.snapshot = run_snapshot(
                self.options, self.parser_modules, self.last_usable,
                reverse_filters=self._order_reversed,
            )
        except Exception as exc:  # noqa: BLE001
            self.snapshot = None
            self.query_one("#header", Static).update(
                "live run failed: {}: {}".format(type(exc).__name__, exc))
            return
        self.store.set(self.snapshot)
        panels = render_flow_app(self.snapshot, self.options, self.url)
        consistent = panels.pop("_consistent")
        for panel_id, body in panels.items():
            self.query_one("#" + panel_id, Static).update(body)
        diff_panel = self.query_one("#diff", Panel)
        diff_panel.set_class(not consistent, "conflict")

    _order_reversed = False

    def action_cycle_parser(self) -> None:
        names = sorted(self.parser_modules)
        if self._explicit_index is None:
            self._explicit_index = 0
        else:
            self._explicit_index = (self._explicit_index + 1) % (len(names) + 1)
        if self._explicit_index == len(names):
            self.options.explicit_logtype = None  # back to auto-detect
        else:
            self.options.explicit_logtype = names[self._explicit_index]
        self.rerun()

    def action_next_file(self) -> None:
        files = list_log_files(self.options.logdir)
        if files:
            self.options.file_index = (self.options.file_index + 1) % len(files)
        self.rerun()

    def action_toggle_order(self) -> None:
        self._order_reversed = not self._order_reversed
        self.rerun()

    def action_cycle_grep(self) -> None:
        self._grep_index = (self._grep_index + 1) % len(GREP_PRESETS)
        self.options.filters["grep"] = GREP_PRESETS[self._grep_index]
        self.options.filters["rgrep"] = None
        self._rgrep_index = 0
        self.rerun()

    def action_cycle_rgrep(self) -> None:
        self._rgrep_index = (self._rgrep_index + 1) % len(RGROUP_PRESETS)
        self.options.filters["rgrep"] = RGROUP_PRESETS[self._rgrep_index]
        self.options.filters["grep"] = None
        self._grep_index = 0
        self.rerun()

    def action_cycle_time(self) -> None:
        self._time_index = (self._time_index + 1) % len(TIME_PRESETS)
        preset = TIME_PRESETS[self._time_index]
        for key in ("range", "utc", "last"):
            self.options.filters[key] = preset.get(key)
        if "utc" not in preset:
            self.options.filters["utc"] = False
        self.rerun()

    def action_cycle_tzone(self) -> None:
        self._tzone_index = (self._tzone_index + 1) % len(TZONE_PRESETS)
        self.options.tzone = TZONE_PRESETS[self._tzone_index]
        self.rerun()

    def action_rerun(self) -> None:
        self.rerun()


def _http_get(url: str) -> Tuple[int, Dict[str, Any]]:
    import urllib.request
    import urllib.error

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def run_verify(logdir: str, port: int) -> int:
    """Headless acceptance: serve, fetch /flow.json, assert and exit nonzero."""
    parser_modules = load_parser_modules()
    options = FlowOptions(logdir=logdir)
    last_usable: Dict[str, str] = {}

    # 1) Two live runs over the first input; run_snapshot already executes it
    #    twice and diffs the node order.
    snapshot = run_snapshot(options, parser_modules, last_usable)

    # 2) Serve and fetch /flow.json.
    store = SnapshotStore()
    store.set(snapshot)
    server, url = start_server(store, port)
    failures: List[str] = []
    try:
        status, served = _http_get(url)
        if status != STATUS_OK:
            failures.append("expected HTTP 200 for a deterministic run, "
                            "got {}".format(status))

        # 3) Served nodes must match the measured snapshot (this run only).
        for path in (PARSE_FIRST_PATH, FILTER_FIRST_PATH):
            expected = [n["qualname"] for n in
                        snapshot["paths"][path]["nodes"]]
            served_nodes = [n["qualname"] for n in
                            served["paths"][path]["nodes"]]
            if served_nodes != expected:
                failures.append(
                    "served node order for {} disagrees with measured run"
                    .format(path))

        # 4) The two live runs recorded in the snapshot must agree.
        if not snapshot["diff"]["consistent"]:
            failures.append("two live runs produced different node order")

        # 5) Force a mismatch and confirm /flow.json answers 409, proving the
        #    contract end to end.
        corrupted = json.loads(json.dumps(snapshot))
        corrupted["paths"][PARSE_FIRST_PATH]["nodes"].insert(
            0, {"qualname": "logdissect.filters.last.injected_breaker",
                "calls": 1, "elapsed_ms": 0.0})
        conflict = diff_snapshots(snapshot, corrupted)
        corrupted["diff"] = conflict.to_dict()
        store.set(corrupted)
        conflict_status, _ = _http_get(url)
        if conflict_status != STATUS_CONFLICT:
            failures.append("expected HTTP 409 on node-order mismatch, got "
                            "{}".format(conflict_status))
    finally:
        server.shutdown()

    if failures:
        print("FLOW VERIFY FAILED:")
        for failure in failures:
            print("  - " + failure)
        return 1
    print("FLOW VERIFY OK")
    print("  input        : {}".format(snapshot["input"]["file"]))
    print("  logtype      : {}".format(
        snapshot["logtype"]["decision"]["selected"]))
    for path in (PARSE_FIRST_PATH, FILTER_FIRST_PATH):
        block = snapshot["paths"][path]
        print("  {:<13}: {} nodes, {} entries, {:.3f}ms".format(
            path, len(block["nodes"]), block["entries"],
            block["elapsed_ms"]))
    print("  /flow.json   : 200 on match, 409 on mismatch")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="logdissect.flowtui",
        description="interactive flow diagnostics for the logdissect pipeline",
    )
    parser.add_argument("--logdir", default="samples",
                        help="directory of log files to diagnose")
    parser.add_argument("--logtype", default=None,
                        help="explicit parser type (overrides auto-detect)")
    parser.add_argument("--port", type=int, default=0,
                        help="HTTP port for /flow.json (0 = ephemeral)")
    parser.add_argument("--verify", action="store_true",
                        help="headless acceptance check; nonzero on failure")
    options = parser.parse_args(argv)

    if options.verify:
        return run_verify(options.logdir, options.port)

    flow_options = FlowOptions(
        logdir=options.logdir, explicit_logtype=options.logtype)
    app = FlowTUIApp(flow_options, port=options.port)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
