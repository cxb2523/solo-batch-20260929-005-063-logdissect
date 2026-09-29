"""flowdiff - deterministic snapshot diffing for the flowtui diagnostic.

A *flow snapshot* is the ordered trace of real logdissect function calls
captured during one headless run of the parse/filter/output chain (built by
``logdissect.flowtui.run_flow``). Two snapshots are "consistent" when the
same input + parser + filter selection produces the exact same node order.

Timings and byte counts are intentionally excluded from the identity: they
measure performance, not the shape of the pipeline.

Trade-off note (3 of 3, see flowtui for the other two):
    Timestamp timezone fidelity is bounded by serialization format. The
    ``log`` format preserves only the original raw text (offset implicit),
    while ``linejson``/``sojson`` persist the parsed ``tzone`` and both the
    local ``numeric_date_stamp`` and ``numeric_date_stamp_utc``. range
    filters against local stamps and ``last`` (always UTC) therefore see
    different boundaries depending on which stamp they read.
"""

from __future__ import annotations

import sys


# Fields that describe *what ran*, as opposed to *how fast it ran*.
IDENTITY_KEYS = ("input", "selection", "filter_order", "argv")


def node_signature(snapshot):
    """Return the ordered node identities a snapshot was built from."""
    return [node["name"] for node in snapshot.get("nodes", [])]


def diff_snapshots(first, second):
    """Compare two snapshots.

    Returns a result dict::

        {"consistent": bool, "reason": str|None, "first_divergence": int|None}

    Snapshots are only comparable when their identity
    (input/selection/filter_order/argv) matches; otherwise the run was not
    "the same input twice" and that itself is a mismatch the caller must
    surface (HTTP 409 / red panel).
    """
    result = {"consistent": True, "reason": None, "first_divergence": None}

    for key in IDENTITY_KEYS:
        if first.get(key) != second.get(key):
            result.update(
                consistent=False,
                reason="identity field %r differs between snapshots" % key,
                first_divergence=0,
            )
            return result

    first_nodes = node_signature(first)
    second_nodes = node_signature(second)
    if first_nodes != second_nodes:
        divergence = next(
            (
                idx
                for idx, pair in enumerate(zip(first_nodes, second_nodes))
                if pair[0] != pair[1]
            ),
            min(len(first_nodes), len(second_nodes)),
        )
        result.update(
            consistent=False,
            reason="node order diverged at index %d" % divergence,
            first_divergence=divergence,
        )
        return result

    # Same order, same length: same pipeline shape.
    return result


def snapshots_consistent(first, second):
    """Convenience boolean wrapper around :func:`diff_snapshots`."""
    return diff_snapshots(first, second)["consistent"]


def _format_diff(first, second, result):
    """Human readable lines for the TUI diff panel / CLI output."""
    lines = []
    if result["consistent"]:
        lines.append("CONSISTENT: %d nodes, identical order on both runs."
                     % len(node_signature(first)))
        return lines

    lines.append("MISMATCH: %s" % result["reason"])
    at = result["first_divergence"] or 0
    a_nodes = node_signature(first)
    b_nodes = node_signature(second)
    lo = max(0, at - 2)
    hi = max(at + 3, 0)
    lines.append("  run A: " + " -> ".join(a_nodes[lo:hi]))
    lines.append("  run B: " + " -> ".join(b_nodes[lo:hi]))
    return lines


def main(argv=None):
    """CLI: ``python -m logdissect.flowdiff a.json b.json`` -> 0/1."""
    import json

    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print("usage: python -m logdissect.flowdiff <snapshot-a.json> "
              "<snapshot-b.json>", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        first = json.load(fh)
    with open(argv[1], encoding="utf-8") as fh:
        second = json.load(fh)
    result = diff_snapshots(first, second)
    for line in _format_diff(first, second, result):
        print(line)
    return 0 if result["consistent"] else 1