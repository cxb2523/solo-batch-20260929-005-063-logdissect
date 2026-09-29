"""Deterministic snapshot comparison for the logdissect flow TUI.

``flowtui`` drives the *real* logdissect pipeline (``argparse`` ->
``core.LogDissectCore`` -> parsers -> ``filters`` -> the three output
modules) and records, for every live run, the ordered list of function
nodes that actually executed.  Two live runs over the same input must
produce the same ordered node list; that invariant is what this module
checks.

Only the node *order* is part of the determinism contract.  Timings and
entry counts legitimately vary and are deliberately excluded from the
comparison so that jitter can never raise a spurious mismatch.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


# Both filter-order paths that the TUI runs side by side.  These are the
# canonical snapshot keys shared with ``flowtui``.
PARSE_FIRST_PATH = "parse_first"   # upstream order: parse -> merge -> filters
FILTER_FIRST_PATH = "filter_first"  # reverse intent: raw pre-filters -> parse -> filters

# HTTP status for a flow snapshot whose two live runs disagree.
STATUS_CONFLICT = 409
STATUS_OK = 200


@dataclass
class PathDiff:
    """Result of comparing one filter-order path across two snapshots."""

    path: str
    consistent: bool
    run_a: List[str] = field(default_factory=list)
    run_b: List[str] = field(default_factory=list)
    first_divergence: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "consistent": self.consistent,
            "first_divergence_index": self.first_divergence,
            "run_a": self.run_a,
            "run_b": self.run_b,
        }


@dataclass
class FlowDiff:
    """Aggregate comparison across every recorded path."""

    consistent: bool
    status: int
    paths: List[PathDiff] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "consistent": self.consistent,
            "status": self.status,
            "paths": [p.to_dict() for p in self.paths],
        }


def node_order(snapshot: Dict[str, Any], path: str) -> List[str]:
    """Extract the ordered node names for ``path`` from a snapshot."""
    path_block = (snapshot or {}).get("paths", {}).get(path, {})
    return [str(node.get("qualname", "")) for node in path_block.get("nodes", [])]


def compare_orders(run_a: Sequence[str], run_b: Sequence[str]) -> Optional[int]:
    """Return the index of the first divergent node, or ``None`` if equal.

    Both the sequence and its length must match; an extra or missing node
    at the tail is reported at the first differing index.
    """
    for index, (a_node, b_node) in enumerate(zip(run_a, run_b)):
        if a_node != b_node:
            return index
    if len(run_a) != len(run_b):
        return min(len(run_a), len(run_b))
    return None


def diff_snapshots(run_a: Dict[str, Any], run_b: Dict[str, Any]) -> FlowDiff:
    """Compare two live-run snapshots for identical node order."""
    paths: List[PathDiff] = []
    all_consistent = True
    for path in (PARSE_FIRST_PATH, FILTER_FIRST_PATH):
        order_a = node_order(run_a, path)
        order_b = node_order(run_b, path)
        divergence = compare_orders(order_a, order_b)
        consistent = divergence is None
        all_consistent = all_consistent and consistent
        paths.append(
            PathDiff(
                path=path,
                consistent=consistent,
                run_a=order_a,
                run_b=order_b,
                first_divergence=divergence,
            )
        )
    status = STATUS_OK if all_consistent else STATUS_CONFLICT
    return FlowDiff(consistent=all_consistent, status=status, paths=paths)


def _load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI: ``python -m logdissect.flowdiff a.json b.json``."""
    parser = argparse.ArgumentParser(
        prog="logdissect.flowdiff",
        description="Compare two flow snapshots for deterministic node order",
    )
    parser.add_argument("snapshot_a", help="first flow snapshot JSON")
    parser.add_argument("snapshot_b", help="second flow snapshot JSON")
    options = parser.parse_args(argv)

    result = diff_snapshots(_load(options.snapshot_a), _load(options.snapshot_b))
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.consistent else 1


if __name__ == "__main__":
    sys.exit(main())
