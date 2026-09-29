import json
import urllib.error
import urllib.request

import pytest

from logdissect.flowdiff import (
    FILTER_FIRST_PATH,
    PARSE_FIRST_PATH,
    STATUS_CONFLICT,
    STATUS_OK,
    compare_orders,
    diff_snapshots,
)
from logdissect.flowtui import (
    FlowOptions,
    SnapshotStore,
    build_handler,
    choose_logtype,
    list_log_files,
    load_parser_modules,
    run_snapshot,
    run_verify,
    start_server,
)


SAMPLES = "samples"


@pytest.fixture(scope="module")
def parser_modules():
    return load_parser_modules()


@pytest.fixture
def syslog_index():
    files = list_log_files(SAMPLES)
    return next(i for i, name in enumerate(files) if name.endswith("syslog.txt"))


def make_snapshot(nodes_a, nodes_b=None):
    nodes_b = nodes_a if nodes_b is None else nodes_b
    return {
        "paths": {
            PARSE_FIRST_PATH: {"nodes": [{"qualname": n} for n in nodes_a]},
            FILTER_FIRST_PATH: {"nodes": [{"qualname": n} for n in nodes_b]},
        }
    }


def test_compare_orders_equal_and_divergent():
    assert compare_orders(["a", "b"], ["a", "b"]) is None
    assert compare_orders(["a", "b"], ["a", "c"]) == 1
    assert compare_orders(["a"], ["a", "b"]) == 1


def test_diff_consistent_and_conflict():
    ok = diff_snapshots(make_snapshot(["a", "b"]), make_snapshot(["a", "b"]))
    assert ok.consistent is True
    assert ok.status == STATUS_OK

    bad = diff_snapshots(
        make_snapshot(["a", "b"]), make_snapshot(["a", "x"])
    )
    assert bad.consistent is False
    assert bad.status == STATUS_CONFLICT
    assert bad.paths[0].first_divergence == 1


def test_autodetect_picks_syslog(parser_modules, syslog_index):
    path = list_log_files(SAMPLES)[syslog_index]
    decision, _ = choose_logtype(path, None, parser_modules, {})
    assert decision.selected == "syslog"
    assert decision.source == "auto"


def test_explicit_overrides_detected(parser_modules, syslog_index):
    path = list_log_files(SAMPLES)[syslog_index]
    decision, _ = choose_logtype(
        path, "windowsrsyslog", parser_modules, {}
    )
    assert decision.selected == "windowsrsyslog"
    assert decision.detected == "syslog"
    assert decision.conflict is True


def test_detection_failure_falls_back_to_default(parser_modules):
    files = list_log_files(SAMPLES)
    path = next(n for n in files if n.endswith("unrecognized.txt"))
    decision, _ = choose_logtype(path, None, parser_modules, {})
    assert decision.selected == "syslog"
    assert decision.source == "fallback"
    assert "default" in decision.reason


def test_detection_failure_remembers_last_usable(parser_modules, syslog_index):
    last_usable = {}
    files = list_log_files(SAMPLES)
    good = files[syslog_index]
    bad = next(n for n in files if n.endswith("unrecognized.txt"))
    choose_logtype(good, None, parser_modules, last_usable)
    decision, _ = choose_logtype(bad, None, parser_modules, last_usable)
    assert decision.selected == "syslog"
    assert "most recently usable" in decision.reason


def test_snapshot_is_live_and_deterministic(parser_modules, syslog_index):
    snapshot = run_snapshot(
        FlowOptions(logdir=SAMPLES, file_index=syslog_index),
        parser_modules, {},
    )
    assert snapshot["diff"]["status"] == STATUS_OK
    nodes = snapshot["paths"][PARSE_FIRST_PATH]["nodes"]
    names = [n["qualname"] for n in nodes]
    # Real captured functions from the genuine pipeline:
    assert any("core" in n and "run_parse" in n for n in names)
    assert any("filters" in n and "filter_data" in n for n in names)
    assert any("output" in n and "write_output" in n for n in names)


def test_grep_filter_first_reduces_raw_lines(parser_modules, syslog_index):
    options = FlowOptions(
        logdir=SAMPLES, file_index=syslog_index,
        filters={"grep": "systemd", "rgrep": None, "range": None,
                 "utc": False, "last": None},
    )
    snapshot = run_snapshot(options, parser_modules, {})
    ff = snapshot["paths"][FILTER_FIRST_PATH]
    assert ff["pre_parse_input_lines"] > ff["pre_parse_output_lines"]
    assert ff["pre_parse_output_lines"] == ff["entries"]
    assert any("@raw" in row["filter"] for row in ff["filter_counts"])


def test_timezone_reports_original_and_output_offsets(
        parser_modules, syslog_index):
    options = FlowOptions(
        logdir=SAMPLES, file_index=syslog_index, tzone="+0500",
    )
    snapshot = run_snapshot(options, parser_modules, {})
    tz = snapshot["timezone"]
    assert tz["original_offset"] == "+0500"
    assert tz["output_offset"]["linejson"] == "+0500"
    assert tz["output_offset"]["sojson"] == "+0500"
    # The raw-text log serializer preserves no structured offset.
    assert tz["output_offset"]["log"] is None


def test_range_uses_local_but_last_uses_utc(parser_modules, syslog_index):
    options = FlowOptions(
        logdir=SAMPLES, file_index=syslog_index,
        filters={"grep": None, "rgrep": None,
                 "range": "202609300800-202609301000",
                 "utc": False, "last": None},
    )
    snapshot = run_snapshot(options, parser_modules, {})
    assert snapshot["timezone"]["range"]["compare_field"] == \
        "numeric_date_stamp"

    options.filters["utc"] = True
    snapshot_utc = run_snapshot(options, parser_modules, {})
    assert snapshot_utc["timezone"]["range"]["compare_field"] == \
        "numeric_date_stamp_utc"


def test_flow_json_200_then_409_on_mismatch(parser_modules, syslog_index):
    snapshot = run_snapshot(
        FlowOptions(logdir=SAMPLES, file_index=syslog_index),
        parser_modules, {},
    )
    store = SnapshotStore()
    store.set(snapshot)
    server, url = start_server(store, 0)
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            assert response.status == STATUS_OK

        corrupted = json.loads(json.dumps(snapshot))
        corrupted["paths"][PARSE_FIRST_PATH]["nodes"].insert(
            0, {"qualname": "logdissect.break.order", "calls": 1,
                "elapsed_ms": 0.0})
        corrupted["diff"] = diff_snapshots(snapshot, corrupted).to_dict()
        store.set(corrupted)

        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(url, timeout=10)
        assert exc.value.code == STATUS_CONFLICT
    finally:
        server.shutdown()


def test_run_verify_passes(monkeypatch):
    assert run_verify(SAMPLES, 0) == 0
