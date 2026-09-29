# flowtui — interactive parse-pipeline diagnostics

`flowtui` is a Textual, multi-panel diagnostic layer over the real
logdissect parse chain. It launches with:

```
python -m logdissect.flowtui --logdir samples
```

Headless acceptance (starts a loopback server, fetches `/flow.json`, asserts
the served node order matches the measured run and that two live runs agree,
then proves the 409 contract; exits non-zero on failure):

```
python -m logdissect.flowtui --verify
```

Snapshot comparison is also available standalone:

```
python -m logdissect.flowdiff first.json second.json   # 0 = same, 1 = differ
```

Every panel and the `/flow.json` document are populated **from the current
live run only** — nothing is cached or invented. Function names and order are
captured with `sys.setprofile` while the genuine `argparse` configuration,
`core.LogDissectCore`, parser, `filters` and output functions execute.

## Keys

| key | action |
|-----|--------|
| `p` | cycle parser: auto-detect, then each explicit `--logtype` |
| `n` | next file in `--logdir` |
| `o` | toggle filter invocation order (core sorted vs reversed) |
| `g` | cycle a grep preset (pre-parse capable) |
| `x` | cycle an rgrep preset (pre-parse capable) |
| `t` | cycle time filters: none, wide range, tight range, `--utc` range, `--last` |
| `z` | cycle explicit timezone offset (`-t`) |
| `r` | re-run |
| `q` | quit |

## The three labelled tradeoffs

1. **Auto-detection vs `--logtype`** (`[TRADEOFF 1]`). An explicit type always
   wins when it disagrees with auto-detection; the panel flags the conflict.
   When detection fails, the tool falls back to the most recently usable type
   for that directory (or the `syslog` default), and states why. Detection is
   a plurality vote across sampled lines (JSON formats are detected
   structurally), with field count and a fixed specificity ladder breaking
   ties such as `syslog` vs `windowsrsyslog`.
2. **Filter-first vs parse-first** (`[TRADEOFF 2]`). The upstream order is
   parse → merge → filters. The reversed-intent path runs only raw-capable
   filters (`grep`/`rgrep`) on the raw lines, re-parses the reduced file, then
   runs the remaining field-based filters. Both paths show live entry counts
   and timings side by side.
3. **Timestamp/timezone fidelity** (`[TRADEOFF 3]`). `range` compares local
   `numeric_date_stamp` unless `--utc` is set, while `last` always compares
   `numeric_date_stamp_utc`. The `log` serializer emits `raw_text` (no
   offset); `linejson`/`sojson` carry `tzone` and both stamps. The panel
   reports both the original parsed offset and the serialized offset per
   format, and surfaces upstream fidelity edges (for example a malformed
   local offset or parsers that raise under the running interpreter).

## Determinism and HTTP

Each interaction executes the identical input twice. `flowdiff` compares the
ordered node lists (timings and counts are excluded so jitter cannot cause a
false alarm). A mismatch turns the determinism panel red and makes
`GET /flow.json` respond **409 Conflict**; a stable run responds **200 OK**.
