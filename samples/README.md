# flowtui sample logs

Static fixtures used by `python -m logdissect.flowtui --logdir samples`.

- `app-syslog.log` — RFC3164-style syslog (detected as the `syslog`
  parser; timezone supplied via `-t +0800` in the live run).
- `app-iso.log` — ISO-8601 timestamps with three authored offsets
  (`+08:00`, `+00:00`/`Z`, `-05:00`); detected as `syslogiso`, each entry
  keeps its own original offset.

Dates are fixed in September 2026 so `--range` results are deterministic;
`--last 4000d` keeps all entries selected regardless of wall clock.
