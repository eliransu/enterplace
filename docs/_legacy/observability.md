# Metrics and log shipping

Two ways to watch Gantry: Prometheus metrics for alerts and dashboards, and the audit log shipped to the log system you already run. The audit log stays the record of what happened; metrics are counts for alerting.

## Metrics

```bash
gantry serve gantry.policy.yaml --metrics 127.0.0.1:9464
```

`GET /metrics` is served on that address only, in the Prometheus text format. It is off unless `--metrics` names an address, and it takes no key: anyone who reaches it sees team, model and provider names and what each team spent. Keep it on loopback, or on a network only your scraper reaches (in a container, publish that port only to the scraper's network). The gateway's own address never serves it, so a caller with a Gantry key cannot read it. Scrapes are not written to the audit log.

| Metric | Type | Labels | What it counts |
|---|---|---|---|
| `gantry_requests_total` | counter | `route`, `verdict` (`allow`, `refused`), `code` (the refusal code, empty when allowed), `provider` | Every decision, as the audit log records it. `route` is `chat_completions`, `messages`, `count_tokens`, `responses`, `embeddings`, `models` or `other` |
| `gantry_upstream_responses_total` | counter | `provider`, `outcome` (HTTP status, or the code when the provider gave none, such as `upstream_timeout`) | Every attempt at a provider, retries and fallbacks included |
| `gantry_upstream_seconds` | histogram | `provider` | Time from sending to a provider to its answer's headers |
| `gantry_overhead_seconds` | histogram | none | Gantry's own time on a forwarded request: identify, decide, guardrails, record, and handing the answer back. The same figure as the `Server-Timing: gantry` header |
| `gantry_audit_write_seconds` | histogram | none | Time of each write to the audit log (the writer takes many records per write under load) |
| `gantry_audit_queue_depth` | gauge | none | Records waiting for the audit writer |
| `gantry_audit_broken` | gauge | none | 1 when the audit log cannot be written: every request is refused until a restart |
| `gantry_spend_usd_total` | counter | `team`, `model` | US dollars charged since Gantry started, as usage records write them |

Counters start at zero when Gantry starts; Prometheus's `rate()` and `increase()` handle that. Spend that counts against budgets is read from the audit log at start, so budgets survive a restart even though this counter does not.

Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: gantry
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

Three alerts to start with:

```yaml
groups:
  - name: gantry
    rules:
      - alert: GantryAuditLogBroken
        expr: gantry_audit_broken == 1
        annotations:
          summary: Gantry cannot write its audit log and refuses every request. Look at the disk and restart it.
      - alert: GantryRefusalRateHigh
        expr: sum(rate(gantry_requests_total{verdict="refused"}[10m])) / sum(rate(gantry_requests_total[10m])) > 0.2
        for: 10m
        annotations:
          summary: More than a fifth of requests are refused. Group by code to see why.
      - alert: GantryTeamSpendHigh
        expr: sum by (team) (increase(gantry_spend_usd_total[1d])) > 500
        annotations:
          summary: A team spent more than $500 in a day.
```

The metrics never hold a prompt, a key, a person's name or a decision ID.

## Shipping the audit log

The audit log is a file of JSON lines (`gantry-audit.jsonl`, or the `audit: { path: ... }` in the policy). Gantry only appends to it, so any shipper that tails a file can send it on. Ship each line as it is: the `hash` and `prev` fields chain every record to the one before, and that chain is what `gantry audit verify` checks.

What a record holds is in docs/audit.md. Fields worth indexing: `event` (absent on request records; `usage`, `config_loaded`, `config_rejected`, `admin`, `attempts`), `id` (the decision ID), `person`, `team`, `key`, `verdict`, `code`, `model`, `provider`, `charged_usd`.

The examples below read the file from its start and keep their place across restarts. Point the sink at your own log system; they print to stdout here. They are examples written from each tool's documentation, not configurations tested in this release: check them against the version you run.

### Vector

```yaml
sources:
  gantry_audit:
    type: file
    include: [/var/lib/gantry/gantry-audit.jsonl]
    read_from: beginning
transforms:
  gantry_parsed:
    type: remap
    inputs: [gantry_audit]
    # Keeps the original line in .line, so the chain can be checked from what was shipped.
    source: |
      .line = .message
      . = merge!(., object!(parse_json!(.message)))
sinks:
  out:
    type: console
    inputs: [gantry_parsed]
    encoding:
      codec: json
```

### Fluent Bit

```yaml
pipeline:
  inputs:
    - name: tail
      path: /var/lib/gantry/gantry-audit.jsonl
      read_from_head: true
      db: /var/lib/fluent-bit/gantry-audit.db
      parser: json
      tag: gantry.audit
  outputs:
    - name: stdout
      match: gantry.audit
      format: json_lines
```

`parser: json` is the `json` parser from Fluent Bit's stock `parsers.conf`. To keep each line unparsed as well, leave the parser out and parse in the log system.

### OpenTelemetry Collector

Gantry has no OTLP exporter of its own: the audit log file is the source, and the Collector's `filelog` receiver (in the contrib distribution, `otelcol-contrib`) turns each line into an OpenTelemetry log record and sends it on over OTLP. The whole configuration:

```yaml
receivers:
  filelog/gantry:
    include: [/var/lib/gantry/gantry-audit.jsonl]
    start_at: beginning
    storage: file_storage
    operators:
      - type: json_parser
        parse_to: attributes
        timestamp:
          parse_from: attributes.time
          layout_type: gotime
          layout: "2006-01-02T15:04:05.000Z07:00"
extensions:
  file_storage:
    directory: /var/lib/otelcol/storage
processors:
  batch: {}
exporters:
  otlphttp:
    endpoint: https://otel.example.com:4318
  debug:
    verbosity: detailed
service:
  extensions: [file_storage]
  pipelines:
    logs:
      receivers: [filelog/gantry]
      processors: [batch]
      exporters: [otlphttp, debug]
```

- Each record's fields become log attributes (`attributes.person`, `attributes.code`, ...). The original line stays in the log record's body, which is what to export for `gantry audit verify` below.
- The record's `time` (always UTC with milliseconds, such as `2026-11-12T14:02:11.482Z`) becomes the log record's timestamp.
- `file_storage` keeps the receiver's place in the file across Collector restarts, so records are neither skipped nor sent twice. Its folder must exist and be writable by the Collector.
- `otlphttp` sends to `<endpoint>/v1/logs`. Replace the endpoint with your backend's; drop `debug` once it works. Recent Collector releases name this exporter `otlp_http` and accept `otlphttp` as a deprecated alias: use `otlp_http` if your version has it.

On Kubernetes, run the Collector as a second container in the Gantry pod with the data volume mounted read-only at `/var/lib/gantry` (a `ReadWriteOnce` volume can be shared by containers of one pod), and give `file_storage` an `emptyDir` or a volume of its own: [Kubernetes](kubernetes.html).

**Tested:** the YAML above parses, and every line of an audit log written by this release is one JSON object with a `time` in exactly that layout (`scripts/check_deploy.py` checks both). **Not tested:** the Collector itself, which was not installed on the build machine. The receiver, operator, extension and exporter names and fields follow the Collector's documentation; check them against the version you run.

## Checking what was shipped

A copy in a log system can be edited or lose records like any other copy. Check it the same way as the file:

1. On Gantry's host, run `gantry audit verify /var/lib/gantry/gantry-audit.jsonl`. It prints the count and the last hash. Keep that hash in the log system or a ticket, where Gantry's host cannot change it.
2. To check the shipped copy, export the original lines (the `line` field above, or the record body), sorted by `n`, into a file, and run `gantry audit verify exported.jsonl --expect-last <hash kept in step 1>`. It passes only if every record up to that hash is there, unchanged and in order.

A shipped copy that starts in the middle of the log (the shipper started late) does not verify on its own: export from record 1, or verify the file on the host.
