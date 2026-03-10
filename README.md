# xscanpro

A custom scanning pipeline inspired by:

- crawl.go (URL collection)
- linkfinder.go (JS endpoint and param discovery)
- xscan (reflected XSS detection and dedupe ideas)

This project does not reuse xscan payload lists.
It uses neutral markers and context-aware verification.

## Features

- URL collection with two tools:
  - waymore (roots auto-derived from `-u/-i`)
  - katana (directly from `-u/-i` URL input)
- Collector scheduling strategy:
  - waymore + katana standard round run in parallel
  - katana headless round runs after standard round (for SPA routes/XHR-triggered links)
  - headless round supports optional `-no-sandbox` (configurable)
  - if katana headless process is killed (e.g. OOM), it will be skipped without breaking the whole pipeline
  - both katana rounds apply static-extension exclusion to reduce invalid asset crawling
  - merged URL results are scope-filtered by hosts/roots derived from `-u/-i`
- JS endpoint and parameter extraction
- Reflected XSS focused scanning
- Optional DingTalk notification when findings are produced (with per-site cap)
- Quick probe with GET batch params (default batch size: 45)
- Optional POST reflected scan for `application/x-www-form-urlencoded` forms (batched body params)
- Verify only hit params in second stage (with same-batch parameter context to improve combo detection)
- In `batch` mode, scan-stage hidden params are limited to small high-value additions only
- In `batch` mode, verify stage uses fewer representative probes and stops on first strong hit
- Context-aware semantic probes in second stage (`test html` / `test attributes` / `special attributes` / `script sub-types` / `comment`)
- Similar-page strategy:
  - template grouping
  - sample scan first (or disable by `sample_per_group: 0`)
  - expand only on hit groups
  - query-bearing URLs are always scanned in phase-1
- Value-shape dedupe to skip semantically similar requests
  - request-level fingerprint threshold dedupe (xscan-like)

## Run

```powershell
cd xscanpro
go run .\cmd\scanner\main.go -config .\config.yaml
```

## Binary

Linux amd64 executable:

```text
xscanpro
```

Manual build example:

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
go build -o .\xscanpro .\cmd\scanner
```

Run on Linux:

```bash
./xscanpro -config config.yaml -i urls.txt
```

## Minimal CLI flags

```powershell
-config config.yaml   # config file path
-u https://a.example.com/path    # single URL input
-i urls.txt           # batch URL list input file
-xss-only urls.txt    # xss-only mode: skip collector, scan this URL file directly
-out output           # output directory
-mode balanced        # fast | balanced | deep
-waymore false        # override collector.use_waymore (true/false)
-v                    # verbose logs
```

Input rule:

- `-u` and `-i` are mutually exclusive.
- In full mode, provide exactly one of them.

Notes:

- Advanced settings are configured in `config.yaml`.
- CLI is intentionally minimal.

## Config

Edit `config.yaml` (fully commented).
Common keys:

- `input_url` (single URL input, same as `-u`)
- `input_file` (batch URL file input, same as `-i`)
- `input_url` and `input_file` are mutually exclusive in full mode
- `xss_only_file` (set this to enable xss-only mode and skip collector)
- `collector.use_waymore`
- `collector.use_katana`
- `collector.use_katana_headless`
- `collector.katana_headless_no_sandbox`
- `collector.katana_concurrency`
- `collector.katana_depth`
- `collector.katana_headless_concurrency`
- `collector.katana_headless_depth`
- `target.smart_dedupe`
- `target.param_strategy`
- `target.high_value_global_params`
- `batch` mode also keeps scan-stage hidden params and verify probes more conservative.
- `scanner.all_params`
- `scanner.param_batch_size`
- `scanner.scan_batch_enabled`
- `scanner.scan_batch_size`
- `scanner.enable_post_scan`
- `scanner.post_param_batch_size`
- `scanner.max_post_forms_per_url`
- `scanner.max_post_params_per_form`
- `scanner.sample_per_group`
- `scanner.expand_on_hit`
- `scanner.shape_dedupe_enabled`
- `scanner.shape_threshold`
- `scanner.target_workers`
- `scanner.quick_workers`
- `scanner.verify_workers`
- `notify.enabled`
- `notify.max_per_site`
- `notify.dingtalk.webhook`
- `notify.dingtalk.secret`

Notification behavior:

- Notifications are sent when findings are produced during scan.
- Dedup key for finding notifications is per-site + param, so same param with different payloads will not keep spamming.
- A final scan summary notification is sent at the end of the run.
- To avoid flooding, each site (hostname) sends at most `notify.max_per_site` messages in one run.
- Severity grading is not used in notification or reporting.

## Output

Terminal output style:

- startup summary (mode/input/output/workers/notify)
- stage blocks for collector / JS discovery / target generation / scanner
- inline progress lines for JS and scan phases
- highlighted `[HIT]` blocks for findings
- final summary block

Artifacts:

- `urls.txt`
- `js_urls.txt`
- `endpoints.txt`
- `params.txt`
- `findings.json`
- `xss_report.md`

## Current scan flow

1. Collect URLs (full mode) or load URLs (xss-only mode)
   - full mode:
     - input from `-u` or `-i` (mutually exclusive)
     - waymore with unique root domains auto-derived from input URLs
     - katana standard round with input URL list
     - katana headless round for SPA dynamic routes
     - static extensions are excluded in katana crawling
     - merge and dedupe all collector outputs
   - xss-only mode:
     - read user provided URL file directly
     - skip waymore/katana completely
2. Extract endpoints and params from JS
   - JS extracted endpoints are scope-filtered again before target generation
3. Build scan targets
   - keep crawled URLs directly (avoid dropping known vulnerable links)
   - `batch` strategy: URL params + related JS params + high-value globals
   - `deep` strategy: use nearly all discovered params
4. Scan
   - template sample phase
   - GET batch quick probe
   - scan targets can run in batches (memory-friendly)
   - optional POST form-urlencoded quick probe
   - `batch`: hidden params are filtered to high-value names and capped
   - `batch`: verify probes are reduced to representative contexts and stop on first hit
   - `deep`: hidden params and verify probes keep broad coverage
   - verify hit params
5. Write output files
6. Optional notification
   - push findings to DingTalk webhook
   - each site sends at most `notify.max_per_site` notifications

## Important

- Main focus is reflected XSS.
- POST mode only tests `application/x-www-form-urlencoded` style body submissions.
- CSRF logic is intentionally not handled in this scanner.
- Results should be manually validated in authorized scope.
- `balanced`/`fast` are intended to use `batch` parameter strategy by default.
- `deep` mode is intended to use `deep` parameter strategy by default.




