# xscanpro

A custom scanning pipeline inspired by:

- crawl.go (URL collection)
- linkfinder.go (JS endpoint and param discovery)
- xscan (reflected XSS detection and dedupe ideas)

This project does not reuse xscan payload lists.
It uses neutral markers and context-aware verification.

## Features

- URL collection with three tools:
  - waymore (root domain input)
  - katana (subdomain URL list input)
  - crawlergo (subdomain URL list input)
- Collector scheduling strategy:
  - waymore + katana run in parallel
  - crawlergo runs after them (serial, lower peak memory pressure)
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
dist/xscanpro-linux-amd64
```

Manual build example:

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
go build -o .\dist\xscanpro-linux-amd64 .\cmd\scanner
```

## Minimal CLI flags

```powershell
-config config.yaml   # config file path
-domain example.com   # root domain for waymore -i
-i subs.txt           # subdomain URL list file for katana/crawlergo
-out output           # output directory
-mode balanced        # fast | balanced | deep
-waymore false        # override collector.use_waymore (true/false)
-v                    # verbose logs
```

Notes:

- Advanced settings are configured in `config.yaml`.
- CLI is intentionally minimal.

## Config

Edit `config.yaml` (fully commented).
Common keys:

- `collector.use_waymore`
- `collector.use_katana`
- `collector.use_crawlergo`
- `collector.crawlergo_bin`
- `collector.crawlergo_chrome_path`
- `collector.crawlergo_tabs`
- `collector.crawlergo_robots_path`
- `collector.crawlergo_timeout_sec`
- `target.smart_dedupe`
- `target.param_strategy`
- `target.high_value_global_params`
- `batch` mode also keeps scan-stage hidden params and verify probes more conservative.
- `scanner.all_params`
- `scanner.param_batch_size`
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

- startup summary (mode/domain/output/workers/notify)
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

1. Collect URLs
   - waymore with root domain
   - katana with subdomain URL list file
   - crawlergo with subdomain URL list file
   - merge and dedupe all collector outputs
2. Extract endpoints and params from JS
3. Build scan targets
   - keep crawled URLs directly (avoid dropping known vulnerable links)
   - `batch` strategy: URL params + related JS params + high-value globals
   - `deep` strategy: use nearly all discovered params
4. Scan
   - template sample phase
   - GET batch quick probe
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
- When `collector.use_crawlergo=true`, ensure `crawlergo` and Chrome path are available.
- `balanced`/`fast` are intended to use `batch` parameter strategy by default.
- `deep` mode is intended to use `deep` parameter strategy by default.
