package main

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"xscanpro/internal/collector"
	"xscanpro/internal/config"
	"xscanpro/internal/fetch"
	"xscanpro/internal/jsfinder"
	"xscanpro/internal/model"
	"xscanpro/internal/notify"
	"xscanpro/internal/output"
	"xscanpro/internal/scanner"
	"xscanpro/internal/targetgen"
	"xscanpro/internal/util"
)

const logo = `
 __  _____  ____    ___   _   _ ____  ____  _____
 \ \/ / ___|/ ___|  / _ \ | \ | |  _ \|  _ \| ____|
  \  /\___ \ |     | | | ||  \| | |_) | |_) |  _|
  /  \ ___) | |___ | |_| || |\  |  __/|  _ <| |___
 /_/\_\____/ \____| \___/ |_| \_|_|   |_| \_\_____|
`

const (
	clrReset  = "\033[0m"
	clrBold   = "\033[1m"
	clrBlue   = "\033[1;34m"
	clrCyan   = "\033[1;36m"
	clrGreen  = "\033[1;32m"
	clrYellow = "\033[1;33m"
	clrRed    = "\033[1;31m"
	clrGray   = "\033[90m"
)

var (
	jsURLRe      = regexp.MustCompile(`(?i)\.m?js(?:\?|$)`)
	staticExtSet = map[string]struct{}{
		".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".svg": {}, ".webp": {}, ".bmp": {}, ".ico": {},
		".css": {}, ".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {}, ".otf": {},
		".mp4": {}, ".mp3": {}, ".wav": {}, ".avi": {}, ".mov": {}, ".webm": {},
		".pdf": {}, ".zip": {}, ".rar": {}, ".7z": {}, ".tar": {}, ".gz": {},
		".map": {}, ".webmanifest": {}, ".swf": {}, ".apk": {}, ".exe": {}, ".bin": {}, ".dmg": {}, ".iso": {},
		".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {}, ".ppt": {}, ".pptx": {},
	}
)

func paint(color, s string) string {
	return color + s + clrReset
}

func line(ch string, n int) string {
	if n <= 0 {
		n = 64
	}
	return strings.Repeat(ch, n)
}

func printHeader(cfg config.Config) {
	fmt.Println(paint(clrBlue, line("=", 72)))
	fmt.Print(paint(clrBlue, logo))
	fmt.Println(paint(clrBlue, line("=", 72)))
	fmt.Println(paint(clrBold+clrCyan, " PROFILE"))
	fmt.Printf("  %-18s %s\n", "mode", cfg.Mode)
	if strings.TrimSpace(cfg.InputURL) != "" {
		fmt.Printf("  %-18s %s\n", "input(-u)", cfg.InputURL)
	}
	if strings.TrimSpace(cfg.InputFile) != "" {
		fmt.Printf("  %-18s %s\n", "input(-i)", cfg.InputFile)
	}
	fmt.Printf("  %-18s %s\n", "out", filepath.Clean(cfg.OutDir))
	fmt.Printf("  %-18s %s\n", "param strategy", cfg.Target.ParamStrategy)
	if strings.TrimSpace(cfg.XSSOnlyFile) != "" {
		fmt.Printf("  %-18s %s\n", "xss only", cfg.XSSOnlyFile)
	}
	fmt.Printf("  %-18s waymore=%t, katana=%t\n", "collector", cfg.Collector.UseWaymore, cfg.Collector.UseKatana)
	fmt.Printf("  %-18s enabled=%t, c=%d, d=%d, no-sandbox=%t\n", "katana hl", cfg.Collector.UseKatanaHeadless, cfg.Collector.KatanaHeadlessConcurrency, cfg.Collector.KatanaHeadlessDepth, cfg.Collector.KatanaHeadlessNoSandbox)
	fmt.Printf("  %-18s js=%d, scan=%d\n", "workers", cfg.Scanner.JSWorkers, cfg.Scanner.ScanWorkers)
	fmt.Printf("  %-18s enabled=%t, batch=%d\n", "post scan", cfg.Scanner.EnablePostScan, cfg.Scanner.PostParamBatchSize)
	fmt.Printf("  %-18s enabled=%t, size=%d\n", "scan batch", cfg.Scanner.ScanBatchEnabled, cfg.Scanner.ScanBatchSize)
	fmt.Printf("  %-18s dingtalk=%t\n", "notify", cfg.Notify.Enabled)
	fmt.Println(paint(clrGray, line("-", 72)))
}

func stageStart(idx int, total int, name string) time.Time {
	fmt.Println()
	fmt.Println(paint(clrCyan, fmt.Sprintf("[%d/%d] >>> %s", idx, total, name)))
	fmt.Println(paint(clrGray, line("-", 72)))
	return time.Now()
}

func stageInfo(label string, value interface{}) {
	fmt.Printf("  %s %-16s %v\n", paint(clrGray, "|"), label+":", value)
}

func stageWarn(msg string) {
	fmt.Println(paint(clrYellow, "  [WARN] "+msg))
}

func stageError(msg string) {
	fmt.Println(paint(clrRed, "  [ERR ] "+msg))
}

func stageDone(start time.Time, detail string) {
	fmt.Println(paint(clrGreen, "  [OK  ] "+detail))
	stageInfo("elapsed", time.Since(start).Round(time.Millisecond))
	fmt.Println(paint(clrGray, line("-", 72)))
}

func trimForConsole(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

func chunkScanTargets(targets []model.ScanTarget, enabled bool, size int) [][]model.ScanTarget {
	if len(targets) == 0 {
		return nil
	}
	if !enabled {
		return [][]model.ScanTarget{targets}
	}
	if size <= 0 {
		size = len(targets)
	}
	out := make([][]model.ScanTarget, 0, (len(targets)+size-1)/size)
	for i := 0; i < len(targets); i += size {
		end := i + size
		if end > len(targets) {
			end = len(targets)
		}
		out = append(out, targets[i:end])
	}
	return out
}

func isStaticLikeURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	if ext == "" {
		return false
	}
	_, ok := staticExtSet[ext]
	return ok
}

func loadXSSOnlyInput(filePath string) (model.CrawlResult, error) {
	var out model.CrawlResult
	lines, err := util.ReadLines(filePath)
	if err != nil {
		return out, err
	}
	seen := make(map[string]struct{}, len(lines))
	urls := make([]string, 0, len(lines))
	for _, line := range lines {
		canon, err := util.CanonicalURL(line)
		if err != nil {
			continue
		}
		if isStaticLikeURL(canon) {
			continue
		}
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		urls = append(urls, canon)
	}
	sort.Strings(urls)
	js := make([]string, 0, len(urls))
	for _, u := range urls {
		if jsURLRe.MatchString(u) {
			js = append(js, u)
		}
	}
	js = util.UniqueStrings(js)
	sort.Strings(js)
	out.URLs = urls
	out.JSURLs = js
	return out, nil
}

func loadCollectorInputs(singleURL, inputFile string) ([]string, error) {
	raw := make([]string, 0, 128)
	u := strings.TrimSpace(singleURL)
	f := strings.TrimSpace(inputFile)
	if u != "" {
		raw = append(raw, u)
	}
	if f != "" {
		lines, err := util.ReadLines(f)
		if err != nil {
			return nil, err
		}
		raw = append(raw, lines...)
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		canon, err := util.CanonicalURL(line)
		if err != nil {
			continue
		}
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid URLs from -u/-i")
	}
	return out, nil
}

func summarizeScope(urls []string) string {
	if len(urls) == 0 {
		return "unknown"
	}
	hosts := map[string]struct{}{}
	roots := map[string]struct{}{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if h == "" {
			continue
		}
		hosts[h] = struct{}{}
		if rd := registrableDomain(h); rd != "" {
			roots[rd] = struct{}{}
		}
	}
	if len(roots) == 1 {
		for rd := range roots {
			return rd
		}
	}
	return fmt.Sprintf("multi-root(%d), hosts=%d", len(roots), len(hosts))
}

func registrableDomain(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return ""
	}
	rd, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err == nil && rd != "" {
		return rd
	}
	parts := strings.Split(h, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return h
}

func scopeFromURLs(urls []string) (map[string]struct{}, map[string]struct{}) {
	hosts := map[string]struct{}{}
	roots := map[string]struct{}{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if host == "" {
			continue
		}
		hosts[host] = struct{}{}
		if rd := registrableDomain(host); rd != "" {
			roots[rd] = struct{}{}
		}
	}
	return hosts, roots
}

func inScopeBySets(host string, hosts, roots map[string]struct{}) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if _, ok := hosts[h]; ok {
		return true
	}
	for ah := range hosts {
		if strings.HasSuffix(h, "."+ah) {
			return true
		}
	}
	if rd := registrableDomain(h); rd != "" {
		if _, ok := roots[rd]; ok {
			return true
		}
	}
	return false
}

func filterScopeURLs(urls []string, domain string, hosts, roots map[string]struct{}) []string {
	if strings.TrimSpace(domain) == "" && len(hosts) == 0 && len(roots) == 0 {
		return urls
	}
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if host == "" {
			continue
		}
		if strings.TrimSpace(domain) != "" {
			if !util.ScopeMatch(host, domain) {
				continue
			}
		} else if !inScopeBySets(host, hosts, roots) {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	sort.Strings(out)
	return out
}

func printFinding(f model.Finding) {
	method := strings.ToUpper(strings.TrimSpace(f.Method))
	if method == "" {
		method = "GET"
	}
	fmt.Println(paint(clrRed, line("!", 72)))
	fmt.Println(paint(clrRed+clrBold, "[HIT] Reflected XSS"))
	stageInfo("method", method)
	stageInfo("url", f.URL)
	stageInfo("param", f.Param)
	stageInfo("payload", trimForConsole(f.InjectedValue, 180))
	stageInfo("context", f.Context)
	stageInfo("evidence", trimForConsole(f.Indicator, 180))
	fmt.Println(paint(clrRed, line("!", 72)))
}

func printSummary(cfg config.Config, targets int, report model.Report, start time.Time) {
	fmt.Println()
	fmt.Println(paint(clrGreen, line("=", 72)))
	fmt.Println(paint(clrGreen+clrBold, " FINAL SUMMARY"))
	stageInfo("output", filepath.Clean(cfg.OutDir))
	stageInfo("targets", targets)
	stageInfo("findings", report.TotalFindings)
	stageInfo("elapsed", time.Since(start).Round(time.Millisecond))
	fmt.Println(paint(clrGreen, line("=", 72)))
}

func main() {
	cfg := config.Parse()
	start := time.Now()
	xssOnlyMode := strings.TrimSpace(cfg.XSSOnlyFile) != ""

	printHeader(cfg)

	var collectorInputs []string
	if !xssOnlyMode {
		var err error
		collectorInputs, err = loadCollectorInputs(cfg.InputURL, cfg.InputFile)
		if err != nil {
			stageError(fmt.Sprintf("load collector input failed: %v", err))
			os.Exit(1)
		}
	}

	client := fetch.New(cfg.Scanner.HTTPTimeoutSec)
	notifier := notify.New(notify.Config{
		Enabled:    cfg.Notify.Enabled,
		MaxPerSite: cfg.Notify.MaxPerSite,
		QueueSize:  cfg.Notify.QueueSize,
		TimeoutSec: cfg.Notify.TimeoutSec,
		DingTalk: notify.DingTalkConfig{
			Webhook: cfg.Notify.DingTalk.Webhook,
			Secret:  cfg.Notify.DingTalk.Secret,
		},
	}, cfg.Verbose)
	defer notifier.Close()

	totalStages := 4

	var crawled model.CrawlResult
	if xssOnlyMode {
		s1 := stageStart(1, totalStages, "Input URLs (XSS Only)")
		stageInfo("source file", cfg.XSSOnlyFile)
		stageInfo("collector", "skipped")
		var err error
		crawled, err = loadXSSOnlyInput(cfg.XSSOnlyFile)
		if err != nil {
			stageError(fmt.Sprintf("load xss-only input failed: %v", err))
			os.Exit(1)
		}
		if len(crawled.URLs) == 0 {
			stageError("xss-only input has no valid URLs after normalization")
			os.Exit(1)
		}
		stageInfo("urls", len(crawled.URLs))
		stageInfo("js urls", len(crawled.JSURLs))
		stageDone(s1, "input loaded")
	} else {
		s1 := stageStart(1, totalStages, "Collector")
		headlessNoSandbox := cfg.Collector.KatanaHeadlessNoSandbox
		stageInfo("sources", "waymore + katana(std) + katana(headless)")
		stageInfo("scope", summarizeScope(collectorInputs))
		stageInfo("input urls", len(collectorInputs))
		stageInfo("katana std", fmt.Sprintf("enabled=%t,c=%d,d=%d", cfg.Collector.UseKatana, cfg.Collector.KatanaConcurrency, cfg.Collector.KatanaDepth))
		stageInfo("katana hl", fmt.Sprintf("enabled=%t,c=%d,d=%d,no-sandbox=%t", cfg.Collector.UseKatanaHeadless, cfg.Collector.KatanaHeadlessConcurrency, cfg.Collector.KatanaHeadlessDepth, headlessNoSandbox))
		var err error
		crawled, err = collector.Collect(cfg.OutDir, collectorInputs, collector.Options{
			UseWaymore:                cfg.Collector.UseWaymore,
			UseKatana:                 cfg.Collector.UseKatana,
			UseKatanaHeadless:         cfg.Collector.UseKatanaHeadless,
			KatanaConcurrency:         cfg.Collector.KatanaConcurrency,
			KatanaDepth:               cfg.Collector.KatanaDepth,
			KatanaHeadlessConcurrency: cfg.Collector.KatanaHeadlessConcurrency,
			KatanaHeadlessDepth:       cfg.Collector.KatanaHeadlessDepth,
		})
		if err != nil {
			stageError(fmt.Sprintf("collection failed: %v", err))
			os.Exit(1)
		}
		stageInfo("urls", len(crawled.URLs))
		stageInfo("js urls", len(crawled.JSURLs))
		stageDone(s1, "collection completed")
	}

	s2 := stageStart(2, totalStages, "JS Discovery")
	stageInfo("js workers", cfg.Scanner.JSWorkers)
	jsf := jsfinder.New(client, "", cfg.Scanner.JSWorkers, cfg.Verbose)
	jsd := jsf.Discover(crawled.JSURLs)
	scopeHosts, scopeRoots := scopeFromURLs(crawled.URLs)
	beforeEndpoints := len(jsd.Endpoints)
	jsd.Endpoints = filterScopeURLs(jsd.Endpoints, "", scopeHosts, scopeRoots)
	if len(jsd.Endpoints) != beforeEndpoints {
		stageInfo("scope filter", fmt.Sprintf("endpoints %d -> %d", beforeEndpoints, len(jsd.Endpoints)))
	}
	if cfg.ParamDictFile != "" {
		if extra, err := util.ReadLines(cfg.ParamDictFile); err == nil {
			jsd.Params = util.UniqueStrings(append(jsd.Params, extra...))
			stageInfo("custom params", fmt.Sprintf("+%d from %s", len(extra), cfg.ParamDictFile))
		} else {
			stageWarn(fmt.Sprintf("failed to read param dict (%s): %v", cfg.ParamDictFile, err))
		}
	}
	stageInfo("endpoints", len(jsd.Endpoints))
	stageInfo("params", len(jsd.Params))
	stageDone(s2, "js discovery completed")

	s3 := stageStart(3, totalStages, "Target Generation")
	stageInfo("param strategy", cfg.Target.ParamStrategy)
	stageInfo("smart dedupe", cfg.Target.SmartDedupe)
	targets := targetgen.BuildTargets("", crawled.URLs, jsd.Endpoints, jsd.Params, targetgen.Options{
		MaxParamsPerURL: cfg.Scanner.MaxParamsPerURL,
		AllParams:       cfg.Scanner.AllParams,
		SmartDedupe:     cfg.Target.SmartDedupe,
		MaxPerPattern:   cfg.Target.MaxPerPattern,
		ParamStrategy:   cfg.Target.ParamStrategy,
		RelatedParams:   jsd.RelatedParams,
		HighValueParams: cfg.Target.HighValueGlobalParams,
	})
	stageInfo("targets", len(targets))
	stageDone(s3, "target generation completed")

	s4 := stageStart(4, totalStages, "Scanner")
	stageInfo("scan workers", cfg.Scanner.ScanWorkers)
	stageInfo("max params/url", cfg.Scanner.MaxParamsPerURL)
	stageInfo("post scan", cfg.Scanner.EnablePostScan)
	stageInfo("post batch", cfg.Scanner.PostParamBatchSize)
	stageInfo("scan batch", fmt.Sprintf("enabled=%t,size=%d", cfg.Scanner.ScanBatchEnabled, cfg.Scanner.ScanBatchSize))
	scan := scanner.New(client, cfg.Scanner.ScanWorkers, cfg.Scanner.MaxParamsPerURL, cfg.Verbose)
	scan.SetTemplateStrategy(cfg.Scanner.SamplePerGroup, cfg.Scanner.ExpandOnHit)
	scan.SetBatchStrategy(cfg.Scanner.AllParams, cfg.Scanner.ParamBatchSize)
	scan.SetPostStrategy(cfg.Scanner.EnablePostScan, cfg.Scanner.PostParamBatchSize, cfg.Scanner.MaxPostFormsPerURL, cfg.Scanner.MaxPostParamsPerForm)
	scan.SetWorkerSplit(cfg.Scanner.TargetWorkers, cfg.Scanner.QuickWorkers, cfg.Scanner.VerifyWorkers)
	scan.SetShapeDedupe(cfg.Scanner.ShapeDedupeEnabled, cfg.Scanner.ShapeThreshold)
	scan.SetParamStrategy(cfg.Target.ParamStrategy, cfg.Target.HighValueGlobalParams)
	scan.SetFindingCallback(func(f model.Finding) {
		printFinding(f)
		notifier.EnqueueFinding(f)
	})

	scanBatches := chunkScanTargets(targets, cfg.Scanner.ScanBatchEnabled, cfg.Scanner.ScanBatchSize)
	allFindings := make([]model.Finding, 0)
	for i, batch := range scanBatches {
		stageInfo("scan chunk", fmt.Sprintf("%d/%d targets=%d", i+1, len(scanBatches), len(batch)))
		part := scan.Scan(batch)
		allFindings = append(allFindings, part.Findings...)
	}
	report := model.Report{
		TotalTargets:  len(targets),
		TotalFindings: len(allFindings),
		Findings:      allFindings,
	}
	stageInfo("findings", report.TotalFindings)
	stageDone(s4, "scan completed")

	if err := output.WritePipelineArtifacts(
		cfg.OutDir,
		crawled.URLs,
		crawled.JSURLs,
		jsd.Endpoints,
		jsd.Params,
		report,
	); err != nil {
		stageError(fmt.Sprintf("write output failed: %v", err))
		os.Exit(1)
	}

	summaryScope := summarizeScope(crawled.URLs)
	if xssOnlyMode {
		summaryScope = "xss-only"
	}
	notifier.NotifySummary(summaryScope, len(targets), report.TotalFindings, time.Since(start), cfg.OutDir)
	printSummary(cfg, len(targets), report, start)
}
