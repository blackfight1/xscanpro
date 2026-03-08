package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	fmt.Printf("  %-18s %s\n", "domain", cfg.Domain)
	fmt.Printf("  %-18s %s\n", "out", filepath.Clean(cfg.OutDir))
	fmt.Printf("  %-18s %s\n", "param strategy", cfg.Target.ParamStrategy)
	fmt.Printf("  %-18s waymore=%t, katana=%t, crawlergo=%t\n", "collector", cfg.Collector.UseWaymore, cfg.Collector.UseKatana, cfg.Collector.UseCrawlergo)
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

	printHeader(cfg)

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

	s1 := stageStart(1, totalStages, "Collector")
	stageInfo("sources", "waymore + katana(full) + crawlergo(batch)")
	stageInfo("crawlergo batch", fmt.Sprintf("enabled=%t,size=%d,continue_timeout=%t", cfg.Collector.CrawlergoBatchEnabled, cfg.Collector.CrawlergoBatchSize, cfg.Collector.CrawlergoContinueOnTimeout))
	stageInfo("scope", cfg.Domain)
	crawled, err := collector.Collect(cfg.OutDir, cfg.Domain, cfg.SubsFile, collector.Options{
		UseWaymore:                 cfg.Collector.UseWaymore,
		UseKatana:                  cfg.Collector.UseKatana,
		UseCrawlergo:               cfg.Collector.UseCrawlergo,
		KatanaConcurrency:          cfg.Collector.KatanaConcurrency,
		KatanaDepth:                cfg.Collector.KatanaDepth,
		CrawlergoBin:               cfg.Collector.CrawlergoBin,
		CrawlergoChrome:            cfg.Collector.CrawlergoChrome,
		CrawlergoTabs:              cfg.Collector.CrawlergoTabs,
		CrawlergoRobots:            cfg.Collector.CrawlergoRobots,
		CrawlergoTimeout:           cfg.Collector.CrawlergoTimeout,
		CrawlergoBatchEnabled:      cfg.Collector.CrawlergoBatchEnabled,
		CrawlergoBatchSize:         cfg.Collector.CrawlergoBatchSize,
		CrawlergoContinueOnTimeout: cfg.Collector.CrawlergoContinueOnTimeout,
	})
	if err != nil {
		stageError(fmt.Sprintf("collection failed: %v", err))
		os.Exit(1)
	}
	stageInfo("urls", len(crawled.URLs))
	stageInfo("js urls", len(crawled.JSURLs))
	stageDone(s1, "collection completed")

	s2 := stageStart(2, totalStages, "JS Discovery")
	stageInfo("js workers", cfg.Scanner.JSWorkers)
	jsf := jsfinder.New(client, cfg.Domain, cfg.Scanner.JSWorkers, cfg.Verbose)
	jsd := jsf.Discover(crawled.JSURLs)
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
	targets := targetgen.BuildTargets(cfg.Domain, crawled.URLs, jsd.Endpoints, jsd.Params, targetgen.Options{
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

	notifier.NotifySummary(cfg.Domain, len(targets), report.TotalFindings, time.Since(start), cfg.OutDir)
	printSummary(cfg, len(targets), report, start)
}
