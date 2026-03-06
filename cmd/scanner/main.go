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
	colorBlue   = "\033[1;34m%s\033[0m"
	colorCyan   = "\033[1;36m%s\033[0m"
	colorGreen  = "\033[1;32m%s\033[0m"
	colorYellow = "\033[1;33m%s\033[0m"
	colorRed    = "\033[1;31m%s\033[0m"
)

func printColor(format, text string) {
	fmt.Printf(format, text)
}

func printHeader(cfg config.Config) {
	printColor(colorBlue, logo)
	printColor(colorBlue, "xscanpro\n")
	fmt.Printf("  mode:           %s\n", cfg.Mode)
	fmt.Printf("  domain:         %s\n", cfg.Domain)
	fmt.Printf("  out:            %s\n", filepath.Clean(cfg.OutDir))
	fmt.Printf("  param strategy: %s\n", cfg.Target.ParamStrategy)
	fmt.Printf("  collector:      waymore=%t, katana=%t, crawlergo=%t\n", cfg.Collector.UseWaymore, cfg.Collector.UseKatana, cfg.Collector.UseCrawlergo)
	fmt.Printf("  workers:        js=%d, scan=%d\n", cfg.Scanner.JSWorkers, cfg.Scanner.ScanWorkers)
	fmt.Printf("  notify:         dingtalk=%t\n", cfg.Notify.Enabled)
	fmt.Println()
}

func stageStart(idx int, total int, name string) time.Time {
	printColor(colorCyan, fmt.Sprintf("[%d/%d] %s\n", idx, total, name))
	return time.Now()
}

func stageInfo(label string, value interface{}) {
	fmt.Printf("  - %-16s %v\n", label+":", value)
}

func stageWarn(msg string) {
	printColor(colorYellow, fmt.Sprintf("  ! %s\n", msg))
}

func stageError(msg string) {
	printColor(colorRed, fmt.Sprintf("  x %s\n", msg))
}

func stageDone(start time.Time, detail string) {
	printColor(colorGreen, fmt.Sprintf("  ok %s\n", detail))
	stageInfo("elapsed", time.Since(start).Round(time.Millisecond))
	fmt.Println()
}

func trimForConsole(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

func printFinding(f model.Finding) {
	printColor(colorRed, "[HIT] Reflected XSS\n")
	stageInfo("url", f.URL)
	stageInfo("param", f.Param)
	stageInfo("payload", trimForConsole(f.InjectedValue, 180))
	stageInfo("context", f.Context)
	stageInfo("evidence", trimForConsole(f.Indicator, 180))
	fmt.Println()
}

func printSummary(cfg config.Config, targets int, report model.Report, start time.Time) {
	printColor(colorGreen, "Summary\n")
	stageInfo("output", filepath.Clean(cfg.OutDir))
	stageInfo("targets", targets)
	stageInfo("findings", report.TotalFindings)
	stageInfo("elapsed", time.Since(start).Round(time.Millisecond))
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
	stageInfo("sources", "waymore + katana parallel, crawlergo serial")
	stageInfo("scope", cfg.Domain)
	crawled, err := collector.Collect(cfg.OutDir, cfg.Domain, cfg.SubsFile, collector.Options{
		UseWaymore:        cfg.Collector.UseWaymore,
		UseKatana:         cfg.Collector.UseKatana,
		UseCrawlergo:      cfg.Collector.UseCrawlergo,
		KatanaConcurrency: cfg.Collector.KatanaConcurrency,
		KatanaDepth:       cfg.Collector.KatanaDepth,
		CrawlergoBin:      cfg.Collector.CrawlergoBin,
		CrawlergoChrome:   cfg.Collector.CrawlergoChrome,
		CrawlergoTabs:     cfg.Collector.CrawlergoTabs,
		CrawlergoRobots:   cfg.Collector.CrawlergoRobots,
		CrawlergoTimeout:  cfg.Collector.CrawlergoTimeout,
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
	scan := scanner.New(client, cfg.Scanner.ScanWorkers, cfg.Scanner.MaxParamsPerURL, cfg.Verbose)
	scan.SetTemplateStrategy(cfg.Scanner.SamplePerGroup, cfg.Scanner.ExpandOnHit)
	scan.SetBatchStrategy(cfg.Scanner.AllParams, cfg.Scanner.ParamBatchSize)
	scan.SetWorkerSplit(cfg.Scanner.TargetWorkers, cfg.Scanner.QuickWorkers, cfg.Scanner.VerifyWorkers)
	scan.SetShapeDedupe(cfg.Scanner.ShapeDedupeEnabled, cfg.Scanner.ShapeThreshold)
	scan.SetParamStrategy(cfg.Target.ParamStrategy, cfg.Target.HighValueGlobalParams)
	scan.SetFindingCallback(func(f model.Finding) {
		printFinding(f)
		notifier.EnqueueFinding(f)
	})
	report := scan.Scan(targets)
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
