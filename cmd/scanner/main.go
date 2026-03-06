package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	colorBlue  = "\033[1;34m%s\033[0m"
	colorCyan  = "\033[1;36m%s\033[0m"
	colorGreen = "\033[1;32m%s\033[0m"
)

func stageStart(idx int, name string) time.Time {
	fmt.Printf(colorCyan, fmt.Sprintf("[*] [%d/4] %s\n", idx, name))
	return time.Now()
}

func stageDone(start time.Time, detail string) {
	fmt.Printf("      [ok] %s (%s)\n", detail, time.Since(start).Round(time.Millisecond))
}

func main() {
	cfg := config.Parse()
	start := time.Now()

	fmt.Printf(colorBlue, logo)
	fmt.Printf(colorBlue, fmt.Sprintf(
		" profile=%s | domain=%s | out=%s | tools(waymore=%t,katana=%t,crawlergo=%t)\n",
		cfg.Mode, cfg.Domain, cfg.OutDir, cfg.Collector.UseWaymore, cfg.Collector.UseKatana, cfg.Collector.UseCrawlergo,
	))

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

	s1 := stageStart(1, "collecting URLs (waymore + katana in parallel, then crawlergo)")
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
		fmt.Printf("collection failed: %v\n", err)
		os.Exit(1)
	}
	stageDone(s1, fmt.Sprintf("urls=%d js=%d", len(crawled.URLs), len(crawled.JSURLs)))

	s2 := stageStart(2, "extracting endpoints/params from JS")
	jsf := jsfinder.New(client, cfg.Domain, cfg.Scanner.JSWorkers, cfg.Verbose)
	jsd := jsf.Discover(crawled.JSURLs)
	if cfg.ParamDictFile != "" {
		if extra, err := util.ReadLines(cfg.ParamDictFile); err == nil {
			jsd.Params = util.UniqueStrings(append(jsd.Params, extra...))
			if cfg.Verbose {
				fmt.Printf("      merged custom params: +%d from %s\n", len(extra), cfg.ParamDictFile)
			}
		} else {
			fmt.Printf("      warning: failed to read param dict (%s): %v\n", cfg.ParamDictFile, err)
		}
	}
	stageDone(s2, fmt.Sprintf("endpoints=%d params=%d", len(jsd.Endpoints), len(jsd.Params)))

	s3 := stageStart(3, "generating scan targets")
	targets := targetgen.BuildTargets(cfg.Domain, crawled.URLs, jsd.Endpoints, jsd.Params, targetgen.Options{
		MaxParamsPerURL: cfg.Scanner.MaxParamsPerURL,
		AllParams:       cfg.Scanner.AllParams,
		SmartDedupe:     cfg.Target.SmartDedupe,
		MaxPerPattern:   cfg.Target.MaxPerPattern,
	})
	stageDone(s3, fmt.Sprintf("targets=%d", len(targets)))

	s4 := stageStart(4, "scanning reflected xss candidates")
	scan := scanner.New(client, cfg.Scanner.ScanWorkers, cfg.Scanner.MaxParamsPerURL, cfg.Verbose)
	scan.SetTemplateStrategy(cfg.Scanner.SamplePerGroup, cfg.Scanner.ExpandOnHit)
	scan.SetBatchStrategy(cfg.Scanner.AllParams, cfg.Scanner.ParamBatchSize)
	scan.SetWorkerSplit(cfg.Scanner.TargetWorkers, cfg.Scanner.QuickWorkers, cfg.Scanner.VerifyWorkers)
	scan.SetShapeDedupe(cfg.Scanner.ShapeDedupeEnabled, cfg.Scanner.ShapeThreshold)
	scan.SetFindingCallback(func(f model.Finding) {
		notifier.EnqueueFinding(f)
	})
	report := scan.Scan(targets)
	stageDone(s4, fmt.Sprintf("findings=%d", report.TotalFindings))

	if err := output.WritePipelineArtifacts(
		cfg.OutDir,
		crawled.URLs,
		crawled.JSURLs,
		jsd.Endpoints,
		jsd.Params,
		report,
	); err != nil {
		fmt.Printf("write output failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(colorGreen, "\n[ok] Scan Completed\n")
	fmt.Printf("Output: %s\n", filepath.Clean(cfg.OutDir))
	fmt.Printf("Elapsed: %s\n", time.Since(start).Round(time.Millisecond))
}
