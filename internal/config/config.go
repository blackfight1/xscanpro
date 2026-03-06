package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Domain        string          `yaml:"domain"`
	SubsFile      string          `yaml:"subs_file"`
	OutDir        string          `yaml:"out_dir"`
	Mode          string          `yaml:"mode"`
	ParamDictFile string          `yaml:"param_dict_file"`
	Collector     CollectorConfig `yaml:"collector"`
	Target        TargetConfig    `yaml:"target"`
	Scanner       ScannerConfig   `yaml:"scanner"`
	Notify        NotifyConfig    `yaml:"notify"`
	Verbose       bool            `yaml:"verbose"`
}

type CollectorConfig struct {
	UseWaymore        bool   `yaml:"use_waymore"`
	UseKatana         bool   `yaml:"use_katana"`
	UseCrawlergo      bool   `yaml:"use_crawlergo"`
	KatanaConcurrency int    `yaml:"katana_concurrency"`
	KatanaDepth       int    `yaml:"katana_depth"`
	CrawlergoBin      string `yaml:"crawlergo_bin"`
	CrawlergoChrome   string `yaml:"crawlergo_chrome_path"`
	CrawlergoTabs     int    `yaml:"crawlergo_tabs"`
	CrawlergoRobots   bool   `yaml:"crawlergo_robots_path"`
	CrawlergoTimeout  int    `yaml:"crawlergo_timeout_sec"`
}

type TargetConfig struct {
	SmartDedupe           bool     `yaml:"smart_dedupe"`
	MaxPerPattern         int      `yaml:"max_per_pattern"`
	ParamStrategy         string   `yaml:"param_strategy"`
	HighValueGlobalParams []string `yaml:"high_value_global_params"`
}

type ScannerConfig struct {
	JSWorkers          int  `yaml:"js_workers"`
	ScanWorkers        int  `yaml:"scan_workers"`
	TargetWorkers      int  `yaml:"target_workers"`
	QuickWorkers       int  `yaml:"quick_workers"`
	VerifyWorkers      int  `yaml:"verify_workers"`
	HTTPTimeoutSec     int  `yaml:"http_timeout_sec"`
	MaxParamsPerURL    int  `yaml:"max_params_per_url"`
	AllParams          bool `yaml:"all_params"`
	ParamBatchSize     int  `yaml:"param_batch_size"`
	SamplePerGroup     int  `yaml:"sample_per_group"`
	ExpandOnHit        bool `yaml:"expand_on_hit"`
	ShapeDedupeEnabled bool `yaml:"shape_dedupe_enabled"`
	ShapeThreshold     int  `yaml:"shape_threshold"`
}

type NotifyConfig struct {
	Enabled    bool           `yaml:"enabled"`
	Provider   string         `yaml:"provider"`
	MaxPerSite int            `yaml:"max_per_site"`
	QueueSize  int            `yaml:"queue_size"`
	TimeoutSec int            `yaml:"timeout_sec"`
	DingTalk   DingTalkConfig `yaml:"dingtalk"`
}

type DingTalkConfig struct {
	Webhook string `yaml:"webhook"`
	Secret  string `yaml:"secret"`
}

func Parse() Config {
	cfg := defaultConfig()

	configPath := flag.String("config", "config.yaml", "yaml config file path")
	domain := flag.String("domain", "", "root domain for waymore, e.g. example.com")
	subsFile := flag.String("i", "", "subdomain URL list file for katana/crawlergo")
	outDir := flag.String("out", "", "output directory")
	mode := flag.String("mode", "", "scan profile: fast | balanced | deep")
	waymore := flag.String("waymore", "", "override collector.use_waymore (true/false)")
	verbose := flag.Bool("v", false, "verbose output")

	flag.Parse()

	loadConfigFile(configPath, &cfg)
	applyCLIOverrides(&cfg, func() map[string]bool {
		seen := map[string]bool{}
		flag.Visit(func(f *flag.Flag) {
			seen[f.Name] = true
		})
		return seen
	}(), domain, subsFile, outDir, mode, waymore, verbose)

	applyModeDefaults(&cfg)

	if strings.TrimSpace(cfg.Domain) == "" {
		fmt.Println("missing -domain")
		flag.Usage()
		os.Exit(1)
	}
	if !cfg.Collector.UseWaymore && !cfg.Collector.UseKatana && !cfg.Collector.UseCrawlergo {
		fmt.Println("collector.use_waymore, collector.use_katana and collector.use_crawlergo cannot all be false")
		os.Exit(1)
	}
	if (cfg.Collector.UseKatana || cfg.Collector.UseCrawlergo) && strings.TrimSpace(cfg.SubsFile) == "" {
		fmt.Println("missing -i / subs_file (required when katana or crawlergo is enabled)")
		flag.Usage()
		os.Exit(1)
	}
	if cfg.Collector.UseCrawlergo && strings.TrimSpace(cfg.Collector.CrawlergoChrome) == "" {
		fmt.Println("missing collector.crawlergo_chrome_path (required when crawlergo is enabled)")
		os.Exit(1)
	}
	if cfg.Notify.Enabled {
		provider := strings.ToLower(strings.TrimSpace(cfg.Notify.Provider))
		if provider == "" {
			provider = "dingtalk"
		}
		cfg.Notify.Provider = provider
		if provider != "dingtalk" {
			fmt.Println("notify.provider only supports dingtalk currently")
			os.Exit(1)
		}
		if strings.TrimSpace(cfg.Notify.DingTalk.Webhook) == "" {
			fmt.Println("missing notify.dingtalk.webhook (required when notify is enabled)")
			os.Exit(1)
		}
	}
	return cfg
}

func defaultConfig() Config {
	return Config{
		OutDir: "output",
		Mode:   "balanced",
		Collector: CollectorConfig{
			UseWaymore:       true,
			UseKatana:        true,
			UseCrawlergo:     true,
			CrawlergoBin:     "crawlergo",
			CrawlergoChrome:  "/usr/bin/google-chrome",
			CrawlergoTabs:    10,
			CrawlergoRobots:  true,
			CrawlergoTimeout: 1200,
		},
		Target: TargetConfig{
			SmartDedupe:   true,
			ParamStrategy: "batch",
			HighValueGlobalParams: []string{
				"q", "query", "search", "keyword", "url", "redirect", "return", "next", "callback",
			},
		},
		Scanner: ScannerConfig{
			AllParams:          true,
			ParamBatchSize:     45,
			SamplePerGroup:     0,
			ExpandOnHit:        true,
			ShapeDedupeEnabled: true,
			ShapeThreshold:     10,
		},
		Notify: NotifyConfig{
			Enabled:    false,
			Provider:   "dingtalk",
			MaxPerSite: 10,
			QueueSize:  200,
			TimeoutSec: 8,
			DingTalk: DingTalkConfig{
				Webhook: "",
				Secret:  "",
			},
		},
	}
}

func loadConfigFile(configPath *string, cfg *Config) {
	path := strings.TrimSpace(*configPath)
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) && filepath.Base(path) == "config.yaml" {
			return
		}
		fmt.Printf("failed to read config file: %v\n", err)
		os.Exit(1)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("failed to read config file: %v\n", err)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		fmt.Printf("failed to parse config file: %v\n", err)
		os.Exit(1)
	}
}

func applyCLIOverrides(
	cfg *Config,
	seen map[string]bool,
	domain, subsFile, outDir, mode *string,
	waymore *string,
	verbose *bool,
) {
	if seen["domain"] {
		cfg.Domain = strings.TrimSpace(*domain)
	}
	if seen["i"] {
		cfg.SubsFile = strings.TrimSpace(*subsFile)
	}
	if seen["out"] {
		cfg.OutDir = strings.TrimSpace(*outDir)
	}
	if seen["mode"] {
		cfg.Mode = strings.TrimSpace(*mode)
	}
	if seen["waymore"] {
		v, err := strconv.ParseBool(strings.TrimSpace(*waymore))
		if err != nil {
			fmt.Println("invalid -waymore value, use true/false")
			os.Exit(1)
		}
		cfg.Collector.UseWaymore = v
	}
	if seen["v"] {
		cfg.Verbose = *verbose
	}
}

func applyModeDefaults(cfg *Config) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "balanced"
	}
	cfg.Mode = mode
	switch mode {
	case "fast":
		if cfg.Collector.KatanaConcurrency <= 0 {
			cfg.Collector.KatanaConcurrency = 40
		}
		if cfg.Collector.KatanaDepth <= 0 {
			cfg.Collector.KatanaDepth = 2
		}
		if cfg.Collector.CrawlergoTabs <= 0 {
			cfg.Collector.CrawlergoTabs = 12
		}
		if cfg.Collector.CrawlergoTimeout <= 0 {
			cfg.Collector.CrawlergoTimeout = 900
		}
		if cfg.Scanner.JSWorkers <= 0 {
			cfg.Scanner.JSWorkers = 35
		}
		if cfg.Scanner.ScanWorkers <= 0 {
			cfg.Scanner.ScanWorkers = 45
		}
		if cfg.Scanner.HTTPTimeoutSec <= 0 {
			cfg.Scanner.HTTPTimeoutSec = 10
		}
		if cfg.Scanner.MaxParamsPerURL <= 0 {
			cfg.Scanner.MaxParamsPerURL = 12
		}
		if cfg.Scanner.ParamBatchSize <= 0 {
			cfg.Scanner.ParamBatchSize = 45
		}
		if cfg.Scanner.SamplePerGroup < 0 {
			cfg.Scanner.SamplePerGroup = 0
		}
		if cfg.Scanner.ShapeThreshold <= 0 {
			cfg.Scanner.ShapeThreshold = 8
		}
		if cfg.Target.MaxPerPattern <= 0 {
			cfg.Target.MaxPerPattern = 2
		}
	case "deep":
		if strings.TrimSpace(cfg.Target.ParamStrategy) == "" {
			cfg.Target.ParamStrategy = "deep"
		}
		if cfg.Collector.KatanaConcurrency <= 0 {
			cfg.Collector.KatanaConcurrency = 12
		}
		if cfg.Collector.KatanaDepth <= 0 {
			cfg.Collector.KatanaDepth = 4
		}
		if cfg.Collector.CrawlergoTabs <= 0 {
			cfg.Collector.CrawlergoTabs = 8
		}
		if cfg.Collector.CrawlergoTimeout <= 0 {
			cfg.Collector.CrawlergoTimeout = 1800
		}
		if cfg.Scanner.JSWorkers <= 0 {
			cfg.Scanner.JSWorkers = 12
		}
		if cfg.Scanner.ScanWorkers <= 0 {
			cfg.Scanner.ScanWorkers = 16
		}
		if cfg.Scanner.HTTPTimeoutSec <= 0 {
			cfg.Scanner.HTTPTimeoutSec = 20
		}
		if cfg.Scanner.MaxParamsPerURL <= 0 {
			cfg.Scanner.MaxParamsPerURL = 35
		}
		if cfg.Scanner.ParamBatchSize <= 0 {
			cfg.Scanner.ParamBatchSize = 45
		}
		if cfg.Scanner.SamplePerGroup < 0 {
			cfg.Scanner.SamplePerGroup = 0
		}
		if cfg.Scanner.ShapeThreshold <= 0 {
			cfg.Scanner.ShapeThreshold = 14
		}
		if cfg.Target.MaxPerPattern <= 0 {
			cfg.Target.MaxPerPattern = 8
		}
	default:
		cfg.Mode = "balanced"
		if strings.TrimSpace(cfg.Target.ParamStrategy) == "" {
			cfg.Target.ParamStrategy = "batch"
		}
		if cfg.Collector.KatanaConcurrency <= 0 {
			cfg.Collector.KatanaConcurrency = 16
		}
		if cfg.Collector.KatanaDepth <= 0 {
			cfg.Collector.KatanaDepth = 3
		}
		if cfg.Collector.CrawlergoTabs <= 0 {
			cfg.Collector.CrawlergoTabs = 8
		}
		if cfg.Collector.CrawlergoTimeout <= 0 {
			cfg.Collector.CrawlergoTimeout = 1200
		}
		if cfg.Scanner.JSWorkers <= 0 {
			cfg.Scanner.JSWorkers = 14
		}
		if cfg.Scanner.ScanWorkers <= 0 {
			cfg.Scanner.ScanWorkers = 20
		}
		if cfg.Scanner.HTTPTimeoutSec <= 0 {
			cfg.Scanner.HTTPTimeoutSec = 15
		}
		if cfg.Scanner.MaxParamsPerURL <= 0 {
			cfg.Scanner.MaxParamsPerURL = 20
		}
		if cfg.Scanner.ParamBatchSize <= 0 {
			cfg.Scanner.ParamBatchSize = 45
		}
		if cfg.Scanner.SamplePerGroup < 0 {
			cfg.Scanner.SamplePerGroup = 0
		}
		if cfg.Scanner.ShapeThreshold <= 0 {
			cfg.Scanner.ShapeThreshold = 10
		}
		if cfg.Target.MaxPerPattern <= 0 {
			cfg.Target.MaxPerPattern = 4
		}
	}
	if cfg.Scanner.TargetWorkers < 0 {
		cfg.Scanner.TargetWorkers = 0
	}
	if cfg.Scanner.QuickWorkers < 0 {
		cfg.Scanner.QuickWorkers = 0
	}
	if cfg.Scanner.VerifyWorkers < 0 {
		cfg.Scanner.VerifyWorkers = 0
	}
	if strings.TrimSpace(cfg.Collector.CrawlergoBin) == "" {
		cfg.Collector.CrawlergoBin = "crawlergo"
	}
	if strings.TrimSpace(cfg.Target.ParamStrategy) == "" {
		cfg.Target.ParamStrategy = "batch"
	}
	if len(cfg.Target.HighValueGlobalParams) == 0 {
		cfg.Target.HighValueGlobalParams = []string{"q", "query", "search", "keyword", "url", "redirect", "return", "next", "callback"}
	}
	if cfg.Notify.MaxPerSite <= 0 {
		cfg.Notify.MaxPerSite = 10
	}
	if cfg.Notify.QueueSize <= 0 {
		cfg.Notify.QueueSize = 200
	}
	if cfg.Notify.TimeoutSec <= 0 {
		cfg.Notify.TimeoutSec = 8
	}
	if strings.TrimSpace(cfg.Notify.Provider) == "" {
		cfg.Notify.Provider = "dingtalk"
	}
}
