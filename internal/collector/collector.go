package collector

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"xscanpro/internal/model"
	"xscanpro/internal/util"
)

const (
	waymoreOut   = "tmp_waymore_urls.txt"
	katanaOut    = "tmp_katana_urls.txt"
	crawlergoOut = "tmp_crawlergo_urls.txt"
)

var jsRe = regexp.MustCompile(`(?i)\.m?js(?:\?|$)`)

var staticExclude = []string{
	"png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico",
	"css", "woff", "woff2", "ttf", "eot", "otf",
	"mp4", "mp3", "wav", "avi", "mov", "webm",
	"pdf", "zip", "rar", "7z", "tar", "gz",
}

var staticExtSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(staticExclude))
	for _, ext := range staticExclude {
		m["."+strings.ToLower(ext)] = struct{}{}
	}
	return m
}()

type Options struct {
	UseWaymore        bool
	UseKatana         bool
	UseCrawlergo      bool
	InputBatchEnabled bool
	InputBatchSize    int
	KatanaConcurrency int
	KatanaDepth       int
	CrawlergoBin      string
	CrawlergoChrome   string
	CrawlergoTabs     int
	CrawlergoRobots   bool
	CrawlergoTimeout  int
}

func Collect(outDir, domain, subsFile string, opt Options) (model.CrawlResult, error) {
	var out model.CrawlResult
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return out, err
	}
	root := normalizeRootDomain(domain)
	if opt.UseWaymore && root == "" {
		return out, fmt.Errorf("invalid -domain: %s", domain)
	}
	if !opt.UseWaymore && !opt.UseKatana && !opt.UseCrawlergo {
		return out, fmt.Errorf("waymore, katana and crawlergo are all disabled")
	}

	waymoreTmpPath := filepath.Join(outDir, waymoreOut)
	defer safeRemove(waymoreTmpPath)

	if opt.UseWaymore {
		if _, err := exec.LookPath("waymore"); err != nil {
			return out, fmt.Errorf("waymore not found: %w", err)
		}
	}
	if opt.UseKatana {
		if _, err := exec.LookPath("katana"); err != nil {
			return out, fmt.Errorf("katana not found: %w", err)
		}
	}
	if opt.UseCrawlergo {
		if strings.TrimSpace(opt.CrawlergoBin) == "" {
			opt.CrawlergoBin = "crawlergo"
		}
		if _, err := exec.LookPath(opt.CrawlergoBin); err != nil {
			return out, fmt.Errorf("crawlergo not found (%s): %w", opt.CrawlergoBin, err)
		}
		if strings.TrimSpace(opt.CrawlergoChrome) == "" {
			return out, fmt.Errorf("crawlergo chrome path is empty")
		}
		if opt.CrawlergoTabs <= 0 {
			opt.CrawlergoTabs = 10
		}
		if opt.CrawlergoTimeout <= 0 {
			opt.CrawlergoTimeout = 1200
		}
	}
	if opt.InputBatchSize <= 0 {
		opt.InputBatchSize = 200
	}

	var batchSubs [][]string
	if opt.UseKatana || opt.UseCrawlergo {
		if _, err := os.Stat(subsFile); err != nil {
			return out, fmt.Errorf("invalid -i file: %w", err)
		}
		lines, err := util.ReadLines(subsFile)
		if err != nil {
			return out, fmt.Errorf("read -i file: %w", err)
		}
		if len(lines) == 0 {
			return out, fmt.Errorf("-i file is empty")
		}
		lines = util.UniqueStrings(lines)
		sort.Strings(lines)
		if opt.InputBatchEnabled && len(lines) > opt.InputBatchSize {
			batchSubs = chunkLines(lines, opt.InputBatchSize)
		} else {
			batchSubs = [][]string{lines}
		}
	}

	ctx := context.Background()
	if opt.UseWaymore {
		if err := run(ctx, outDir, "waymore",
			"-i", root,
			"-mode", "U",
			"-nlf",
			"-fc", "404",
			"-oU", waymoreOut,
		); err != nil {
			return out, fmt.Errorf("waymore failed: %w", err)
		}
	}

	files := make([]string, 0, 1+len(batchSubs)*2)
	if opt.UseWaymore {
		files = append(files, waymoreTmpPath)
	}
	for i, lines := range batchSubs {
		idx := i + 1
		subsPath := filepath.Join(outDir, fmt.Sprintf("tmp_subs_batch_%03d.txt", idx))
		if err := util.WriteLines(subsPath, lines); err != nil {
			return out, fmt.Errorf("write subs batch %d: %w", idx, err)
		}
		defer safeRemove(subsPath)

		if opt.UseKatana {
			katOut := filepath.Join(outDir, fmt.Sprintf("tmp_katana_urls_%03d.txt", idx))
			defer safeRemove(katOut)
			absSubs, _ := filepath.Abs(subsPath)
			if err := run(ctx, outDir, "katana",
				"-list", absSubs,
				"-jc",
				"-kf", "all",
				"-d", fmt.Sprintf("%d", opt.KatanaDepth),
				"-c", fmt.Sprintf("%d", opt.KatanaConcurrency),
				"-ef", strings.Join(staticExclude, ","),
				"-o", filepath.Base(katOut),
			); err != nil {
				return out, fmt.Errorf("katana failed (batch %d/%d): %w", idx, len(batchSubs), err)
			}
			files = append(files, katOut)
		}

		if opt.UseCrawlergo {
			cgOut := filepath.Join(outDir, fmt.Sprintf("tmp_crawlergo_urls_%03d.txt", idx))
			defer safeRemove(cgOut)
			absSubs, _ := filepath.Abs(subsPath)
			ctxCrawlergo, cancel := context.WithTimeout(context.Background(), time.Duration(opt.CrawlergoTimeout)*time.Second)
			args := []string{
				"-i", absSubs,
				"-o", "txt",
				"--output-txt", filepath.Base(cgOut),
				"-c", opt.CrawlergoChrome,
				"-t", fmt.Sprintf("%d", opt.CrawlergoTabs),
			}
			if opt.CrawlergoRobots {
				args = append(args, "--robots-path")
			}
			if err := run(ctxCrawlergo, outDir, opt.CrawlergoBin, args...); err != nil {
				cancel()
				if errors.Is(ctxCrawlergo.Err(), context.DeadlineExceeded) {
					return out, fmt.Errorf("crawlergo timed out after %ds (batch %d/%d)", opt.CrawlergoTimeout, idx, len(batchSubs))
				}
				return out, fmt.Errorf("crawlergo failed (batch %d/%d): %w", idx, len(batchSubs), err)
			}
			cancel()
			files = append(files, cgOut)
		}
	}

	urls, err := mergeURLFiles(files...)
	if err != nil {
		return out, err
	}
	js := extractJS(urls)

	out.URLs = urls
	out.JSURLs = js
	return out, nil
}

func chunkLines(lines []string, size int) [][]string {
	if len(lines) == 0 {
		return nil
	}
	if size <= 0 {
		size = len(lines)
	}
	out := make([][]string, 0, (len(lines)+size-1)/size)
	for i := 0; i < len(lines); i += size {
		end := i + size
		if end > len(lines) {
			end = len(lines)
		}
		out = append(out, lines[i:end])
	}
	return out
}
func safeRemove(path string) {
	_ = os.Remove(path)
}

func run(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	return cmd.Run()
}

func mergeURLFiles(files ...string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range files {
		lines, err := util.ReadLines(f)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			canon, err := util.CanonicalURL(line)
			if err != nil {
				continue
			}
			if shouldSkipStatic(canon) {
				continue
			}
			if _, ok := seen[canon]; ok {
				continue
			}
			seen[canon] = struct{}{}
			out = append(out, canon)
		}
	}
	sort.Strings(out)
	return out, nil
}

func shouldSkipStatic(raw string) bool {
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

func extractJS(urls []string) []string {
	var out []string
	for _, u := range urls {
		if jsRe.MatchString(u) {
			out = append(out, u)
		}
	}
	out = util.UniqueStrings(out)
	sort.Strings(out)
	return out
}

func normalizeRootDomain(input string) string {
	s := strings.TrimSpace(strings.ToLower(input))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "//")
	if strings.Contains(s, "/") {
		s = strings.SplitN(s, "/", 2)[0]
	}
	if strings.Contains(s, ":") {
		s = strings.SplitN(s, ":", 2)[0]
	}
	return s
}
