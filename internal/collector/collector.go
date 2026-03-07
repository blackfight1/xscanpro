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
	"sync"
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
	katanaTmpPath := filepath.Join(outDir, katanaOut)
	crawlergoTmpPath := filepath.Join(outDir, crawlergoOut)
	defer safeRemove(waymoreTmpPath)
	defer safeRemove(katanaTmpPath)
	defer safeRemove(crawlergoTmpPath)

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
	if opt.UseKatana || opt.UseCrawlergo {
		if _, err := os.Stat(subsFile); err != nil {
			return out, fmt.Errorf("invalid -i file: %w", err)
		}
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	var wayErr, katErr error

	if opt.UseWaymore {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wayErr = run(ctx, outDir, "waymore",
				"-i", root,
				"-mode", "U",
				"-nlf",
				"-fc", "404",
				"-oU", waymoreOut,
			)
		}()
	}

	if opt.UseKatana {
		wg.Add(1)
		go func() {
			defer wg.Done()
			absSubs, _ := filepath.Abs(subsFile)
			katErr = run(ctx, outDir, "katana",
				"-list", absSubs,
				"-jc",
				"-kf", "all",
				"-d", fmt.Sprintf("%d", opt.KatanaDepth),
				"-c", fmt.Sprintf("%d", opt.KatanaConcurrency),
				"-ef", strings.Join(staticExclude, ","),
				"-o", katanaOut,
			)
		}()
	}

	wg.Wait()
	if opt.UseWaymore && wayErr != nil {
		return out, fmt.Errorf("waymore failed: %w", wayErr)
	}
	if opt.UseKatana && katErr != nil {
		return out, fmt.Errorf("katana failed: %w", katErr)
	}
	if opt.UseCrawlergo {
		absSubs, _ := filepath.Abs(subsFile)
		ctxCrawlergo, cancel := context.WithTimeout(context.Background(), time.Duration(opt.CrawlergoTimeout)*time.Second)
		defer cancel()

		args := []string{
			"-i", absSubs,
			"-o", "txt",
			"--output-txt", crawlergoOut,
			"-c", opt.CrawlergoChrome,
			"-t", fmt.Sprintf("%d", opt.CrawlergoTabs),
		}
		if opt.CrawlergoRobots {
			args = append(args, "--robots-path")
		}

		if err := run(ctxCrawlergo, outDir, opt.CrawlergoBin, args...); err != nil {
			if errors.Is(ctxCrawlergo.Err(), context.DeadlineExceeded) {
				return out, fmt.Errorf("crawlergo timed out after %ds", opt.CrawlergoTimeout)
			}
			return out, fmt.Errorf("crawlergo failed: %w", err)
		}
	}

	var files []string
	if opt.UseWaymore {
		files = append(files, waymoreTmpPath)
	}
	if opt.UseKatana {
		files = append(files, katanaTmpPath)
	}
	if opt.UseCrawlergo {
		files = append(files, crawlergoTmpPath)
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
