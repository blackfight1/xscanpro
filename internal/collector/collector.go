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

	"golang.org/x/net/publicsuffix"

	"xscanpro/internal/model"
	"xscanpro/internal/util"
)

const (
	waymoreOut        = "tmp_waymore_urls.txt"
	waymoreRootsIn    = "tmp_waymore_roots.txt"
	katanaInputFile   = "tmp_katana_input_urls.txt"
	katanaOut         = "tmp_katana_urls.txt"
	katanaHeadlessOut = "tmp_katana_headless_urls.txt"
)

var jsRe = regexp.MustCompile(`(?i)\.m?js(?:\?|$)`)

var staticExclude = []string{
	"png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico",
	"css", "woff", "woff2", "ttf", "eot", "otf",
	"mp4", "mp3", "wav", "avi", "mov", "webm",
	"pdf", "zip", "rar", "7z", "tar", "gz",
	"map", "webmanifest", "swf", "apk", "exe", "bin", "dmg", "iso",
	"doc", "docx", "xls", "xlsx", "ppt", "pptx",
}

var staticExtSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(staticExclude))
	for _, ext := range staticExclude {
		m["."+strings.ToLower(ext)] = struct{}{}
	}
	return m
}()

type Options struct {
	UseWaymore                bool
	UseKatana                 bool
	UseKatanaHeadless         bool
	KatanaHeadlessNoSandbox   bool
	KatanaConcurrency         int
	KatanaDepth               int
	KatanaHeadlessConcurrency int
	KatanaHeadlessDepth       int
}

func Collect(outDir string, inputURLs []string, opt Options) (model.CrawlResult, error) {
	var out model.CrawlResult
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return out, err
	}
	if len(inputURLs) == 0 {
		return out, fmt.Errorf("empty collector input URLs")
	}
	if !opt.UseWaymore && !opt.UseKatana && !opt.UseKatanaHeadless {
		return out, fmt.Errorf("waymore and katana rounds are all disabled")
	}

	if opt.UseWaymore {
		if _, err := exec.LookPath("waymore"); err != nil {
			return out, fmt.Errorf("waymore not found: %w", err)
		}
	}
	if opt.UseKatana || opt.UseKatanaHeadless {
		if _, err := exec.LookPath("katana"); err != nil {
			return out, fmt.Errorf("katana not found: %w", err)
		}
	}
	allowedHosts := map[string]struct{}{}
	allowedRoots := map[string]struct{}{}
	katanaInputs := make([]string, 0, len(inputURLs))
	for _, line := range inputURLs {
		canon, host := normalizeInputURL(line)
		if canon == "" || host == "" {
			continue
		}
		katanaInputs = append(katanaInputs, canon)
		allowedHosts[host] = struct{}{}
		if rd := registrableDomain(host); rd != "" {
			allowedRoots[rd] = struct{}{}
		}
	}
	katanaInputs = util.UniqueStrings(katanaInputs)
	sort.Strings(katanaInputs)
	if len(katanaInputs) == 0 {
		return out, fmt.Errorf("collector input has no valid URLs")
	}
	if len(allowedHosts) == 0 {
		return out, fmt.Errorf("collector input has no valid hosts")
	}
	if opt.UseWaymore && len(allowedRoots) == 0 {
		return out, fmt.Errorf("collector input has no valid root domains for waymore")
	}

	waymoreTmpPath := filepath.Join(outDir, waymoreOut)
	waymoreRootsPath := filepath.Join(outDir, waymoreRootsIn)
	katanaInputPath := filepath.Join(outDir, katanaInputFile)
	defer safeRemove(waymoreTmpPath)
	defer safeRemove(waymoreRootsPath)
	defer safeRemove(katanaInputPath)
	if err := util.WriteLines(katanaInputPath, katanaInputs); err != nil {
		return out, fmt.Errorf("write katana input file: %w", err)
	}
	if opt.UseWaymore {
		roots := make([]string, 0, len(allowedRoots))
		for rd := range allowedRoots {
			roots = append(roots, rd)
		}
		sort.Strings(roots)
		if err := util.WriteLines(waymoreRootsPath, roots); err != nil {
			return out, fmt.Errorf("write waymore roots file: %w", err)
		}
	}

	if opt.KatanaDepth <= 0 {
		opt.KatanaDepth = 4
	}
	if opt.KatanaConcurrency <= 0 {
		opt.KatanaConcurrency = 16
	}
	if opt.KatanaHeadlessDepth <= 0 {
		opt.KatanaHeadlessDepth = opt.KatanaDepth
	}
	if opt.KatanaHeadlessConcurrency <= 0 {
		opt.KatanaHeadlessConcurrency = 8
	}

	ctx := context.Background()
	katOut := filepath.Join(outDir, katanaOut)
	katHeadlessOut := filepath.Join(outDir, katanaHeadlessOut)
	defer safeRemove(katOut)
	defer safeRemove(katHeadlessOut)
	files := make([]string, 0, 3)
	if opt.UseWaymore || opt.UseKatana {
		var wg sync.WaitGroup
		errCh := make(chan error, 2)

		if opt.UseWaymore {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := run(ctx, outDir, "waymore",
					"-i", filepath.Base(waymoreRootsPath),
					"-mode", "U",
					"-nlf",
					"-fc", "404",
					"-oU", waymoreOut,
				); err != nil {
					errCh <- fmt.Errorf("waymore failed: %w", err)
				}
			}()
		}
		if opt.UseKatana {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runKatana(ctx, outDir, katanaInputPath, katOut, opt.KatanaDepth, opt.KatanaConcurrency, false, false); err != nil {
					errCh <- fmt.Errorf("katana failed: %w", err)
				}
			}()
		}

		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				return out, err
			}
		}
	}
	if opt.UseWaymore {
		files = append(files, waymoreTmpPath)
	}
	if opt.UseKatana {
		files = append(files, katOut)
	}
	if opt.UseKatanaHeadless {
		if err := runKatana(ctx, outDir, katanaInputPath, katHeadlessOut, opt.KatanaHeadlessDepth, opt.KatanaHeadlessConcurrency, true, opt.KatanaHeadlessNoSandbox); err != nil {
			if isProcessKilledError(err) {
				fmt.Printf("[collector] katana headless was killed, skip headless round and continue\n")
			} else {
				return out, fmt.Errorf("katana headless failed: %w", err)
			}
		} else {
			files = append(files, katHeadlessOut)
		}
	}

	urls, err := mergeURLFiles(files...)
	if err != nil {
		return out, err
	}
	urls = filterScopeURLs(urls, allowedHosts, allowedRoots)
	js := extractJS(urls)

	out.URLs = urls
	out.JSURLs = js
	return out, nil
}

func safeRemove(path string) {
	_ = os.Remove(path)
}

func runKatana(ctx context.Context, outDir, inputFile, outFile string, depth, concurrency int, headless, noSandbox bool) error {
	absInput, _ := filepath.Abs(inputFile)
	args := []string{
		"-list", absInput,
		"-fs", "rdn",
		"-jc",
		"-kf", "all",
		"-d", fmt.Sprintf("%d", depth),
		"-c", fmt.Sprintf("%d", concurrency),
		"-ef", strings.Join(staticExclude, ","),
		"-o", filepath.Base(outFile),
	}
	if headless {
		args = append(args, "-hl")
		if noSandbox {
			args = append(args, "-no-sandbox")
		}
	}
	return run(ctx, outDir, "katana", args...)
}

func parseInputHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	if !strings.Contains(s, "://") {
		u2, err2 := url.Parse("http://" + s)
		if err2 == nil && u2.Hostname() != "" {
			return strings.ToLower(u2.Hostname())
		}
	}
	return ""
}

func filterScopeURLs(urls []string, allowedHosts, allowedRoots map[string]struct{}) []string {
	if len(allowedHosts) == 0 && len(allowedRoots) == 0 {
		return urls
	}
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
		if hostInAllowed(host, allowedHosts) || hostInAllowedRoots(host, allowedRoots) {
			out = append(out, raw)
		}
	}
	return out
}

func normalizeInputURL(raw string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "http" && scheme != "https" {
		return "", ""
	}
	canon, err := util.CanonicalURL(u.String())
	if err != nil {
		return "", ""
	}
	return canon, strings.ToLower(strings.TrimSpace(u.Hostname()))
}

func hostInAllowed(host string, allowedHosts map[string]struct{}) bool {
	if len(allowedHosts) == 0 {
		return false
	}
	if _, ok := allowedHosts[host]; ok {
		return true
	}
	for ah := range allowedHosts {
		if strings.HasSuffix(host, "."+ah) {
			return true
		}
	}
	return false
}

func hostInAllowedRoots(host string, allowedRoots map[string]struct{}) bool {
	if len(allowedRoots) == 0 {
		return false
	}
	rd := registrableDomain(host)
	if rd == "" {
		return false
	}
	_, ok := allowedRoots[rd]
	return ok
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

func run(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	return cmd.Run()
}

func isProcessKilledError(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code == 137 || code == 9 {
			return true
		}
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "signal: killed") {
		return true
	}
	if strings.Contains(s, "killed") && strings.Contains(s, "signal") {
		return true
	}
	if strings.Contains(s, "exit status 137") {
		return true
	}
	return false
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
