package util

import (
	"fmt"
	"strings"
	"time"
)

func RenderProgressLine(prefix string, done, total int64, width int, startedAt time.Time, extra string) string {
	if width <= 0 {
		width = 24
	}
	if total < 0 {
		total = 0
	}
	if done < 0 {
		done = 0
	}
	if total > 0 && done > total {
		done = total
	}

	bar := renderBar(done, total, width)
	pct := int64(0)
	if total > 0 {
		pct = done * 100 / total
	}

	elapsed := time.Since(startedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	rate := 0.0
	if elapsed > 0 && done > 0 {
		rate = float64(done) / elapsed.Seconds()
	}

	etaText := "--"
	if total > 0 && done < total && rate > 0 {
		etaSec := float64(total-done) / rate
		etaText = formatDuration(time.Duration(etaSec * float64(time.Second)))
	}

	rateText := "--/s"
	if rate > 0 {
		rateText = fmt.Sprintf("%.1f/s", rate)
	}

	line := fmt.Sprintf("%s [%s] %3d%% %d/%d | %s | ETA %s", prefix, bar, pct, done, total, rateText, etaText)
	if strings.TrimSpace(extra) != "" {
		line += " | " + extra
	}
	return line
}

func renderBar(done, total int64, width int) string {
	if width <= 0 {
		width = 24
	}
	if total <= 0 {
		return strings.Repeat("-", width)
	}
	fill := int(done * int64(width) / total)
	if fill < 0 {
		fill = 0
	}
	if fill > width {
		fill = width
	}
	return strings.Repeat("=", fill) + strings.Repeat("-", width-fill)
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%02dm", h, m)
}
