package ui

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

// chartDays is how far back the overview's charts go.
const chartDays = 30

// chart is one bar chart of a count per day, drawn on the server as SVG so
// that it needs no script and no inline style.
type chart struct {
	ID, Title, Note string
	Total           int64
	Max             int64
	Bars            []chartBar
	Ticks           []chartTick
	// Width and Height are the SVG viewBox; bars are laid out inside it.
	Width, Height int
}

type chartBar struct {
	X, Y, W, H float64
	Day        string // "2 Nov"
	Value      int64
}

type chartTick struct {
	X     float64
	Label string
}

// dayChart lays out a bar per day from oldest to newest, with zeros for the
// days rows does not mention.
func dayChart(id, title, note string, rows []models.DailyCount, now time.Time) *chart {
	counts := map[string]int64{}
	for _, row := range rows {
		counts[row.Day] = row.Count
	}
	c := &chart{ID: id, Title: title, Note: note, Width: 600, Height: 172}
	const top, bottom = 8.0, 32.0
	plot := float64(c.Height) - top - bottom
	slot := float64(c.Width) / chartDays
	start := now.UTC().AddDate(0, 0, -(chartDays - 1))
	values := make([]int64, chartDays)
	for i := range values {
		values[i] = counts[start.AddDate(0, 0, i).Format("2006-01-02")]
		c.Total += values[i]
		c.Max = max(c.Max, values[i])
	}
	for i, value := range values {
		day := start.AddDate(0, 0, i)
		h := 0.0
		if c.Max > 0 {
			h = plot * float64(value) / float64(c.Max)
		}
		if value > 0 && h < 2 {
			h = 2 // a non-zero day stays visible
		}
		bar := chartBar{X: float64(i)*slot + 2, W: slot - 4, H: h, Y: top + plot - h, Day: day.Format("2 Jan"), Value: value}
		c.Bars = append(c.Bars, bar)
		// A date every week, counted back from today so the last bar has one.
		if (chartDays-1-i)%7 == 0 {
			c.Ticks = append(c.Ticks, chartTick{X: bar.X + bar.W/2, Label: bar.Day})
		}
	}
	return c
}

// overviewCharts builds the charts the stores can count for. A store that
// cannot count per day, or a failed query, leaves its chart out.
func (m *UIModule) overviewCharts(r *http.Request) []*chart {
	ctx := r.Context()
	now := timeNow()
	since := now.UTC().AddDate(0, 0, -(chartDays - 1)).Truncate(24 * time.Hour)
	var charts []*chart
	if counter, ok := m.deps.Storage.Core().Users().(models.UserSignupCounter); ok {
		if rows, err := counter.CountCreatedPerDay(ctx, since); err == nil {
			charts = append(charts, dayChart("signups", "Sign-ups", "New accounts per day", rows, now))
		} else {
			m.deps.Logger.Warn("ui: sign-up chart unavailable", "error", err)
		}
	}
	if m.auditService() != nil && m.deps.Storage.AuditLog() != nil {
		if counter, ok := m.deps.Storage.AuditLog().AuditLogs().(models.AuditActionCounter); ok {
			for _, series := range []struct{ id, action, title, note string }{
				{"signins", "auth.login.success", "Sign-ins", "Successful sign-ins per day"},
				{"failed", "auth.login.failed", "Failed sign-ins", "Wrong passwords and refused sign-ins per day"},
			} {
				rows, err := countAction(ctx, counter, series.action, since)
				if err != nil {
					m.deps.Logger.Warn("ui: activity chart unavailable", "action", series.action, "error", err)
					continue
				}
				charts = append(charts, dayChart(series.id, series.title, series.note, rows, now))
			}
		}
	}
	return charts
}

func countAction(ctx context.Context, counter models.AuditActionCounter, action string, since time.Time) ([]models.DailyCount, error) {
	rows, err := counter.CountActionPerDay(ctx, action, since)
	if err != nil {
		return nil, fmt.Errorf("count %s: %w", action, err)
	}
	return rows, nil
}
