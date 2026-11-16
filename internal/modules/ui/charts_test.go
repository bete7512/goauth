package ui

import (
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/stretchr/testify/suite"
)

type ChartSuite struct {
	suite.Suite
}

func TestChartSuite(t *testing.T) {
	suite.Run(t, new(ChartSuite))
}

func (s *ChartSuite) TestDayChartFillsMissingDaysAndScales() {
	now := time.Date(2026, 11, 16, 15, 0, 0, 0, time.UTC)
	c := dayChart("x", "X", "", []models.DailyCount{{Day: "2026-11-16", Count: 10}, {Day: "2026-11-01", Count: 5}, {Day: "2026-01-01", Count: 99}}, now)
	s.Len(c.Bars, chartDays)
	s.Equal(int64(15), c.Total, "days outside the window are ignored")
	s.Equal(int64(10), c.Max)
	last := c.Bars[chartDays-1]
	s.Equal("16 Nov", last.Day)
	s.InDelta(132, last.H, 0.01, "the largest day fills the plot")
	s.InDelta(66, c.Bars[chartDays-16].H, 0.01)
	s.Equal(int64(0), c.Bars[0].Value)
	s.Len(c.Ticks, 5)
	s.Equal("16 Nov", c.Ticks[len(c.Ticks)-1].Label)
}

func (s *ChartSuite) TestEmptyChart() {
	c := dayChart("x", "X", "", nil, time.Now())
	s.Equal(int64(0), c.Max)
	for _, bar := range c.Bars {
		s.Zero(bar.H)
	}
}
