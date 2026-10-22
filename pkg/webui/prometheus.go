package webui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// metricSample is one line of the Prometheus text exposition format.
type metricSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

type metricsSnapshot struct {
	FetchedAt time.Time
	Samples   []metricSample
}

func (m *metricsSnapshot) sum(name string) float64 {
	total := 0.0

	for _, sample := range m.Samples {
		if sample.Name == name {
			total += sample.Value
		}
	}

	return total
}

func (m *metricsSnapshot) value(name string) (float64, bool) {
	for _, sample := range m.Samples {
		if sample.Name == name {
			return sample.Value, true
		}
	}

	return 0, false
}

func (m *metricsSnapshot) groupSum(name, label string) map[string]float64 {
	counts := map[string]float64{}

	for _, sample := range m.Samples {
		if sample.Name != name {
			continue
		}

		if value, ok := sample.Labels[label]; ok && value != "" {
			counts[value] += sample.Value
		}
	}

	return counts
}

// histogramAverage returns sum/count for a histogram, in the unit of the metric.
func (m *metricsSnapshot) histogramAverage(name string) (float64, bool) {
	sum, okSum := m.value(name + "_sum")
	count, okCount := m.value(name + "_count")

	if !okSum || !okCount || count == 0 {
		return 0, false
	}

	return sum / count, true
}

func (m *metricsSnapshot) labelValues(name, label string) []string {
	values := []string{}
	seen := map[string]bool{}

	for _, sample := range m.Samples {
		if sample.Name != name {
			continue
		}

		value := sample.Labels[label]
		if value != "" && !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}

	sort.Strings(values)

	return values
}

func scrapeMetrics(ctx context.Context, url string) (*metricsSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building metrics request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scraping metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics endpoint returned %s", resp.Status)
	}

	samples, err := parseMetrics(resp.Body)
	if err != nil {
		return nil, err
	}

	return &metricsSnapshot{FetchedAt: time.Now(), Samples: samples}, nil
}

func parseMetrics(r io.Reader) ([]metricSample, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 8<<20)

	samples := make([]metricSample, 0, 256)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		sample, err := parseMetricLine(line)
		if err != nil {
			continue
		}

		samples = append(samples, sample)
	}

	return samples, scanner.Err()
}

func parseMetricLine(line string) (metricSample, error) {
	var (
		name   string
		labels = map[string]string{}
		rest   string
	)

	if open := strings.IndexByte(line, '{'); open >= 0 {
		name = line[:open]

		closeIdx := strings.LastIndexByte(line, '}')
		if closeIdx < open {
			return metricSample{}, fmt.Errorf("malformed metric line")
		}

		labels = parseMetricLabels(line[open+1 : closeIdx])
		rest = strings.TrimSpace(line[closeIdx+1:])
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return metricSample{}, fmt.Errorf("malformed metric line")
		}

		name = fields[0]
		rest = fields[1]
	}

	valueField := strings.Fields(rest)
	if len(valueField) == 0 {
		return metricSample{}, fmt.Errorf("missing value")
	}

	value, err := strconv.ParseFloat(valueField[0], 64)
	if err != nil {
		return metricSample{}, fmt.Errorf("invalid value: %w", err)
	}

	return metricSample{Name: name, Labels: labels, Value: value}, nil
}

func parseMetricLabels(raw string) map[string]string {
	labels := map[string]string{}

	i := 0

	for i < len(raw) {
		for i < len(raw) && (raw[i] == ' ' || raw[i] == ',') {
			i++
		}

		start := i
		for i < len(raw) && raw[i] != '=' {
			i++
		}

		if i >= len(raw) {
			break
		}

		key := strings.TrimSpace(raw[start:i])
		i++ // skip '='

		if i >= len(raw) || raw[i] != '"' {
			break
		}

		i++

		var value strings.Builder

		for i < len(raw) {
			ch := raw[i]
			if ch == '\\' && i+1 < len(raw) {
				value.WriteByte(raw[i+1])
				i += 2
				continue
			}

			if ch == '"' {
				i++
				break
			}

			value.WriteByte(ch)
			i++
		}

		labels[key] = value.String()
	}

	return labels
}
