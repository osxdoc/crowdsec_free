package webui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const sampleExposition = `# HELP cs_parser_hits_total Total events entered the parser.
# TYPE cs_parser_hits_total counter
cs_parser_hits_total{source="/var/log/auth.log",type="syslog"} 7
cs_parser_hits_total{source="/var/log/nginx.log",type="nginx"} 3
cs_parser_hits_ok_total{source="/var/log/auth.log",type="syslog",acquis_type="file"} 6
cs_parser_hits_ko_total{source="/var/log/auth.log",type="syslog",acquis_type="file"} 1
cs_node_hits_total{name="crowdsecurity/sshd-logs",source="x",type="syslog",stage="s01"} 9
cs_node_hits_total{name="crowdsecurity/syslog-logs",source="x",type="syslog",stage="s00"} 11
cs_buckets{name="crowdsecurity/ssh-bf"} 2
cs_bucket_overflowed_total{name="crowdsecurity/ssh-bf"} 1
cs_parsing_time_seconds_sum 0.5
cs_parsing_time_seconds_count 10
cs_features{feature="lapi"} 1
cs_features{feature="capi"} 0
cs_capi_last_pull_timestamp 1.7e+09
cs_lapi_route_requests_total{route="/v1/alerts",method="GET"} 4
cs_lapi_route_requests_total{route="/v1/alerts",method="POST"} 2
`

func TestParseMetrics(t *testing.T) {
	samples, err := parseMetrics(strings.NewReader(sampleExposition))
	require.NoError(t, err)
	require.Len(t, samples, 15)

	snapshot := &metricsSnapshot{Samples: samples}

	require.Equal(t, 10.0, snapshot.sum("cs_parser_hits_total"))
	require.Equal(t, 6.0, snapshot.sum("cs_parser_hits_ok_total"))
	require.Equal(t, 1.0, snapshot.sum("cs_parser_hits_ko_total"))

	sources := snapshot.groupSum("cs_parser_hits_total", "source")
	require.Equal(t, 7.0, sources["/var/log/auth.log"])
	require.Equal(t, 3.0, sources["/var/log/nginx.log"])

	average, ok := snapshot.histogramAverage("cs_parsing_time_seconds")
	require.True(t, ok)
	require.InDelta(t, 0.05, average, 1e-9)

	value, ok := snapshot.value("cs_capi_last_pull_timestamp")
	require.True(t, ok)
	require.Equal(t, 1.7e9, value)

	require.Equal(t, []string{"capi", "lapi"}, snapshot.labelValues("cs_features", "feature"))
}

func TestBuildMetricsSummary(t *testing.T) {
	samples, err := parseMetrics(strings.NewReader(sampleExposition))
	require.NoError(t, err)

	summary := buildMetricsSummary(&metricsSnapshot{Samples: samples})
	require.NotNil(t, summary)
	require.True(t, summary.Available)

	require.Equal(t, 10.0, summary.ParserHits)
	require.Equal(t, 6.0, summary.ParserOK)
	require.Equal(t, 1.0, summary.ParserKO)
	require.Equal(t, 2.0, summary.BucketsCurrent)
	require.Equal(t, 1.0, summary.BucketOverflows)

	// The KO rate is computed in the UI; only the raw counters matter here.
	require.NotNil(t, summary.AvgParseMS)
	require.InDelta(t, 50, *summary.AvgParseMS, 1e-6)

	require.NotNil(t, summary.CapiLastPull)
	require.Equal(t, []string{"lapi"}, summary.Features)

	require.Equal(t, "crowdsecurity/syslog-logs", summary.TopNodes[0].Name)
	require.Equal(t, 11, summary.TopNodes[0].Count)
	require.Equal(t, "/v1/alerts", summary.TopRoutes[0].Name)
	require.Equal(t, 6, summary.TopRoutes[0].Count)
}

func TestParseMetricLabelsEscapes(t *testing.T) {
	labels := parseMetricLabels(`source="a \"quoted\" value",type="syslog",empty=""`)
	require.Equal(t, `a "quoted" value`, labels["source"])
	require.Equal(t, "syslog", labels["type"])
	require.Equal(t, "", labels["empty"])
}

func TestParseMetricLineWithoutLabels(t *testing.T) {
	sample, err := parseMetricLine("cs_info 1")
	require.NoError(t, err)
	require.Equal(t, "cs_info", sample.Name)
	require.Equal(t, 1.0, sample.Value)
	require.Empty(t, sample.Labels)
}

func TestParseMetricsSkipsGarbage(t *testing.T) {
	samples, err := parseMetrics(strings.NewReader("not a metric line\n\n# comment\ncs_ok_total 2\n"))
	require.NoError(t, err)
	require.Len(t, samples, 1)
	require.Equal(t, "cs_ok_total", samples[0].Name)
}

func TestBuildMetricsSummaryEmpty(t *testing.T) {
	require.Nil(t, buildMetricsSummary(nil))

	summary := buildMetricsSummary(&metricsSnapshot{})
	require.True(t, summary.Available)
	require.Equal(t, 0.0, summary.ParserHits)
	require.Nil(t, summary.CapiLastPull)
	require.Nil(t, summary.AvgParseMS)
	require.Empty(t, summary.Features)
}
