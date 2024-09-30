package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// See dns.go for DNS-specific metrics.

var (
	metricMessageMeta = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_message_meta_total",
			Help: "Number of non-update email messages.",
		},
	)
	metricMessageUpdates = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_message_updates_total",
			Help: "Number of update email messages.",
		},
	)
	metricMessageSubmitErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_message_submit_errors_total",
			Help: "Number of messages that failed to submit.",
		},
	)
	metricIMAPConnections = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_imap_connections_total",
			Help: "Number of IMAP connections created.",
		},
	)
	metricWebAPIResults = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gopherwatch_webapi_results_total",
			Help: "WebAPI requests and results.",
		},
		[]string{
			"method", // Name of method, e.g. Send.
			"result", // "ok", "error" or specific error code.
		},
	)
	metricIncomingProcessErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_process_errors_total",
			Help: "Number of errors while processing incoming messages over IMAP/webhooks.",
		},
	)
	metricIncomingIgnored = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_ignored_total",
			Help: "Number of received ignored messages (not DSN/signup).",
		},
	)
	metricIncomingDSN = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_dsn_total",
			Help: "Number of successfully handled DSN messages.",
		},
	)
	metricIncomingProblem = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_problem_total",
			Help: "Number of incoming messages (DSN/signup) that could not be processed.",
		},
	)
	metricIncomingSignup = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_signup_total",
			Help: "Number of successfully handled signup messages.",
		},
	)
	metricWebhookIncoming = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_webhook_incoming_total",
			Help: "Number of webhook calls about incoming deliveries.",
		},
	)
	metricWebhookOutgoing = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gopherwatch_webhook_outgoing_total",
			Help: "Number of webhook calls for outgoing deliveries, per event type.",
		},
		[]string{"event"},
	)
	metricSumdbRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gopherwatch_sumdb_requests_total",
			Help: "Number of requests HTTPS requests to sumdb.",
		},
	)
	metricTlogRecords = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gopherwatch_tlog_records",
			Help: "Last seen record id/count in sumdb.",
		},
	)
	metricTlogProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_tlog_processed",
			Help: "Number of records (module versions) processed.",
		},
	)
	metricTlogSecurityErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_tlog_security_errors",
			Help: "Number of security errors encountered.",
		},
	)
	metricUpdateMatchesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_update_matches_total",
			Help: "Number of updates that matched subscriptions.",
		},
	)
	metricPanics = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_panics_total",
			Help: "Number of unhandled panics.",
		},
	)
	metricHookRequest = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gopherwatch_hook_duration_seconds",
			Help:    "HTTP webhook requests.",
			Buckets: []float64{0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20, 30},
		},
	)
	metricHookResponse = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gopherwatch_hook_response_total",
			Help: "Number of webhook responses and their major status code or error.",
		},
		[]string{"result"}, // "2xx", "3xx", etc, or "error".
	)
)
