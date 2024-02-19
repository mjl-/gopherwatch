package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

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
	metricIncomingProcessErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_process_errors_total",
			Help: "Number of errors while processing incoming messages over IMAP.",
		},
	)
	metricIncomingNonDSN = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_nondsn_total",
			Help: "Number of received non-DSN messages.",
		},
	)
	metricIncomingDSN = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_dsn_total",
			Help: "Number of received DSN messages.",
		},
	)
	metricIncomingDSNProblem = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_incoming_dsn_problem_total",
			Help: "Number of DSN messages that could not be processed.",
		},
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
)
