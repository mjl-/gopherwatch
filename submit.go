package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
)

// Timestamp as used in internet mail messages.
const RFC5322Z = "2 Jan 2006 15:04:05 -0700"

func smtpDial(ctx context.Context) (smtpconn *smtpclient.Client, rerr error) {
	defer func() {
		if rerr != nil {
			metricMessageSubmitErrors.Inc()
		}
	}()

	slog.Info("dialing submission...")
	addr := net.JoinHostPort(config.Submission.Host, fmt.Sprintf("%d", config.Submission.Port))
	d := net.Dialer{}
	var conn net.Conn
	var err error
	if config.Submission.TLS {
		config := tls.Config{InsecureSkipVerify: config.Submission.TLSSkipVerify}
		tlsdialer := tls.Dialer{NetDialer: &d, Config: &config}
		conn, err = tlsdialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial submission: %v", err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	auth := func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
		noplus := true
		for _, m := range mechanisms {
			if m == "SCRAM-SHA-256-PLUS" {
				noplus = false
			}
		}
		for _, m := range mechanisms {
			if m == "SCRAM-SHA-256" {
				return sasl.NewClientSCRAMSHA256(config.Submission.Username, config.Submission.Password, noplus), nil
			}
		}
		return nil, nil
	}
	client, err := smtpclient.New(ctx, slog.Default(), conn, smtpclient.TLSSkip, false, dns.Domain{ASCII: "localhost"}, dns.Domain{ASCII: "localhost"}, smtpclient.Opts{Auth: auth})
	if err != nil {
		return nil, fmt.Errorf("smtp login: %v", err)
	}
	conn = nil
	return client, nil
}

// smtpCanSend returns whether it is likely the ratelimiter won't block on a subsequent call.
func smtpCanSend() bool {
	return ratelimitEmail.CanAdd(net.IPv6zero, time.Now(), 1)
}

// smtpTake consumes from the rate limiter, blocking until sending is allowed.
func smtpTake() {
	for !ratelimitEmail.Add(net.IPv6zero, time.Now(), 1) {
		slog.Info("slowing down outgoing messages")
		time.Sleep(time.Second)
	}
}

// smtpSubmit sends a single message on the connection.
// caller must have called smtpTake to consume from the ratelimiter.
func smtpSubmit(ctx context.Context, smtpconn *smtpclient.Client, meta bool, mailFrom, rcptTo string, msg []byte, eightbit, smtputf8 bool) (rerr error) {
	slog.Info("submitting message...")
	if meta {
		metricMessageMeta.Inc()
	} else {
		metricMessageUpdates.Inc()
	}
	defer func() {
		if rerr != nil {
			metricMessageSubmitErrors.Inc()
		}
	}()

	if err := smtpconn.Deliver(ctx, mailFrom, rcptTo, int64(len(msg)), bytes.NewReader(msg), eightbit, smtputf8, false); err != nil {
		return fmt.Errorf("submit email message: %v", err)
	}
	return nil
}
