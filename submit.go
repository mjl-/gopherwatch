package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net"
	"net/textproto"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
)

// Timestamp as used in internet mail messages.
const RFC5322Z = "2 Jan 2006 15:04:05 -0700"

// compose returns an email message that can be sent over smtp, indicating whether
// it uses 8bitmime and smtputf8.
//
// Each message gets a unique sendID, which is also added to the mailFrom, which
// must be used as SMTP MAIL FROM, so DSNs go there an can be matched back to the
// message and processed.
//
// Unless skipunsubscribe is true, List-Unsubscribe headers are added, and the
// unsubscribe URL is added as signature to the body.
//
// If configured, the message subject prefix is prepended to the subject before
// adding it to the message.
func compose(meta bool, user User, origMessageID, subject, text, html string) (mailFrom, sendID string, msg []byte, eightbit, smtputf8 bool, rerr error) {
	// message.Composer uses panic for error handling...
	defer func() {
		x := recover()
		if x != nil {
			if err, ok := x.(error); ok && errors.Is(err, message.ErrCompose) {
				rerr = err
				return
			}
			panic(x)
		}
	}()

	var buf bytes.Buffer
	c := message.NewComposer(&buf, 0, smtputf8)

	rcptToAddr, err := smtp.ParseAddress(user.Email)
	if err != nil {
		// This shouldn't fail, we've validated the address before.
		return "", "", nil, false, false, fmt.Errorf("parsing recipient address: %v", err)
	}
	for _, ch := range string(rcptToAddr.Localpart + config.SubmissionIMAP.Submission.From.ParsedLocalpartBase) {
		if ch >= 0x80 {
			c.SMTPUTF8 = true
			c.Has8bit = true
			break
		}
	}

	sendID = xrandomID(16)
	mailFromAddr := smtp.Address{
		Localpart: config.SubmissionIMAP.Submission.From.ParsedLocalpartBase,
		Domain:    config.SubmissionIMAP.Submission.From.DNSDomain,
	}
	// We send from our address that uses "+<id>" in the SMTP MAIL FROM address.
	c.HeaderAddrs("From", []message.NameAddress{
		{DisplayName: config.SubmissionIMAP.Submission.From.Name, Address: mailFromAddr},
	})
	// But we ask replies to go to the admin address. That should signal that a real
	// person will read replies. Better than "noreply", or a service-like name in
	// between that users can't tell will bounce or be read.
	c.HeaderAddrs("Reply-To", []message.NameAddress{
		{Address: config.Admin.AddressParsed},
	})

	c.HeaderAddrs("To", []message.NameAddress{{Address: rcptToAddr}})
	c.Subject(subject)
	c.Header("Date", time.Now().Format(RFC5322Z))
	c.Header("Message-ID", fmt.Sprintf("<%s@%s>", sendID, hostname))
	if origMessageID != "" {
		c.Header("In-Reply-To", fmt.Sprintf("<%s>", origMessageID))
		c.Header("References", fmt.Sprintf("<%s>", origMessageID))
	}
	c.Header("User-Agent", "gopherwatch/"+version)

	// Try to prevent out-of-office notifications. RFC 3834.
	c.Header("Auto-Submitted", "auto-generated")
	// RFC 2076 discourages "Precedence", it seems old and doesn't neatly fit.

	// RFC 2919
	c.Header("List-Id", fmt.Sprintf("%s <%d.%s>", config.ServiceName, user.ID, strings.ReplaceAll(config.SignupAddress, "@", ".")))
	c.Header("List-Post", "NO")
	c.Header("List-Owner", "<mailto:"+config.Admin.Address+">")
	unsubToken := user.UpdatesUnsubscribeToken
	if meta {
		unsubToken = user.MetaUnsubscribeToken
	}
	unsubscribeURL := fmt.Sprintf("%s/unsubscribe?id=%s", config.BaseURL, unsubToken)
	c.Header("List-Unsubscribe", "<"+unsubscribeURL+">")            // // RFC 2369
	c.Header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click") // RFC 8058

	mp := multipart.NewWriter(c)
	c.Header("MIME-Version", "1.0")
	c.Header("Content-Type", fmt.Sprintf(`multipart/alternative; boundary="%s"`, mp.Boundary()))
	c.Line()

	// TextPart converts \n to \r\n.
	textBody, textCT, textCTE := c.TextPart("plain", text)
	thdrs := textproto.MIMEHeader{
		"Content-Type":              []string{textCT},
		"Content-Transfer-Encoding": []string{textCTE},
	}
	tp, err := mp.CreatePart(thdrs)
	c.Checkf(err, "adding text part")
	_, err = tp.Write([]byte(textBody))
	c.Checkf(err, "writing text part")

	htmlBody, htmlCT, htmlCTE := c.TextPart("html", html)
	hhdrs := textproto.MIMEHeader{
		"Content-Type":              []string{htmlCT},
		"Content-Transfer-Encoding": []string{htmlCTE},
	}
	hp, err := mp.CreatePart(hhdrs)
	c.Checkf(err, "writing html part headers")
	_, err = hp.Write([]byte(htmlBody))
	c.Checkf(err, "writing html part")

	err = mp.Close()
	c.Checkf(err, "closing multipart")

	c.Flush()

	// We send from an address that includes the sendID, to relate bounces to this
	// message.
	mailFromAddr.Localpart += smtp.Localpart("+" + sendID)
	mailFrom = mailFromAddr.String()

	return mailFrom, sendID, buf.Bytes(), c.Has8bit, c.SMTPUTF8, nil
}

var smtpConn struct {
	sync.Mutex

	// connection that may returned by smtpPut after using a connection, and retrieved
	// by smtpGet. the smtpPut that sets this field is responsible to closing it after
	// the idle time, unless it was taken again.
	conn *smtpclient.Client

	// smtpPut sets this to a channel it monitors until its connection idle timeout is
	// reached. if an smtpGet comes along first to use the connection, it sends on this
	// channel, and smtpPut knows its no longer responsible and cancels its scheduled
	// connection cleanup.
	used chan struct{}
}

// smtpGet returns a cached connection or dials a new connection.
func smtpGet(ctx context.Context) (*smtpclient.Client, error) {
	smtpConn.Lock()
	conn := smtpConn.conn
	smtpConn.conn = nil
	if conn != nil {
		smtpConn.used <- struct{}{} // Will not block.
		smtpConn.used = nil
	}
	smtpConn.Unlock()
	if conn != nil {
		slog.Debug("reusing smtp connection")
		// todo: we could do a NOOP command, and dial a new connection if that fails.
		return conn, nil
	}
	return smtpDial(ctx)
}

// return connection to pool, closing existing idle connection if any. schedule the
// newly returned connection for closing after 5 seconds, unless someone takes it
// off our hands before that time.
func smtpPut(nconn *smtpclient.Client) {
	smtpConn.Lock()
	defer smtpConn.Unlock()

	oconn := smtpConn.conn
	if oconn != nil {
		// Already have a connection. It's probably older, replace it.
		smtpConn.used <- struct{}{}

		// Close old connection in background, it involves sending an SMTP QUIT command,
		// which may take a while and we're holding the smtpConn lock.
		go func() {
			defer func() {
				x := recover()
				if x != nil {
					metricPanics.Inc()
					slog.Error("unhandled panic cleaning up old smtp connection", "panic", x)
					debug.PrintStack()
				}
			}()

			if err := oconn.Close(); err != nil {
				slog.Error("closing smtp connection", "err", err)
			} else {
				slog.Debug("closed old smtp connection")
			}
		}()
	}

	smtpConn.conn = nconn
	used := make(chan struct{}, 1)
	smtpConn.used = used

	// We keep this connection around for 5 seconds. If someone wakes us up, the
	// connection has been used and they are now responsible for returning it and
	// scheduling cleanup.
	t := time.NewTimer(5 * time.Second)
	go func() {
		defer t.Stop()

		select {
		case <-t.C:
			// Timeout, we'll close the connection, unless someone took the connection just now.
			smtpConn.Lock()
			defer smtpConn.Unlock()
			select {
			case <-used:
				// Whoever took the connection is now responsible.
				return
			default:
			}

			// We close the connection in a goroutine. Like earlier, we'll write an SMTP QUIT
			// command, which can block, and we still hold the smtpConn.
			xconn := smtpConn.conn
			smtpConn.conn = nil
			smtpConn.used = nil
			go func() {
				defer func() {
					x := recover()
					if x != nil {
						metricPanics.Inc()
						slog.Error("unhandled panic cleaning up idle smtp connection", "panic", x)
						debug.PrintStack()
					}
				}()

				if err := xconn.Close(); err != nil {
					slog.Error("closing idle smtp connection", "err", err)
				} else {
					slog.Debug("closed idle smtp connection")
				}
			}()
		case <-used:
			// Someone wake us up and took the connection, nothing to do.
		}
	}()
}

func smtpDial(ctx context.Context) (smtpconn *smtpclient.Client, rerr error) {
	defer func() {
		if rerr != nil {
			metricMessageSubmitErrors.Inc()
		}
	}()

	slog.Info("dialing submission...")
	addr := net.JoinHostPort(config.SubmissionIMAP.Submission.Host, fmt.Sprintf("%d", config.SubmissionIMAP.Submission.Port))
	d := net.Dialer{}
	var conn net.Conn
	var err error
	if config.SubmissionIMAP.Submission.TLS {
		config := tls.Config{InsecureSkipVerify: config.SubmissionIMAP.Submission.TLSSkipVerify}
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
				return sasl.NewClientSCRAMSHA256(config.SubmissionIMAP.Submission.Username, config.SubmissionIMAP.Submission.Password, noplus), nil
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
