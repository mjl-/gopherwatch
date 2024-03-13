package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"runtime/debug"
	"strings"
	"time"

	"github.com/mjl-/bstore"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/smtp"
)

func mailWatch() {
	for {
		if err := imapWatch(); err != nil {
			logErrorx("watch imap mailbox for dsn", err)
		}

		// Wait a while before trying again.
		// todo: exponential backoff? need to know if failure was immediate or delayed.
		time.Sleep(time.Minute)
	}
}

// most of the time, a connection/protocol error and status != ok are just as bad
// and cause us to abort the connection.
func imapresult(result imapclient.Result, err error) error {
	if err != nil {
		return err
	} else if result.Status != imapclient.OK {
		return fmt.Errorf("imap response code %s", result.Status)
	}
	return nil
}

// make an IMAP connection, and select the inbox.
func imapConnectSelect() (rimapconn *imapclient.Conn, rerr error) {
	addr := net.JoinHostPort(config.IMAP.Host, fmt.Sprintf("%d", config.IMAP.Port))

	var conn net.Conn
	var err error
	if config.IMAP.TLS {
		config := tls.Config{InsecureSkipVerify: config.IMAP.TLSSkipVerify}
		conn, err = tls.Dial("tcp", addr, &config)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial imap server: %v", err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	metricIMAPConnections.Inc()

	imapconn, err := imapclient.New(conn, false)
	if err != nil {
		return nil, fmt.Errorf("new imapclient: %v", err)
	}
	conn = nil
	defer func() {
		if rerr != nil {
			err := imapconn.Close()
			logCheck(err, "closing imap connection after error")
			imapconn = nil
		}
	}()

	_, result, err := imapconn.AuthenticateSCRAM("SCRAM-SHA-256", sha256.New, config.IMAP.Username, config.IMAP.Password)
	if err := imapresult(result, err); err != nil {
		return nil, fmt.Errorf("imap authenticate: %v", err)
	}

	_, result, err = imapconn.Select("Inbox")
	if err := imapresult(result, err); err != nil {
		return nil, fmt.Errorf("imap select inbox: %v", err)
	}

	return imapconn, nil
}

// Make IMAP connection, call IDLE. When it returns, look for unseen messages
// without flags indicating we've processed them. Read through each, adding flags
// and marking as read.
func imapWatch() (rerr error) {
	defer func() {
		x := recover()
		if x != nil {
			metricPanics.Inc()
			rerr = fmt.Errorf("unhandled panic: %v", x)
			slog.Error("unhandled panic", "panic", x)
			debug.PrintStack()
		}
	}()

	slog.Info("connecting to imap to idle until message comes in...")

	imapconn, err := imapConnectSelect()
	if err != nil {
		return fmt.Errorf("making imap connection: %v", err)
	}
	defer imapconn.Close()

	// Process messages currently in mailbox.
	if err := imapProcess(); err != nil {
		metricIncomingProcessErrors.Inc()
		return fmt.Errorf("processing new messages in mailbox: %v", err)
	}

	// Keep executing an IDLE command. It returns when something happened (e.g. message
	// delivered). We'll then process it and wait for the next event.
	for {
		if err := imapWait(imapconn); err != nil {
			return fmt.Errorf("waiting for event from idle: %v", err)
		}
	}
}

// Wait for an "exists" response from idle. Other untagged responses are
// ignored and we continue idling. When we see an "exists", we process it on a
// new temporary connection.
func imapWait(imapconn *imapclient.Conn) error {
	if err := imapconn.Commandf("", "idle"); err != nil {
		return fmt.Errorf("writing idle command: %v", err)
	}
	line, err := imapconn.Readline()
	if err != nil {
		return fmt.Errorf("reading continuation response after idle command: %v", err)
	}
	if !strings.HasPrefix(line, "+ ") {
		return fmt.Errorf("unexpected response from server to idle command: %q", line)
	}

	// todo: write "done" after 15 minutes, then search for new messages and start again. or better: make mail server send untagged nop responses for keepalive.

	slog.Info("imap idle: waiting for deliveries")
	for {
		untagged, err := imapconn.ReadUntagged()
		if err != nil {
			return fmt.Errorf("waiting and reading for idle events: %v", err)
		}
		_, ok := untagged.(imapclient.UntaggedExists)
		if !ok {
			continue
		}
		if err := imapProcess(); err != nil {
			metricIncomingProcessErrors.Inc()
			return fmt.Errorf("processing new messages in mailbox: %v", err)
		}
	}
}

// Connect to imap server and handle all messages that are unread and we haven't
// labeled yet.
func imapProcess() error {
	slog.Info("connecting to process new messages after untagged exists message from idle...")

	imapconn, err := imapConnectSelect()
	if err != nil {
		return fmt.Errorf("making imap connection: %v", err)
	}
	defer imapconn.Close()

	// Search messages that we haven't processed yet, and aren't read yet.
	prefix := config.IMAP.KeywordPrefix
	untagged, result, err := imapconn.Transactf("uid search return (all) unseen unkeyword %ssignup unkeyword %sdsn unkeyword %signored unkeyword %sproblem", prefix, prefix, prefix, prefix)
	if err := imapresult(result, err); err != nil {
		return fmt.Errorf("imap search: %v", err)
	}
	slog.Info("imap search for messages", "nuntagged", len(untagged))
	for _, r := range untagged {
		esearch, ok := r.(imapclient.UntaggedEsearch)
		if !ok {
			slog.Info("received unusable untagged message, we're only processing esearch responses", "untagged", r)
			continue
		}

		slog.Info("handling esearch response with one or more new messages")

		for _, r := range esearch.All.Ranges {
			first := r.First
			last := r.First
			if r.Last != nil {
				last = *r.Last
			}
			if last < first {
				first, last = last, first
			}
			for uid := first; uid <= last; uid++ {
				if problem, err := processMessage(imapconn, uid); err != nil {
					return fmt.Errorf("processing message with uid %d: %v", uid, err)
				} else if problem != "" {
					metricIncomingProblem.Inc()
					slog.Info("problem processing message, marking as failed", "uid", uid, "problem", problem)
					_, sresult, err := imapconn.Transactf("uid store %d +flags.silent (%sproblem)", uid, config.IMAP.KeywordPrefix)
					if err := imapresult(sresult, err); err != nil {
						return fmt.Errorf("setting flag problem: %v", err)
					}
				}
			}
		}
	}

	_, result, err = imapconn.Unselect()
	if err := imapresult(result, err); err != nil {
		return fmt.Errorf("unselect: %v", err)
	}

	_, result, err = imapconn.Logout()
	if err := imapresult(result, err); err != nil {
		return fmt.Errorf("imap logout: %v", err)
	}

	return nil
}

// processMessages tries to parse the message as signup or DSN. If there is a
// connection/protocol error, an error is returned and further operations on the
// connection stopped. If problem is non-empty, the message should be marked as
// broken and continued with the next message.
func processMessage(imapconn *imapclient.Conn, uid uint32) (problem string, rerr error) {
	log := slog.With("uid", uid)

	// Fetch message. See if it is a signup and that's enabled. If so, process and mark
	// with signup label. Otherwise check if it's a dsn. If not, add keyword ignored.
	// If so, fetch it, parse it, look up the original message we sent and mark it as
	// failed and the user as needing backoff. Add other related message flags on
	// various handling errors.
	const headerFields = "header.fields (delivered-to to list-id list-unsubscribe list-unsubscribe-post auto-submitted precedence authentication-results)"
	meta, mresult, err := imapconn.Transactf(`uid fetch %d (envelope flags bodystructure body.peek[%s])`, uid, headerFields)
	if err := imapresult(mresult, err); err != nil {
		return fmt.Sprintf("fetch new message metadata: %v", err), nil
	}

	// We need these four reponse messages.
	var fetchEnv *imapclient.FetchEnvelope
	var fetchFlags *imapclient.FetchFlags
	var fetchBody *imapclient.FetchBody
	var fetchBodystructure *imapclient.FetchBodystructure

	for _, m := range meta {
		f, ok := m.(imapclient.UntaggedFetch)
		if !ok {
			continue
		}
		for _, a := range f.Attrs {
			switch fa := a.(type) {
			case imapclient.FetchEnvelope:
				fetchEnv = &fa

			case imapclient.FetchFlags:
				fetchFlags = &fa

			case imapclient.FetchBody:
				fetchBody = &fa

			case imapclient.FetchBodystructure:
				fetchBodystructure = &fa

			case imapclient.FetchUID:
				// Ignore.

			default:
				log.Info("unexpected fetch attribute", "attr", fmt.Sprintf("%#v", a))
			}
		}
	}

	if fetchEnv == nil || fetchFlags == nil || fetchBody == nil || fetchBodystructure == nil {
		return fmt.Sprintf("imap server did not send all requested fields, envelope %v, flags %v, body %v, bodystructure %v", fetchEnv != nil, fetchFlags != nil, fetchBody != nil, fetchBodystructure != nil), nil
	}

	// We should only be processing messages without certain flags.
	for _, flag := range *fetchFlags {
		if strings.EqualFold(flag, `\Seen`) || strings.EqualFold(flag, config.IMAP.KeywordPrefix+"signup") || strings.EqualFold(flag, config.IMAP.KeywordPrefix+"dsn") || strings.EqualFold(flag, config.IMAP.KeywordPrefix+"ignored") {
			log.Error("bug: message already has flag? continuing", "flag", flag)
		}
	}

	// Parse headers
	// We need an address that the message (if DSN) was addressed to. It contains the
	// ID of the message (sendID) that we need to match against.
	if !strings.EqualFold(fetchBody.Section, headerFields) {
		return fmt.Sprintf("bug: received a fetch body result, but not for requested header fields? section %q", fetchBody.Section), nil
	}
	msg, err := mail.ReadMessage(strings.NewReader(fetchBody.Body))
	if err != nil {
		return fmt.Sprintf("parsing headers for delivered-to or to: %s", err), nil
	}

	listID := strings.TrimSpace(msg.Header.Get("List-Id"))
	listUnsubscribe := strings.TrimSpace(msg.Header.Get("List-Unsubscribe"))
	listUnsubscribePost := strings.TrimSpace(msg.Header.Get("List-Unsubscribe-Post"))
	autoSubmitted := strings.TrimSpace(msg.Header.Get("Auto-Submitted"))
	precedence := strings.TrimSpace(msg.Header.Get("Precedence"))
	if strings.EqualFold(strings.TrimSpace(fetchEnv.Subject), "signup for "+config.ServiceName) {
		log.Debug("looking at signup message")

		// See RFC 3834.
		if listID != "" || listUnsubscribe != "" || listUnsubscribePost != "" || autoSubmitted != "" || precedence != "" {
			return fmt.Sprintf("signup message has headers indicating it was sent automatically or through a list, not processing (list-id %q, list-unsubscribe %q, list-unsubscribe-post %q, auto-submitted %q, precedence %q)", listID, listUnsubscribe, listUnsubscribePost, autoSubmitted, precedence), nil
		}

		env := fetchEnv
		if len(env.From) != 1 {
			return fmt.Sprintf(`signup message with %d "from" addresses, expecting 1`, len(env.From)), nil
		}

		if len(env.To) != 1 {
			return fmt.Sprintf(`signup message with %d "to" addresses (%#v), expecting 1`, len(env.To), env.To), nil
		}

		// Errors are logged and an empty address returned: callers do comparisons which
		// will fail.
		parseAddress := func(a imapclient.Address) smtp.Address {
			lp, err := smtp.ParseLocalpart(a.Mailbox)
			if err != nil {
				log.Info("parsing localpart failed", "err", err, "imapaddress", a)
				return smtp.Address{}
			}
			dom, err := dns.ParseDomain(a.Host)
			if err != nil {
				log.Info("parsing domain failed", "err", err, "imapaddress", a)
				return smtp.Address{}
			}
			return smtp.Address{Localpart: lp, Domain: dom}
		}

		toAddr := parseAddress(env.To[0])
		expAddr := smtp.Address{Localpart: config.Submission.From.ParsedLocalpartBase, Domain: config.Submission.From.DNSDomain}
		if toAddr != expAddr {
			return fmt.Sprintf(`signup message "to" unrecognized address %s, expecting %s`, toAddr, expAddr), nil
		}
		fromAddr := parseAddress(env.From[0])
		log.Info("signup message", "from", fromAddr, "to", toAddr)
		if len(env.ReplyTo) > 1 || len(env.ReplyTo) == 1 && parseAddress(env.ReplyTo[0]) != fromAddr {
			return fmt.Sprintf(`signup message with reply-to %#v different than "from" address %#v`, env.ReplyTo, env.From[0]), nil
		}

		// We'll parse the Authentication-Results of the message to find dmarc/spf/dkim
		// status. Not great to have to parse this, but it'll do. We only use the top-most.
		// We don't want to trust whatever the message already contained, can be forged.
		// If we find a dmarc=pass or dmarc=fail, we know our answer. Otherwise, we'll look
		// for spf and dkim pass, and apply relaxed validation.
		// todo: if we didn't find dmarc=none, we could try looking up the dmarc record and applying it. perhaps good to again evaluate the dmarc record with the spf/dkim details we found: the dmarc policy may have a setting where it applies to fewer than 100% of the messages. we can probably be more strict.
		authres := msg.Header.Get("Authentication-Results")
		if authres == "" {
			return "missing authentication-results in message, cannot validate from address", nil
		}
		ar, err := message.ParseAuthResults(authres + "\n")
		if err != nil {
			return fmt.Sprintf(`parsing authentication-results in message, cannot validate from address: %v (%q)`, err, authres), nil
		}

		aligned := func(d dns.Domain) bool {
			ctx := context.Background()
			return d == fromAddr.Domain || publicsuffix.Lookup(ctx, log, d) == publicsuffix.Lookup(ctx, log, fromAddr.Domain)
		}
		var good bool
	Methods:
		for _, am := range ar.Methods {
			getProp := func(typ, prop string) string {
				for _, ap := range am.Props {
					if ap.Type == typ && ap.Property == prop {
						return ap.Value
					}
				}
				return ""

			}
			switch am.Method {
			case "dmarc":
				switch am.Result {
				case "pass":
					log.Info("message has dmarc pass")
					good = true
					break Methods
				case "fail":
					return `message contained a dmarc failure, not responding`, nil
				}
			case "spf":
				if am.Result == "pass" {
					v := getProp("smtp", "mailfrom")
					addr, err := smtp.ParseAddress(v)
					var spfDom dns.Domain
					if err == nil {
						spfDom = addr.Domain
					} else {
						spfDom, err = dns.ParseDomain(v)
					}
					if err != nil {
						log.Debug("parsing mailfrom address from spf=pass", "err", err, "mailfrom", v)
						continue
					}
					ok := aligned(spfDom)
					log.Debug("message spf alignment", "aligned", ok)
					if ok {
						good = true
					}
				}
			case "dkim":
				if am.Result == "pass" {
					v := getProp("header", "d")
					dkimDom, err := dns.ParseDomain(v)
					if err != nil {
						log.Debug("parsing domain from dkim=pass", "err", err, "domain", v)
						continue
					}
					ok := aligned(dkimDom)
					log.Debug("message dkim alignment", "aligned", ok)
					if ok {
						good = ok
					}
				}
			}
		}
		if !good {
			return `"from" address not aligned-dmarc-verified`, nil
		}

		// Message seems legit. Lookup the user. If no account yet, we'll try to create it.
		// If user exists, we'll send a password reset. Like the regular signup form.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		user, msg, mailFrom, eightbit, smtputf8, m, err := signup(ctx, fromAddr, env.MessageID, false)
		if err != nil {
			return fmt.Sprintf("registering signup for user %q: %v", fromAddr.String(), err), nil
		} else if user.ID == 0 {
			// Should not happen for email-based signup.
			return "missing user id after signup", nil
		}

		// Check if we can send. If not, abort.
		for i := 0; !smtpCanSend(); i++ {
			if i >= 15 {
				return "signup reply not sent due to outgoing rate limit", nil
			}
			time.Sleep(time.Second)
		}

		log.Info("marking message as signup before sending")
		_, sresult, err := imapconn.Transactf(`uid store %d +flags.silent (%ssignup)`, uid, config.IMAP.KeywordPrefix)
		if err := imapresult(sresult, err); err != nil {
			return fmt.Sprintf("setting flag signup: %v", err), nil
		}

		// Send message.
		smtpconn, err := smtpDial(ctx)
		if err == nil {
			defer smtpconn.Close()
			err = smtpSubmit(ctx, smtpconn, true, mailFrom, user.Email, msg, eightbit, smtputf8)
		}
		if err != nil {
			logErrorx("submission for signup/passwordreset", err, "userid", user.ID)
			if err := database.Delete(context.Background(), &m); err != nil {
				logErrorx("removing metamessage added before submission error", err)
			}
			return fmt.Sprintf("dialing submission for signup reply to %q: %v", fromAddr.String(), err), nil
		}

		_, sresult, err = imapconn.Transactf(`uid store %d +flags.silent (\seen \answered)`, uid)
		if err := imapresult(sresult, err); err != nil {
			return "", fmt.Errorf("setting flags answered and seen: %v", err)
		}
		metricIncomingSignup.Inc()

		return "", nil
	}

	deliveredTo := strings.TrimSpace(msg.Header.Get("Delivered-To"))
	if deliveredTo == "" {
		to, err := msg.Header.AddressList("To")
		if err == mail.ErrHeaderNotPresent {
			return "message has no delivered-to and no to headers", nil
		} else if len(to) != 1 {
			return fmt.Sprintf("message has %d address in To header (%v), need 1", len(to), to), nil
		}
		deliveredTo = to[0].Address
	}

	// Look at the structure, whether it is a DSN.
	var isdsn, dsnutf8 bool
	mp, ok := fetchBodystructure.Body.(imapclient.BodyTypeMpart)
	if ok {
		if len(mp.Bodies) >= 2 {
			basic, ok := mp.Bodies[1].(imapclient.BodyTypeBasic)
			if ok && strings.EqualFold(basic.MediaType, "message") && (strings.EqualFold(basic.MediaSubtype, "delivery-status") || strings.EqualFold(basic.MediaSubtype, "global-delivery-status")) {
				isdsn = true
				dsnutf8 = strings.EqualFold(basic.MediaSubtype, "global-delivery-status")
			}
		}
	}
	if !isdsn {
		log.Info("marking message as ignored")
		_, sresult, err := imapconn.Transactf("uid store %d +flags.silent (%signored)", uid, config.IMAP.KeywordPrefix)
		if err := imapresult(sresult, err); err != nil {
			return "", fmt.Errorf("setting flag ignored: %v", err)
		}
		metricIncomingIgnored.Inc()
		return "", nil
	}

	// Fetch binary (decoded) second part, and parse its dsn metadata.
	binary, bresult, err := imapconn.Transactf("uid fetch %d (binary.peek[2])", uid)
	if err != nil {
		return "", fmt.Errorf("fetching dsn data: %v", err)
	} else if err := imapresult(bresult, err); err != nil {
		return fmt.Sprintf("fetching dsn data: %v", err), nil
	}
	var fetchBinary *imapclient.FetchBinary
	for _, b := range binary {
		f, ok := b.(imapclient.UntaggedFetch)
		if !ok {
			continue
		}
		for _, a := range f.Attrs {
			fa, ok := a.(imapclient.FetchBinary)
			if ok {
				fetchBinary = &fa
				break
			}
		}
	}
	if fetchBinary == nil {
		return "fetch did not return binary data", nil
	}

	dsnmsg, err := dsn.Decode(strings.NewReader(fetchBinary.Data), dsnutf8)
	var badsyntax, ignore bool
	var sendID string
	if err != nil {
		log.Error("parsing dsn message", "err", err)
		badsyntax = true
	} else if len(dsnmsg.Recipients) != 1 {
		log.Error("expect exactly 1 recipient", "nrecipients", len(dsnmsg.Recipients))
		badsyntax = true
	} else {
		log.Info("found dsn, with 1 recipient", "to", deliveredTo)
		switch dsnmsg.Recipients[0].Action {
		case dsn.Delayed, dsn.Failed:
			// We'll process it.
			if deliveredTo == "" {
				ignore = true
			} else {
				addr, err := smtp.ParseAddress(deliveredTo)
				if err != nil {
					ignore = true
				} else {
					t := strings.SplitN(string(addr.Localpart), "+", 2)
					if len(t) != 2 {
						ignore = true
						log.Warn("no separator in localpart for sendid", "address", deliveredTo)
					} else {
						sendID = t[1]
					}
				}
			}
		default:
			ignore = true
			log.Warn("unknown dsn action, ignoring", "action", dsnmsg.Recipients[0].Action)
		}
		log.Info("found dsn", "action", dsnmsg.Recipients[0].Action, "to", deliveredTo, "sendid", sendID)
	}
	var recognized bool
	if !badsyntax && !ignore {
		recognized, err = processDSN(uid, sendID, dsnmsg, fetchBinary.Data)
		if err != nil {
			return fmt.Sprintf("processing as dsn: %v", err), nil
		}
	}
	flags := []string{config.IMAP.KeywordPrefix + "dsn"}
	var more string
	if badsyntax {
		more = "dsnsyntax"
	} else if ignore {
		more = "dsnignore"
	} else if !recognized {
		more = "dsnunknown"
	}
	if more == "" {
		flags = append(flags, `\seen`)
	} else {
		flags = append(flags, config.IMAP.KeywordPrefix+more)
	}
	_, result, err := imapconn.Transactf("uid store %d +flags.silent (%s)", uid, strings.Join(flags, " "))
	if err := imapresult(result, err); err != nil {
		return "", fmt.Errorf("storing dsn flags %q for message with uid %d: %v", flags, uid, err)
	}
	if more != "" {
		metricIncomingProblem.Inc()
	} else {
		metricIncomingDSN.Inc()
	}
	log.Info("marked dsn message", "flags", flags)
	return "", nil
}

// Process a message as DSN in the database. Return whether it was recognized as a
// message we sent. Backoff state for the user may be extended/started.
func processDSN(uid uint32, sendID string, dsnmsg *dsn.Message, dsnData string) (recognized bool, rerr error) {
	rcpt := dsnmsg.Recipients[0]

	log := slog.With("uid", uid, "sendid", sendID)

	log.Info("processing dsn")

	err := database.Write(context.Background(), func(tx *bstore.Tx) error {
		var known bool
		var userID int64
		m, err := bstore.QueryTx[Message](tx).FilterNonzero(Message{SendID: sendID}).Get()
		if err == bstore.ErrAbsent {
			return nil
		} else if err != nil {
			return fmt.Errorf("looking up message in database by message-id: %v", err)
		}

		recognized = true

		known = m.Failed
		userID = m.UserID
		m.Modified = time.Now()
		m.Failed = true
		m.TemporaryFailure = rcpt.Action == dsn.Delayed
		m.Error = rcpt.Status // todo: could include more, like the textual part of the message
		m.DSNData += dsnData + "\n\n"
		if err := tx.Update(&m); err != nil {
			return fmt.Errorf("updating message in database: %v", err)
		}

		user := User{ID: userID}
		if err := tx.Get(&user); err != nil {
			return fmt.Errorf("get user: %v", err)
		}

		// Recognize specific actions that are not failures. We assume otherwise it is
		// either failed/delayed, but could be set incorrectly or not at all.
		switch rcpt.Action {
		case dsn.Delivered, dsn.Relayed, dsn.Expanded:
			// todo: for delivered, should we clear the backoff?
			if err := addUserLogf(tx, user.ID, "Received dsn %q, no action taken", rcpt.Action); err != nil {
				return fmt.Errorf("marking dsn in userlog: %v", err)
			}
			return nil
		}

		if known {
			if err := addUserLogf(tx, user.ID, "Received dsn %q, message was already marked as failed, not taking further backoff actions", rcpt.Action); err != nil {
				return fmt.Errorf("marking dsn in userlog: %v", err)
			}
			return nil
		}

		// We start/extend backing off from sending more messages. We don't look at whether
		// this is a permanent or temporary failure. We'll retry after a while anyway, best
		// to hold off until we know more. Backoff is potentially reset when we look at
		// whether we should send a message again.
		if user.Backoff == BackoffNone || time.Since(user.BackoffUntil) > 0 && user.Backoff < BackoffPermanent {
			if user.Backoff == BackoffNone {
				user.BackoffUntil = time.Now()
			}
			// Set new Backoff end time (unless already permanent).
			user.Backoff++
			// If we are likely blocklisted, backoff for a week. The blocklist is likely not
			// resolved in a day, and sending more messages may contribute to staying
			// blocklisted.
			if rcpt.Status == "5."+smtp.SePol7DeliveryUnauth1 && user.Backoff < BackoffWeek {
				user.Backoff = BackoffWeek
			}
			if user.Backoff < BackoffPermanent {
				d := 24 * time.Hour
				if user.Backoff >= BackoffWeek {
					d *= 7
				}
				if user.Backoff >= BackoffMonth {
					d *= 31
				}
				user.BackoffUntil = user.BackoffUntil.Add(d)
			}
			// Reset whether we've "tried" after the end time. When we check if we can send,
			// we'll optimistically try again after the end time, to recover to regular
			// sending.
			user.BackoffTried = false
			if err := tx.Update(&user); err != nil {
				return fmt.Errorf("starting/extending backoff for user: %v", err)
			}
			if err := addUserLogf(tx, user.ID, "Received dsn %q, starting/extending backoff until %s", rcpt.Action, user.BackoffUntil.UTC()); err != nil {
				return fmt.Errorf("marking dsn in userlog: %v", err)
			}
		} else if err := addUserLogf(tx, user.ID, "Received dsn %q, no backoff extension/start", rcpt.Action); err != nil {
			return fmt.Errorf("marking dsn in userlog: %v", err)
		}
		return nil
	})
	return recognized, err
}
