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
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/smtp"
)

func watchDSN() {
	for {
		if err := imapWatchDSN(); err != nil {
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

// Make IMAP connection, call IDLE (with a timeout?). When it returns, look for
// unseen messages without dsn or notdsn flags. Read through each, adding flags and
// marking dsn's as read.
func imapWatchDSN() (rerr error) {
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

	// Keep executing an IDLE command. It returns when something happened (e.g. message
	// delivered). We'll then process it and wait for the next event.
	for {
		if err := imapWait(imapconn); err != nil {
			return fmt.Errorf("waiting for event from idle: %v", err)
		}
	}
}

// Wait for an "exists" response from idle. Other untagged responses are ignored and we continue idling. When we see an "exists", we process it on a new temporary connection.
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

// Connect to imap server and handle all messages that are unread and we haven't labeled yet.
func imapProcess() error {
	slog.Info("connecting to process new messages after untagged exists message from idle...")

	imapconn, err := imapConnectSelect()
	if err != nil {
		return fmt.Errorf("making imap connection: %v", err)
	}
	defer imapconn.Close()

	// Search messages that we haven't processed yet, and aren't read yet.
	prefix := config.IMAP.KeywordPrefix
	untagged, result, err := imapconn.Transactf("uid search return (all) unseen unkeyword %sdsn unkeyword %snotdsn unkeyword %sproblem", prefix, prefix, prefix)
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

// processMessages tries to parse the message as DSN. If there is a
// connection/protocol error, an error is returned and further operations on the
// connection stopped. If problem is non-empty, the message should be marked as
// broken and continued with the next message.
func processMessage(imapconn *imapclient.Conn, uid uint32) (problem string, rerr error) {
	log := slog.With("uid", uid)

	// Fetch message.See if it is a dsn. If not, add keyword notdsn. If so, fetch it,
	// parse it, look up the original message we sent and mark it as failed and the
	// user as needing backoff. Add other related message flags on various handling
	// errors.
	meta, mresult, err := imapconn.Transactf(`uid fetch %d (flags bodystructure body.peek[header.fields (delivered-to to)])`, uid)
	if err := imapresult(mresult, err); err != nil {
		return fmt.Sprintf("fetch new message metadata: %v", err), nil
	}

	// We need these three reponse messages.
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

	if fetchFlags == nil || fetchBody == nil || fetchBodystructure == nil {
		return fmt.Sprintf("imap server did not send all requested fields, flags %v, body %v, bodystructure %v", fetchFlags != nil, fetchBody != nil, fetchBodystructure != nil), nil
	}

	// We should only be processing messages without certain flags.
	for _, flag := range *fetchFlags {
		if strings.EqualFold(flag, `\Seen`) || strings.EqualFold(flag, config.IMAP.KeywordPrefix+"dsn") || strings.EqualFold(flag, config.IMAP.KeywordPrefix+"notdsn") {
			log.Error("bug: message already has flag? continuing", "flag", flag)
		}
	}

	// We need an address that the message (if DSN) was addressed to. It contains the
	// ID of the message (sendID) that we need to match against.
	var deliveredTo string
	if !strings.EqualFold(fetchBody.Section, "header.fields (delivered-to to)") {
		return fmt.Sprintf("bug: received a fetch body result, but not for requested header fields? section %q", fetchBody.Section), nil
	}
	msg, err := mail.ReadMessage(strings.NewReader(fetchBody.Body))
	if err != nil {
		return fmt.Sprintf("parsing headers for delivered-to or to: %s", err), nil
	}
	deliveredTo = strings.TrimSpace(msg.Header.Get("Delivered-To"))
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
		log.Info("marking message as not a dsn")
		_, sresult, err := imapconn.Transactf("uid store %d +flags.silent (%snotdsn)", uid, config.IMAP.KeywordPrefix)
		if err := imapresult(sresult, err); err != nil {
			return "", fmt.Errorf("setting flag notdsn: %v", err)
		}
		metricIncomingNonDSN.Inc()
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
		metricIncomingDSNProblem.Inc()
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
