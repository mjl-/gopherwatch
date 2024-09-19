package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/webapi"
	"github.com/mjl-/mox/webhook"
)

type loggingWebAPIClient struct {
	c webapi.Client
}

func (c loggingWebAPIClient) log(t0 time.Time, method string, err *error) func() {
	return func() {
		slog.Debug("webapi call finished", "err", *err, "method", method, "duration", time.Since(t0))
	}
}

func (lc loggingWebAPIClient) MessageFlagsAdd(ctx context.Context, req webapi.MessageFlagsAddRequest) (resp webapi.MessageFlagsAddResult, err error) {
	defer lc.log(time.Now(), "MessageFlagsAdd", &err)()
	return lc.c.MessageFlagsAdd(ctx, req)
}

func (lc loggingWebAPIClient) Send(ctx context.Context, req webapi.SendRequest) (resp webapi.SendResult, err error) {
	defer lc.log(time.Now(), "Send", &err)()
	return lc.c.Send(ctx, req)
}

// verifies request, and parses a webhook into v. if ok is false, an error
// response has already been written.
func parseWebhook(w http.ResponseWriter, r *http.Request, v any) (ok bool) {
	if username, password, xok := r.BasicAuth(); !xok || username != config.Mox.Webhook.Username || password != config.Mox.Webhook.Password {
		w.Header().Set("WWW-Authenticate", `Basic realm="gopherwatch webhook"`)
		httpErrorf(w, r, http.StatusUnauthorized, "missing or bad credentials")
		return
	}
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && !strings.EqualFold(ct, "application/json") {
		err = fmt.Errorf("got %v, expected application/json", ct)
	}
	if err != nil {
		httpErrorf(w, r, http.StatusBadRequest, "parsing content-type: %v", err)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		httpErrorf(w, r, http.StatusBadRequest, "invalid payload, parsing: %v", err)
		return
	}
	return true
}

func webhookOutgoing(w http.ResponseWriter, r *http.Request) {
	var h webhook.Outgoing
	if !parseWebhook(w, r, &h) {
		return
	}

	metricWebhookOutgoing.WithLabelValues(string(h.Event)).Inc()
	slog.Debug("receiving webhook for outgoing delivery", "webhook", h)

	if h.FromID == "" {
		slog.Info("receiving webhook for outgoing delivery without fromid", "webhook", h)
		fmt.Fprintln(w, "ok, but missing fromid")
		return
	}

	err := database.Write(r.Context(), func(tx *bstore.Tx) error {
		m, err := bstore.QueryTx[Message](tx).FilterNonzero(Message{SendID: h.FromID}).Get()
		if err == bstore.ErrAbsent {
			slog.Info("unknown fromid in webhook for outgoing webhook, ignoring", "fromid", h.FromID, "webhook", h)
			return nil
		}

		m.Modified = time.Now()
		m.History = append(m.History, fmt.Sprintf("event %q, dsn %v, suppressing %v, queuemsgid %d, error %q, time %s", h.Event, h.DSN, h.Suppressing, h.QueueMsgID, h.Error, m.Modified))

		switch h.Event {
		case webhook.EventDelivered:
			m.Failed = false
			m.TemporaryFailure = false
			m.Error = ""
		case webhook.EventSuppressed:
			m.Failed = true
			m.TemporaryFailure = false
			if h.Error != "" {
				m.Error = h.Error
			} else {
				m.Error = "suppressed"
			}
		case webhook.EventDelayed:
			m.Failed = true
			m.TemporaryFailure = true
			m.Error = h.Error
		case webhook.EventFailed:
			m.Failed = true
			m.TemporaryFailure = false
			m.Error = h.Error
		case webhook.EventRelayed:
		case webhook.EventExpanded:
		case webhook.EventCanceled:
			m.Failed = true
			m.TemporaryFailure = false
			m.Error = h.Error
			if m.Error == "" {
				m.Error = "delivery canceled by admin"
			}
		case webhook.EventUnrecognized:
		default:
			slog.Info("unknown event for webhook for outgoing message", "event", h.Event, "webhook", h)
		}

		if h.Event == webhook.EventSuppressed || h.Suppressing {
			u := User{ID: m.UserID}
			if err := tx.Get(&u); err != nil {
				return fmt.Errorf("get user to mark as unsubscribed: %v", err)
			}
			if !u.MetaUnsubscribed || !u.UpdatesUnsubscribed {
				u.MetaUnsubscribed = true
				u.UpdatesUnsubscribed = true
				if err := tx.Update(&u); err != nil {
					return fmt.Errorf("mark user as unsubscribed: %v", err)
				}
				addUserLogf(tx, u.ID, "Unsubscribing user due to delivery failures")
			}
		} else if h.Event == webhook.EventDelayed || h.Event == webhook.EventFailed {
			u := User{ID: m.UserID}
			if err := tx.Get(&u); err != nil {
				return fmt.Errorf("get user to mark as unsubscribed: %v", err)
			}
			if err := markBackoff(tx, &u, string(h.Event), h.SMTPEnhancedCode); err != nil {
				return fmt.Errorf("marking backoff for user: %v", err)
			}
		}

		if err := tx.Update(&m); err != nil {
			return fmt.Errorf("update message with event: %v", err)
		}

		return nil
	})
	if err != nil {
		httpErrorf(w, r, http.StatusInternalServerError, "processing webhook for outgoing message: %v", err)
		return
	}
	fmt.Fprintln(w, "ok")
}

func webhookIncoming(w http.ResponseWriter, r *http.Request) {
	// parse request. if this is a signup message, make registration and send a reply.

	var h webhook.Incoming
	if !parseWebhook(w, r, &h) {
		return
	}

	metricWebhookIncoming.Inc()
	slog.Debug("receiving webhook for incoming delivery", "webhook", h)

	check := func() error {
		if strings.TrimSpace(h.Subject) != "signup for "+config.ServiceName {
			return fmt.Errorf("other message subject")
		}
		if len(h.From) != 1 {
			return fmt.Errorf("%d from headers, need 1", len(h.From))
		}
		if h.Meta.Automated {
			return fmt.Errorf("automated message")
		}
		if !h.Meta.MsgFromValidated {
			return fmt.Errorf("message from address not validated")
		}
		return nil
	}

	if err := check(); err != nil {
		metricIncomingIgnored.Inc()
		slog.Info("incoming message not a signup", "err", err)
		fmt.Fprintln(w, "ok, no signup")
		return
	}

	// Looks good, let's try to signup/passwordreset.

	process := func() error {
		// Check if we can send. If not, abort.
		for i := 0; !sendCan(); i++ {
			if i >= 15 {
				return fmt.Errorf("signup reply not sent due to outgoing rate limit")
			}
			time.Sleep(time.Second)
		}

		ctx := r.Context()

		fromAddr, err := smtp.ParseAddress(h.From[0].Address)
		if err != nil {
			return fmt.Errorf("parsing from address: %v", err)
		}
		user, m, subject, text, html, err := signup(ctx, fromAddr, false)
		if err != nil {
			return fmt.Errorf("registering signup for user %q: %v", fromAddr.String(), err)
		} else if user.ID == 0 {
			// Should not happen for email-based signup.
			return fmt.Errorf("missing user id after signup")
		}

		sendTake()

		sendID, err := send(ctx, true, user, h.MessageID, subject, text, html)
		if err != nil {
			logErrorx("sending signup/passwordreset message", err, "userid", user.ID)
			if err := database.Delete(context.Background(), &m); err != nil {
				logErrorx("removing metamessage added before submission error", err)
			}
			return fmt.Errorf("sending signup/passwordreset for message %q: %v", user.Email, err)
		}
		ctx = context.Background()
		m.SendID = sendID
		if err := database.Update(ctx, &m); err != nil {
			logErrorx("setting sendid for sent message after submitting", err)
			return fmt.Errorf("setting sendid for sent message after submitting: %v", err)
		}

		flagsReq := webapi.MessageFlagsAddRequest{
			MsgID: h.Meta.MsgID,
			Flags: []string{config.KeywordPrefix + "signup", `\seen`, `\answered`},
		}
		if _, err := webapiClient.MessageFlagsAdd(ctx, flagsReq); err != nil {
			metricWebAPIResults.WithLabelValues("MessageFlagsAdd", webapiErrorCode(err))
			return fmt.Errorf("setting seen and answered message flags: %v", err)
		}
		metricWebAPIResults.WithLabelValues("MessageFlagsAdd", "ok")

		metricIncomingSignup.Inc()
		return nil
	}

	if err := process(); err != nil {
		metricIncomingProcessErrors.Inc()
		slog.Error("processing incoming signup request", "err", err)
		fmt.Fprintln(w, "ok, but error "+err.Error())
		return
	}
	fmt.Fprintln(w, "ok, signed up")
}

func webapiSend(ctx context.Context, meta bool, user User, origMessageID string, subject, text, html string) (fromID, messageID string, queueMsgID int64, rerr error) {
	unsubToken := user.UpdatesUnsubscribeToken
	if meta {
		unsubToken = user.MetaUnsubscribeToken
	}
	unsubscribeURL := fmt.Sprintf("%s/unsubscribe?id=%s", config.BaseURL, unsubToken)

	headers := [][2]string{
		{"User-Agent", "gopherwatch/" + version},

		// Try to prevent out-of-office notifications. RFC 3834.
		{"Auto-Submitted", "auto-generated"},

		// RFC 2919
		{"List-Id", fmt.Sprintf("%s <%d.%s>", config.ServiceName, user.ID, strings.ReplaceAll(config.SignupAddress, "@", "."))},
		{"List-Post", "NO"},
		{"List-Owner", "<mailto:" + config.Admin.Address + ">"},

		{"List-Unsubscribe", "<" + unsubscribeURL + ">"},        // // RFC 2369
		{"List-Unsubscribe-Post", "List-Unsubscribe=One-Click"}, // RFC 8058

		// RFC 2076 discourages "Precedence", it seems old and doesn't neatly fit.
	}

	var refs []string
	if origMessageID != "" {
		refs = []string{origMessageID}
	}

	req := webapi.SendRequest{
		Message: webapi.Message{
			To:         []webapi.NameAddress{{Address: user.Email}},
			References: refs,
			Subject:    subject,
			Text:       text,
			HTML:       html,
		},
		Extra:   map[string]string{"userID": fmt.Sprintf("%d", user.ID)},
		Headers: headers,
	}
	defer func() {
		result := "ok"
		if rerr != nil {
			result = webapiErrorCode(rerr)
		}
		metricWebAPIResults.WithLabelValues("Send", result)
	}()
	resp, err := webapiClient.Send(ctx, req)
	if err != nil {
		return "", "", 0, err
	}
	if len(resp.Submissions) == 0 {
		return "", "", 0, fmt.Errorf("missing submission details in response")
	}
	sub := resp.Submissions[0]
	return sub.FromID, resp.MessageID, sub.QueueMsgID, nil
}

func webapiErrorCode(err error) string {
	if xerr, ok := err.(webapi.Error); ok && xerr.Code != "" {
		return xerr.Code
	}
	return "error"
}
