package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/mjl-/bstore"
)

var hookactivity = make(chan struct{})
var hooktokens chan struct{}
var hookClient = &http.Client{Transport: hookTransport()}

func kickHooksQueue() {
	select {
	case hookactivity <- struct{}{}:
	default:
	}
}

func hookTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	// We are not likely to talk to the host again soon.
	t.IdleConnTimeout = 3 * time.Second
	t.DisableKeepAlives = true
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// We first resolve to IPs. If there are any fishy IPs, we fail the dial. Otherwise
		// we do a regular dial.
		// todo: should make sure we actually dial those same ip's. dial could do another lookup.

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("parse dial address %q: %v", addr, err)
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, strings.Replace(network, "tcp", "ip", 1), host)
		if err != nil {
			return nil, fmt.Errorf("looking up ips for host %q: %v", host, err)
		}
		for _, ip := range ips {
			if !config.WebhooksAllowInternalIPs && (ip.IsLoopback() || ip.IsPrivate()) || ip.IsMulticast() || ip.IsUnspecified() {
				return nil, fmt.Errorf("host %q resolves to ip %s, not allowed", host, ip)
			}
		}
		d := net.Dialer{}
		return d.DialContext(ctx, network, addr)
	}
	return t
}

// todo: make configurable?
const concurrentHooksMax = 10

// todo: group notifications for multiple versions of a single package in a single webhook call?

func deliverHooks() {
	// Up to N concurrent webhook calls.
	hooktokens = make(chan struct{}, concurrentHooksMax)
	for i := 0; i < concurrentHooksMax; i++ {
		hooktokens <- struct{}{}
	}

	// Wait a bit before making calls. If our process gets restarted in a loop, we
	// don't want to hammer anyone too hard.
	time.Sleep(3 * time.Second)

	timer := time.NewTimer(0)
Schedule:
	for {
		// Fetch time of first next hook to process.
		qn := bstore.QueryDB[Hook](context.Background(), database)
		qn.FilterEqual("Done", false)
		qn.FilterLessEqual("NextAttempt", time.Now())
		qn.SortAsc("NextAttempt")
		qn.Limit(1)
		firsthook, err := qn.Get()
		if err == bstore.ErrAbsent {
			// No hook to handle, wait for something to happen.
			slog.Debug("no hook to schedule, waiting for activity")
			<-hookactivity
			continue Schedule
		}
		if err != nil {
			logFatalx("looking up next hook to deliver", err)
		}
		d := time.Until(firsthook.NextAttempt)
		if d < 0 {
			d = 0
		}
		timer.Reset(d)
		select {
		case <-hookactivity:
			// Schedule again.
			continue Schedule
		case <-timer.C:
			// Time to go!
		}

		// Retrieve all hooks we might be able to start.
		qw := bstore.QueryDB[Hook](context.Background(), database)
		qw.FilterEqual("Done", false)
		qw.FilterLessEqual("NextAttempt", time.Now())
		qw.SortAsc("NextAttempt")
		qw.Limit(concurrentHooksMax)
		hooks, err := qw.List()
		if err != nil {
			logFatalx("looking up next hooks to deliver", err)
		}
		if len(hooks) == 0 {
			// Single scheduled hook could have been deleted in the mean time.
			continue Schedule
		}
		slog.Debug("found hooks to deliver", "nhooks", len(hooks))
		for _, h := range hooks {
			// Wait for token.
			<-hooktokens

			// Try to get delivered.
			if err := prepareDeliverHook(h); err != nil {
				slog.Error("delivering hook", "err", err, "hook", h.ID)
			}
		}
	}
}

// Mark hook as busy delivering (setting NextAttempt and Attempts), fetch needed
// data. If all good, launch request in goroutine.
func prepareDeliverHook(h Hook) (rerr error) {
	log := slog.With("hook", h.ID, "attempts", h.Attempts)

	// Ensure we are returning the token if we end up not delivering.
	var delivering bool
	defer func() {
		if !delivering {
			hooktokens <- struct{}{}
			kickHooksQueue()
		}
	}()

	// Get hookconfig, for url. Increase attempts and set nextattempt in future early
	// on, so we won't be hammering servers in failure modes.
	var modup ModuleUpdate
	var hc HookConfig
	var nodeliver bool
	err := database.Write(context.Background(), func(tx *bstore.Tx) error {
		// Get fresh hook again, it could have vanished in the mean time.
		if err := tx.Get(&h); err != nil {
			return err
		}

		// We need the URL.
		hc = HookConfig{ID: h.HookConfigID}
		if err := tx.Get(&hc); err != nil {
			return fmt.Errorf("lookup hook config: %v", err)
		}
		log = log.With("webhookconfig", hc.Name, "url", hc.URL)

		// Get the ModuleUpdate, needed to form the payload.
		var err error
		modup, err = bstore.QueryTx[ModuleUpdate](tx).FilterNonzero(ModuleUpdate{HookID: h.ID}).Get()
		if err != nil {
			return fmt.Errorf("looking up moduleupdate: %v", err)
		}

		// Set next attempt before we start processing, so we at least won't keep
		// processing the same hook in case of fatal errors.

		// If hook config got disabled in the mean time, mark as done and failed.
		if hc.Disabled {
			log.Info("hook config is disabled, not delivering hook")
			h.Done = true
			h.Results = append(h.Results, HookResult{Error: "Hook config is disabled."})
			nodeliver = true
			return tx.Update(&h)
		}

		d := 15 * time.Minute / 2
		for i := 0; i < h.Attempts; i++ {
			d *= 2
		}
		h.Attempts++
		h.NextAttempt = h.NextAttempt.Add(d)

		// If we've seen a 429 in the past minute for this HookConfig, we postpone.
		q := bstore.QueryTx[Hook](tx)
		q.FilterNonzero(Hook{HookConfigID: hc.ID})
		q.FilterGreater("LastResult", time.Now().Add(-time.Minute))
		q.FilterFn(func(qh Hook) bool {
			return len(qh.Results) > 0 && qh.Results[len(qh.Results)-1].StatusCode == http.StatusTooManyRequests
		})
		toofast, err := q.Exists()
		if err != nil {
			return fmt.Errorf(`checking for recent http "429 too many request" responses: %v`, err)
		}

		log = log.With("nextattempt", h.NextAttempt, "newattempts", h.Attempts)
		if toofast {
			log.Info("not delivering hook due to too many requests")
			nodeliver = true
		} else {
			log.Debug("ready to deliver hook")
		}
		return tx.Update(&h)
	})
	if err != nil {
		return fmt.Errorf("updating hook before delivery attempt: %v", err)
	}

	if nodeliver {
		return nil
	}

	// Make request in goroutine. It is responsible for returning the token.
	go deliverHook(h, hc, modup)
	delivering = true
	return nil
}

// todo: should we have signatures on our webhook calls? what would we protect against?

// Actually try to deliver.
func deliverHook(h Hook, hc HookConfig, modup ModuleUpdate) (rerr error) {
	// rerr is only used in recover.

	log := slog.With("hook", h.ID, "attempts", h.Attempts)

	// Always return token.
	defer func() {
		hooktokens <- struct{}{}
		kickHooksQueue()
	}()

	// Prevent crash for panic.
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		metricPanics.Inc()
		slog.Error("uncaught panic delivering hook", "x", x, "hook", h.ID)
		debug.PrintStack()
	}()

	// If we encountered an error, we may disable the HookConfig automatically.
	defer func() {
		if !h.Done || len(h.Results) == 0 || h.Results[len(h.Results)-1].StatusCode/100 == 2 {
			return
		}
		// Delivery failed. If the last 10 deliveries all failed, or if all deliveries in
		// the past 7 days failed (minimum 2), we mark the hookconfig as disabled to
		// prevent continued annoyance.
		var n int
		err := database.Write(context.Background(), func(tx *bstore.Tx) error {
			q := bstore.QueryTx[Hook](tx)
			q.FilterNonzero(Hook{HookConfigID: h.HookConfigID})
			q.FilterGreater("LastResult", time.Now().Add(-7*24*time.Hour))
			q.Limit(10)
			err := q.ForEach(func(qh Hook) error {
				if qh.Done && len(qh.Results) > 0 && qh.Results[len(qh.Results)-1].StatusCode/100 != 2 {
					n++
				}
				if qh.Done {
					// Successful delivery.
					n = 0
					return bstore.StopForEach
				}
				return nil
			})
			if err != nil {
				return err
			}
			if n >= 2 {
				// todo: should send an email about this, if possible according to rate limits and metasubscription.
				log.Info("disabling webhook config due to repeated delivery failures")
				hc = HookConfig{ID: hc.ID}
				if err := tx.Get(&hc); err != nil {
					return fmt.Errorf("get hook config: %v", err)
				}
				hc.Disabled = true
				if err := tx.Update(&hc); err != nil {
					return fmt.Errorf("disabling hook config: %v", err)
				}
				msg := "Disabling webhook config %q due to repeated delivery failures"
				log.Info("adding log for user id", "userid", h.UserID, "msg", msg)
				if err := tx.Insert(&UserLog{UserID: h.UserID, Text: msg}); err != nil {
					return fmt.Errorf("inserting user log about disabling webhook config")
				}
			}
			return nil
		})
		if err != nil {
			log.Error("looking at disabling hook config after delivery failure", "err", err)
		}
	}()

	// todo: should we do more checks against the URL we are about to request? eg have a blocklist of domains/ips (against abuse), or rate limit per destination domain?

	// Turn a Go error into a HookResult and possibly mark as completely failed. These
	// results are used by the defer funtion above. Not triggered for negatory HTTP
	// responses.
	defer func() {
		if rerr == nil {
			return
		}

		log.Debug("webhook request failed", "err", rerr)
		metricHookResponse.WithLabelValues("error").Inc()
		h.LastResult = time.Now()
		h.Results = append(h.Results, HookResult{Start: h.LastResult, Error: rerr.Error()})
		h.Done = h.Attempts >= 9
		if err := database.Update(context.Background(), &h); err != nil {
			log.Error("error while adding delivery error to hook", "err", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// todo: also send sum? parsed version? last known version we had? more fields?
	data := hookData{modup.Module, modup.Version, modup.LogRecordID, modup.Discovered}
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal hook json payload: %v", err)
	}

	// Request we'll be sending.
	req, err := http.NewRequestWithContext(ctx, "POST", hc.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("new http request: %v", err)
	}

	// Add headers. We use Set, not Add. Let's keep it simple.
	for _, tup := range hc.Headers {
		req.Header.Set(tup[0], tup[1])
	}
	// todo: store unsubscribe token in hookconfig, include it in user-agent, and allow website owner to enter it on /webhooks to disable future calls from this hook config.
	req.Header.Set("User-Agent", fmt.Sprintf("gopherwatch/%s (see %s/webhooks)", version, config.BaseURL))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	// Finally make the call.
	start := time.Now()
	resp, err := hookClient.Do(req)
	metricHookRequest.Observe(float64(time.Since(start) / time.Second))
	if err != nil {
		return fmt.Errorf("http transaction: %v", err)
	}
	defer resp.Body.Close()

	log.Debug("webhook response", "status", resp.StatusCode)
	result := fmt.Sprintf("%dxx", resp.StatusCode/100)
	metricHookResponse.WithLabelValues(result).Inc()

	// Be nice and read a reasonable amount of response data. We don't want to consume
	// much more. We don't care about errors, the status code is what matters.
	respFragment, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	var response string
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	if ct == "text/plain" || ct == "application/json" {
		response = string(respFragment)
	}
	h.LastResult = time.Now()
	h.Results = append(h.Results, HookResult{
		StatusCode: resp.StatusCode,
		Start:      start,
		Response:   response,
		DurationMS: int64(h.LastResult.Sub(start) / time.Millisecond),
	})
	// Attempts: 0m, 7.5m, 15m, 30m, 1h, 2h, 4h, 8h, 16h; 9 total.
	h.Done = resp.StatusCode/100 == 2 || resp.StatusCode == http.StatusForbidden || h.Attempts >= 9
	// Store the result.
	if err = database.Update(context.Background(), &h); err != nil {
		// We're not returning an error anymore, we don't want to add another result.
		log.Error("updating hook after delivery", "err", err)
	}
	return nil
}

// JSON payload we send in webhook.
type hookData struct {
	Module      string
	Version     string
	LogRecordID int64
	Discovered  time.Time
}
