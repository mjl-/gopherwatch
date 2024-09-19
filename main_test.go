package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/dirhash"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/webapi"
	"github.com/mjl-/mox/webhook"
	"github.com/mjl-/sherpa"
)

// todo: test rate limits, imap/submission, more backing off, webhook delivery failure handling and HookCancel/HookKick api calls.

var ctxbg = context.Background()

func tcheckf(t *testing.T, err error, format string, args ...any) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func tcompare(t *testing.T, got, exp any) {
	if !reflect.DeepEqual(got, exp) {
		t.Helper()
		t.Fatalf("got %v, expected %v (%#v != %#v)", got, exp, got, exp)
	}
}

func thttppost(t *testing.T, mux http.Handler, path string, data url.Values, expCode int) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != expCode {
		t.Fatalf("http post to %s: got status %d, expected %d", path, w.Code, expCode)
	}
}

func thttpget(t *testing.T, mux http.Handler, path string, headers map[string]string, expCode int) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != expCode {
		t.Fatalf("http post to %s: got status %d, expected %d", path, w.Code, expCode)
	}
}

func thttpsherpa(t *testing.T, mux http.Handler, path string, csrf, session string, params []any, expCode string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"params": params})
	tcheckf(t, err, "marshal request")
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Add("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Add("x-csrf", csrf)
	}
	if session != "" {
		c := http.Cookie{
			Name:     "gopherwatchsession",
			Value:    session,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
		req.AddCookie(&c)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("http post to %s: got status %d, expected 200 ok", path, w.Code)
	}
	var resp struct {
		Error  *sherpa.Error `json:"error"`
		Result any           `json:"result"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	tcheckf(t, err, "unmarshal body")
	if (expCode == "") != (resp.Error == nil) || expCode != "" && resp.Error.Code != expCode {
		t.Fatalf("expected code %q, got error %v", expCode, resp.Error)
	}
}

func tneederr(t *testing.T, code string, fn func()) {
	t.Helper()
	defer func() {
		t.Helper()
		x := recover()
		// We panic so we get stack traces in the error.
		if x == nil {
			panic(fmt.Sprintf("expected error code %q, got no error", code))
		}
		err, ok := x.(*sherpa.Error)
		if !ok {
			panic(fmt.Sprintf("expected error code %q, got other panic type %T %v", code, x, x))
		}
		if err.Code != code {
			panic(fmt.Sprintf("expected error code %q, got  %q", code, err.Code))
		}
	}()
	fn()
}

func tneedmail(t *testing.T, subject string) moxtx {
	t.Helper()
	return tneedmail0(t, config.SubjectPrefix+subject)
}

func tneedmail0(t *testing.T, subject string) moxtx {
	t.Helper()
	select {
	case mailSubmitted <- struct{}{}:
		// Trigger mox webhook for outgoing delivery.
	case <-time.After(time.Second):
		t.Fatalf("no mail submission within 1s")
	}
	select {
	case <-mailDelivered:
		// Wait for mail delivery.
	case <-time.After(time.Second):
		t.Fatalf("no mail received within 1s")
	}
	if len(moxapiTx) != 1 {
		t.Fatalf("mails sent %#v", moxapiTx)
	}
	tcompare(t, len(moxapiTx), 1)
	tx := moxapiTx[0]
	tcompare(t, tx.Subject, subject)
	moxapiTx = nil
	return tx
}

var sumsrv *sumdb.TestServer
var sumindex []indexMod

type indexMod struct {
	Path      string
	Version   string
	Timestamp time.Time
}

func gosumOK(path, version string) ([]byte, error) {
	escpath, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	escvers, err := module.EscapeVersion(version)
	if err != nil {
		return nil, err
	}
	h1, err := dirhash.Hash1(nil, nil)
	if err != nil {
		return nil, err
	}
	sumindex = append(sumindex, indexMod{path, version, time.Now()})
	s := fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", escpath, escvers, h1, escpath, escvers, h1)
	return []byte(s), nil
}

var gosum = gosumOK

func indexHandler(w http.ResponseWriter, r *http.Request) {
	for _, m := range sumindex {
		if err := json.NewEncoder(w).Encode(m); err != nil {
			break
		}
	}
}

type moxtx struct {
	webapi.SendRequest
	webapi.SendResult
}

var moxapiTx []moxtx
var moxapiCount int64
var moxhookout *httptest.Server
var moxhookin *httptest.Server
var mailSubmitted = make(chan struct{})
var mailDelivered = make(chan struct{})
var outgoingEvent = webhook.EventDelivered

func moxapiHandler(w http.ResponseWriter, r *http.Request) {
	// Calls by gopherwatch to mox, typically to send an email.

	if r.URL.Path == "/MessageFlagsAdd" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webapi.MessageFlagsAddResult{})
		return
	}
	if r.URL.Path != "/Send" {
		http.NotFound(w, r)
		return
	}

	reqstr := r.PostFormValue("request")
	var req webapi.SendRequest
	err := json.Unmarshal([]byte(reqstr), &req)
	if err != nil {
		log.Printf("parsing send request: %v", err)
		http.Error(w, "500 - server error - "+err.Error(), http.StatusInternalServerError)
		return
	}

	moxapiCount++
	result := webapi.SendResult{
		MessageID: random() + "@localhost",
		Submissions: []webapi.Submission{
			{
				Address:    req.To[0].Address,
				QueueMsgID: moxapiCount,
				FromID:     random(),
			},
		},
	}

	// Send webhook for success.
	out := webhook.Outgoing{
		Event:         outgoingEvent,
		QueueMsgID:    result.Submissions[0].QueueMsgID,
		FromID:        result.Submissions[0].FromID,
		MessageID:     result.MessageID,
		Subject:       req.Subject,
		WebhookQueued: time.Now(),
		Extra:         req.Extra,
	}
	outbuf, err := json.Marshal(out)
	if err != nil {
		log.Printf("marshal mox outgoing webhook: %v", err)
		http.Error(w, "500 - server error - "+err.Error(), http.StatusInternalServerError)
		return
	}
	u := moxhookout.URL + config.Mox.Webhook.OutgoingPath
	outreq, err := http.NewRequest("POST", u, bytes.NewReader(outbuf))
	if err != nil {
		log.Printf("request for outgoing webhook: %v", err)
		http.Error(w, "500 - server error - "+err.Error(), http.StatusInternalServerError)
		return
	}
	outreq.Header.Set("Content-Type", "application/json")
	outreq.SetBasicAuth(config.Mox.Webhook.Username, config.Mox.Webhook.Password)

	moxapiTx = append(moxapiTx, moxtx{req, result})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)

	go func() {
		<-mailSubmitted // Interaction with test, waiting for SendID/FromID to be registered.
		outresp, err := http.DefaultClient.Do(outreq)
		if err != nil {
			log.Printf("http transaction for outgoing webhook: %v", err)
			http.Error(w, "500 - server error - "+err.Error(), http.StatusInternalServerError)
			return
		}
		if outresp.StatusCode != http.StatusOK {
			log.Printf("http transaction status for outgoing webhook: %v", outresp.Status)
			http.Error(w, "500 - server error - "+err.Error(), http.StatusInternalServerError)
			return
		}
		mailDelivered <- struct{}{}
	}()
}

func TestMain(t *testing.M) {
	log.SetFlags(0)
	loglevel.Set(slog.LevelDebug)

	dataDir = "testdata/tmp/data"
	os.RemoveAll(dataDir)

	dbpath := "testdata/tmp/gopherwatch.db"
	os.MkdirAll(filepath.Dir(dbpath), 0750)
	os.Remove(dbpath)

	ratelimitSumdb = makeLimiter(windowLimit(time.Second, 1000, 1000, 1000))

	const skey = "PRIVATE+KEY+localhost+7af406a6+AR65vBDzmd0yI/rsoMwbg5sYgFWIF2Z3TgtWaGxWEu1+"
	const vkey = "localhost+7af406a6+AfWA0P/5hn0K1/QybqsBg3fD+9XzPNB/v1QG73x/K8Gi"
	sumsrv = sumdb.NewTestServer(skey, func(path, version string) ([]byte, error) {
		return gosum(path, version)
	})

	fakemox := httptest.NewServer(http.HandlerFunc(moxapiHandler))
	moxhookout = httptest.NewServer(http.HandlerFunc(webhookOutgoing))
	moxhookin = httptest.NewServer(http.HandlerFunc(webhookIncoming))
	sumhttpsrv := httptest.NewServer(NewServer(sumsrv)) // todo: replace with sumdb.NewServer once fixed
	fakeindex := httptest.NewServer(http.HandlerFunc(indexHandler))

	config = Config{
		BaseURL:     "http://localhost",
		TokenSecret: "test1234",
		ServiceName: "gw test",
		Admin: Admin{
			Address:       "gopherwatch@gw.example",
			AddressParsed: smtp.Address{Localpart: "gopherwatch", Domain: dns.Domain{ASCII: "gw.example"}},
			Password:      "admin1234",
		},
		SubjectPrefix:        "gwtest: ",
		DailyMetaMessagesMax: 100,
		EmailUpdateInterval:  0,
		SumDB: SumDB{
			BaseURL:             sumhttpsrv.URL,
			VerifierKey:         vkey,
			QueryLatestInterval: time.Hour, // We manually forward the tlog during tests.
		},
		IndexBaseURL:  fakeindex.URL,
		SignupAddress: "signup@gw.example",
		KeywordPrefix: "gw:",
		Mox: &Mox{
			WebAPI: WebAPI{
				BaseURL:  fakemox.URL + "/",
				Username: "mox@localhost",
				Password: "test1234",
			},
			Webhook: Webhook{
				OutgoingPath: "/out",
				IncomingPath: "/in",
				Username:     "gw@localhost",
				Password:     "test1234",
			},
		},
		WebhooksAllowInternalIPs: true,
		SkipModulePrefixes:       []string{"mirror.localhost/"},
		SkipModulePaths:          []string{"huge.localhost"},
	}

	servePrep(dbpath)

	if err := tlogclient.init(); err != nil {
		log.Fatalf("tlogclient init: %v", err)
	}
	if _, err := initTlog(); err != nil {
		log.Fatalf("tlog init: %v", err)
	}

	os.Exit(t.Run())
}
