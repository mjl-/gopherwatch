package main

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	"embed"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mjl-/bstore"
	"github.com/mjl-/mox/webapi"
	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"
)

var dbtypes = []any{TreeState{}, User{}, UserLog{}, Subscription{}, ModuleUpdate{}, Message{}, ModuleVersion{}, HookConfig{}, Hook{}, HookResult{}}

// All users, subscriptions, updates and sumdb state are in the database.
var database *bstore.DB

var dataDir string

// The sumdb transparency log we keep moving forward, verifying the new entries and
// matching new packages against subscriptions.
var tlogclient *Client

var webapiClient loggingWebAPIClient

// For Message-ID headers.
var hostname string

//go:embed api.json
var apiJSON []byte

//go:embed index.html
var indexHTML []byte

//go:embed index.js
var indexJS []byte

//go:embed webhooks.html
var webhooksHTML []byte

//go:embed unsubscribe.html
var unsubscribeHTML string

//go:embed unsubscribed.html
var unsubscribedHTML string

//go:embed viewuser.template.html
var viewuserHTML string
var viewuserTemplate = htmltemplate.Must(htmltemplate.New("viewuser").Parse(viewuserHTML))

//go:embed mail.template.html
var mailTemplateHTML string

//go:embed mail.signup.txt
var mailSignupText string

//go:embed mail.signup.html
var mailSignupHTML string

//go:embed mail.passwordreset.txt
var mailPasswordResetText string

//go:embed mail.passwordreset.html
var mailPasswordResetHTML string

//go:embed mail.moduleupdates.txt
var mailModuleUpdatesText string

//go:embed mail.moduleupdates.html
var mailModuleUpdatesHTML string

//go:embed favicon.ico
var files embed.FS

var (
	templateHTML = htmltemplate.Must(htmltemplate.New("mail.template.html").Parse(mailTemplateHTML))

	templSignupText = texttemplate.Must(texttemplate.New("mail.signup.txt").Parse(mailSignupText))
	templSignupHTML = htmltemplate.Must(htmltemplate.New("mail.signup.html").Parse(mailSignupHTML))

	templPasswordResetText = texttemplate.Must(texttemplate.New("mail.passwordreset.txt").Parse(mailPasswordResetText))
	templPasswordResetHTML = htmltemplate.Must(htmltemplate.New("mail.passwordreset.html").Parse(mailPasswordResetHTML))

	templModuleUpdatesText = texttemplate.Must(texttemplate.New("mail.moduleupdates.txt").Parse(mailModuleUpdatesText))
	templModuleUpdatesHTML = htmltemplate.Must(htmltemplate.New("mail.moduleupdates.html").Parse(mailModuleUpdatesHTML))
)

func mustParseAPI(api string, buf []byte) (doc sherpadoc.Section) {
	err := json.Unmarshal(buf, &doc)
	if err != nil {
		logFatalx("parsing api docs", err)
	}
	return doc
}

var resetTree bool
var publicMux = http.NewServeMux()
var metricsMux = http.NewServeMux()
var webhookMux *http.ServeMux

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var configPath string
	var listenAddr, metricsAddr, adminAddr, webhookAddr string
	var dbpath string
	fs.StringVar(&configPath, "config", "gopherwatch.conf", "path to config file")
	fs.StringVar(&listenAddr, "listenaddr", "127.0.0.1:8073", "address to listen and serve public gopherwatch on")
	fs.StringVar(&metricsAddr, "metricsaddr", "127.0.0.1:8074", "address to listen and serve metrics on")
	fs.StringVar(&adminAddr, "adminaddr", "127.0.0.1:8075", "address to listen and serve the admin requests on")
	fs.StringVar(&webhookAddr, "webhookaddr", "127.0.0.1:8076", "address to listen and serve the mox webhook requests on")
	fs.StringVar(&dbpath, "dbpath", "gopherwatch.db", "database, with users, subscriptions, etc")
	fs.StringVar(&dataDir, "datadir", "data", "directory with tile cache and where instance notes are read from")
	fs.BoolVar(&resetTree, "resettree", false, "reset tree state, useful to prevent catching up for a long time after not running local/test instance for a while")
	fs.Parse(args)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gopherwatch serve [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}
	args = fs.Args()
	if len(args) != 0 {
		fs.Usage()
	}

	if err := parseConfig(configPath); err != nil {
		logFatalx("parsing config file", err)
	}

	// Prepare environment, also used by tests.
	servePrep(dbpath)

	go openTlog()

	// Start delivery of webhooks.
	go deliverHooks()

	slog.Warn("listening for public", "addr", listenAddr)
	if metricsAddr != "" {
		slog.Warn("listening for metrics", "metricsaddr", metricsAddr)
		go func() {
			logFatalx("metrics listener", http.ListenAndServe(metricsAddr, metricsMux))
		}()
	}
	if adminAddr != "" {
		slog.Warn("listening for admin", "adminaddr", adminAddr)
		go func() {
			logFatalx("admin listener", http.ListenAndServe(adminAddr, nil))
		}()
	}
	if webhookMux != nil && webhookAddr != "" {
		slog.Warn("listening for webhooks", "webhookaddr", webhookAddr)
		go func() {
			logFatalx("webhook listener", http.ListenAndServe(webhookAddr, webhookMux))
		}()
	}
	logFatalx("public listener", http.ListenAndServe(listenAddr, publicMux))
}

func servePrep(dbpath string) {
	// todo: get fqdn from host somehow, only needed for smtp/imap-mode, where we compose our message ourselves and we use the hostname in message-id headers, which should be unique.
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		logFatalx("get hostname", err)
	}

	db, err := bstore.Open(context.Background(), dbpath, nil, dbtypes...)
	if err != nil {
		logFatalx("opening database", err)
	}
	if err = db.HintAppend(true, ModuleVersion{}); err != nil {
		logFatalx("append-only hint: %v", err)
	}
	database = db

	cops := ops{URL: config.SumDB.BaseURL}
	tlogclient = NewClient(config.SumDB.VerifierKey, &cops)
	if err := tlogclient.init(); err != nil {
		logFatalx("client init", err)
	}

	publicMux.HandleFunc("GET /{$}", serveIndexHTML)
	publicMux.Handle("GET /favicon.ico", http.FileServerFS(files))
	publicMux.HandleFunc("GET /webhooks", serveWebhooksHTML)
	publicMux.HandleFunc("GET /forward", serveForward)

	// Unsubscribe is not part of regular frontend JS because we cannot have parameters
	// in the URL fragment in List-Unsubscribe: It would be lost when we automatically
	// submit the form to unsubscribe. The HTML has a JS that triggers the unsubscribe
	// after 1 second. That should prevent automated tools from unsubscribing.
	publicMux.HandleFunc("GET /unsubscribe", serveUnsubscribeGet)
	// For one-click unsubscribe, and HTML page also submits to it.
	publicMux.HandleFunc("POST /unsubscribe", serveUnsubscribePost)

	apiDoc := mustParseAPI("api", apiJSON)

	collector, err := sherpaprom.NewCollector("gopherwatch", nil)
	if err != nil {
		logFatalx("creating sherpa prometheus collector", err)
	}
	sherpaOpts := sherpa.HandlerOpts{Collector: collector, AdjustFunctionNames: "none", NoCORS: true}
	apiHandler, err := sherpa.NewHandler("/api/", version, API{}, &apiDoc, &sherpaOpts)
	if err != nil {
		logFatalx("making api handler", err)
	}

	publicMux.HandleFunc("/api/", serveAPI(apiHandler))
	publicMux.HandleFunc("GET /preview/{$}", serveMailPreviewIndex)
	publicMux.HandleFunc("GET /preview/{kind}/{$}", serveMailPreviewFormats)
	publicMux.HandleFunc("GET /preview/{kind}/{format}", serveMailPreview)

	// Prometheus metrics served on a separate port.
	metricsMux = http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())

	// Admin endpoints served on a separate port. Requires HTTP basic auth from the config file.
	http.HandleFunc("GET /", serveAdmin)

	if config.SubmissionIMAP != nil {
		// Watch mailbox over IMAP for DSNs and signup messages. uses IMAP IDLE to wait for
		// incoming messages.
		go mailWatch()
	} else {
		// Register HTTP handler for webhooks.
		webhookMux = http.NewServeMux()
		webhookMux.HandleFunc("POST "+config.Mox.Webhook.OutgoingPath, webhookOutgoing)
		webhookMux.HandleFunc("POST "+config.Mox.Webhook.IncomingPath, webhookIncoming)

		initWebAPIClient()
	}
}

func safeHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'; form-action 'self'")
}

func httpErrorf(w http.ResponseWriter, r *http.Request, code int, format string, args ...any) {
	err := fmt.Errorf(format, args...)
	if code/100 == 5 {
		slog.Error("http request error", "err", err, "code", code, "method", r.Method, "path", r.URL.Path)
		debug.PrintStack()
	} else {
		slog.Debug("http request error", "err", err, "code", code, "method", r.Method, "path", r.URL.Path)
	}
	http.Error(w, fmt.Sprintf("%d - %s - %s", code, http.StatusText(code), err), code)
}

func initWebAPIClient() {
	webapiClient = loggingWebAPIClient{webapi.Client{
		BaseURL:    config.Mox.WebAPI.BaseURL,
		Username:   config.Mox.WebAPI.Username,
		Password:   config.Mox.WebAPI.Password,
		HTTPClient: &http.Client{Transport: transportShortIdle()},
	}}
}

func transportShortIdle() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 3
	t.IdleConnTimeout = 5 * time.Second
	return t
}

func serveIndexHTML(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile("index.html")
	if err != nil {
		html = indexHTML
	}
	js, err := os.ReadFile("index.js")
	if err != nil {
		js = indexJS
	}
	out := string(html)
	out = strings.ReplaceAll(out, "/* placeholder */", string(js))

	// todo: keep combined version around, also compressed.

	h := w.Header()
	safeHeaders(h)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache, max-age=0")
	w.Write([]byte(out))
}

func serveWebhooksHTML(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	safeHeaders(h)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache, max-age=0")
	w.Write(webhooksHTML)
}

func serveForward(w http.ResponseWriter, r *http.Request) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		err, ok := x.(*sherpa.Error)
		if !ok {
			panic(x)
		}
		code := http.StatusBadRequest
		if strings.HasPrefix(err.Code, "server:") {
			code = http.StatusInternalServerError
		}
		httpErrorf(w, r, code, "%s: %s", err.Code, err.Message)
	}()

	reqInfo := requestInfo{"", 0, w, r}
	ctx := context.WithValue(r.Context(), requestInfoCtxKey, reqInfo)
	API{}.Forward(ctx)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "ok")
}

func serveUnsubscribeGet(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	safeHeaders(h)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache, max-age=0")
	w.Write([]byte(unsubscribeHTML))
}

func serveUnsubscribePost(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		httpErrorf(w, r, http.StatusBadRequest, "missing id to identify user")
		return
	}

	err := database.Write(r.Context(), func(tx *bstore.Tx) error {
		var meta bool
		user, err := bstore.QueryTx[User](tx).FilterNonzero(User{UpdatesUnsubscribeToken: id}).Get()
		if err == bstore.ErrAbsent {
			user, err = bstore.QueryTx[User](tx).FilterNonzero(User{MetaUnsubscribeToken: id}).Get()
			if err == nil {
				meta = true
			}
		}
		if err != nil {
			return err
		}
		var kind string
		user.UpdatesUnsubscribed = true
		if meta {
			user.MetaUnsubscribed = true
			kind = "module updates and service messages"
		} else {
			kind = "module updates"
		}
		if err := tx.Update(&user); err != nil {
			return fmt.Errorf("marking user as unsubscribed in database: %v", err)
		}

		xaddUserLogf(tx, user.ID, "Unsubscribed for %s", kind)
		return nil
	})
	if err != nil && errors.Is(err, bstore.ErrAbsent) {
		httpErrorf(w, r, http.StatusBadRequest, "cannot find user for unsubscribe id")
		return
	} else if err != nil {
		httpErrorf(w, r, http.StatusInternalServerError, "unsubscribing: %v", err)
		return
	}

	h := w.Header()
	safeHeaders(h)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache, max-age=0")
	w.Write([]byte(unsubscribedHTML))
}

func serveAPI(apiHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		safeHeaders(w.Header())

		if r.Method != "POST" && r.URL.Path != "/api/" {
			httpErrorf(w, r, http.StatusMethodNotAllowed, "use post")
			return
		}

		// Check auth, except for some calls.
		var user User
		switch r.URL.Path {
		case "/api/",
			"/api/_docs",
			"/api/Prep",
			"/api/Signup",
			"/api/SignupEmail",
			"/api/VerifySignup",
			"/api/Login",
			"/api/RequestPasswordReset",
			"/api/ResetPassword",
			"/api/Redeem",
			"/api/Home",
			"/api/Recents",
			"/api/Forward",
			"/api/TestSend":
		default:
			// Handle authentication-related sherpa errors.
			defer func() {
				x := recover()
				if x == nil {
					return
				}
				err, ok := x.(*sherpa.Error)
				if !ok {
					panic(x)
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Cache-Control", "no-cache, max-age=0")
				json.NewEncoder(w).Encode(struct {
					Error error `json:"error"`
				}{err})
			}()

			// All other endpoints require authentication.
			csrfToken := r.Header.Get("x-csrf")
			sessionCookie, _ := r.Cookie("gopherwatchsession")
			if csrfToken == "" && sessionCookie == nil || sessionCookie.Value == "" {
				panic(&sherpa.Error{Code: "user:noAuth", Message: "no session"})
			}

			csrfUserID := xtokenVerify(tokentypeCSRF, csrfToken)
			sessionUserID := xtokenVerify(tokentypeSession, sessionCookie.Value)
			if csrfUserID != sessionUserID {
				panic(&sherpa.Error{Code: "user:badAuth", Message: "bad csrf/session"})
			}
			user = User{ID: csrfUserID}
			if err := database.Get(r.Context(), &user); err == bstore.ErrAbsent {
				// user:badAuth will trigger the login prompt.
				panic(&sherpa.Error{Code: "user:badAuth", Message: "unknown user"})
			} else if err != nil {
				panic(&sherpa.Error{Code: "server:error", Message: "server error while validating user"})
			}
		}

		// Note: user email and id may be zero values.
		reqInfo := requestInfo{user.Email, user.ID, w, r}
		ctx := context.WithValue(r.Context(), requestInfoCtxKey, reqInfo)
		apiHandler.ServeHTTP(w, r.WithContext(ctx))
	}
}

func serveMailPreviewIndex(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	safeHeaders(h)
	h.Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><body>Templates: <a href="signup/">signup</a> <a href="passwordreset/">passwordreset</a> <a href="moduleupdates/">moduleupdates</a></body></html>`)
}

func serveMailPreviewFormats(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	safeHeaders(h)

	switch r.PathValue("kind") {
	case "signup", "passwordreset", "moduleupdates":
	default:
		http.NotFound(w, r)
		return
	}

	h.Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><style>iframe { border: 1px solid #ccc; background-color: white; }</style></head><body style="background-color: #eee"><div style="display: flex; justify-content: space-between"><div><h1>Text</h1><iframe style="width: 45vw; min-height: 90vh" src="text"></iframe></div><div><h1>HTML</h1><iframe style="width: 45vw; min-height: 90vh" src="html"></iframe></div></div></body></html>`)
}

func serveMailPreview(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	safeHeaders(h)

	format := r.PathValue("format")
	switch format {
	case "text", "html":
	default:
		http.NotFound(w, r)
		return
	}
	user := User{
		ID:                      1,
		Email:                   "gopherwatch@example.org",
		VerifyToken:             "SNrFOQ3bJ1kB90f7uIcpqQ",
		PasswordResetToken:      "Z8jE8SCACkZxny78zRnlwg",
		MetaUnsubscribeToken:    "uCU5AOH3vuxf8uycCCMlyg",
		UpdatesUnsubscribeToken: "lMfq7mAwtnZqvBO_3mqQJg",
	}
	loginToken := "naV4yBLcSNRCmCYoECffHy0A5QIABIqv971xSwxZ1q6w3QwC"
	_, text, html, err := composeSample(r.PathValue("kind"), user, loginToken)
	if err != nil {
		httpErrorf(w, r, http.StatusInternalServerError, "composing message: %v", err)
		return
	}
	h.Set("Cache-Control", "no-cache, max-age=0")
	if format == "text" {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(text))
	} else {
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
	}
}

type dbtype struct {
	Name    string
	Fields  []string
	Records [][]string
}

func gatherType[T any](tx *bstore.Tx, typeValues map[string]dbtype, typeName string, filter T, getID func(v T) int64) error {
	t := dbtype{Name: typeName}

	err := bstore.QueryTx[T](tx).FilterNonzero(filter).SortDesc("ID").ForEach(func(v T) error {
		id := getID(v)
		kv, err := tx.Record(typeName, fmt.Sprintf("%d", id), &t.Fields)
		if err != nil {
			return err
		}
		r := make([]string, len(t.Fields))
		for i, f := range t.Fields {
			r[i] = fmt.Sprintf("%v", kv[f])
		}
		t.Records = append(t.Records, r)
		return nil
	})
	if err != nil {
		return err
	}
	if len(t.Records) > 0 {
		typeValues[typeName] = t
	}
	return nil
}

func serveAdmin(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if config.Admin.Password == "" || auth != "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:"+config.Admin.Password)) {
		w.Header().Set("WWW-Authenticate", `Basic realm="gopherwatch admin"`)
		httpErrorf(w, r, http.StatusUnauthorized, "missing/bad basic authentication credentials")
		return
	}

	switch r.URL.Path {
	case "/viewuser", "/viewuser.csv.zip":
		// Serve all information we have for an account. The .csv.zip variant returns the
		// same information, but as zip file, for offline comparison.

		email := r.FormValue("email")
		if email == "" {
			httpErrorf(w, r, http.StatusBadRequest, "missing parameter email")
			return
		}

		var user User
		typeValues := map[string]dbtype{}

		err := database.Read(r.Context(), func(tx *bstore.Tx) error {
			var err error
			user, err = bstore.QueryTx[User](tx).FilterNonzero(User{Email: email}).Get()
			if err != nil {
				return err
			}

			if err := gatherType(tx, typeValues, "User", User{ID: user.ID}, func(v User) int64 { return v.ID }); err != nil {
				return err
			}
			if err := gatherType(tx, typeValues, "UserLog", UserLog{UserID: user.ID}, func(v UserLog) int64 { return v.ID }); err != nil {
				return err
			}
			if err := gatherType(tx, typeValues, "Subscription", Subscription{UserID: user.ID}, func(v Subscription) int64 { return v.ID }); err != nil {
				return err
			}
			if err := gatherType(tx, typeValues, "HookConfig", HookConfig{UserID: user.ID}, func(v HookConfig) int64 { return v.ID }); err != nil {
				return err
			}
			if err := gatherType(tx, typeValues, "Hook", Hook{UserID: user.ID}, func(v Hook) int64 { return v.ID }); err != nil {
				return err
			}
			if err := gatherType(tx, typeValues, "ModuleUpdate", ModuleUpdate{UserID: user.ID}, func(v ModuleUpdate) int64 { return v.ID }); err != nil {
				return err
			}
			if err := gatherType(tx, typeValues, "Message", Message{UserID: user.ID}, func(v Message) int64 { return v.ID }); err != nil {
				return err
			}

			return nil
		})
		if err == bstore.ErrAbsent {
			httpErrorf(w, r, http.StatusBadRequest, "user not found")
			return
		} else if err != nil {
			httpErrorf(w, r, http.StatusInternalServerError, "gathering user data: %v", err)
			return
		}

		var l []dbtype
		for _, t := range typeValues {
			l = append(l, t)
		}
		sort.Slice(l, func(i, j int) bool {
			return l[i].Name < l[j].Name
		})

		h := w.Header()
		if r.URL.Path == "/viewuser" {
			h.Set("Content-Type", "text/html; charset=utf-8")
			h.Set("Cache-Control", "no-cache, max-age=0")

			if err := viewuserTemplate.Execute(w, map[string]any{"Email": email, "Types": l}); err != nil {
				logErrorx("render template", err)
			}
		} else {
			h.Set("Content-Type", "application/zip")
			h.Set("Cache-Control", "no-cache, max-age=0")
			zw := zip.NewWriter(w)
			for _, dt := range l {
				zf, err := zw.Create(dt.Name + ".csv")
				if err != nil {
					logErrorx("adding csv file to zip", err)
					return
				}
				cw := csv.NewWriter(zf)
				cw.Write(dt.Fields)
				cw.WriteAll(dt.Records)
				cw.Flush()
				if err := cw.Error(); err != nil {
					logErrorx("write csv file", err)
					return
				}
			}
			if err := zw.Close(); err != nil {
				logErrorx("close zip file", err)
			}
		}

	case "/gopherwatch.db":
		// Give consistent copy of entire database for offline inspection.
		err := database.Read(r.Context(), func(tx *bstore.Tx) error {
			h := w.Header()
			h.Set("Content-Type", "application/octet-stream")
			h.Set("Cache-Control", "no-cache, max-age=0")
			h.Set("Content-Disposition", `attachment; filename="gopherwatch.db"`)
			if _, err := tx.WriteTo(w); err != nil {
				logErrorx("write database to http client", err)
			}
			return nil
		})
		if err != nil {
			logErrorx("dumping database", err)
		}
	default:
		http.NotFound(w, r)
	}
}
