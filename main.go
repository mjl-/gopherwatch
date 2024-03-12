// Command gopherwatch monitors a Go module transparency log (sum database) and
// sends notifications by email for subscriptions of registered users.
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
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	_ "embed"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mjl-/bstore"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/sconf"
	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"
)

// All users, subscriptions, updates and sumdb state are in the database.
var database *bstore.DB

// The sumdb transparency log we keep moving forward, verifying the new entries and
// matching new packages against subscriptions.
var tlogclient *Client

// For Message-ID headers.
var hostname string

//go:embed api.json
var apiJSON []byte

//go:embed index.html
var indexHTML []byte

//go:embed index.js
var indexJS []byte

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

var config struct {
	BaseURL     string `sconf-doc:"URL to where this gopherwatch is hosted, without trailing slash, it is added when composing URLs."`
	TokenSecret string `sconf-doc:"Secret used for signing and verifying tokens. Used in HMAC."`
	ServiceName string `sconf-doc:"Public name of this service, e.g. GopherWatch.org, or another domain-like name."`
	Admin       struct {
		Address       string       `sconf-doc:"Email address of admin. Used on home page, as contact about this instance."`
		AddressParsed smtp.Address `sconf:"-"`
		Password      string       `sconf-doc:"Password for HTTP basic authentication for admin interface, for downloading copy of database. Use username admin."`
	} `sconf-doc:"Information about the admin."`
	SubjectPrefix            string        `sconf-doc:"Prefix to add to subject for outgoing messages. E.g. 'GopherWatch'. If non-empty, the text, and ': ' is prepended."`
	ReverseProxied           bool          `sconf-doc:"Whether incoming requests are reverse proxied. If set, X-Forwarded-* headers are taken into account for evaluation use of HTTPS (for secure cookies) and remote IP address (for rate limiting)."`
	DailyMetaMessagesMax     int           `sconf-doc:"Maximum number of meta email messages to send to a single email recipient in the last 24 hours. This rate limits the outgoing messages about password resets. Not update messages."`
	EmailUpdateInterval      time.Duration `sconf-doc:"Minimum interval between sending an email about module/version updates to an email address. To prevent sending too many."`
	ModuleVersionHistorySize int64         `sconf-doc:"Number of most recent modules/versions seen in transparency log to keep in database. If <= 0, all are kept."`
	SumDB                    struct {
		BaseURL             string        `sconf-doc:"Base URL of sumdb, e.g. https://sum.golang.org."`
		VerifierKey         string        `sconf-doc:"Verifier key of sumdb, e.g. sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"`
		QueryLatestInterval time.Duration `sconf-doc:"Interval between requests for /latest, to move transparency log forward. E.g. 10 minutes."`
	} `sconf-doc:"Transparency log that we are following. The verifier key cannot be changed after initializing the state."`
	IndexBaseURL string `sconf:"optional" sconf-doc:"Base URL of index, e.g. https://index.golang.org. Only used for explicitly trying to forward to the latest, non-cached module added to the transparency log."`
	Submission   struct {
		Host          string `sconf-doc:"Hostname or IP address of submission service."`
		Port          int    `sconf-doc:"Port number for sumission. Typically 465 for immediate TLS, and 587 for plain and STARTTLS. Some old services use port 25."`
		TLS           bool   `sconf-doc:"For immediate TLS."`
		TLSSkipVerify bool   `sconf:"optional" sconf-doc:"If set, not TLS certificate validation is done."`
		Username      string `sconf-doc:"Username for account."`
		Password      string `sconf-doc:"Password for account."`
		From          struct {
			Name          string     `sconf-doc:"Display name for use in message From headers."`
			LocalpartBase string     `sconf-doc:"Localpart of the 'From' email address. Used in From message header. The SMTP MAIL FROM address starts with this localpart, then '+' and a per-message unique ID is added."`
			Domain        string     `sconf-doc:"Domain used to compose the email address."`
			DNSDomain     dns.Domain `sconf:"-"`
		} `sconf-doc:"For From message header of outgoing messages, and used to compose unique SMTP MAIL FROM addresses."`
	} `sconf-doc:"For sending email message."`
	IMAP struct {
		Host          string `sconf-doc:"Hostname or IP of IMAP server."`
		Port          int    `sconf-doc:"Port of IMAP server. Typically 993 for immediate TLS, and 143 for plain or STARTTLS."`
		TLS           bool   `sconf-doc:"For immediate TLS."`
		TLSSkipVerify bool   `sconf:"optional" sconf-doc:"If set, not TLS certificate validation is done."`
		Username      string `sconf-doc:"Username for account."`
		Password      string `sconf-doc:"Password for account."`
		KeywordPrefix string `sconf:"optional" sconf-doc:"Prefix of keywords (or flags/tags) set on incoming messages to indicate whether they have been processed. E.g. 'gopherwatch:'."`
	} `sconf-doc:"For waiting for, and processing DSN messages. If we receive DSNs about an email address, we disable sending further messages."`
	SkipModulePrefixes []string `sconf:"optional" sconf-doc:"Modules matching this prefix (e.g. 'githubmirror.example.com/') are not notified about, and not shown on the home page."`
	SkipModulePaths    []string `sconf-doc:"Module paths that we won't notify about. E.g. the bare github.com, which would result in too many matches and notification emails."`
}

func main() {
	slog.SetDefault(slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if len(groups) == 0 {
					if a.Key == slog.TimeKey {
						return slog.Attr{}
					} else if a.Key == slog.LevelKey {
						return slog.String("l", strings.ToLower(a.Value.String()))
					} else if a.Key == "msg" {
						a.Key = "m"
					}
				}
				return a
			},
		},
		)))

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gopherwatch serve [flags]")
		fmt.Fprintln(os.Stderr, "       gopherwatch describeconf >gopherwatch.conf")
		fmt.Fprintln(os.Stderr, "       gopherwatch checkconf gopherwatch.conf")
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
	}
	cmd, args := args[0], args[1:]

	switch cmd {
	case "serve":
		serve(args)

	case "describeconf":
		if len(args) != 0 {
			flag.Usage()
		}
		if err := sconf.Describe(os.Stdout, config); err != nil {
			logFatalx("describing config", err)
		}
	case "checkconf":
		if len(args) != 1 {
			flag.Usage()
		}
		if err := parseConfig(args[0]); err != nil {
			logFatalx("parsing config", err)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand")
		flag.Usage()
	}
}

func logCheck(err error, msg string, args ...any) {
	if err != nil {
		slog.Error(msg, append([]any{slog.Any("err", err)}, args...)...)
	}
}

func logFatalx(msg string, err error, args ...any) {
	slog.Error(msg, append([]any{slog.Any("err", err)}, args...)...)
	os.Exit(1)
}

func logErrorx(msg string, err error, args ...any) {
	slog.Error(msg, append([]any{slog.Any("err", err)}, args...)...)
}

func parseConfig(filename string) error {
	err := sconf.ParseFile(filename, &config)
	if err != nil {
		return err
	}

	config.Submission.From.DNSDomain, err = dns.ParseDomain(config.Submission.From.Domain)
	if err != nil {
		return fmt.Errorf("parsing dns from domain: %v", err)
	}

	config.Admin.AddressParsed, err = smtp.ParseAddress(config.Admin.Address)
	if err != nil {
		return fmt.Errorf("parsing admin address: %v", err)
	}

	return nil
}

var testlog, resetTree bool

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var configPath string
	var listenAddr, metricsAddr, adminAddr string
	var dbpath string
	fs.StringVar(&configPath, "config", "gopherwatch.conf", "path to config file")
	fs.StringVar(&listenAddr, "listenaddr", "127.0.0.1:8073", "address to listen and serve public gopherwatch on")
	fs.StringVar(&metricsAddr, "metricsaddr", "127.0.0.1:8074", "address to listen and serve metrics on")
	fs.StringVar(&adminAddr, "adminaddr", "127.0.0.1:8075", "address to listen and serve the admin requests on")
	fs.StringVar(&dbpath, "dbpath", "gopherwatch.db", "database, with users, subscriptions, etc")
	fs.BoolVar(&testlog, "testlog", false, "use preset sumdb positions, forward the log only manually through api call; for testing")
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

	var err error
	hostname, err = os.Hostname()
	if err != nil {
		logFatalx("get hostname", err)
	}

	db, err := bstore.Open(context.Background(), dbpath, nil, TreeState{}, User{}, UserLog{}, Subscription{}, ModuleUpdate{}, Message{}, ModuleVersion{})
	if err != nil {
		logFatalx("opening database", err)
	}
	database = db

	ops := &ops{
		URL: config.SumDB.BaseURL,
	}
	tlogclient = NewClient(config.SumDB.VerifierKey, ops)
	if err := tlogclient.init(); err != nil {
		logFatalx("client init", err)
	}

	if testlog {
		initTlogTest()
	} else {
		go openTlog()
	}

	publicMux := http.NewServeMux()

	safeHeaders := func(h http.Header) {
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'; form-action 'self'")
	}

	publicMux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
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
	})

	publicMux.HandleFunc("GET /forward", func(w http.ResponseWriter, r *http.Request) {
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
			http.Error(w, fmt.Sprintf("%d - %s: %s", code, err.Code, err.Message), code)
		}()

		reqInfo := requestInfo{"", 0, w, r}
		ctx := context.WithValue(r.Context(), requestInfoCtxKey, reqInfo)
		API{}.Forward(ctx)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	// Unsubscribe is not part of regular frontend JS because we cannot have parameters
	// in the URL fragment in List-Unsubscribe: It would be lost when we automatically
	// submit the form to unsubscribe. The HTML has a JS that triggers the unsubscribe
	// after 1 second. That should prevent automated tools from unsubscribing.
	publicMux.HandleFunc("GET /unsubscribe", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		safeHeaders(h)
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-cache, max-age=0")
		w.Write([]byte(unsubscribeHTML))
	})
	// For one-click unsubscribe, and HTML page also submits to it.
	publicMux.HandleFunc("POST /unsubscribe", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "400 - bad request - missing id to identify user", http.StatusBadRequest)
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
			if meta {
				user.MetaUnsubscribed = true
				user.UpdatesUnsubscribed = true
				kind = "module updates and service messages"
			} else {
				user.UpdatesUnsubscribed = true
				kind = "service messages"
			}
			if err := tx.Update(&user); err != nil {
				return fmt.Errorf("marking user as unsubscribed in database: %v", err)
			}

			xaddUserLogf(tx, user.ID, "Unsubscribed for %s", kind)
			return nil
		})
		if err != nil && errors.Is(err, bstore.ErrAbsent) {
			http.Error(w, "400 - bad request - cannot find user for unsubscribe id", http.StatusBadRequest)
			return
		} else if err != nil {
			http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
			return
		}

		h := w.Header()
		safeHeaders(h)
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-cache, max-age=0")
		w.Write([]byte(unsubscribedHTML))
	})

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

	publicMux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		safeHeaders(w.Header())

		if r.Method != "POST" && r.URL.Path != "/api/" {
			http.Error(w, "405 - method not allowed - use post", http.StatusMethodNotAllowed)
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
			"/api/TestForward",
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
	})

	publicMux.HandleFunc("GET /preview/{$}", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		safeHeaders(h)
		h.Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><body>Templates: <a href="signup/">signup</a> <a href="passwordreset/">passwordreset</a> <a href="moduleupdates/">moduleupdates</a></body></html>`)
	})
	publicMux.HandleFunc("GET /preview/{kind}/{$}", func(w http.ResponseWriter, r *http.Request) {
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
	})
	publicMux.HandleFunc("GET /preview/{kind}/{format}", func(w http.ResponseWriter, r *http.Request) {
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
			http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
		}
		h.Set("Cache-Control", "no-cache, max-age=0")
		if format == "text" {
			h.Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte(text))
		} else {
			h.Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(html))
		}
	})

	// Prometheus metrics served on a separate port.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())

	// Admin endpoints served on a separate port. Requires HTTP basic auth from the config file.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if config.Admin.Password == "" || auth != "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:"+config.Admin.Password)) {
			w.Header().Set("WWW-Authenticate", `Basic realm="gopherwatch admin"`)
			http.Error(w, "401 - unauthorized", http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/viewuser", "/viewuser.csv.zip":
			// Serve all information we have for an account. The .csv.zip variant returns the
			// same information, but as zip file, for offline comparison.

			email := r.FormValue("email")
			if email == "" {
				http.Error(w, "400 - bad request - missing parameter email", http.StatusBadRequest)
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
				if err := gatherType(tx, typeValues, "ModuleUpdate", ModuleUpdate{UserID: user.ID}, func(v ModuleUpdate) int64 { return v.ID }); err != nil {
					return err
				}
				if err := gatherType(tx, typeValues, "Message", Message{UserID: user.ID}, func(v Message) int64 { return v.ID }); err != nil {
					return err
				}

				return nil
			})
			if err == bstore.ErrAbsent {
				http.Error(w, "400 - bad request - user not found", http.StatusBadRequest)
				return
			} else if err != nil {
				http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
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
		}
	})

	// Watch mailbox over IMAP for DSNs. uses IMAP IDLE to wait for incoming messages.
	go watchDSN()

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
	slog.Warn("listening for public", "addr", listenAddr)
	logFatalx("public listener", http.ListenAndServe(listenAddr, publicMux))
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
