// Command gopherwatch monitors a Go module transparency log (sum database) and
// sends notifications by email for subscriptions of registered users.
package main

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/sconf"
)

var config Config

type Config struct {
	BaseURL                  string          `sconf-doc:"URL to where this gopherwatch is hosted, without trailing slash, it is added when composing URLs."`
	TokenSecret              string          `sconf-doc:"Secret used for signing and verifying tokens. Used in HMAC."`
	ServiceName              string          `sconf-doc:"Public name of this service, e.g. GopherWatch.org, or another domain-like name. Also used in the subject of signup emails."`
	Admin                    Admin           `sconf-doc:"Information about the admin."`
	SubjectPrefix            string          `sconf-doc:"Prefix to add to subject for outgoing messages. E.g. 'GopherWatch: ' or '[GophererWatch] '."`
	ReverseProxied           bool            `sconf-doc:"Whether incoming requests are reverse proxied. If set, X-Forwarded-* headers are taken into account for evaluation use of HTTPS (for secure cookies) and remote IP address (for rate limiting)."`
	DailyMetaMessagesMax     int             `sconf-doc:"Maximum number of meta email messages to send to a single email recipient in the last 24 hours. This rate limits the outgoing messages about password resets. Not update messages."`
	EmailUpdateInterval      time.Duration   `sconf-doc:"Minimum interval between sending an email about module/version updates to an email address. To prevent sending too many."`
	SignupEmailDisabled      bool            `sconf:"optional" sconf-doc:"Whether signup via email is disabled."`
	SignupWebsiteDisabled    bool            `sconf:"optional" sconf-doc:"Whether signup via website is disabled."`
	ModuleVersionHistorySize int64           `sconf-doc:"Number of most recent modules/versions seen in transparency log to keep in database. If <= 0, all are kept."`
	SumDB                    SumDB           `sconf-doc:"Transparency log that we are following. The verifier key cannot be changed after initializing the state."`
	IndexBaseURL             string          `sconf:"optional" sconf-doc:"Base URL of index, e.g. https://index.golang.org. Only used for explicitly trying to forward to the latest, non-cached module added to the transparency log."`
	SignupAddress            string          `sconf-doc:"Address to which signup emails should be sent."`
	KeywordPrefix            string          `sconf:"optional" sconf-doc:"Prefix of keywords (or flags/tags) set on incoming messages to indicate whether they have been processed. E.g. 'gopherwatch:'."`
	SubmissionIMAP           *SubmissionIMAP `sconf:"optional" sconf-doc:"Configuration for sending/receiving email with SMTP submission and IMAP."`
	Mox                      *Mox            `sconf:"optional" sconf-doc:"Configuration for sending/receiving email with mox webapi."`
	SkipModulePrefixes       []string        `sconf:"optional" sconf-doc:"Modules matching this prefix (e.g. 'githubmirror.example.com/') are not notified about, and not shown on the home page."`
	SkipModulePaths          []string        `sconf-doc:"Module paths that we won't notify about. E.g. the bare github.com, which would result in too many matches and notification emails."`
	WebhooksAllowInternalIPs bool            `sconf:"optional" sconf-doc:"Allow delivering webhooks to internal IPs."`
}

type SubmissionIMAP struct {
	Submission Submission `sconf-doc:"For sending email message."`
	IMAP       IMAP       `sconf-doc:"For waiting for, and processing DSN messages. If we receive DSNs about an email address, we disable sending further messages."`
}

type Mox struct {
	WebAPI  WebAPI  `sconf-doc:"For making API calls."`
	Webhook Webhook `sconf-doc:"For authentication of incoming webhook calls."`
}

type WebAPI struct {
	BaseURL  string `sconf-doc:"BaseURL of webapi, typically ending in /webapi/v0/."`
	Username string `sconf-doc:"Used for HTTP Basic authentication at BaseURL."`
	Password string
}

type Webhook struct {
	OutgoingPath string `sconf-doc:"Path on webhook listener to handle calls for outgoing deliveries on."`
	IncomingPath string `sconf-doc:"Path on webhook listener for handling incoming deliveries."`
	Username     string `sconf-doc:"HTTP basic auth to require for incoming webhook calls."`
	Password     string
}

type Admin struct {
	Address       string       `sconf-doc:"Email address of admin. Used on home page, as contact about this instance."`
	AddressParsed smtp.Address `sconf:"-"`
	Password      string       `sconf-doc:"Password for HTTP basic authentication for admin interface, for downloading copy of database. Use username admin."`
}

type SumDB struct {
	BaseURL             string        `sconf-doc:"Base URL of sumdb, e.g. https://sum.golang.org."`
	VerifierKey         string        `sconf-doc:"Verifier key of sumdb, e.g. sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"`
	QueryLatestInterval time.Duration `sconf-doc:"Interval between requests for /latest, to move transparency log forward. E.g. 10 minutes."`
}

type SubmissionFrom struct {
	Name          string `sconf-doc:"Display name for use in message From headers."`
	LocalpartBase string `sconf-doc:"Localpart of the 'From' email address. Used in From message header. The SMTP MAIL FROM address starts with this localpart, then '+' and a per-message unique ID is added."`
	Domain        string `sconf-doc:"Domain used to compose the email address."`

	ParsedLocalpartBase smtp.Localpart `sconf:"-"`
	DNSDomain           dns.Domain     `sconf:"-"`
}
type Submission struct {
	Host          string         `sconf-doc:"Hostname or IP address of submission service."`
	Port          int            `sconf-doc:"Port number for sumission. Typically 465 for immediate TLS, and 587 for plain and STARTTLS. Some old services use port 25."`
	TLS           bool           `sconf-doc:"For immediate TLS."`
	TLSSkipVerify bool           `sconf:"optional" sconf-doc:"If set, not TLS certificate validation is done."`
	Username      string         `sconf-doc:"Username for account."`
	Password      string         `sconf-doc:"Password for account."`
	From          SubmissionFrom `sconf-doc:"For From message header of outgoing messages, and used to compose unique SMTP MAIL FROM addresses."`
}

type IMAP struct {
	Host          string `sconf-doc:"Hostname or IP of IMAP server."`
	Port          int    `sconf-doc:"Port of IMAP server. Typically 993 for immediate TLS, and 143 for plain or STARTTLS."`
	TLS           bool   `sconf-doc:"For immediate TLS."`
	TLSSkipVerify bool   `sconf:"optional" sconf-doc:"If set, not TLS certificate validation is done."`
	Username      string `sconf-doc:"Username for account."`
	Password      string `sconf-doc:"Password for account."`
}

func random() string {
	buf := make([]byte, 10)
	cryptorand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

var loglevel slog.LevelVar

func init() {
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
			Level: &loglevel,
		}),
	))
}

func main() {
	flag.TextVar(&loglevel, "loglevel", &loglevel, "log level, default is info")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gopherwatch serve [flags]")
		fmt.Fprintln(os.Stderr, "       gopherwatch describeconf >gopherwatch.conf")
		fmt.Fprintln(os.Stderr, "       gopherwatch checkconf gopherwatch.conf")
		fmt.Fprintln(os.Stderr, "       gopherwatch genconf [-mox] >gopherwatch.conf")
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

	case "genconf":
		config = Config{
			BaseURL:              "http://localhost:8073",
			TokenSecret:          random(),
			ServiceName:          "gopherwatch.localhost",
			Admin:                Admin{Address: "gopherwatch@localhost", Password: random()},
			SubjectPrefix:        "GopherWatch: ",
			DailyMetaMessagesMax: 10,
			SumDB:                SumDB{"https://sum.golang.org", "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8", 10 * time.Minute},
			IndexBaseURL:         "https://index.golang.org",
			SignupAddress:        "gopherwatch@localhost",
			KeywordPrefix:        "gw:",
			SubmissionIMAP: &SubmissionIMAP{
				Submission: Submission{"localhost", 1465, true, true, "mox@localhost", "moxmoxmox", SubmissionFrom{"gopherwatch", "mox", "localhost", "", dns.Domain{}}},
				IMAP:       IMAP{"localhost", 1993, true, true, "mox@localhost", "moxmoxmox"},
			},
			SkipModulePrefixes:       []string{"github.1git.de/", "github.hscsec.cn/", "github.phpd.cn/", "github.skymusic.top/"},
			SkipModulePaths:          []string{"github.com"},
			WebhooksAllowInternalIPs: true,
		}
		if len(args) == 1 && args[0] == "-mox" {
			config.SubmissionIMAP = nil
			config.Mox = &Mox{
				WebAPI{"http://mox@localhost:moxmoxmox@localhost:1080/webapi/v0/", "mox@localhost", "moxmoxmox"},
				Webhook{"/webhook/outgoing", "/webhook/incoming", "gopherwatch", random()},
			}
		} else if len(args) != 0 {
			flag.Usage()
		}
		if err := sconf.Describe(os.Stdout, config); err != nil {
			logFatalx("describing config", err)
		}
		fmt.Fprintln(os.Stderr, `wrote config that works with "mox localserve" as mail server, see https://github.com/mjl-/mox`)

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

	if _, err := smtp.ParseAddress(config.SignupAddress); err != nil {
		return fmt.Errorf("parsing signup address %q: %v", config.SignupAddress, err)
	}

	if config.SubmissionIMAP == nil && config.Mox == nil {
		return fmt.Errorf("require either SubmissionIMAP or Mox")
	} else if config.SubmissionIMAP != nil && config.Mox != nil {
		return fmt.Errorf("require either SubmissionIMAP or Mox, not both")
	} else if config.SubmissionIMAP != nil {
		config.SubmissionIMAP.Submission.From.ParsedLocalpartBase, err = smtp.ParseLocalpart(config.SubmissionIMAP.Submission.From.LocalpartBase)
		if err != nil {
			return fmt.Errorf("parsing localpart of submission from: %v", err)
		}

		config.SubmissionIMAP.Submission.From.DNSDomain, err = dns.ParseDomain(config.SubmissionIMAP.Submission.From.Domain)
		if err != nil {
			return fmt.Errorf("parsing dns of submission from domain: %v", err)
		}
	} else {
		_, err := url.Parse(config.Mox.WebAPI.BaseURL)
		if err != nil {
			return fmt.Errorf("parsing mox webapi baseurl: %v", err)
		}
		if config.Mox.Webhook.OutgoingPath == config.Mox.Webhook.IncomingPath {
			return fmt.Errorf("cannot use same path for webhooks about outgoing and incoming deliveries")
		}
	}

	config.Admin.AddressParsed, err = smtp.ParseAddress(config.Admin.Address)
	if err != nil {
		return fmt.Errorf("parsing admin address: %v", err)
	}

	return nil
}
