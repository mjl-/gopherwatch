package main

import (
	"bytes"
	"context"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	"golang.org/x/mod/semver"
)

// sendCan returns whether it is likely the ratelimiter won't block on a subsequent call.
func sendCan() bool {
	return ratelimitEmail.CanAdd(net.IPv6zero, time.Now(), 1)
}

// sendTake consumes from the rate limiter, blocking until sending is allowed.
func sendTake() {
	for !ratelimitEmail.Add(net.IPv6zero, time.Now(), 1) {
		slog.Info("slowing down outgoing messages")
		time.Sleep(time.Second)
	}
}

// send sends a message, either by composing itself and submitting over smtp, or
// through a mox webapi request.
// Caller must have checked the rate limiter.
func send(ctx context.Context, meta bool, user User, origMessageID, subject, text, html string) (sendID string, rerr error) {
	if config.Mox != nil {
		sendID, _, _, err := webapiSend(ctx, meta, user, origMessageID, subject, text, html)
		return sendID, err
	}

	// Compose ourselves and submit over SMTP.
	mailFrom, sendID, msg, eightbit, smtputf8, err := compose(meta, user, origMessageID, subject, text, html)
	if err != nil {
		return "", fmt.Errorf("composing message: %v", err)
	}

	conn, err := smtpGet(ctx)
	if err != nil {
		return sendID, fmt.Errorf("dial submission: %v", err)
	}
	defer func() {
		if rerr == nil {
			smtpPut(conn)
		} else {
			err := conn.Close()
			logCheck(err, "closing submission connection")
		}
	}()
	err = smtpSubmit(ctx, conn, meta, mailFrom, user.Email, msg, eightbit, smtputf8)
	if err != nil {
		return sendID, fmt.Errorf("submitting message to queue: %v", err)
	}
	return sendID, nil
}

func composeRender(templText *texttemplate.Template, templHTML *htmltemplate.Template, args any) (text, html string, rerr error) {
	var textBuf, htmlBuf bytes.Buffer
	if err := templText.Execute(&textBuf, args); err != nil {
		return "", "", err
	}

	if err := templHTML.Execute(&htmlBuf, args); err != nil {
		return "", "", err
	}

	var pageBuf bytes.Buffer
	if err := templateHTML.Execute(&pageBuf, htmltemplate.HTML(htmlBuf.String())); err != nil {
		return "", "", err
	}

	return textBuf.String(), pageBuf.String(), nil
}

func composeSignup(u User, fromWebsite bool) (subject, text, html string, err error) {
	subject = config.SubjectPrefix + "Verify new account"
	if !fromWebsite {
		subject = "re: signup for " + config.ServiceName
	}
	args := struct {
		BaseURL string
		Subject string
		User    User
	}{config.BaseURL, subject, u}
	text, html, err = composeRender(templSignupText, templSignupHTML, args)
	return subject, text, html, err
}

func composePasswordReset(u User, fromWebsite bool) (subject, text, html string, err error) {
	subject = config.SubjectPrefix + "Password reset requested"
	if !fromWebsite {
		subject = "re: signup for " + config.ServiceName
	}
	args := struct {
		BaseURL string
		Subject string
		User    User
	}{config.BaseURL, subject, u}
	text, html, err = composeRender(templPasswordResetText, templPasswordResetHTML, args)
	return subject, text, html, err
}

var pseudolikeRegexp = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-.*[0-9]{14}-[0-9a-f]{12}.*$`)

func guessURLs(module, version string) (repoURL, tagURL, docURL string) {
	baseVersion, _, _ := strings.Cut(version, "+")

	t := strings.Split(module, "/")
	host := t[0]
	if strings.Contains(host, "github") && len(t) >= 3 {
		repoURL = "https://" + strings.Join(t[:3], "/")
		tagURL = repoURL + "/releases/tag/" + url.QueryEscape(strings.Join(append(t[3:], baseVersion), "/"))
	} else if strings.Contains(host, "gitlab") && len(t) >= 3 {
		repoURL = "https://" + strings.Join(t[:3], "/")
		tagURL = repoURL + "/-/tags/" + baseVersion
	} else if strings.Contains(host, "codeberg") {
		repoURL = "https://" + strings.Join(t[:3], "/")
		tagURL = repoURL + "/releases/tag/" + baseVersion
	} else if strings.Contains(host, "sr.ht") {
		repoURL = "https://" + strings.Join(t[:3], "/")
		tagURL = repoURL + "/refs/" + baseVersion
	} else if host == "golang.org" && len(t) >= 3 && t[1] == "x" {
		repoURL = "https://github.com/golang/" + t[2]
		tagURL = repoURL + "/releases/tag/" + url.QueryEscape(strings.Join(append(t[3:], baseVersion), "/"))
	}
	// bitbucket doesn't seem to have a URL for just the tag (and the message associated), only trees or commits.

	// e.g. v0.0.10-0.20240216191305-fd359d597383 and variants
	if pseudolikeRegexp.MatchString(baseVersion) {
		tagURL = ""
	}

	if host != "gopkg.in" {
		docURL = "https://pkg.go.dev/" + module + "@" + version
	}
	return
}

func composeModuleUpdates(u User, loginToken string, updates []ModuleUpdate) (subject, text, html string, err error) {
	type version struct {
		Version string
		DocURL  string
		TagURL  string
	}
	type moduleVersion struct {
		Module   string
		RepoURL  string
		Versions []version
	}

	modVersions := map[string]moduleVersion{}
	for _, up := range updates {
		mv, ok := modVersions[up.Module]
		if !ok {
			mv = moduleVersion{up.Module, "", nil}
		}
		repoURL, tagURL, docURL := guessURLs(up.Module, up.Version)
		mv.RepoURL = repoURL
		mv.Versions = append(mv.Versions, version{up.Version, docURL, tagURL})
		modVersions[up.Module] = mv
	}
	var l []moduleVersion
	for _, mv := range modVersions {
		sort.Slice(mv.Versions, func(i, j int) bool {
			return semver.Compare(mv.Versions[i].Version, mv.Versions[j].Version) < 0
		})
		l = append(l, mv)
	}
	sort.Slice(l, func(i, j int) bool {
		return l[i].Module < l[j].Module
	})

	smod := "s"
	if len(l) == 1 {
		smod = ""
	}
	sup := "s"
	if len(updates) == 1 {
		sup = ""
	}
	subject = fmt.Sprintf("%s%d module%s with %d new version%s", config.SubjectPrefix, len(l), smod, len(updates), sup)

	var truncated bool
	if len(l) > 1100 {
		l = l[:1000]
	}

	var args = struct {
		BaseURL          string
		Subject          string
		User             User
		UpdatesTruncated bool
		ModuleVersions   []moduleVersion
		LoginToken       string
	}{config.BaseURL, subject, u, truncated, l, loginToken}

	text, html, err = composeRender(templModuleUpdatesText, templModuleUpdatesHTML, args)
	return subject, text, html, err
}

func composeSample(kind string, user User, loginToken string) (subject, text, html string, err error) {
	switch kind {
	case "signup":
		return composeSignup(user, true)
	case "passwordreset":
		return composePasswordReset(user, true)
	case "moduleupdates":
		updates := []ModuleUpdate{
			{
				Module:  "github.com/mjl-/gopherwatch",
				Version: "v0.0.1",
			},
			{
				Module:  "github.com/mjl-/gopherwatch",
				Version: "v0.0.2",
			},
			{
				Module:  "github.com/mjl-/mox",
				Version: "v0.0.9",
			},
		}
		return composeModuleUpdates(user, loginToken, updates)
	}
	return "", "", "", fmt.Errorf("unknown message kind %q", kind)
}
