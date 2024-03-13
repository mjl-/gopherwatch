package main

import (
	"bytes"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	"golang.org/x/mod/semver"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
)

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
	c := message.NewComposer(&buf, 0)

	rcptToAddr, err := smtp.ParseAddress(user.Email)
	if err != nil {
		// This shouldn't fail, we've validated the address before.
		return "", "", nil, false, false, fmt.Errorf("parsing recipient address: %v", err)
	}
	for _, ch := range string(rcptToAddr.Localpart + config.Submission.From.ParsedLocalpartBase) {
		if ch >= 0x80 {
			c.SMTPUTF8 = true
			c.Has8bit = true
			break
		}
	}

	sendID = xrandomID(16)
	mailFromAddr := smtp.Address{
		Localpart: config.Submission.From.ParsedLocalpartBase,
		Domain:    config.Submission.From.DNSDomain,
	}
	// We send from our address that uses "+<id>" in the SMTP MAIL FROM address.
	c.HeaderAddrs("From", []message.NameAddress{
		{DisplayName: config.Submission.From.Name, Address: mailFromAddr},
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
	c.Header("List-Id", fmt.Sprintf("%s <%d.%s.%s>", config.Submission.From.Name, user.ID, config.Submission.From.LocalpartBase, config.Submission.From.Domain))
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
	textBody, textCT, textCTE := c.TextPart(text)
	thdrs := textproto.MIMEHeader{
		"Content-Type":              []string{textCT},
		"Content-Transfer-Encoding": []string{textCTE},
	}
	tp, err := mp.CreatePart(thdrs)
	c.Checkf(err, "adding text part")
	_, err = tp.Write([]byte(textBody))
	c.Checkf(err, "writing text part")

	htmlBody, htmlCT, htmlCTE := c.TextPart(html)
	hhdrs := textproto.MIMEHeader{
		"Content-Type":              []string{strings.ReplaceAll(htmlCT, "text/plain", "text/html")},
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

	subject = fmt.Sprintf("%s%d modules with %d new versions", config.SubjectPrefix, len(l), len(updates))

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
