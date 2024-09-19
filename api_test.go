package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"

	"github.com/mjl-/bstore"
	"github.com/mjl-/mox/webhook"
)

type httpResponse struct {
	header http.Header
}

func (w *httpResponse) Header() http.Header           { return w.header }
func (w *httpResponse) Write(buf []byte) (int, error) { return len(buf), nil }
func (w *httpResponse) WriteHeader(statusCode int)    {}

func TestAPI(t *testing.T) {
	api := API{}

	api.Home(ctxbg)
	api.Recents(ctxbg)

	req := http.Request{Header: http.Header{}, RemoteAddr: "127.0.0.1:1234"} // For rate limiter.
	resp := httpResponse{http.Header{}}                                      // For capturing cookies to use in next call.
	reqInfo := requestInfo{"", 0, &resp, &req}
	xctx := context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)
	propagateCookies := func() {
		for _, cs := range resp.header.Values("Set-Cookie") {
			c, err := http.ParseSetCookie(cs)
			tcheckf(t, err, "parse set-cookie")
			req.AddCookie(c)
		}
		resp.header = http.Header{}
	}
	prep := func() string {
		req.Header = http.Header{}
		resp.header = http.Header{}
		prepToken := api.Prep(xctx)
		req.Header = http.Header{}
		propagateCookies()
		return prepToken
	}

	// Signup: Start new account registration process.
	api.Signup(xctx, prep(), "gw@gw.example")
	tneedmail(t, "Verify new account")

	tneederr(t, "user:error", func() { api.Signup(xctx, prep(), "invalid email address") })

	// Signup again for same user, updates user.
	api.Signup(xctx, prep(), "gw@gw.example")
	tneedmail(t, "Verify new account")

	user, err := bstore.QueryDB[User](xctx, database).Get()
	tcheckf(t, err, "get user for verify token")

	// SignupEmail: Check email was registered properly.
	email := api.SignupEmail(xctx, prep(), user.VerifyToken)
	tcompare(t, email, "gw@gw.example")
	tneederr(t, "user:error", func() { api.SignupEmail(xctx, prep(), "") })
	tneederr(t, "user:error", func() { api.SignupEmail(xctx, prep(), "bogus") })

	// VerifySignup: complete signup process, setting a password.
	tneederr(t, "user:error", func() { api.VerifySignup(xctx, prep(), "", user.Email, "user1234") })
	tneederr(t, "user:error", func() { api.VerifySignup(xctx, prep(), "bad", user.Email, "user1234") })
	tneederr(t, "user:error", func() { api.VerifySignup(xctx, prep(), user.VerifyToken, user.Email, "short") })
	api.VerifySignup(xctx, prep(), user.VerifyToken, user.Email, "user1234")
	tneederr(t, "user:error", func() { api.VerifySignup(xctx, prep(), user.VerifyToken, user.Email, "user1234") }) // Already used.

	// API methods for user data require a csrf header and session cookie.
	thttpsherpa(t, publicMux, "/api/Prep", "", "", nil, "") // No auth required, still bad request.
	thttpsherpa(t, publicMux, "/api/Overview", "", "", nil, "user:noAuth")
	thttpsherpa(t, publicMux, "/api/Overview", "bogus", "bogus", nil, "user:badAuth")
	csrfToken := tokenSign(tokentypeCSRF, time.Now(), user.ID)
	sessionToken := tokenSign(tokentypeSession, time.Now(), user.ID)
	thttpsherpa(t, publicMux, "/api/Overview", csrfToken, sessionToken, nil, "")
	thttpsherpa(t, publicMux, "/api/Overview", csrfToken, "bogus", nil, "user:badAuth")
	thttpsherpa(t, publicMux, "/api/Overview", "bogus", sessionToken, nil, "user:badAuth")
	thttpsherpa(t, publicMux, "/api/Overview", sessionToken, csrfToken, nil, "user:badAuth") // csrf/session swapped
	csrfTokenExp := tokenSign(tokentypeCSRF, time.Now().Add(-25*time.Hour), user.ID)
	sessionTokenExp := tokenSign(tokentypeSession, time.Now().Add(-25*time.Hour), user.ID)
	thttpsherpa(t, publicMux, "/api/Overview", sessionTokenExp, csrfToken, nil, "user:badAuth")
	thttpsherpa(t, publicMux, "/api/Overview", sessionToken, csrfTokenExp, nil, "user:badAuth")
	csrfTokenOther := tokenSign(tokentypeCSRF, time.Now(), user.ID+1)
	thttpsherpa(t, publicMux, "/api/Overview", csrfTokenOther, sessionToken, nil, "user:badAuth") // user id mismatch

	// RequestPasswordReset
	api.RequestPasswordReset(xctx, prep(), user.Email)
	tneedmail(t, "Password reset requested")

	user, err = bstore.QueryDB[User](xctx, database).Get()
	tcheckf(t, err, "get user for password reset token")

	tneederr(t, "user:error", func() { api.ResetPassword(xctx, prep(), user.Email, "user4321", "") })
	tneederr(t, "user:error", func() { api.ResetPassword(xctx, prep(), user.Email, "short", user.PasswordResetToken) })
	api.ResetPassword(xctx, prep(), user.Email, "user4321", user.PasswordResetToken)
	tneederr(t, "user:error", func() { api.ResetPassword(xctx, prep(), user.Email, "user4321", user.PasswordResetToken) }) // Already used.

	// Signup again, we should get password reset email instead.
	api.Signup(xctx, prep(), "gw@gw.example")
	tneedmail(t, "Password reset requested")

	api.Login(xctx, prep(), user.Email, "user4321")

	// Logout
	api.Logout(xctx)
	// todo: this only asks us to clear cookies, which we don't. we need to check this against the api handler auth code.

	reqInfo = requestInfo{user.Email, user.ID, &resp, &req}
	ctx := context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)

	// Overview page
	overview := api.Overview(ctx)
	// todo: check user & settings
	tcompare(t, overview.MetaUnsubscribed, false)
	tcompare(t, overview.UpdatesUnsubscribed, false)

	// Unsubscribe
	api.SubscribeSet(ctx, true, false)
	api.SubscribeSet(ctx, false, false)
	overview = api.Overview(ctx)
	tcompare(t, overview.MetaUnsubscribed, true)
	tcompare(t, overview.UpdatesUnsubscribed, true)

	// Subscribe again.
	api.SubscribeSet(ctx, true, true)
	api.SubscribeSet(ctx, false, true)

	// IntervalSet
	api.IntervalSet(ctx, IntervalDay)
	overview = api.Overview(ctx)
	tcompare(t, overview.UpdateInterval, IntervalDay)

	// Restore.
	api.IntervalSet(ctx, IntervalImmediate)

	var hooks []hookData
	hookHandler := func(w http.ResponseWriter, r *http.Request) {
		var data hookData
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "500 - error - "+err.Error(), http.StatusInternalServerError)
			return
		}
		hooks = append(hooks, data)
		w.Write([]byte("ok"))
	}
	hookServer := httptest.NewServer(http.HandlerFunc(hookHandler))
	defer hookServer.Close()

	hc := HookConfig{
		Name:     "hooktest",
		URL:      hookServer.URL,
		Headers:  nil,
		Disabled: false,
	}
	nhc := api.HookConfigAdd(ctx, hc)
	overview = api.Overview(ctx)
	tcompare(t, overview.HookConfigs, []HookConfig{nhc})

	nhc.Name = "hooktest2"
	nhc.URL += "/test"
	api.HookConfigSave(ctx, nhc)
	overview = api.Overview(ctx)
	tcompare(t, overview.HookConfigs, []HookConfig{nhc})

	api.HookConfigRemove(ctx, nhc.ID)
	overview = api.Overview(ctx)
	tcompare(t, len(overview.HookConfigs), 0)

	nhc = api.HookConfigAdd(ctx, hc)

	hsub := Subscription{
		Module:        "vcs.localhost/testrepo",
		BelowModule:   false,
		OlderVersions: false,
		Prerelease:    false,
		Pseudo:        false,
		Comment:       "testing",
		HookConfigID:  nhc.ID,
	}
	nhsub := api.SubscriptionCreate(ctx, hsub)
	msub := Subscription{
		Module:        "vcs.localhost/testrepo",
		BelowModule:   false,
		OlderVersions: false,
		Prerelease:    false,
		Pseudo:        false,
		Comment:       "testing",
	}
	nmsub := api.SubscriptionCreate(ctx, msub)
	overview = api.Overview(ctx)
	tcompare(t, overview.Subscriptions, []Subscription{nhsub, nmsub})

	imp := SubscriptionImport{
		GoMod: `
module github.com/mjl-/gopherwatch

go 1.23.0

require (
        vcs.localhost/dep1 v0.0.6
        vcs.localhost/dep2 v0.0.12-0.20240628083946-367e968199bb
)
`,
	}
	nsubs := api.SubscriptionImport(ctx, imp)
	tcompare(t, len(nsubs), 2)
	tcompare(t, nsubs[0].Module, "vcs.localhost/dep1")
	overview = api.Overview(ctx)
	tcompare(t, overview.Subscriptions, []Subscription{nhsub, nmsub, nsubs[0], nsubs[1]})

	// SubscriptionSave
	nsubs[0].Module = "vcs.localhost/dep0"
	api.SubscriptionSave(ctx, nsubs[0])

	// SubscriptionRemove
	api.SubscriptionRemove(ctx, nsubs[1].ID)
	overview = api.Overview(ctx)
	tcompare(t, overview.Subscriptions, []Subscription{nhsub, nmsub, nsubs[0]})

	// Redeem logintoken, typically through links in email notifications.
	loginToken := tokenSign(tokentypeLogin, time.Now(), user.ID)
	api.Redeem(ctx, prep(), loginToken)
	tneederr(t, "user:error", func() { api.Redeem(ctx, prep(), "") })
	tneederr(t, "user:badAuth", func() { api.Redeem(ctx, prep(), csrfToken) })                                      // Wrong kind of token.
	tneederr(t, "user:error", func() { api.Redeem(ctx, prep(), tokenSign(tokentypeLogin, time.Now(), user.ID+1)) }) // User does exist (anymore).
	api.Overview(ctx)

	var lastUpdateID int64
	updates := func() []ModuleUpdate {
		t.Helper()
		l, err := bstore.QueryDB[ModuleUpdate](ctxbg, database).FilterGreater("ID", lastUpdateID).SortAsc("ID").List()
		tcheckf(t, err, "list registered module updates")
		if len(l) > 0 {
			lastUpdateID = l[len(l)-1].ID
		}
		return l
	}

	// Move tlog forward. Nothing was added. No notifications to receive.
	err = stepTlog()
	tcheckf(t, err, "moving empty tlog forward")
	up := updates()
	tcompare(t, len(up), 0)

	// Add record to sumdb, move tlog forward, and check user has received a notification.
	id, err := sumsrv.Lookup(ctxbg, module.Version{Path: "vcs.localhost/testrepo", Version: "v0.0.1"})
	tcheckf(t, err, "add module to sumdb")
	tcompare(t, id, int64(0))
	id, err = sumsrv.Lookup(ctxbg, module.Version{Path: "vcs.localhost/testrepo", Version: "v0.0.1"})
	tcheckf(t, err, "fetch existing module from sumdb")
	tcompare(t, id, int64(0))

	err = stepTlog()
	tcheckf(t, err, "moving empty tlog forward")
	up = updates()
	tcompare(t, len(up), 1+1)

	nmsub.Module = "golang.org/toolchain"
	nmsub.OlderVersions = true
	nmsub.Prerelease = true
	api.SubscriptionSave(ctx, nmsub)
	_, err = sumsrv.Lookup(ctxbg, module.Version{Path: "golang.org/toolchain", Version: "v0.0.1-go1.21.1.linux-amd64"})
	tcheckf(t, err, "add module to sumdb")
	api.Forward(xctx) // Forward through index.
	up = updates()
	tcompare(t, len(up), 1+0)
	mailtx := tneedmail(t, "2 modules with 2 new versions")

	_, err = sumsrv.Lookup(ctxbg, module.Version{Path: "golang.org/toolchain", Version: "v0.0.1-go1.21.1.openbsd-amd64"})
	tcheckf(t, err, "add module to sumdb")
	err = stepTlog()
	tcheckf(t, err, "moving tlog after adding record")
	up = updates()
	tcompare(t, len(up), 1)

	_, err = sumsrv.Lookup(ctxbg, module.Version{Path: "golang.org/toolchain", Version: "v0.0.1-go1.21.2.openbsd-amd64"})
	tcheckf(t, err, "add module to sumdb")
	err = stepTlog()
	tcheckf(t, err, "moving tlog after adding record")
	up = updates()
	tcompare(t, len(up), 1)

	xsub := Subscription{Module: "vcs.localhost/sub"}
	xsub = api.SubscriptionCreate(ctx, xsub)

	// Test various subscription scenario's.
	checkMatch := func(sub Subscription, path, version string, expMatch bool) {
		t.Helper()

		sub.ID = xsub.ID
		sub.Module = xsub.Module
		api.SubscriptionSave(ctx, sub)

		_, err = sumsrv.Lookup(ctxbg, module.Version{Path: path, Version: version})
		tcheckf(t, err, "add module to sumdb")
		err = stepTlog()
		tcheckf(t, err, "moving tlog after adding record")
		up = updates()
		if expMatch {
			tcompare(t, len(up), 1)
		} else {
			tcompare(t, len(up), 0)
		}
	}

	// OlderVersions
	checkMatch(Subscription{OlderVersions: true}, "vcs.localhost/sub", "v0.0.5", true)
	checkMatch(Subscription{OlderVersions: true}, "vcs.localhost/sub", "v0.0.6", true)
	checkMatch(Subscription{}, "vcs.localhost/sub", "v0.0.1", false)                    // Older, no match.
	checkMatch(Subscription{OlderVersions: true}, "vcs.localhost/sub", "v0.0.2", true)  // Older now matches.
	checkMatch(Subscription{OlderVersions: true}, "vcs.localhost/sub", "v0.0.2", false) // Not again.

	// BelowModule
	checkMatch(Subscription{BelowModule: true}, "vcs.localhost/sub/submod", "v0.0.5", true) // Independent version.
	checkMatch(Subscription{BelowModule: true}, "vcs.localhost/sub/submod", "v0.0.6", true)
	checkMatch(Subscription{BelowModule: true}, "vcs.localhost/sub/submod", "v0.0.1", false)                      // Older.
	checkMatch(Subscription{BelowModule: true, OlderVersions: true}, "vcs.localhost/sub/submod", "v0.0.2", true)  // Older now matches.
	checkMatch(Subscription{BelowModule: true, OlderVersions: true}, "vcs.localhost/sub/submod", "v0.0.2", false) // Not again.
	checkMatch(Subscription{}, "vcs.localhost/sub/submod2", "v0.0.5", false)                                      // Not below modules.

	// Prerelease
	checkMatch(Subscription{Prerelease: true}, "vcs.localhost/sub", "v0.0.7-pre5", true)
	checkMatch(Subscription{Prerelease: true}, "vcs.localhost/sub", "v0.0.7-pre6", true)
	checkMatch(Subscription{}, "vcs.localhost/sub", "v0.0.7-pre1", false)                                     // No prereleases.
	checkMatch(Subscription{Prerelease: true}, "vcs.localhost/sub", "v0.0.7-pre2", false)                     // Older.
	checkMatch(Subscription{Prerelease: true, OlderVersions: true}, "vcs.localhost/sub", "v0.0.7-pre3", true) // Older now okay.
	checkMatch(Subscription{Prerelease: true}, "vcs.localhost/sub", "v0.0.7-pre7", true)
	checkMatch(Subscription{Prerelease: true}, "vcs.localhost/sub", "v0.0.7-pre7", false) // Not again.

	// Pseudo, note difference in timestamp in version.
	checkMatch(Subscription{Prerelease: true, Pseudo: false}, "vcs.localhost/sub", "v0.0.12-0.20240915151855-a7bdc41cd407", false)
	checkMatch(Subscription{Prerelease: true, Pseudo: true}, "vcs.localhost/sub", "v0.0.12-0.20240915151856-a7bdc41cd407", true)
	checkMatch(Subscription{Prerelease: true, Pseudo: true}, "vcs.localhost/sub", "v0.0.12-0.20240915151851-a7bdc41cd407", false)                      // Older.
	checkMatch(Subscription{Prerelease: true, Pseudo: true, OlderVersions: true}, "vcs.localhost/sub", "v0.0.12-0.20240915151852-a7bdc41cd407", true)  // Older now OK.
	checkMatch(Subscription{Prerelease: true, Pseudo: true, OlderVersions: true}, "vcs.localhost/sub", "v0.0.12-0.20240915151852-a7bdc41cd407", false) // Not again.

	// Ignore.
	xsub.Module = "mirror.localhost/sub"
	checkMatch(Subscription{}, "mirror.localhost/sub", "v0.0.5", false)
	xsub.Module = "huge.localhost"
	checkMatch(Subscription{BelowModule: true}, "huge.localhost/sub", "v0.0.5", false)

	// Check that users unsubscribe id is in the message and that a POST to the endpoint (clicking the link) will unsubscribe.
	user, err = bstore.QueryDB[User](ctx, database).Get()
	tcheckf(t, err, "get user for unsubscriptions")
	tcompare(t, user.UpdatesUnsubscribed, false)
	tcompare(t, strings.Contains(mailtx.HTML, user.UpdatesUnsubscribeToken), true)
	thttppost(t, publicMux, "/unsubscribe?id="+url.QueryEscape(user.UpdatesUnsubscribeToken), url.Values{}, http.StatusOK)
	user, err = bstore.QueryDB[User](ctx, database).Get()
	tcheckf(t, err, "get user for unsubscriptions")
	tcompare(t, user.UpdatesUnsubscribed, true)

	// Various checks for unsubscribe
	thttppost(t, publicMux, "/unsubscribe", url.Values{}, http.StatusBadRequest)
	thttppost(t, publicMux, "/unsubscribe?id=bogus", url.Values{}, http.StatusBadRequest)

	// Check that password reset request email has unsubscription token, and that a POST to unsubscribe causes unsubscribe.
	api.RequestPasswordReset(ctx, prep(), user.Email)
	mailtx = tneedmail(t, "Password reset requested")
	tcompare(t, strings.Contains(mailtx.HTML, user.MetaUnsubscribeToken), true)
	thttppost(t, publicMux, "/unsubscribe?id="+url.QueryEscape(user.MetaUnsubscribeToken), url.Values{}, http.StatusOK)
	user, err = bstore.QueryDB[User](ctx, database).Get()
	tcheckf(t, err, "get user for unsubscriptions")
	tcompare(t, user.MetaUnsubscribed, true)

	// Test admin endpoint downloading user data.
	thttpget(t, http.DefaultServeMux, "/viewuser", nil, http.StatusUnauthorized)
	thttpget(t, http.DefaultServeMux, "/viewuser.csv.zip", nil, http.StatusUnauthorized)
	thttpget(t, http.DefaultServeMux, "/gopherwatch.db", nil, http.StatusUnauthorized)
	badauth := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:badpass"))}
	thttpget(t, http.DefaultServeMux, "/viewuser", badauth, http.StatusUnauthorized)
	thttpget(t, http.DefaultServeMux, "/viewuser.csv.zip", badauth, http.StatusUnauthorized)
	thttpget(t, http.DefaultServeMux, "/gopherwatch.db", badauth, http.StatusUnauthorized)
	// Missing email parameter.
	okauth := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"+config.Admin.Password))}
	thttpget(t, http.DefaultServeMux, "/viewuser", okauth, http.StatusBadRequest)
	thttpget(t, http.DefaultServeMux, "/viewuser.csv.zip", okauth, http.StatusBadRequest)

	thttpget(t, http.DefaultServeMux, "/viewuser?email="+url.QueryEscape("gw@gw.example"), okauth, http.StatusOK)
	thttpget(t, http.DefaultServeMux, "/viewuser.csv.zip?email="+url.QueryEscape("gw@gw.example"), okauth, http.StatusOK)
	thttpget(t, http.DefaultServeMux, "/gopherwatch.db", okauth, http.StatusOK)
	thttpget(t, http.DefaultServeMux, "/viewuser?email="+url.QueryEscape("bogus@gw.example"), okauth, http.StatusBadRequest)

	// Now with recent modules fetched from sumdb.
	api.Recents(ctxbg)
	api.Overview(ctx)

	// Cause removal of module versions, checking that all related records are removed (eg no foreign key constraints left).
	config.ModuleVersionHistorySize = 2
	_, err = sumsrv.Lookup(ctxbg, module.Version{Path: "golang.org/toolchain", Version: "v0.0.1-go1.21.3.openbsd-amd64"})
	tcheckf(t, err, "add module to sumdb")
	err = stepTlog()
	tcheckf(t, err, "moving tlog after adding record")
	config.ModuleVersionHistorySize = 0 // Restore.

	// Send email. One message with all subscriptions so far.
	notify()
	mailtx = tneedmail(t, "3 modules with 14 new versions")

	// No email at second try.
	notify()

	// Delivery webhooks.
	hooktokens = make(chan struct{})
	go deliverHooksOnce()
	select {
	case hooktokens <- struct{}{}:
	case <-time.After(time.Second):
		t.Fatalf("no request for hook delivery in 1s")
	}
	select {
	case <-hooktokens: // Wait for completion
	case <-time.After(time.Second):
		t.Fatalf("hook delivery not seen within 1s")
	}
	select {
	case hooktokens <- struct{}{}:
		t.Fatalf("saw unexpected hook delivery request")
	case <-time.After(time.Second / 10):
	}
	tcompare(t, len(hooks), 1)
	const hookID = 1                                                  // First.
	tneederr(t, "user:error", func() { api.HookCancel(ctx, hookID) }) // Already done.
	tneederr(t, "user:error", func() { api.HookKick(ctx, hookID) })   // Already done.
	tneederr(t, "user:error", func() { api.HookCancel(ctx, 999) })    // Does not exist.
	tneederr(t, "user:error", func() { api.HookKick(ctx, 999) })      // Does not exist.
	hooks = nil

	tneederr(t, "user:error", func() { api.HookCancel(ctx, 0) }) // Bad 0.
	tneederr(t, "user:error", func() { api.HookKick(ctx, 0) })   // Bad 0.

	// Try again, should not see anything.
	go deliverHooksOnce()
	select {
	case hooktokens <- struct{}{}:
		t.Fatalf("saw unexpected hook delivery request")
	case <-time.After(time.Second / 10):
	}
	tcompare(t, len(hooks), 0)
	hooks = nil

	// Try delivering an email again, and make it fail. That should cause backoff to be
	// set to a week.
	user, err = bstore.QueryDB[User](xctx, database).Get()
	tcheckf(t, err, "get user for resubscribing")
	user.MetaUnsubscribed = false
	user.UpdatesUnsubscribed = false
	err = database.Update(ctxbg, &user)
	tcheckf(t, err, "resubscribe user")
	xsub.Module = "other.localhost/fail"
	checkMatch(xsub, "other.localhost/fail", "v0.1.0", true)
	outgoingEvent = webhook.EventFailed
	notify()
	tneedmail(t, "1 modules with 1 new versions")

	user, err = bstore.QueryDB[User](xctx, database).Get()
	tcheckf(t, err, "get user for backoff")
	tcompare(t, user.Backoff, BackoffDay)

	// No mail at the moment.
	xsub.Module = "vcs.localhost/fail"
	checkMatch(xsub, "vcs.localhost/fail", "v0.1.1", true)
	outgoingEvent = webhook.EventFailed
	notify()

	// Now get destination address on suppression list. That should cause
	// unsubscription of all messages.
	outgoingEvent = webhook.EventSuppressed
	api.RequestPasswordReset(xctx, prep(), user.Email)
	tneedmail(t, "Password reset requested")
	outgoingEvent = webhook.EventDelivered

	user, err = bstore.QueryDB[User](xctx, database).Get()
	tcheckf(t, err, "get user for subscriptions")
	tcompare(t, user.MetaUnsubscribed, true)
	tcompare(t, user.UpdatesUnsubscribed, true)

	// UserRemove.
	api.UserRemove(ctx)
	_, err = bstore.QueryDB[User](ctx, database).Get()
	if err != bstore.ErrAbsent {
		t.Fatalf("get user after removing, got %v, expected ErrAbsent", err)
	}

	// Token/session is still signed for user id, but it no longer exists and should fail.
	thttpsherpa(t, publicMux, "/api/Overview", csrfToken, sessionToken, nil, "user:badAuth")

	api.TestSend(xctx, config.Admin.Password, "signup", "gw@gw.example")
	tneedmail(t, "Verify new account")
	tneederr(t, "user:error", func() { api.TestSend(xctx, "", "signup", "gw@gw.example") })
	tneederr(t, "user:error", func() { api.TestSend(xctx, "bogus", "signup", "gw@gw.example") })
	tneederr(t, "user:error", func() { api.TestSend(xctx, config.Admin.Password, "bogus", "gw@gw.example") })
	tneederr(t, "user:error", func() { api.TestSend(xctx, config.Admin.Password, "signup", "invalid address") })
}
