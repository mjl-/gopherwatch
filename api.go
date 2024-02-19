package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/mjl-/bstore"
	"github.com/mjl-/mox/ratelimit"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/sherpa"
)

func makeLimiter(wl ...ratelimit.WindowLimit) *ratelimit.Limiter {
	return &ratelimit.Limiter{WindowLimits: wl}
}

func windowLimit(w time.Duration, l0, l1, l2 int64) ratelimit.WindowLimit {
	return ratelimit.WindowLimit{Window: w, Limits: [3]int64{l0, l1, l2}}
}

// We limit operations per ip/subnet, over various windows to allow some burstiness but not prolonged use.
var (
	ratelimitSignup               = makeLimiter(windowLimit(time.Minute, 5, 15, 45), windowLimit(time.Hour, 10, 30, 90), windowLimit(24*time.Hour, 20, 60, 180))
	ratelimitSignupEmail          = makeLimiter(windowLimit(time.Minute, 5, 15, 45), windowLimit(time.Hour, 10, 30, 90), windowLimit(24*time.Hour, 20, 60, 180))
	ratelimitVerify               = makeLimiter(windowLimit(time.Minute, 5, 15, 45), windowLimit(time.Hour, 10, 30, 90), windowLimit(24*time.Hour, 20, 60, 180))
	ratelimitRequestPasswordReset = makeLimiter(windowLimit(time.Minute, 5, 15, 45), windowLimit(time.Hour, 10, 30, 90), windowLimit(24*time.Hour, 20, 60, 180))
	ratelimitResetPassword        = makeLimiter(windowLimit(time.Minute, 5, 15, 45), windowLimit(time.Hour, 10, 30, 90), windowLimit(24*time.Hour, 20, 60, 180))
	ratelimitLogin                = makeLimiter(windowLimit(time.Minute, 10, 20, 40), windowLimit(time.Hour, 20, 40, 80), windowLimit(24*time.Hour, 40, 80, 160))
	ratelimitRedeem               = makeLimiter(windowLimit(time.Minute, 10, 20, 40), windowLimit(time.Hour, 20, 40, 80), windowLimit(24*time.Hour, 40, 80, 160))
	ratelimitBadLogin             = makeLimiter(windowLimit(time.Minute, 5, 10, 20), windowLimit(time.Hour, 10, 20, 40), windowLimit(24*time.Hour, 20, 40, 80))

	ratelimitForward = makeLimiter(windowLimit(time.Minute, 2, 4, 8), windowLimit(time.Hour, 10, 30, 90), windowLimit(24*time.Hour, 20, 60, 180))

	// We reuse the ip-based ratelimiter for outgoing connections too, with ip 0.0.0.0.
	ratelimitSumdb = makeLimiter(windowLimit(time.Second, 5, 5, 5), windowLimit(time.Minute, 25, 25, 25), windowLimit(time.Hour, 120, 120, 120))
	ratelimitEmail = makeLimiter(windowLimit(time.Minute, 60, 60, 60), windowLimit(time.Minute, 500, 500, 500), windowLimit(time.Hour, 3000, 3000, 3000))
)

func xusererrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	slog.Error("user error", "msg", msg)
	panic(&sherpa.Error{Code: "user:error", Message: msg})
}

func xusercheckf(err error, format string, args ...any) {
	if err != nil {
		msg := fmt.Sprintf("%s: %s", fmt.Sprintf(format, args...), err)
		slog.Error("user error", "msg", msg)
		panic(&sherpa.Error{Code: "user:error", Message: msg})
	}
}

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		msg := fmt.Sprintf("%s: %s", fmt.Sprintf(format, args...), err)
		slog.Error("server error", "msg", msg)
		panic(&sherpa.Error{Code: "server:error", Message: msg})
	}
}

type ctxKey string

// For passing authenticated user, and request/response object to API calls.
var requestInfoCtxKey ctxKey = "requestInfo"

type requestInfo struct {
	// Only set for API calls that require auth.
	Email  string
	UserID int64

	// Always set.
	Response http.ResponseWriter // For setting cookies.
	Request  *http.Request       // For X-Forwarded-* headers.
}

// For setting secure cookies.
func isHTTPS(r *http.Request) bool {
	if config.ReverseProxied {
		return r.Header.Get("X-Forwarded-Proto") == "https"
	}
	return r.TLS != nil
}

// For rate-limiting.
func remoteIP(r *http.Request) net.IP {
	if config.ReverseProxied {
		s := r.Header.Get("X-Forwarded-For")
		ipstr := strings.TrimSpace(strings.Split(s, ",")[0])
		return net.ParseIP(ipstr)
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}

// Add history to user account.
func addUserLogf(tx *bstore.Tx, userID int64, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	slog.Info("adding log for user id", "userid", userID, "msg", msg)
	return tx.Insert(&UserLog{UserID: userID, Text: msg})
}

func xaddUserLogf(tx *bstore.Tx, userID int64, format string, args ...any) {
	err := addUserLogf(tx, userID, format, args...)
	xcheckf(err, "adding user log")
}

// API holds functions for the frontend.
type API struct{}

func xrandomID(n int) string {
	return base64.RawURLEncoding.EncodeToString(xrandom(16))
}

func xrandom(n int) []byte {
	buf := make([]byte, n)
	x, err := cryptorand.Read(buf)
	if err != nil {
		panic("read random")
	} else if x != n {
		panic("short random read")
	}
	return buf
}

func xrate(limit *ratelimit.Limiter, r *http.Request) {
	ip := remoteIP(r)
	if ip != nil && !limit.Add(ip, time.Now(), 1) {
		xusererrorf("ip-based rate limit for this operation reached, try again later")
	}
}

// We limit the number of non-update-email-messages to a user. Don't want to
// overwhelm anyone with signup or password reset messages.
func xratemeta(tx *bstore.Tx, user User, signup bool) {
	if !signup && user.VerifyToken != "" {
		xusererrorf("must first verify account")
	}

	q := bstore.QueryTx[Message](tx)
	q.FilterNonzero(Message{UserID: user.ID, Meta: true})
	q.FilterGreater("Submitted", time.Now().Add(-24*time.Hour))
	q.SortDesc("ID")
	q.Limit(config.DailyMetaMessagesMax + 1)
	count, err := q.Count()
	xcheckf(err, "checking outgoing messages for rate limit")
	if count > config.DailyMetaMessagesMax {
		xusererrorf("too many email messages to this address in past 24 hours, try again later")
	}
}

func xcanonicalAddress(email string) string {
	addr, err := smtp.ParseAddress(email)
	xusercheckf(err, "validating address")
	return addr.Pack(true)
}

// Signup registers a new account. We send an email for users to verify they
// control the email address. If we already have a verified account, we send a
// password reset instead.
func (API) Signup(ctx context.Context, email string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	xrate(ratelimitSignup, reqInfo.Request)

	email = xcanonicalAddress(email)

	// Make SMTP connection. If it fails, return error to user.
	if !smtpCanSend() {
		xcheckf(errors.New("rate limiter"), "cannot send email verification messages at this moment, please try again soon")
	}
	smtpTake()
	dialctx, dialcancel := context.WithTimeout(ctx, 10*time.Second)
	smtpconn, err := smtpDial(dialctx)
	dialcancel()
	xcheckf(err, "preparing connection to mail server before creating user")
	defer func() {
		err := smtpconn.Close()
		logCheck(err, "closing smtp connectiong")
	}()

	var user User
	var msg []byte
	var mailFrom, sendID string
	var eightbit, smtputf8 bool
	var m Message
	err = database.Write(ctx, func(tx *bstore.Tx) error {
		user, err = bstore.QueryTx[User](tx).FilterNonzero(User{Email: email}).Get()
		if err == bstore.ErrAbsent || err == nil && user.VerifyToken != "" {
			metaUnsubToken := user.MetaUnsubscribeToken
			if metaUnsubToken == "" {
				metaUnsubToken = xrandomID(16)
			}
			updatesUnsubToken := user.MetaUnsubscribeToken
			if updatesUnsubToken == "" {
				updatesUnsubToken = xrandomID(16)
			}
			verifyToken := user.VerifyToken
			if verifyToken == "" {
				verifyToken = xrandomID(16)
			}
			user = User{
				ID:                      user.ID,
				Email:                   email,
				VerifyToken:             verifyToken,
				MetaUnsubscribeToken:    metaUnsubToken,
				UpdatesUnsubscribeToken: updatesUnsubToken,
				UpdateInterval:          user.UpdateInterval,
			}
			if user.ID > 0 {
				xratemeta(tx, user, true)
				err = tx.Update(&user)
			} else {
				user.UpdateInterval = IntervalDay
				err = tx.Insert(&user)
			}
			if err != nil {
				return fmt.Errorf("adding user to database: %v", err)
			}

			subject, text, html, err := composeSignup(user)
			xcheckf(err, "composing signup text")
			mailFrom, sendID, msg, eightbit, smtputf8, err = compose(true, user, subject, text, html)
			xcheckf(err, "composing signup message")

			m = Message{
				UserID: user.ID,
				Meta:   true,
				SendID: sendID,
			}
			if err := tx.Insert(&m); err != nil {
				return fmt.Errorf("adding outgoing message to database: %v", err)
			}
			xaddUserLogf(tx, user.ID, "Signup through website")

			return nil
		}
		xcheckf(err, "looking up user in database")

		// Already exists and has been verified. We'll send a message for a password reset instead.
		xratemeta(tx, user, false)

		user.PasswordResetToken = xrandomID(16)
		if err := tx.Update(&user); err != nil {
			return fmt.Errorf("updating user in database: %v", err)
		}

		subject, text, html, err := composePasswordReset(user)
		xcheckf(err, "composing password reset text")
		mailFrom, sendID, msg, eightbit, smtputf8, err = compose(true, user, subject, text, html)
		xcheckf(err, "composing password reset message")

		m = Message{
			UserID: user.ID,
			Meta:   true,
			SendID: sendID,
		}
		if err := tx.Insert(&m); err != nil {
			return fmt.Errorf("adding outgoing message to database: %v", err)
		}
		xaddUserLogf(tx, user.ID, "Signup for existing account, sending password reset.")

		return nil
	})
	xcheckf(err, "adding user to database")

	// Send the message.
	submitctx, submitcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer submitcancel()
	if err := smtpSubmit(submitctx, smtpconn, true, mailFrom, email, msg, eightbit, smtputf8); err != nil {
		logErrorx("submission for signup/passwordreset", err, "userid", user.ID)
		if err := database.Delete(context.Background(), &m); err != nil {
			logErrorx("removing metamessage added before submission error", err)
		}
		xcheckf(err, "submitting verification/password reset email")
	}
	slog.Info("submitted signup/passwordreset email", "userid", user.ID)
}

// SignupEmail returns the email address for a verify token. So we can show it, and
// the user can get prompted for saving full full login credentials by a password
// manager after verifying the signup.
func (API) SignupEmail(ctx context.Context, prepToken, verifyToken string) (email string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xrate(ratelimitSignupEmail, reqInfo.Request)

	if verifyToken == "" {
		xusererrorf("token cannot be empty")
	}

	xcheckprep(reqInfo, prepToken)

	err := database.Write(ctx, func(tx *bstore.Tx) error {
		user, err := bstore.QueryTx[User](tx).FilterNonzero(User{VerifyToken: verifyToken}).Get()
		if err == bstore.ErrAbsent {
			xusererrorf("unknown verification token for email address, your account may already have been verified")
		}
		xcheckf(err, "checking verification token")
		email = user.Email
		return nil
	})
	xcheckf(err, "storing verification")
	return
}

// VerifySignup verifies a new account by checking the token. The token was in the
// URL in the signup email.
func (API) VerifySignup(ctx context.Context, prepToken, verifyToken, email, password string) (csrfToken string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xrate(ratelimitVerify, reqInfo.Request)

	xcheckprep(reqInfo, prepToken)

	if verifyToken == "" {
		xusererrorf("token cannot be empty")
	}

	if len(password) < 8 {
		xusererrorf("password must be at least 8 characters")
	}

	email = xcanonicalAddress(email)

	var user User
	err := database.Write(ctx, func(tx *bstore.Tx) error {
		var err error
		user, err = bstore.QueryTx[User](tx).FilterNonzero(User{VerifyToken: verifyToken, Email: email}).Get()
		if err == bstore.ErrAbsent {
			xusererrorf("unknown verification token for email address, your account may already have been verified")
		}
		xcheckf(err, "checking verification token")

		saltedhash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		xcheckf(err, "deriving salted hash")
		user.SaltedHashedPassword = string(saltedhash)
		// Empty verifytoken means account has been verified.
		user.VerifyToken = ""
		err = tx.Update(&user)
		xcheckf(err, "marking user verified")

		xaddUserLogf(tx, user.ID, "Account verified")
		return nil
	})
	xcheckf(err, "storing verification")

	return loginSession(reqInfo.Response, reqInfo.Request, user.ID)
}

// UserRemove lets a user remove their account.
func (API) UserRemove(ctx context.Context) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	user := User{ID: reqInfo.UserID}
	err := database.Write(ctx, func(tx *bstore.Tx) error {
		if err := tx.Get(&user); err != nil {
			return err
		}

		_, err := bstore.QueryTx[UserLog](tx).FilterNonzero(UserLog{UserID: user.ID}).Delete()
		xcheckf(err, "removing user userlogs")

		_, err = bstore.QueryTx[Subscription](tx).FilterNonzero(Subscription{UserID: user.ID}).Delete()
		xcheckf(err, "removing user subscriptions")

		_, err = bstore.QueryTx[ModuleUpdate](tx).FilterNonzero(ModuleUpdate{UserID: user.ID}).Delete()
		xcheckf(err, "removing user moduleudates")

		_, err = bstore.QueryTx[Message](tx).FilterNonzero(Message{UserID: user.ID}).Delete()
		xcheckf(err, "removing user messages")

		err = tx.Delete(&user)
		xcheckf(err, "removing user")

		return nil
	})
	xcheckf(err, "removing user account")

	slog.Info("removed user account", "emailhash", sha256.Sum256([]byte(user.Email)), "userid", user.ID)

	// Remove cookie to prevent any attempt to use the old session for a user that no
	// longer exists.
	http.SetCookie(reqInfo.Response, &http.Cookie{
		Name:     "gopherwatchsession",
		Secure:   isHTTPS(reqInfo.Request),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete cookie
	})
}

// Redeem turns a login token, as used in login-links in notification emails, into
// a session by returning a csrf token and setting a session cookie.
func (API) Redeem(ctx context.Context, prepToken, loginToken string) (csrfToken string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xrate(ratelimitRedeem, reqInfo.Request)

	if loginToken == "" {
		panic(&sherpa.Error{Code: "user:error", Message: "missing token"})
	}

	xcheckprep(reqInfo, prepToken)

	userID := xtokenVerify(tokentypeLogin, loginToken)

	user := User{ID: userID}
	err := database.Get(ctx, &user)
	if err == bstore.ErrAbsent {
		xusererrorf("no such user")
	}
	xcheckf(err, "get user")

	return loginSession(reqInfo.Response, reqInfo.Request, user.ID)
}

// RequestPasswordReset requests a password reset. We send an email with a link
// with a password reset token.
func (API) RequestPasswordReset(ctx context.Context, prepToken, email string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xrate(ratelimitRequestPasswordReset, reqInfo.Request)

	xcheckprep(reqInfo, prepToken)

	email = xcanonicalAddress(email)

	var user User
	err := database.Write(ctx, func(tx *bstore.Tx) error {
		u, err := bstore.QueryTx[User](tx).FilterNonzero(User{Email: email}).Get()
		if err != nil {
			return err
		}
		xratemeta(tx, u, false)

		u.PasswordResetToken = xrandomID(16)
		if err := tx.Update(&u); err != nil {
			return fmt.Errorf("updating user in database: %v", err)
		}
		user = u

		return nil
	})
	if err != nil && errors.Is(err, bstore.ErrAbsent) {
		return
	}
	xcheckf(err, "requesting password reset")

	subject, text, html, err := composePasswordReset(user)
	xcheckf(err, "composing password reset text")

	mailFrom, sendID, msg, eightbit, smtputf8, err := compose(true, user, subject, text, html)
	xcheckf(err, "composing password reset message")

	smtpTake()
	sendctx, sendcancel := context.WithTimeout(ctx, 10*time.Second)
	defer sendcancel()
	smtpconn, err := smtpDial(sendctx)
	xcheckf(err, "dial smtp server")
	defer func() {
		err := smtpconn.Close()
		logCheck(err, "closing smtp connection")
	}()
	err = smtpSubmit(sendctx, smtpconn, true, mailFrom, user.Email, msg, eightbit, smtputf8)
	xcheckf(err, "sending email")

	err = database.Write(context.Background(), func(tx *bstore.Tx) error {
		m := Message{
			UserID: user.ID,
			Meta:   true,
			SendID: sendID,
		}
		err := tx.Insert(&m)
		xcheckf(err, "storing reference to sent message")

		xaddUserLogf(tx, user.ID, "Password reset requested")

		return nil
	})
	xcheckf(err, "storing history (message has been sent)")
}

// ResetPassword resets a password for an account based on a token.
func (API) ResetPassword(ctx context.Context, prepToken, email, password, resetToken string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xrate(ratelimitResetPassword, reqInfo.Request)

	xcheckprep(reqInfo, prepToken)

	if resetToken == "" {
		panic(&sherpa.Error{Code: "user:error", Message: "missing token"})
	}

	if len(password) < 8 {
		xusererrorf("password must be at least 8 characters")
	}

	email = xcanonicalAddress(email)

	err := database.Write(ctx, func(tx *bstore.Tx) error {
		u, err := bstore.QueryTx[User](tx).FilterNonzero(User{Email: email, PasswordResetToken: resetToken}).Get()
		if err != nil {
			return err
		}
		saltedhash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		xcheckf(err, "deriving salted hash")
		u.SaltedHashedPassword = string(saltedhash)
		u.PasswordResetToken = ""
		u.Backoff = BackoffNone
		u.BackoffUntil = time.Time{}
		u.BackoffTried = false
		if err := tx.Update(&u); err != nil {
			return fmt.Errorf("updating user in database: %v", err)
		}
		xaddUserLogf(tx, u.ID, "Password was reset via website")
		return nil
	})
	if err != nil && errors.Is(err, bstore.ErrAbsent) {
		xusererrorf("could not find email address/reset code")
	}
	xcheckf(err, "changing password")
}

// Prep helps prevent CSRF calls. It must be called before calling functions like
// Login, Subscribe. It returns a token, which it also sets as a samesite cookie.
// The subsequent call must pass in the token, and the request must have the cookie
// set.
func (API) Prep(ctx context.Context) (prepToken string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	prepToken = tokenSign(tokentypePrep, time.Now(), 0)
	http.SetCookie(reqInfo.Response, &http.Cookie{
		Name:     "gopherwatchprep",
		Value:    prepToken,
		Secure:   isHTTPS(reqInfo.Request),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30, // Only for one API call.
	})
	return prepToken
}

// loginSession generates a new session for logging in a user. The returned csrf
// token must be included in a x-csrf header in API calls. The response also sets a
// cookie that must be present in API calls. The cookie from the "prep" call is
// deleted.
func loginSession(w http.ResponseWriter, r *http.Request, userID int64) (csrfToken string) {
	now := time.Now()
	csrfToken = tokenSign(tokentypeCSRF, now, userID)
	sessionToken := tokenSign(tokentypeSession, now, userID)

	slog.Info("new session", "userid", userID)

	// Add session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "gopherwatchsession",
		Value:    sessionToken,
		Secure:   isHTTPS(r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Remove prep cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "gopherwatchprep",
		Secure:   isHTTPS(r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete cookie
	})

	return csrfToken
}

// check a prep token and corresponding cookie.
func xcheckprep(reqInfo requestInfo, prepToken string) {
	prepCookie, _ := reqInfo.Request.Cookie("gopherwatchprep")
	if prepCookie == nil || prepToken == "" || prepToken != prepCookie.Value {
		xusererrorf("missing or mismatching csrf/cookie")
	}
	xtokenVerify(tokentypePrep, prepToken)
}

// Login verifies the accounts password and creates a new session, returning a csrf
// token that must be present in an x-csrf header in subsequent calls. A same-site
// cookie is set too.
func (API) Login(ctx context.Context, prepToken, email, password string) (csrfToken string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	xrate(ratelimitLogin, reqInfo.Request)

	email = xcanonicalAddress(email)

	// On a few failed login requests, ip has to wait.
	ip := remoteIP(reqInfo.Request)
	if ip != nil && !ratelimitBadLogin.CanAdd(ip, time.Now(), 1) {
		panic(&sherpa.Error{Code: "user:error", Message: "rate limited, too many authentication failures"})
	}

	xcheckprep(reqInfo, prepToken)

	user, err := bstore.QueryDB[User](ctx, database).FilterNonzero(User{Email: email}).Get()
	if err != bstore.ErrAbsent {
		xcheckf(err, "looking up user")
	}
	// We can continue with zero user. It won't verify.
	if err := bcrypt.CompareHashAndPassword([]byte(user.SaltedHashedPassword), []byte(password)); err != nil || user.VerifyToken != "" {
		if ip != nil {
			ratelimitBadLogin.Add(ip, time.Now(), 1)
		}
		panic(&sherpa.Error{Code: "user:loginFailed", Message: "invalid credentials: wrong email/password, or account not yet verified"})
	}

	return loginSession(reqInfo.Response, reqInfo.Request, user.ID)
}

type tokentype byte

const (
	tokentypeCSRF = iota + 1
	tokentypeSession
	tokentypePrep
	tokentypeLogin
)

// sign a new token. for tokentypePrep, the userID should not be used and be zero.

func tokenSign(tt tokentype, start time.Time, userID int64) string {
	buf := []byte{0, byte(tt)} // Version and Type
	buf = append(buf, xrandom(8)...)
	buf = binary.AppendVarint(buf, start.Unix())
	buf = binary.AppendVarint(buf, userID)
	mac := hmac.New(sha256.New, []byte(config.TokenSecret))
	mac.Write(buf)
	sig := mac.Sum(nil)
	sig = sig[:20]
	tokenBuf := append(sig, buf...)
	return base64.RawURLEncoding.EncodeToString(tokenBuf)
}

// verify a token. a token is valid for 24h after signing. there is no state on the
// server, it cannot be extended and is not invalidated when a user changes a
// password.
//
// for tokentypePrep, failures raise a "user:error". for other tokentypes, failures
// raise a "user:noAuth" or "user:badAuth". these last two cause the frontend the
// show a login window.
//
// tokens consist of:
//   - 20 bytes signature over the rest.
//   - 1 byte version
//   - 1 byte token type
//   - 8 byte random
//   - varint64 time of signing
//   - varint64 user id
func xtokenVerify(tt tokentype, token string) (userID int64) {
	// The *Auth errors trigger the login popup.
	noauth := "user:noAuth"
	badauth := "user:badAuth"
	if tt == tokentypePrep {
		// If the prep check fails, we must not send auth errors, or the login page will
		// hold on to the error to retry after authentication completed, which never
		// happens.
		noauth = "user:error"
		badauth = "user:error"
	}

	if token == "" {
		panic(&sherpa.Error{Code: noauth, Message: "missing token"})
	}
	tokenBuf, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(tokenBuf) < 20+1+1+8 {
		panic(&sherpa.Error{Code: badauth, Message: "malformed token"})
	}
	sig := tokenBuf[:20]
	buf := tokenBuf[20:]
	mac := hmac.New(sha256.New, []byte(config.TokenSecret))
	mac.Write(buf)
	expmac := mac.Sum(nil)
	expsig := expmac[:20]
	if !bytes.Equal(sig, expsig) {
		panic(&sherpa.Error{Code: badauth, Message: "invalid token, bad signature"})
	}
	r := bytes.NewReader(buf)
	version, err := r.ReadByte()
	if err != nil || version != 0 {
		panic(&sherpa.Error{Code: badauth, Message: "invalid token, unknown version"})
	}
	xtt, err := r.ReadByte()
	if err != nil || xtt != byte(tt) {
		panic(&sherpa.Error{Code: badauth, Message: "mismatching token type"})
	}
	var rand [8]byte
	if n, err := r.Read(rand[:]); err != nil || n != len(rand) {
		panic(&sherpa.Error{Code: badauth, Message: "invalid token, bad random"})
	}
	start, err := binary.ReadVarint(r)
	if err != nil {
		panic(&sherpa.Error{Code: badauth, Message: "invalid token, bad time"})
	}
	userID, err = binary.ReadVarint(r)
	if err != nil || userID < 0 {
		panic(&sherpa.Error{Code: badauth, Message: "invalid token, bad userid"})
	}
	if start < time.Now().Unix()-24*3600 || start > time.Now().Unix()+60 {
		panic(&sherpa.Error{Code: badauth, Message: "token expired"})
	}
	return userID
}

// Logout clears the session cookie. It does not invalidate the session.
func (API) Logout(ctx context.Context) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	// Remove cookie used during login.
	http.SetCookie(reqInfo.Response, &http.Cookie{
		Name:     "gopherwatchsession",
		Secure:   isHTTPS(reqInfo.Request),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete cookie
	})
}

type Overview struct {
	// From User
	Email               string
	UpdateInterval      Interval
	MetaUnsubscribed    bool
	UpdatesUnsubscribed bool
	Backoff             string
	BackoffUntil        time.Time

	Subscriptions []Subscription
	ModuleUpdates []ModuleUpdateURLs
	UserLogs      []UserLog
}

type ModuleUpdateURLs struct {
	ModuleUpdate
	RepoURL string
	TagURL  string
	DocURL  string
}

// Overview returns data needed for the overview page, after logging in.
func (API) Overview(ctx context.Context) (overview Overview) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	err := database.Read(ctx, func(tx *bstore.Tx) error {
		u := User{ID: reqInfo.UserID}
		err := tx.Get(&u)
		xcheckf(err, "get user")
		overview.Email = u.Email
		overview.UpdateInterval = u.UpdateInterval
		overview.Backoff = u.Backoff.String()
		overview.BackoffUntil = u.BackoffUntil

		overview.Subscriptions, err = bstore.QueryDB[Subscription](ctx, database).FilterNonzero(Subscription{UserID: reqInfo.UserID}).SortAsc("ID").List()
		xcheckf(err, "listing subscriptions")

		modups, err := bstore.QueryDB[ModuleUpdate](ctx, database).FilterNonzero(ModuleUpdate{UserID: reqInfo.UserID}).SortDesc("ID").Limit(50).List()
		xcheckf(err, "listing module updates")
		overview.ModuleUpdates = make([]ModuleUpdateURLs, len(modups))
		for i, modup := range modups {
			repoURL, tagURL, docURL := guessURLs(modup.Module, modup.Version)
			overview.ModuleUpdates[i] = ModuleUpdateURLs{modup, repoURL, tagURL, docURL}
		}

		overview.UserLogs, err = bstore.QueryDB[UserLog](ctx, database).FilterNonzero(UserLog{UserID: reqInfo.UserID}).SortDesc("ID").Limit(50).List()
		xcheckf(err, "listing userlogs")

		return nil
	})
	xcheckf(err, "gather data")
	return
}

// SubscribeSet changes either meta (service messages) or module updates
// subscriptions. If not subscribed, no messages are sent.
func (API) SubscribeSet(ctx context.Context, meta, subscribed bool) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	err := database.Write(ctx, func(tx *bstore.Tx) error {
		u := User{ID: reqInfo.UserID}
		err := tx.Get(&u)
		xcheckf(err, "get user")

		var kind string
		if meta {
			kind = "service messages"
			if u.MetaUnsubscribed == subscribed {
				xusererrorf("already set")
			} else {
				u.MetaUnsubscribed = subscribed
			}
		} else {
			kind = "module update messages"
			if u.UpdatesUnsubscribed == subscribed {
				xusererrorf("already set")
			} else {
				u.UpdatesUnsubscribed = subscribed
			}
		}

		err = tx.Update(&u)
		xcheckf(err, "updating user in database")

		xaddUserLogf(tx, u.ID, "Changed subscription for %s to %v", kind, subscribed)

		return nil
	})
	xcheckf(err, "update user")
}

// SetInterval sets a new minimum interval between update messages.
func (API) IntervalSet(ctx context.Context, interval Interval) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	switch interval {
	case IntervalImmediate, IntervalHour, IntervalDay, IntervalWeek:
	default:
		xusererrorf("bad value for interval")
	}

	err := database.Write(ctx, func(tx *bstore.Tx) error {
		u := User{ID: reqInfo.UserID}
		err := tx.Get(&u)
		xcheckf(err, "get user")

		u.UpdateInterval = interval
		err = tx.Update(&u)
		xcheckf(err, "updating user in database")

		xaddUserLogf(tx, u.ID, "Interval changed to %s", interval)
		return nil
	})
	xcheckf(err, "update user")
}

func xcheckModule(m string) {
	if strings.HasPrefix(m, "http://") || strings.HasPrefix(m, "https://") {
		xusererrorf("module should not be a url, only a Go module as used in an import statement")
	}
	if strings.Contains(m, " ") {
		xusererrorf("module cannot have a space")
	}
	if strings.Contains(m, "//") || strings.HasPrefix(m, "/") || strings.HasPrefix(m, "/") {
		xusererrorf("module must be a clean path, not start/end with a slash, and not have multiple slashes")
	}
}

// SubscriptionCreate adds a new subscription to a module.
func (API) SubscriptionCreate(ctx context.Context, sub Subscription) Subscription {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	xcheckModule(sub.Module)

	sub.ID = 0
	sub.UserID = reqInfo.UserID
	err := database.Insert(ctx, &sub)
	xusercheckf(err, "inserting new subscription")
	return sub
}

type SubscriptionImport struct {
	GoMod         string
	BelowModule   bool
	OlderVersions bool
	Prerelease    bool
	Pseudo        bool
	Comment       string
	Indirect      bool
}

// SubscriptionImport parses a go.mod file and subscribes to all direct and
// optionally indirect dependencies.
func (API) SubscriptionImport(ctx context.Context, imp SubscriptionImport) (subs []Subscription) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	f, err := modfile.Parse("go.mod", []byte(imp.GoMod), nil)
	xusercheckf(err, "parsing go.mod")

	err = database.Write(ctx, func(tx *bstore.Tx) error {
		for _, r := range f.Require {
			if r.Indirect && !imp.Indirect {
				continue
			}

			q := bstore.QueryTx[Subscription](tx)
			q.FilterNonzero(Subscription{UserID: reqInfo.UserID, Module: r.Mod.Path})
			exists, err := q.Exists()
			xcheckf(err, "check if subscription for dependency exists")
			if exists {
				continue
			}

			sub := Subscription{
				UserID:      reqInfo.UserID,
				Module:      r.Mod.Path,
				BelowModule: imp.BelowModule,
				Prerelease:  imp.Prerelease,
				Pseudo:      imp.Pseudo,
				Comment:     imp.Comment,
			}
			err = tx.Insert(&sub)
			xusercheckf(err, "inserting new subscription")
			subs = append(subs, sub)
		}
		return nil
	})
	xcheckf(err, "importing subscriptions")

	if len(subs) == 0 {
		xusererrorf("no additional dependencies found in go.mod")
	}

	return
}

// SubscriptionSave updates an existing subscription to a module.
func (API) SubscriptionSave(ctx context.Context, sub Subscription) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	xcheckModule(sub.Module)

	err := database.Write(ctx, func(tx *bstore.Tx) error {
		exists, err := bstore.QueryTx[Subscription](tx).FilterNonzero(Subscription{ID: sub.ID, UserID: reqInfo.UserID}).Limit(1).Exists()
		xcheckf(err, "get subscription")
		if !exists {
			xusererrorf("no such subscription")
		}

		sub.UserID = reqInfo.UserID
		err = tx.Update(&sub)
		xcheckf(err, "updating subscription")
		return nil
	})
	xcheckf(err, "updating subscription")
}

// SubscriptionRemove removes an existing subscription.
func (API) SubscriptionRemove(ctx context.Context, subID int64) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	n, err := bstore.QueryDB[Subscription](ctx, database).FilterNonzero(Subscription{UserID: reqInfo.UserID, ID: subID}).Limit(1).Delete()
	xcheckf(err, "removing subscription")
	if n == 0 {
		xusererrorf("subscription not found")
	}
}

type Recent struct {
	Module     string
	Version    string
	Discovered time.Time
	RepoURL    string
	TagURL     string
	DocURL     string
}

type Home struct {
	Version     string
	GoVersion   string
	GoOS        string
	GoArch      string
	ServiceName string
	AdminName   string
	AdminEmail  string
	Note        string
	SignupNote  string
	Recents     []Recent
}

func _recents(ctx context.Context, n int) (recents []Recent) {
	err := bstore.QueryDB[ModuleVersion](ctx, database).FilterEqual("Prerelease", false).SortDesc("ID").ForEach(func(mv ModuleVersion) error {
		for _, p := range config.SkipModulePrefixes {
			if strings.HasPrefix(mv.Module, p) {
				return nil
			}
		}
		repoURL, tagURL, docURL := guessURLs(mv.Module, mv.Version)
		recents = append(recents, Recent{mv.Module, mv.Version, mv.Discovered, repoURL, tagURL, docURL})
		if len(recents) >= n {
			return bstore.StopForEach
		}
		return nil
	})
	xcheckf(err, "listing recent packages")
	return
}

// Home returns data for the home page.
func (API) Home(ctx context.Context) (home Home) {
	home = Home{
		Version:     version,
		GoVersion:   runtime.Version(),
		GoOS:        runtime.GOOS,
		GoArch:      runtime.GOARCH,
		ServiceName: config.ServiceName,
	}

	home.Recents = _recents(ctx, 15)

	notebuf, _ := os.ReadFile("data/notes/home.txt")
	home.Note = string(notebuf)

	signupnotebuf, _ := os.ReadFile("data/notes/signup.txt")
	home.SignupNote = string(signupnotebuf)

	return
}

// Recents returns more recent packages, currently 150.
func (API) Recents(ctx context.Context) (recents []Recent) {
	return _recents(ctx, 150)
}

// Forward tries a bit harder to forward the transparency log. While we
// periodically fetch the /latest database tree state and forward the log, at
// least sum.golang.org only returns new values about once every 10 minutes.
// But we can look at the latest additions to index.golang.org and get the most
// recently added module from it, then look it up to gets the associated tree
// state and forward based on that.
func (API) Forward(ctx context.Context) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	if config.IndexBaseURL == "" {
		xusererrorf("no index url configured")
	}

	xrate(ratelimitForward, reqInfo.Request)

	u := config.IndexBaseURL + "/index?include=all&limit=1000&since=" + time.Now().Add(-5*time.Minute).UTC().Format(time.RFC3339)
	resp, err := httpClient.Get(u)
	xcheckf(err, "get latest modules")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		xusererrorf("index response %s, expected 200 ok", resp.Status)
	}
	var last string
	scan := bufio.NewScanner(resp.Body)
	for scan.Scan() {
		last = scan.Text()
	}
	err = scan.Err()
	xcheckf(err, "scan response")

	if last == "" {
		xusererrorf("no new modules in last 5 minutes")
	}

	var mod struct {
		Path    string
		Version string
	}
	err = json.Unmarshal([]byte(last), &mod)
	xusercheckf(err, "unmarshal module from json")

	path, err := module.EscapePath(mod.Path)
	xusercheckf(err, "escaping module path")
	vers, err := module.EscapeVersion(mod.Version)
	xusercheckf(err, "escaping module version")
	lookupURL := config.SumDB.BaseURL + "/lookup/" + path + "@" + vers
	resp, err = httpClient.Get(lookupURL)
	xcheckf(err, "lookup module")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		xusererrorf("lookup response %s, expected 200 ok", resp.Status)
	}
	lookupBuf, err := io.ReadAll(resp.Body)
	xusercheckf(err, "reading lookup note")

	// First part has the module versions and hashes. Second part is the signed
	// databased tree state. We only care about the second part and try to forward if
	// we can.
	t := bytes.SplitN(lookupBuf, []byte("\n\n"), 2)
	if len(t) != 2 {
		xusererrorf("bad note from lookup")
	}
	noteBuf := t[1]

	recordID := strings.SplitN(string(t[0]), "\n", 2)[0]
	slog.Info("found new module, trying to forward", "recordid", recordID)

	err = forwardProcessLatest(noteBuf)
	xcheckf(err, "forwarding transparency log to latest position and processing modules")
}

func (API) TestForward(ctx context.Context) {
	if !testlog {
		xusererrorf("not in testing mode")
	}

	if testLatestIndex >= len(testLatests) {
		xusererrorf("no more test latests")
	}
	latest := testLatests[testLatestIndex]
	testLatestIndex++

	err := forwardProcessLatest([]byte(latest))
	xcheckf(err, "forward to latest and processing modules")
}

func (API) TestSend(ctx context.Context, secret, kind, email string) {
	if secret == "" || secret != config.Admin.Password {
		xusererrorf("bad secret")
	}
	email = xcanonicalAddress(email)

	u := User{
		ID:                      1,
		Email:                   email,
		VerifyToken:             "SNrFOQ3bJ1kB90f7uIcpqQ",
		PasswordResetToken:      "Z8jE8SCACkZxny78zRnlwg",
		MetaUnsubscribeToken:    "uCU5AOH3vuxf8uycCCMlyg",
		UpdatesUnsubscribeToken: "lMfq7mAwtnZqvBO_3mqQJg",
	}
	loginToken := "naV4yBLcSNRCmCYoECffHy0A5QIABIqv971xSwxZ1q6w3QwC"

	subject, text, html, err := composeSample(kind, u, loginToken)
	xcheckf(err, "compose text")

	mailFrom, sendID, msg, eightbit, smtputf8, err := compose(kind != "moduleupdates", u, subject, text, html)
	xcheckf(err, "compose message")
	slog.Info("composed test message", "sendid", sendID)

	smtpconn, err := smtpDial(ctx)
	xcheckf(err, "dial smtp")
	defer smtpconn.Close()
	err = smtpSubmit(ctx, smtpconn, false, mailFrom, u.Email, msg, eightbit, smtputf8)
	xcheckf(err, "submit message")
}
