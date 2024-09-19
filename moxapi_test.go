package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mjl-/bstore"
	"github.com/mjl-/mox/webhook"
)

func TestSignup(t *testing.T) {
	test := func(from, subject string, validated bool, expUser bool) {
		t.Helper()
		in := webhook.Incoming{
			From:      []webhook.NameAddress{{Address: from}},
			To:        []webhook.NameAddress{{Address: config.SignupAddress}},
			Subject:   subject,
			MessageID: random() + "@localhost",
			Meta: webhook.IncomingMeta{
				MsgFromValidated: validated,
			},
		}

		inbuf, err := json.Marshal(in)
		tcheckf(t, err, "marshal incoming webhook")
		u := moxhookin.URL + config.Mox.Webhook.IncomingPath
		inreq, err := http.NewRequest("POST", u, bytes.NewReader(inbuf))
		tcheckf(t, err, "request for incoming webhook")
		inreq.Header.Set("Content-Type", "application/json")
		inreq.SetBasicAuth(config.Mox.Webhook.Username, config.Mox.Webhook.Password)
		inresp, err := http.DefaultClient.Do(inreq)
		tcheckf(t, err, "http transaction for incoming webhook")
		tcompare(t, inresp.StatusCode, http.StatusOK)
		if expUser {
			tneedmail0(t, "re: signup for "+config.ServiceName)
		}

		user, err := bstore.QueryDB[User](ctxbg, database).Get()
		if !expUser {
			tcompare(t, err, bstore.ErrAbsent)
			return
		}
		tcheckf(t, err, "get user for verify token")
		req := http.Request{Header: http.Header{}, RemoteAddr: "127.0.0.1:1234"} // For rate limiter.
		resp := httpResponse{http.Header{}}                                      // For capturing cookies to use in next call.
		reqInfo := requestInfo{user.Email, user.ID, &resp, &req}
		ctx := context.WithValue(ctxbg, requestInfoCtxKey, reqInfo)
		api := API{}
		api.UserRemove(ctx)
	}

	test("newuser@gw.example", "signup for "+config.ServiceName, true, true)
	test("spammer@gw.example", "spam subject", true, false)
	test("nonvalidated@gw.example", "signup for "+config.ServiceName, false, false)
}
