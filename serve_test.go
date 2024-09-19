package main

import (
	"net/http"
	"testing"
)

func TestServe(t *testing.T) {
	// Render templates.
	thttpget(t, publicMux, "/", nil, http.StatusOK)
	thttpget(t, publicMux, "/webhooks", nil, http.StatusOK)
	thttpget(t, publicMux, "/forward", nil, http.StatusOK)
	thttpget(t, publicMux, "/unsubscribe", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/signup/", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/passwordreset/", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/moduleupdates/", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/signup/html", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/signup/text", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/passwordreset/html", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/passwordreset/text", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/moduleupdates/html", nil, http.StatusOK)
	thttpget(t, publicMux, "/preview/moduleupdates/text", nil, http.StatusOK)
}
