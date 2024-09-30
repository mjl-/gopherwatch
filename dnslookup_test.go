package main

import (
	"reflect"
	"testing"
	"time"
)

func TestLookupName(t *testing.T) {
	check := func(path string, expName string, expErr bool) {
		t.Helper()
		name, err := lookupName("l.beta.gopherwatch.org", path)
		if (err != nil) != expErr {
			t.Fatalf("got err %v, expected error: %v", err, expErr)
		}
		if name != expName {
			t.Fatalf("got name %q, expected %q", name, expName)
		}
	}

	check("github.com/mjl-/test", "test.mjl_2d._.github.com.v0.l.beta.gopherwatch.org.", false)
	check("github.com/mjl-/Test", "_54est.mjl_2d._.github.com.v0.l.beta.gopherwatch.org.", false)
	check("github.com/☺", "", true)
	check("host.example/a b", "", true)                                             // Invalid for Go modules.
	check("host.example/*", "", true)                                               // Invalid for Go modules.
	check("host.example/_", "_5f._.host.example.v0.l.beta.gopherwatch.org.", false) // Escape _.
	check("host.example/a.b", "a_2eb._.host.example.v0.l.beta.gopherwatch.org.", false)
	check("☺.example/test", "", true)
	check("xn--74h.example/test", "test._.xn--74h.example.v0.l.beta.gopherwatch.org.", false) // punycode domain passed verbatim.
	check("example.com/xn--74h", "xn--74h._.example.com.v0.l.beta.gopherwatch.org.", false)   // punycode path element makes it into dns.
}

func TestParseVersions(t *testing.T) {
	check := func(txt string, expVersions []Version, expErr bool) {
		t.Helper()
		versions, err := parseVersions(txt)
		if (err != nil) != expErr {
			t.Fatalf("got err %v, expected error: %v", err, expErr)
		}
		if !reflect.DeepEqual(versions, expVersions) {
			t.Fatalf("got versions %q, expected %q", versions, expVersions)
		}
	}

	check("", nil, true)                  // Missing version.
	check("bad", nil, true)               // Malformed, no k=v.
	check("v=v0.1.2", nil, false)         // No results (missing t).
	check("v=v0.1.2 t=bogus", nil, true)  // Malformed t.
	check("v=bad t=66f8591d", nil, true)  // Malformed v.
	check("v=v1.0 t=66f8591d", nil, true) // Malformed v.
	check("v=v1 t=66f8591d", nil, true)   // Malformed v.
	check("v=v1.2.3 t=66f8591d", []Version{{"v1.2.3", 1, 2, 3, "", time.Unix(0x66f8591d, 0)}}, false)
	check("v=v1.2.3 t=66f8591d; v=v0.99.999 t=66f8591e", []Version{
		{"v1.2.3", 1, 2, 3, "", time.Unix(0x66f8591d, 0)},
		{"v0.99.999", 0, 99, 999, "", time.Unix(0x66f8591e, 0)},
	}, false)
	check("other=ignored;v=v1.2.3 t=66f8591d", []Version{{"v1.2.3", 1, 2, 3, "", time.Unix(0x66f8591d, 0)}}, false)
}
