package main

import (
	"testing"
)

func TestCompose(t *testing.T) {
	var diffURL string

	diffURL = guessDiffURL("github.com/mjl-/mox", "v0.0.2", "v0.0.3")
	tcompare(t, diffURL, "https://github.com/mjl-/mox/compare/v0.0.2...v0.0.3")

	diffURL = guessDiffURL("golang.org/x/crypto", "v0.35.0", "v0.36.0")
	tcompare(t, diffURL, "https://github.com/golang/crypto/compare/v0.35.0...v0.36.0")

	diffURL = guessDiffURL("gitlab.com/x/y", "v0.0.2", "v0.0.3")
	tcompare(t, diffURL, "https://gitlab.com/x/y/-/compare/v0.0.2...v0.0.3")

	diffURL = guessDiffURL("codeberg.org/forgejo/forgejo", "v10.0.0", "v10.0.1")
	tcompare(t, diffURL, "https://codeberg.org/forgejo/forgejo/compare/v10.0.0...v10.0.1")

	diffURL = guessDiffURL("codeberg.org/forgejo/forgejo", "v10.0.0", "v10.0.1")
	tcompare(t, diffURL, "https://codeberg.org/forgejo/forgejo/compare/v10.0.0...v10.0.1")

	diffURL = guessDiffURL("bitbucket.org/x/y", "v0.0.5", "v0.0.6")
	// Yes, versions in reverse...
	tcompare(t, diffURL, "https://bitbucket.org/x/y/branches/compare/v0.0.6%0Dv0.0.5")
}
