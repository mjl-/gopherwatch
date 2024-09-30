GopherWatch is a webapp for subscribing to notifications about new versions of
go modules seen in a go module transparency log (sum database), e.g.
https://sum.golang.org.

The Go toolchain uses proxy.golang.org to fetch modules (with "go get" or "go
install). The proxy adds all modules to sum.golang.org. This means published
library modules with a release tag (e.g. v1.2.3) are almost certain to turn up
in the transparency log. Go modules that are applications are likely to turn up
as well: as soon as someone runs "go install $module@$version", with "latest"
as version, or a specific tag.

https://www.gopherwatch.org/ is a public instance running GopherWatch.

GopherWatch allows registering a new account and add/remove subscriptions to
modules. For example, you can register modules of commands that you use, or
your dependencies, or anything published in your organization.  You can ask for
an exact match, or whole-domain/path prefix matches. You can filter updates by
version: whether to notify for pre-release versions.

GopherWatch periodically forwards its local state of the transparency log,
matches all new/updated go module (versions) against the subscriptions, and
sends out emails about changes. Since there is no real-time feed for appends to
the transparency log, and we don't want to overload the service, there will be
some delay in receiving notifications (typically up to 30 minutes).

GopherWatch also has a DNS server (with DNSSEC support) for querying the latest
version(s) of a module, or of the Go toolchain. For example:

	$ host -t txt mox.mjl_2d._.github.com.v0.l.gopherwatch.org.
	mox.mjl_2d._.github.com.v0.l.gopherwatch.org descriptive text "v=v0.0.11 t=66fa7e15"

	$ host -t txt toolchain.v0.l.gopherwatch.org.
	toolchain.v0.l.gopherwatch.org descriptive text "v=go1.23.1 k=cur t=66fa7e15; v=go1.22.7 k=prev t=66fa7e15"

To compile:

	CGO_ENABLED=0 go install github.com/mjl-/gopherwatch@latest

You'll need a config file to run it:

	./gopherwatch genconf >gopherwatch.conf

Possibly edit the config file. Run it:

	./gopherwatch serve

Spare some time? Help a poor time-strapped open source developer out!
See the issues list.

Created by Mechiel Lukkien, mechiel@ueber.net.

Code is under MIT (LICENSE.MIT), except cache.go and client.go, which are from
golang.org/x/mod (BSD-3-clause). Also see licenses of dependencies.
