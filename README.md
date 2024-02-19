GopherWatch is a webapp for subscribing to notifications about new versions of
go modules seen in a go module transparency log (sum database), e.g.
https://sum.golang.org.

The default transparency log used by the Go toolchain is sum.golang.org, so
published packages are likely to turn up there, though there are no guarantees
modules are added to the log.

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

To compile:

	CGO_ENABLED=0 go install github.com/mjl-/gopherwatch@latest

To run, first create an empty config file:

	./gopherwatch describeconf >gopherwatch.conf

Edit the config file. Run it:

	./gopherwatch serve

Spare some time? Help a poor busy open source developer out! See the issues list.

Created by Mechiel Lukkien, mechiel@ueber.net.

Code is under MIT (LICENSE.MIT), except cache.go and client.go, which are from
golang.org/x/mod (BSD-3-clause). Also see licenses of dependencies.
