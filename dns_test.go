package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"

	"github.com/miekg/dns"
)

func TestDNS(t *testing.T) {
	tresetTree()

	modvers := [][2]string{
		{"github.com/mjl-/mox", "v0.0.9"},
		{"github.com/mjl-/mox", "v0.0.11"},
		{"github.com/mjl-/mox", "v0.0.10"},
		{"github.com/mjl-/ding", "v0.5.2"},
		{"github.com/mjl-/ding", "v0.5.3"},
		{"github.com/mjl-/nextthing", "v0.1.0"},
		{"github.com/mjl-/nextthing", "v0.1.1"},
		{"github.com/mjl-/nextthing", "v1.2.3-rc0"},
		{"github.com/mjl-/nextthing", "v1.2.3"},
		/*
			todo: need better handling of versions >1
			{"github.com/mjl-/nextthing", "v2.1.0"},
			{"github.com/mjl-/nextthing", "v2.1.1-pre"},
		*/
		{"golang.org/toolchain", "v0.0.1-go1.23rc1.aix-ppc64"},
		{"golang.org/toolchain", "v0.0.1-go1.23rc1.darwin-amd64"},
		{"golang.org/toolchain", "v0.0.1-go1.23.0.linux-386"},
		{"golang.org/toolchain", "v0.0.1-go1.23.1.linux-386"},
		{"golang.org/toolchain", "v0.0.1-go1.23.1.linux-amd64"},
		{"golang.org/toolchain", "v0.0.1-go1.22.0.aix-ppc64"},
		{"golang.org/toolchain", "v0.0.1-go1.22.1.netbsd-386"},
		{"golang.org/toolchain", "v0.0.1-go1.22.7.windows-arm64"},
	}
	for _, pv := range modvers {
		_, err := sumsrv.Lookup(ctxbg, module.Version{Path: pv[0], Version: pv[1]})
		tcheckf(t, err, "add module to sumdb")
	}
	tm := fmt.Sprintf("%x", time.Now().Unix()) // todo: wait until start of second
	err := stepTlog()
	tcheckf(t, err, "moving empty tlog forward")

	zoneSOA.Serial = uint32(len(modvers))

	zoneSOANegative := zoneSOA
	zoneSOANegative.Hdr.Ttl = 60

	const noudp = 1 << 0
	const notcp = 1 << 1
	const nodnssec = 1 << 2
	const noplain = 1 << 3
	const noedns0req = 1 << 4
	const edns1 = 1 << 5            // Pretend to have edns1 for negotiation.
	const nocompareresults = 1 << 6 // Don't compare answer/auth/extra sections.
	type test struct {
		name   string // descriptive name, for error reporting
		flags  int
		in     dns.Msg // usually zero, opcode & q are the relevant parts. Id filled in.
		opcode int
		q      string // as rr
		// expected values:
		hdr    *dns.MsgHdr // If nil, no response message is expected.
		answer []string    // rr's
		auth   []string
		extra  []string
	}
	var tests = []test{
		{
			"soa",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"gw.example. soa",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{zoneSOA.String()},
			nil,
			nil,
		},
		{
			"ns",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"gw.example. ns",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{"gw.example. 300 ns ns0.gw.example"},
			nil,
			[]string{"ns0.gw.example. 300 a 127.0.0.1", "ns0.gw.example. 300 aaaa ::1"},
		},
		{
			"dnskey",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"gw.example. dnskey",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{zoneDNSKEY.String()},
			nil,
			nil,
		},
		{
			"ns a",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"ns0.gw.example. a",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{"ns0.gw.example. 300 a 127.0.0.1"},
			nil,
			nil,
		},
		{
			"ns aaaa",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"ns0.gw.example. aaaa",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{"ns0.gw.example. 300 aaaa ::1"},
			nil,
			nil,
		},
		{
			"non-existent",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"bogus.gw.example. a",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeNameError},
			nil,
			[]string{zoneSOANegative.String()},
			nil,
		},
		{
			"toolchain",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"toolchain.v0.gw.example. txt",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{fmt.Sprintf(`toolchain.v0.gw.example. 60 txt "v=go1.23.1 k=cur t=%s; v=go1.22.7 k=prev t=%s"`, tm, tm)},
			nil,
			nil,
		},
		{
			"module lookup single",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"mox.mjl_2d._.github.com.v0.gw.example. txt",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{fmt.Sprintf(`mox.mjl_2d._.github.com.v0.gw.example. 60 txt "v=v0.0.11 t=%s"`, tm)},
			nil,
			nil,
		},
		{
			"module lookup multiple",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"nextthing.mjl_2d._.github.com.v0.gw.example. txt",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{fmt.Sprintf(`nextthing.mjl_2d._.github.com.v0.gw.example. 60 txt "v=v1.2.3 t=%s; v=v0.1.1 t=%s"`, tm, tm)},
			nil,
			nil,
		},
		{
			"module lookup non-terminal",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"mjl_2d._.github.com.v0.gw.example. txt",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			nil,
			[]string{zoneSOANegative.String()},
			nil,
		},
		{
			"module lookup nxdomain",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"absent._.github.com.v0.gw.example. txt",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeNameError},
			nil,
			[]string{zoneSOANegative.String()},
			nil,
		},
		{
			"opcode not implemented",
			0,
			dns.Msg{},
			dns.OpcodeUpdate,
			"toolchain.v0.gw.example. txt",
			&dns.MsgHdr{Rcode: dns.RcodeNotImplemented},
			nil,
			nil,
			nil,
		},
		{
			"multiple queries",
			0,
			dns.Msg{
				Question: []dns.Question{
					{Name: "ns0.gw.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
					{Name: "ns1.gw.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
			dns.OpcodeQuery,
			"",
			&dns.MsgHdr{Rcode: dns.RcodeFormatError},
			nil,
			nil,
			nil,
		},
		{
			"axfr refused",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"gw.example. axfr",
			&dns.MsgHdr{Rcode: dns.RcodeRefused},
			nil,
			nil,
			nil,
		},
		{
			"other class refused",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"toolchain.v0.gw.example. ch txt",
			&dns.MsgHdr{Rcode: dns.RcodeRefused},
			nil,
			nil,
			nil,
		},
		{
			"not our domain refused",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"other.example. ns",
			&dns.MsgHdr{Rcode: dns.RcodeRefused},
			nil,
			nil,
			nil,
		},
		{
			"qtype any hinfo",
			0,
			dns.Msg{},
			dns.OpcodeQuery,
			"gw.example. any",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			[]string{`gw.example. 60 hinfo "RFC8482" ""`},
			nil,
			nil,
		},
		{
			// https://datatracker.ietf.org/doc/html/rfc8906#name-testing-unknown-types
			"qtype unknown",
			0,
			dns.Msg{
				Question: []dns.Question{
					{Name: "gw.example.", Qtype: 1000, Qclass: dns.ClassINET},
				},
			},
			dns.OpcodeQuery,
			"",
			&dns.MsgHdr{Authoritative: true, Rcode: dns.RcodeSuccess},
			nil,
			[]string{zoneSOANegative.String()},
			nil,
		},
		{
			// https://datatracker.ietf.org/doc/html/rfc8906#name-testing-unknown-opcodes
			"opcode unknown",
			0,
			dns.Msg{},
			15,
			"",
			&dns.MsgHdr{Rcode: dns.RcodeNotImplemented},
			nil,
			nil,
			nil,
		},
		{
			// https://datatracker.ietf.org/doc/html/rfc8906#name-testing-edns-version-negoti
			"bad edns version",
			noedns0req | edns1,
			dns.Msg{
				Extra: []dns.RR{
					&dns.OPT{
						Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Ttl: 1 << 16 /* edns version 1 */, Class: 1232 /* udp size */},
					},
				},
			},
			dns.OpcodeQuery,
			"gw.example. soa",
			&dns.MsgHdr{Rcode: dns.RcodeBadVers},
			nil,
			nil,
			nil,
		},
		{
			// https://datatracker.ietf.org/doc/html/rfc8906#name-testing-truncated-responses
			"truncated response",
			notcp | noedns0req | noplain | nocompareresults, // todo: stricter check on results
			dns.Msg{
				Extra: []dns.RR{
					&dns.OPT{
						Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Ttl: 1 << 15 /* DO */, Class: 512 /* udp size */},
					},
				},
			},
			dns.OpcodeQuery,
			"dddddddddddddddddddddddddddddddddddddddd.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc._.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.v0.gw.example. txt",
			&dns.MsgHdr{Authoritative: true, Truncated: true, Rcode: dns.RcodeNameError},
			nil,
			[]string{zoneSOANegative.String()},
			nil,
		},
	}

	// todo: write bogus data, expect no response and connection closed. also write a response.

	for i, ts := range tests {
		var name string

		tcheckf := func(t *testing.T, err error, format string, args ...any) {
			if err != nil {
				t.Helper()
				msg := fmt.Sprintf(format, args...)
				t.Fatalf("test %s: %s: %v", name, msg, err)
			}
		}

		tcompare := func(t *testing.T, what string, got, exp any) {
			if !reflect.DeepEqual(got, exp) {
				t.Helper()
				t.Fatalf("test %q, %s, got:\n%#v (%s)\nexpected:\n%#v (%s)\n", name, what, got, got, exp, exp)
			}
		}

		tcomparemsg := func(t *testing.T, got, exp dns.Msg) {
			t.Helper()
			tcompare(t, "msghdr", got.MsgHdr, exp.MsgHdr)
			tcompare(t, "question", got.Question, exp.Question)
			if ts.flags&nocompareresults != 0 {
				return
			}
			if got.String() != exp.String() {
				t.Fatalf("test %q, got:\n%s\nexpected:\n%s\n", name, got.String(), exp.String())
			}
			tcompare(t, "answer", got.Answer, exp.Answer)
			tcompare(t, "auth", got.Ns, exp.Ns)
			tcompare(t, "extra", got.Extra, exp.Extra)
			tcompare(t, "msg", got, exp)
		}

		rrparse := func(s string) dns.RR {
			rr, err := dns.NewRR(s)
			tcheckf(t, err, "parse rr %q", s)
			if rr == nil {
				t.Fatalf("test %q: error parsing rr %q", name, s)
			}
			return rr
		}

		ts.in.Id = uint16(i + 1)
		ts.in.Compress = true
		ts.in.Opcode = ts.opcode
		if ts.q != "" {
			qrr := rrparse(ts.q)
			qh := qrr.Header()
			ts.in.Question = []dns.Question{{Name: qh.Name, Qtype: qh.Rrtype, Qclass: qh.Class}}
		}

		check := func(respbuf []byte, tcp bool, dnssec bool) {
			t.Helper()
			if (ts.hdr == nil) != (respbuf == nil) {
				t.Fatalf("expecting message %v, have message %v", ts.hdr == nil, respbuf == nil)
			}
			if ts.hdr == nil {
				return
			}

			// Parse message we received.
			var respmsg dns.Msg
			err := respmsg.Unpack(respbuf)
			tcheckf(t, err, "parse response message")

			// Compose message we are expecting.
			exp := dns.Msg{MsgHdr: *ts.hdr}
			exp.Id = ts.in.Id
			exp.Compress = true
			exp.Response = true
			exp.Opcode = ts.opcode
			exp.Question = ts.in.Question
			for _, s := range ts.answer {
				exp.Answer = append(exp.Answer, rrparse(s))
			}
			for _, s := range ts.auth {
				exp.Ns = append(exp.Ns, rrparse(s))
			}
			for _, s := range ts.extra {
				exp.Extra = append(exp.Extra, rrparse(s))
			}
			if dnssec || ts.flags&edns1 != 0 {
				exp.SetEdns0(1232, false)
			}
			if dnssec && ts.flags&edns1 == 0 {
				opt := exp.IsEdns0()
				if tcp {
					opt.Option = append(opt.Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: 50})
				}
				var nxname bool
				if exp.Rcode == dns.RcodeNameError {
					exp.Rcode = dns.RcodeSuccess
					nxname = true
				}
				opt.SetDo(exp.Rcode == dns.RcodeSuccess)

				// Add NSEC record that should exist.
				if exp.Rcode == dns.RcodeSuccess && len(exp.Answer) == 0 && len(ts.in.Question) == 1 {
					var nsec dns.RR
					if nxname {
						nsec = rrparse(ts.in.Question[0].Name + " 60 nsec \000." + ts.in.Question[0].Name + " (rrsig nsec nxname)")
					} else {
						types := []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeHINFO, dns.TypeTXT, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY}
						types = slices.DeleteFunc(types, func(v uint16) bool { return v == ts.in.Question[0].Qtype })
						var typestr []string
						for _, t := range types {
							typestr = append(typestr, dns.Type(t).String())
						}
						nsec = rrparse(ts.in.Question[0].Name + " 60 nsec \000." + ts.in.Question[0].Name + " (" + strings.Join(typestr, " ") + ")")
					}
					if ts.in.Question[0].Qtype == dns.TypeNSEC {
						exp.Answer = append(exp.Answer, nsec)
					} else {
						exp.Ns = append(exp.Ns, nsec)
					}
				}
			}

			// Pack our expected message and parse again, so dns.RR_Header.Rdlength is set as
			// server sets it, for comparison.
			expbuf, err := exp.Pack()
			tcheckf(t, err, "pack expected message")
			var expmsg dns.Msg
			err = expmsg.Unpack(expbuf)
			tcheckf(t, err, "parse response message")

			// Verify RRSIG and return RRs except RRSIG.
			checkRRSIG := func(l []dns.RR, extra bool) []dns.RR {
				if !dnssec {
					return l
				}

				var r []dns.RR
				var rrset []dns.RR
				for _, rr := range l {
					if rrsig, ok := rr.(*dns.RRSIG); ok {
						err := rrsig.Verify(&zoneDNSKEY, rrset)
						tcheckf(t, err, "verify rrset %v", rrset)
						r = append(r, rrset...)
						rrset = nil
					} else {
						rrset = append(rrset, rr)
					}
				}
				if len(rrset) != 0 && !(extra && len(rrset) == 1 && rrset[0].Header().Rrtype == dns.TypeOPT) {
					t.Fatalf("unsigned records %v", rrset)
				}
				r = append(r, rrset...)
				return r
			}

			// origrespmgs := respmsg
			if dnssec && ts.flags&edns1 == 0 {
				respmsg.Answer = checkRRSIG(respmsg.Answer, false)
				respmsg.Ns = checkRRSIG(respmsg.Ns, false)
				respmsg.Extra = checkRRSIG(respmsg.Extra, true)
			}

			respmsg.Compress = true
			nrespbuf, err := respmsg.Pack()
			tcheckf(t, err, "repack response message")
			var nrespmsg dns.Msg
			err = nrespmsg.Unpack(nrespbuf)
			tcheckf(t, err, "reunpack response message")
			respmsg = nrespmsg

			// Received and expected message should match.
			tcomparemsg(t, respmsg, expmsg)
		}

		// Test with and without DNSSEC.
		for _, dnssec := range []bool{false, true} {
			if ts.flags&nodnssec != 0 && dnssec {
				continue
			}
			if ts.flags&noplain != 0 && !dnssec {
				continue
			}
			name = ts.name
			if dnssec {
				name += ", with dnssec"
			} else {
				name += ", without dnssec"
			}

			if dnssec && ts.flags&noedns0req == 0 {
				ts.in.SetEdns0(1232, true)
			}

			reqbuf, err := ts.in.Pack()
			tcheckf(t, err, "pack request message")

			if ts.flags&notcp == 0 {
				pc, ps := net.Pipe()
				go func() {
					serveTCP(ps, false)
					ps.Close()
				}()

				sizebuf := make([]byte, 2)
				binary.BigEndian.PutUint16(sizebuf[:], uint16(len(reqbuf)))
				_, err := pc.Write(sizebuf[:])
				tcheckf(t, err, "write request size")
				_, err = pc.Write(reqbuf)
				tcheckf(t, err, "write request")

				var respbuf []byte
				_, err = io.ReadFull(pc, sizebuf)
				if err != io.EOF {
					tcheckf(t, err, "read response size")

					size := binary.BigEndian.Uint16(sizebuf[:2])
					respbuf = make([]byte, size)
					_, err = io.ReadFull(pc, respbuf)
					tcheckf(t, err, "read response")
				}

				pc.Close()

				check(respbuf, true, dnssec)
			}

			if ts.flags&noudp == 0 {
				w := &towriter{}
				serveUDP(w, reqbuf, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})

				check(w.buf, false, dnssec)
			}
		}
	}
}

type towriter struct {
	buf []byte
}

func (w *towriter) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	w.buf = p
	return len(p), nil
}
