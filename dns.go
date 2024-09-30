package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/mod/semver"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"
)

const tcpReadTimeout = 5 * time.Second // For TCP/TLS DNS connections.
const clockSkewMax = 5 * time.Minute   // For RRSIG validity before & after current time.

// For logging unique IDs for requests and connections.
var dnsTid atomic.Uint64

func init() {
	dnsTid.Store(uint64(time.Now().UnixMicro()))
}

// NS is a name server for the configured DNS domain, returned in DNS NS requests.
type NS struct {
	Name string   `sconf:"Name of server, just below Domain, no trailing dot, lower-case. E.g. ns0."`
	IPs  []string `sconf:"IP addresses of nameservers. At least one required."`

	ns   dns.RR   `sconf:"-"`
	a    []dns.RR `sconf:"-"`
	aaaa []dns.RR `sconf:"-"`
}

// DNS is configuration for the DNS server in gopherwatch.
type DNS struct {
	Domain      string `sconf:"Including trailing dot."`
	NS          []NS   `sconf:"Name servers"`
	SOAMailbox  string `sconf:"As 'user.host.domain.', not 'user@host.domain.', must have trailing dot."`
	TTL         uint32 `sconf:"TTL for positive responses. E.g. 60."`
	NegativeTTL uint32 `sconf:"TTL for negative responses. E.g. 60."`
	MetaTTL     uint32 `sconf:"TTL for positive positive response about zone, like SOA, NS, A, DNSKEY records. E.g. 300."`

	ECDSA ECDSAKey
}

// ECDSAKey is the configuration of a DNSSEC ECDSA P256 key.
type ECDSAKey struct {
	PrivateKey []byte
	PublicKey  []byte
}

var (
	metricDNSRequests = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_dns_requests_total",
			Help: "Total number of DNS requests.",
		},
	)
	metricDNSMalformed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_dns_malformed_total",
			Help: "DNS requests that were malformed.",
		},
	)
	metricDNSTruncated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gopherwatch_dns_truncated_total",
			Help: "DNS responses that were truncated.",
		},
	)
	metricDNSTransport = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gopherwatch_dns_transport_total",
			Help: "DNS requests by transport.",
		},
		[]string{
			"transport", // udp, tcp, tls
		},
	)
	metricDNSOpcode = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gopherwatch_dns_opcode_total",
			Help: "DNS requests by opcode.",
		},
		[]string{
			"opcode", // "query"
		},
	)
	metricDNSQuery = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gopherwatch_dns_query_total",
			Help: "DNS queries by query type and dnssecok and response code.",
		},
		[]string{
			"qtype",  // "a", "aaaa", "txt", "dnskey", "ns", "soa"
			"dnssec", // "yes", "no"
			"rcode",  // "NOERROR", "FORMERR", etc.
		},
	)
	metricDNSEDNSOptionCode = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gopherwatch_dns_edns0_option_total",
			Help: "DNS edns0 option codes.",
		},
		[]string{
			"code",
		},
	)
)

// Set when loading configuration, used during normal operation.
var zonePrivKey *ecdsa.PrivateKey
var zoneSOA dns.SOA
var zoneDNSKEY dns.DNSKEY
var zoneDS dns.DS

// Use with "gopherwatch -loglevel Debug-4 ...", to log DNS requests/responses.
const LevelTrace = slog.LevelDebug - 4

func xfatalf(err error, format string, args ...any) {
	if err != nil {
		logFatalx(fmt.Sprintf(format, args...), err)
	}
}

func xecdsaGen() (private, public []byte) {
	nprivkey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	xfatalf(err, "generate ecdsa p256 key")

	npubkey := append([]byte{}, keybuf(nprivkey.PublicKey.X)...)
	npubkey = append(npubkey, keybuf(nprivkey.PublicKey.Y)...)
	return keybuf(nprivkey.D), npubkey
}

// gendnskey is a subcommand to generate a new ecdsa dnskey.
func gendnskey() {
	nprivkey, npubkey := xecdsaGen()
	fmt.Printf("private key: %s\n", base64.StdEncoding.EncodeToString(nprivkey))
	fmt.Printf("public key: %s\n", base64.StdEncoding.EncodeToString(npubkey))
	fmt.Printf("\n")

	dnskey := dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "gopherwatch.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: base64.StdEncoding.EncodeToString(npubkey),
	}

	fmt.Printf("%s\n", dnskey.String())
	// DS key depends on correct owner name, no point printing it with example name.
	fmt.Printf("DS record will be printed at startup\n")
}

func keybuf(v *big.Int) []byte {
	var buf [32]byte
	x := v.Bytes()
	if len(x) > len(buf) {
		log.Fatalf("value too large (%d > %d)", len(x), len(buf))
	}
	copy(buf[len(buf)-len(x):], x)
	return buf[:]
}

func parseDNSConfig(conf *DNS) error {
	conf.Domain = strings.ToLower(conf.Domain)
	if !strings.HasSuffix(conf.Domain, ".") {
		return fmt.Errorf("config domain %q must have trailing dot", conf.Domain)
	}
	if len(conf.NS) == 0 {
		return fmt.Errorf("parsing namservers: at least 1 ns required")
	}
	for i, ns := range conf.NS {
		ns.Name = strings.ToLower(ns.Name)
		if strings.HasSuffix(ns.Name, ".") {
			return fmt.Errorf("config ns %q must not have trailing dot", ns.Name)
		}
		ns.ns = &dns.NS{
			Hdr: dns.RR_Header{Name: conf.Domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: conf.MetaTTL},
			Ns:  ns.Name + "." + conf.Domain,
		}

		if len(ns.IPs) == 0 {
			return fmt.Errorf("need at least one ip for ns %q", ns.Name)
		}
		for _, s := range ns.IPs {
			ip := net.ParseIP(s)
			if ip == nil {
				return fmt.Errorf("bad IP address %q", ip)
			}

			if ip.To4() != nil {
				ns.a = append(ns.a, &dns.A{
					Hdr: dns.RR_Header{Name: ns.Name + "." + conf.Domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: conf.MetaTTL},
					A:   ip,
				})
			} else {
				ns.aaaa = append(ns.aaaa, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: ns.Name + "." + conf.Domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: conf.MetaTTL},
					AAAA: ip,
				})
			}
		}
		conf.NS[i] = ns
	}
	if !strings.HasSuffix(conf.SOAMailbox, ".") {
		return fmt.Errorf("config soamailbox %q must have trailing dot", conf.SOAMailbox)
	}

	if len(conf.ECDSA.PrivateKey) != 32 {
		return fmt.Errorf("private key must be 32 bytes, is %d", len(conf.ECDSA.PrivateKey))
	}
	if len(conf.ECDSA.PublicKey) != 64 {
		return fmt.Errorf("public key must be 64 bytes, is %d", len(conf.ECDSA.PublicKey))
	}
	zonePrivKey = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     &big.Int{},
			Y:     &big.Int{},
		},
		D: &big.Int{},
	}
	zonePrivKey.D.SetBytes(conf.ECDSA.PrivateKey)
	zonePrivKey.PublicKey.X.SetBytes(conf.ECDSA.PublicKey[:32])
	zonePrivKey.PublicKey.X.SetBytes(conf.ECDSA.PublicKey[32:])
	zoneDNSKEY = dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: conf.Domain, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: conf.MetaTTL},
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: base64.StdEncoding.EncodeToString(conf.ECDSA.PublicKey),
	}
	zoneDS = *zoneDNSKEY.ToDS(dns.SHA256)
	slog.Info("dnssec ds record", "ds", strings.ReplaceAll(zoneDS.String(), "\t", " "))

	zoneSOA = dns.SOA{
		Hdr:     dns.RR_Header{Name: conf.Domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: conf.MetaTTL},
		Ns:      conf.NS[0].Name + "." + conf.Domain,
		Mbox:    conf.SOAMailbox,
		Serial:  0, // Filled in during requests with number of records in log.
		Refresh: config.DNS.MetaTTL,
		Retry:   config.DNS.MetaTTL,
		Expire:  config.DNS.MetaTTL,
		Minttl:  conf.NegativeTTL,
	}

	// Test we can validate our own records.
	soarrsig := dns.RRSIG{
		Hdr:         dns.RR_Header{Name: conf.Domain, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: conf.TTL},
		TypeCovered: dns.TypeSOA,
		Algorithm:   zoneDNSKEY.Algorithm,
		Expiration:  uint32(time.Now().Add(5 * time.Second).Unix()),
		Inception:   uint32(time.Now().Unix()),
		KeyTag:      zoneDS.KeyTag,
		SignerName:  conf.Domain,
	}
	if err := soarrsig.Sign(zonePrivKey, []dns.RR{&zoneSOA}); err != nil {
		return fmt.Errorf("sign soa record: %v", err)
	}
	if err := soarrsig.Verify(&zoneDNSKEY, []dns.RR{&zoneSOA}); err != nil {
		return fmt.Errorf("verify rrsig over soa: %v", err)
	}

	return nil
}

// toWriter, as implemented by net.UDPConn, is used in tests to capture
// response packets.
type toWriter interface {
	WriteTo(p []byte, addr net.Addr) (n int, err error)
}

func serveUDP(uconn toWriter, buf []byte, remaddr net.Addr) {
	log := slog.With("transport", "udp", "remote", remaddr)
	m, _, droppkt, err := process(log, buf, true, remaddr)
	if droppkt {
		log.Debug("dropping bad request packet", "err", err)
		return
	}
	if err != nil {
		if m.Rcode == dns.RcodeServerFailure {
			log.Error("process request", "err", err)
		} else {
			log.Debug("process request", "err", err)
		}
	}
	out, err := m.Pack()
	if err != nil {
		// todo: should response with a prepare servfail packet.
		log.Error("pack response", "err", err)
		return
	}
	if _, err := uconn.WriteTo(out, remaddr); err != nil {
		log.Error("write response", "err", err)
	}
}

// xmakeCert generates a private key and returns a tls.Certificate for ephemeral
// tls.
func xmakeCert() tls.Certificate {
	pubKey, privKey, err := ed25519.GenerateKey(cryptorand.Reader)
	xfatalf(err, "generate ephemeral tls key")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
	}
	localCertBuf, err := x509.CreateCertificate(cryptorand.Reader, template, template, pubKey, privKey)
	xfatalf(err, "make ephemeral tls cert")
	cert, err := x509.ParseCertificate(localCertBuf)
	xfatalf(err, "parse generated ephemeral tls cert")
	c := tls.Certificate{
		Certificate: [][]byte{localCertBuf},
		PrivateKey:  privKey,
		Leaf:        cert,
	}
	return c
}

// serve on TCP or TLS connection.
func serveTCP(conn net.Conn, isTLS bool) {
	defer conn.Close()
	transport := "tcp"
	if isTLS {
		transport = "tls"
	}
	remaddr := conn.RemoteAddr()
	log := slog.With("transport", transport, "remote", remaddr, "cid", dnsTid.Add(1))
	buf := make([]byte, 2+4*1024)
	for {
		_, err := io.ReadFull(conn, buf[:2])
		if err != nil {
			if err != io.EOF {
				log.Error("read request", "err", err)
			}
			return
		}
		// Short timeout. Not likely users need to do multiple requests somewhat far apart.
		if err := conn.SetReadDeadline(time.Now().Add(tcpReadTimeout)); err != nil {
			log.Error("set deadline, dropping connection", "err", err)
			return
		}
		size := binary.BigEndian.Uint16(buf[:2])
		if int(size) > len(buf) {
			log.Error("large message, dropping connection")
			return
		}
		if _, err := io.ReadFull(conn, buf[:int(size)]); err != nil {
			log.Error("read request, dropping connection", "err", err)
			return
		}

		m, dropconn, _, err := process(log, buf[:int(size)], false, remaddr)
		if err != nil {
			if m.Rcode == dns.RcodeServerFailure {
				log.Error("process request", "err", err)
			} else {
				log.Debug("process request", "err", err)
			}
		}
		if dropconn {
			log.Error("could not parse message, dropping connection")
			return
		}
		out, err := m.PackBuffer(buf[2:])
		if err != nil {
			// todo: write prepared servfail response...
			log.Error("pack response message, dropping connection", "err", err)
			return
		}
		binary.BigEndian.PutUint16(buf, uint16(len(out)))
		if _, err := conn.Write(buf[:2+len(out)]); err != nil {
			log.Error("write response, dropping connection", "err", err)
			return
		}
	}
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
var edns0OptionCodeToString = map[uint16]string{
	1:  "LLQ",
	2:  "UPDATELEASE",
	3:  "NSID",
	4:  "ESU",
	5:  "DAU",
	6:  "DHU",
	7:  "N3U",
	8:  "SUBNET",
	9:  "EXPIRE",
	10: "COOKIE",
	11: "TCPKEEPALIVE",
	12: "PADDING",
	13: "CHAIN",
	14: "KEYTAG",
	15: "EDE",
	16: "CLIENTTAG",
	17: "SERVERTAG",
	18: "REPORTCHANNEL",
	19: "ZONEVERSION",
}

// process parses an incoming packet from buf, and returns a response message,
// whether to drop the packet (for udp), and an error during processing. If an
// error occurs, a response message can still be returned, to be sent back to the
// requestor. If the response message is the zero Msg, a tcp connection must be
// aborted because the protocol is botched.
func process(log *slog.Logger, buf []byte, udp bool, remaddr net.Addr) (respmsg dns.Msg, dropconn, droppkt bool, rerr error) {
	metricDNSRequests.Inc()

	// Common mistakes in DNS handling and about handling unrecognized
	// requests/flags/opcodes/queries: https://datatracker.ietf.org/doc/html/rfc8906

	// todo: we should parse the header first and not try parsing the full message if we don't know the opcode. parsing the full packet may fail. we should be returning "not implemented" early. https://datatracker.ietf.org/doc/html/rfc8906#name-response-code-selection

	var inmsg dns.Msg
	if err := inmsg.Unpack(buf); err != nil {
		metricDNSMalformed.Inc()
		return dns.Msg{}, true, true, fmt.Errorf("unpack request message (size %d): %v", len(buf), err)
	}

	log = log.With("tid", dnsTid.Add(1), "dnsmsgid", inmsg.Id)

	if inmsg.Response {
		return response(inmsg, dns.RcodeFormatError), false, true, fmt.Errorf("request has response bit set")
	}

	// Handle EDNS for future versions (> 0).
	// note: the dns library returns any OPT record, not only version 0 of edns.
	opt := inmsg.IsEdns0()
	if opt != nil && opt.Version() != 0 {
		ropt := dns.OPT{
			Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			Option: []dns.EDNS0{},
		}
		// 1232 is recommended since the dns edns0 flag day.
		ropt.SetUDPSize(1232)
		if opt.Do() {
			ropt.SetDo()
		}
		respmsg = response(inmsg, dns.RcodeBadVers)
		respmsg.Extra = append(respmsg.Extra, &ropt)
		return respmsg, false, false, fmt.Errorf("dns eopt with version %d not supported (only edns0)", opt.Version())
	}

	// Prepare EDNS0 response opt, and add it to the response on the way out.
	dnssecok := opt != nil && opt.Do()
	var ropt *dns.OPT
	if opt != nil {
		for _, o := range opt.Option {
			metricDNSEDNSOptionCode.WithLabelValues(edns0OptionCodeToString[o.Option()]).Inc()
		}

		ropt = &dns.OPT{
			Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			Option: []dns.EDNS0{},
		}
		ropt.SetUDPSize(1232)
		if !udp {
			ropt.Option = append(ropt.Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: uint16(tcpReadTimeout / (100 * time.Millisecond))})
		}
	}
	defer func() {
		if ropt == nil {
			return
		}
		respmsg.Extra = append(respmsg.Extra, ropt)

		// Set truncate bit if response is too large for UDP.
		if udp {
			var maxsize uint16 = dns.MinMsgSize
			if opt != nil {
				maxsize = opt.UDPSize()
				if maxsize < dns.MinMsgSize {
					maxsize = dns.MinMsgSize
				}
			}
			// note: opt is always included by the dns library as required, https://datatracker.ietf.org/doc/html/rfc8906#name-truncated-edns-responses
			respmsg.Truncate(int(maxsize))
			if respmsg.Truncated {
				// todo: should we remove trailing non-rrsig records in case of DO? they aren't signed (or the rrsig would be last).
				metricDNSTruncated.Inc()
			}
			respmsg.Compress = true
		}
	}()

	metricDNSOpcode.WithLabelValues(dns.OpcodeToString[inmsg.Opcode])
	if inmsg.Opcode != dns.OpcodeQuery {
		return response(inmsg, dns.RcodeNotImplemented), false, false, fmt.Errorf("request opcode %d %q not implemented", inmsg.Opcode, dns.OpcodeToString[inmsg.Opcode])
	}

	if len(inmsg.Question) != 1 {
		// todo: are there cases where the request has zero queries? eg only edns0 options?
		// https://datatracker.ietf.org/doc/html/rfc9619#name-updates-to-rfc-1035
		return response(inmsg, dns.RcodeFormatError), false, false, fmt.Errorf("not exactly 1 query in request, but %d", len(inmsg.Question))
	}

	q := inmsg.Question[0]

	defer func() {
		dnssec := "no"
		if dnssecok {
			dnssec = "yes"
		}
		metricDNSQuery.WithLabelValues(dns.TypeToString[q.Qtype], dnssec, dns.RcodeToString[respmsg.Rcode])
	}()

	// Special queries that are actually more like opcodes. ANY is handled later.
	switch q.Qtype {
	case dns.TypeIXFR, dns.TypeAXFR, dns.TypeMAILB, dns.TypeMAILA:
		// todo: we could also return "not implemented"? https://datatracker.ietf.org/doc/html/rfc8906#name-unknown-unsupported-type-qu
		return response(inmsg, dns.RcodeRefused), false, false, fmt.Errorf("request query type %d %q refused", q.Qtype, dns.TypeToString[q.Qtype])
	}

	if q.Qclass != dns.ClassINET {
		return response(inmsg, dns.RcodeRefused), false, false, fmt.Errorf("request query class %d %q refused", q.Qtype, dns.ClassToString[q.Qclass])
	}

	// todo future: could implement dns cookies option
	// todo future: could implement padding
	// note: we don't have a use for options DAU, DHU, N3U ("dnssec algorithm/hash/nsec3 understood"). we only have one way to respond.
	// todo: should we do anything special for unexpected answer/authority section, and anything in extra we don't understand (and isn't edns0)? we currently just ignore it.

	log.Log(context.Background(), LevelTrace, "incoming request", "size", len(buf), "addr", remaddr, "dnssecok", dnssecok, "msg", inmsg, "question", q)

	var qname, bname, sname, path, version string
	defer func() {
		defer func() {
			log.Log(context.Background(), LevelTrace, "outgoing response", "qtype", dns.Type(q.Qtype), "qname", qname, "bname", bname, "sname", sname, "path", path, "version", version, "rerr", rerr, "respmsg", respmsg)
		}()

		// Add a SOA record to authority section in case of NXDOMAIN and NODATA.
		if (respmsg.Rcode == dns.RcodeNameError || respmsg.Rcode == dns.RcodeSuccess) && len(respmsg.Answer) == 0 && !(dnssecok && q.Qtype == dns.TypeNSEC) {
			rsoa := zoneSOA
			// https://datatracker.ietf.org/doc/html/rfc2308#section-5
			// https://datatracker.ietf.org/doc/html/rfc9077
			if rsoa.Hdr.Ttl > zoneSOA.Minttl {
				rsoa.Hdr.Ttl = zoneSOA.Minttl
			}
			// Set zone serial to number of records in our log.
			state := TreeState{ID: 1}
			if err := database.Get(context.Background(), &state); err != nil {
				respmsg = response(inmsg, dns.RcodeServerFailure)
				rerr = fmt.Errorf("get serial from state for soa: %v", err)
				return
			}
			rsoa.Serial = uint32(state.RecordsProcessed)
			respmsg.Ns = append(respmsg.Ns, &rsoa)
		}
		// Handle DNSSEC signing.
		if !dnssecok {
			return
		}
		// Turn nxdomain into nodata, below we add NXNAME to the NSEC record.
		nxname := respmsg.Rcode == dns.RcodeNameError
		if nxname {
			respmsg.Rcode = dns.RcodeSuccess
		}
		if respmsg.Rcode != dns.RcodeSuccess {
			return
		}

		ropt.SetDo(true)
		// Add NSEC for nodata (and nxdomain, which was changed to nodata above).
		if len(respmsg.Answer) == 0 {
			nsec := dns.NSEC{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: config.DNS.TTL},
				NextDomain: "\000." + q.Name,
			}
			if nxname {
				// NXNAME is from https://datatracker.ietf.org/doc/html/draft-ogud-fake-nxdomain-type/#section-4
				nsec.TypeBitMap = []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME}
			} else {
				nsec.TypeBitMap = []uint16{}
				// note: these types have to be in ascending order of their id.
				// todo: can we leave out NS and DNSKEY if under ".v0."? so resolvers know there will be no delegation, and they won't do qname minimization.
				for _, t := range []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeHINFO, dns.TypeTXT, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY} {
					if t != q.Qtype {
						nsec.TypeBitMap = append(nsec.TypeBitMap, t)
					}
				}
			}
			if q.Qtype == dns.TypeNSEC {
				respmsg.Answer = append(respmsg.Answer, &nsec)
			} else {
				respmsg.Ns = append(respmsg.Ns, &nsec)
			}
		}
		// Sign all result sections with RRSIG records.
		if err := sign(&respmsg); err != nil {
			respmsg = response(inmsg, dns.RcodeServerFailure)
			rerr = fmt.Errorf("signing response: %v", err)
		}
	}()

	qname = strings.ToLower(q.Name)
	if qname != config.DNS.Domain && !strings.HasSuffix("."+qname, config.DNS.Domain) {
		// Make it clear something is wrong on the requestor side.
		return response(inmsg, dns.RcodeRefused), false, false, fmt.Errorf("request for unknown domain %q", qname)
	}
	bname = strings.TrimSuffix(qname, config.DNS.Domain)
	if bname == "" {
		bname = "."
	}

	if q.Qtype == dns.TypeANY {
		// We don't want to respond with anything useful. https://datatracker.ietf.org/doc/html/rfc8482
		hinfo := dns.HINFO{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: config.DNS.TTL}, Cpu: "RFC8482"}
		return response(inmsg, dns.RcodeSuccess, &hinfo), false, false, nil
	}

	// bname is now something like: "." (for soa or ns record), "ns." (for "a" record of ns), "<pathhost>.v0."
	switch {
	case bname == ".":
		var rr []dns.RR
		switch q.Qtype {
		case dns.TypeSOA:
			rsoa := zoneSOA
			state := TreeState{ID: 1}
			if err := database.Get(context.Background(), &state); err != nil {
				return response(inmsg, dns.RcodeServerFailure), false, false, fmt.Errorf("get serial from state for soa: %v", err)
			}
			rsoa.Serial = uint32(state.RecordsProcessed)
			rr = append(rr, &rsoa)

		case dns.TypeNS:
			respmsg = response(inmsg, dns.RcodeSuccess)
			for _, ns := range config.DNS.NS {
				respmsg.Answer = append(respmsg.Answer, ns.ns)
				respmsg.Extra = append(respmsg.Extra, ns.a...)
				respmsg.Extra = append(respmsg.Extra, ns.aaaa...)
			}
			return respmsg, false, false, nil

		case dns.TypeDNSKEY:
			rr = append(rr, &zoneDNSKEY)
		}
		return response(inmsg, dns.RcodeSuccess, rr...), false, false, nil

	case strings.HasSuffix(bname, ".v0."):
		// todo: should we be responding to qtype rrsig & nsec (besides txt)? it seems so: https://datatracker.ietf.org/doc/html/rfc4035#section-3

		sname = strings.TrimSuffix(bname, ".v0.")
		if sname == "toolchain" {
			if q.Qtype != dns.TypeTXT {
				return response(inmsg, dns.RcodeSuccess), false, false, nil
			}

			// Handle specially.
			dbq := bstore.QueryDB[ModuleVersion](context.Background(), database)
			mvl, err := dbq.FilterNonzero(ModuleVersion{Module: "golang.org/toolchain"}).List()
			if err != nil {
				return response(inmsg, dns.RcodeServerFailure), false, false, fmt.Errorf("lookup module %q in db: %v", path, err)
			}

			tc := toolchains(mvl)
			var l []string
			add := func(kind string, version string, t time.Time) {
				if version != "" {
					l = append(l, fmt.Sprintf("v=%s k=%s t=%x", version, kind, t.Unix()))
				}
			}
			add("cur", tc.Cur, tc.CurFound)
			add("prev", tc.Prev, tc.PrevFound)
			add("next", tc.Next, tc.NextFound)

			txt := dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: config.DNS.TTL},
				Txt: []string{strings.Join(l, "; ")},
			}
			return response(inmsg, dns.RcodeSuccess, &txt), false, false, nil
		}

		var err error
		path, err = parseName(sname)
		if err != nil {
			log.Debug("parsing request name", "err", err, "name", sname)
			return response(inmsg, dns.RcodeNameError), false, false, nil
		}

		// Iterate through versions. We cannot get the latest version just by reverse sort
		// and taking the first: v0.0.9 would be "newer" than v0.0.10.
		majorVersions := map[int]string{}
		majorFound := map[int]time.Time{}
		dbq := bstore.QueryDB[ModuleVersion](context.Background(), database)
		err = dbq.FilterNonzero(ModuleVersion{Module: path}).ForEach(func(mv ModuleVersion) error {
			// We only return non-prerelease versions.
			if semver.Prerelease(mv.Version) != "" {
				return nil
			}
			major := semver.Major(mv.Version)
			mm, err := strconv.ParseInt(strings.TrimPrefix(major, "v"), 10, 64)
			if err != nil {
				return nil
			}
			m := int(mm)
			if v, ok := majorVersions[m]; !ok || semver.Compare(mv.Version, v) > 0 {
				majorVersions[m] = mv.Version
				majorFound[m] = mv.Discovered

				if q.Qtype != dns.TypeTXT {
					// Stop now, we only need to know a version exists.
					return bstore.StopForEach
				}
			}
			return nil
		})
		if err != nil {
			return response(inmsg, dns.RcodeServerFailure), false, false, fmt.Errorf("lookup module %q in db: %v", path, err)
		}
		if len(majorVersions) > 0 {
			if q.Qtype != dns.TypeTXT {
				return response(inmsg, dns.RcodeSuccess), false, false, nil
			}

			var l []string
			for _, m := range slices.Sorted(maps.Keys(majorVersions)) {
				l = append(l, fmt.Sprintf("v=%s t=%x", majorVersions[m], majorFound[m].Unix()))
			}
			slices.Reverse(l)
			var s string
			for _, v := range l {
				if len(s)+2+len(v) > 255 {
					break
				}
				if s != "" {
					s += "; "
				}
				s += v
			}
			txt := dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: config.DNS.TTL},
				Txt: []string{s},
			}
			return response(inmsg, dns.RcodeSuccess, &txt), false, false, nil
		}

		// Look for next path. If the requested path is a delimited prefix, we return
		// nodata instead of nxdomain as the requestor may be asking for a partial name.
		dbq = bstore.QueryDB[ModuleVersion](context.Background(), database)
		mv, err := dbq.FilterGreater("Module", path).SortAsc("Module").Limit(1).Get()
		if err == bstore.ErrAbsent || err == nil && !strings.HasPrefix(mv.Module, path+"/") {
			return response(inmsg, dns.RcodeNameError), false, false, fmt.Errorf("module %q does not exist", path)
		} else if err != nil {
			return response(inmsg, dns.RcodeServerFailure), false, false, fmt.Errorf("looking up next module for %q: %v", path, err)
		} else {
			// Return "nodata": success without an answer. Works for qtype TXT and all others.
			return response(inmsg, dns.RcodeSuccess), false, false, nil
		}

	default:
		// Check if this was a request for a name server.
		for _, ns := range config.DNS.NS {
			if ns.Name+"." != bname {
				continue
			}
			var rr []dns.RR
			switch q.Qtype {
			case dns.TypeA:
				rr = append(rr, ns.a...)
			case dns.TypeAAAA:
				rr = append(rr, ns.aaaa...)
			}
			return response(inmsg, dns.RcodeSuccess, rr...), false, false, nil
		}

		// nxdomain.
		return response(inmsg, dns.RcodeNameError), false, false, nil
	}
}

func response(inmsg dns.Msg, rcode int, rr ...dns.RR) dns.Msg {
	return dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:            inmsg.Id,
			Response:      true,
			Opcode:        inmsg.Opcode,
			Authoritative: rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError,
			Rcode:         rcode,
		},
		Compress: true,
		Question: inmsg.Question,
		Answer:   rr,
	}
}

// parseName parses the domain labels before the ".v0." into a module path,
// unescaping _xx (hexadecimal) as byte, with bare _ as separator between
// hostname and path.
//
// we don't have to take IDNA into account: go module paths cannot have non-ascii.
// they can have IDNA xn-- for domain names, but we would get them as such
// (A-labels), and we would just keep them as such.
func parseName(name string) (string, error) {
	t := strings.Split(name, ".")
	var r string
	host := true
	for i := len(t) - 1; i >= 0; i-- {
		s := t[i]
		if s == "_" {
			if host {
				host = false
				continue
			}
			return "", fmt.Errorf("two bare underscores")
		}
		var ns []byte
		for i := 0; i < len(s); i++ {
			b := byte(s[i])
			if b < ' ' || b >= 0x7f {
				return "", fmt.Errorf("invalid character %x", s[i])
			}
			if b == '_' {
				if host {
					return "", fmt.Errorf("underscore not allowed in hostname")
				}
				if i+2 >= len(s) {
					return "", fmt.Errorf("not enough chars after underscore")
				}
				v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
				if err != nil {
					return "", fmt.Errorf("bad hex: %v", err)
				}
				b = byte(v)
				i += 2
			}
			if !host && b == '/' {
				return "", fmt.Errorf("encoded slash not allowed in path, use dot")
			}
			ns = append(ns, b)
		}
		if host {
			if r != "" {
				r = "." + r
			}
			r = string(ns) + r
		} else {
			r += "/" + string(ns)
		}
	}
	if r == "" {
		return "", fmt.Errorf("empty name")
	}
	return r, nil
}

func sign(resp *dns.Msg) error {
	// Sign the rrsets in the result sections.
	var err error
	if resp.Answer, err = signrrset(resp.Answer, true); err != nil {
		return fmt.Errorf("sign answers: %v", err)
	}
	if resp.Ns, err = signrrset(resp.Ns, false); err != nil {
		return fmt.Errorf("sign authority: %v", err)
	}
	if resp.Extra, err = signrrset(resp.Extra, false); err != nil {
		return fmt.Errorf("sign additional: %v", err)
	}
	return nil
}

func signrrset(section []dns.RR, answer bool) ([]dns.RR, error) {
	if len(section) == 0 {
		return section, nil
	}

	var out []dns.RR
	i := 0
	for i < len(section) {
		rr := section[i]
		h0 := rr.Header()
		last := i
		for last+1 < len(section) {
			h := section[last+1].Header()
			if h.Name == h0.Name && h.Rrtype == h0.Rrtype {
				last++
			} else {
				break
			}
		}

		now := time.Now()
		rrsig := dns.RRSIG{
			Hdr:         dns.RR_Header{Name: h0.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h0.Ttl},
			TypeCovered: h0.Rrtype,
			Algorithm:   zoneDNSKEY.Algorithm,
			Inception:   uint32(now.Add(-clockSkewMax).Unix()),
			Expiration:  uint32(now.Add(time.Duration(h0.Ttl) * time.Second).Add(clockSkewMax).Unix()),
			KeyTag:      zoneDS.KeyTag,
			SignerName:  config.DNS.Domain,
		}
		rrset := section[i : last+1]
		// Sign sorts rrset and canonicalizes names, per https://datatracker.ietf.org/doc/html/rfc4034#section-6.2 and section 6.3.
		if err := rrsig.Sign(zonePrivKey, rrset); err != nil {
			return nil, fmt.Errorf("signing response: %v", err)
		}
		out = append(out, rrset...)
		out = append(out, &rrsig)

		i = last + 1
	}
	return out, nil
}
