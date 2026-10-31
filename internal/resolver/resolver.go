package resolver

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var QTypes = []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"}

const (
	RcodeTimeout = "TIMEOUT"
	RcodeNetErr  = "NETERR"
)

type Observation struct {
	TS         time.Time
	Domain     string
	QType      string
	Resolver   string
	Rcode      string
	TTL        uint32
	Rdata      []string
	Answers    []Answer
	AnswerHash uint64
	LatencyMs  uint32
	Truncated  bool
	Wire       []byte
}

// Answer is one RR of the answer section, keyed by its owner name.
type Answer struct {
	Name  string
	Type  string
	Value string
}

type Client struct {
	timeout time.Duration
	udp     *dns.Client
	tcp     *dns.Client
}

func New(timeout time.Duration) *Client {
	return &Client{
		timeout: timeout,
		udp:     &dns.Client{Net: "udp", Timeout: timeout, UDPSize: 4096},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
	}
}

func (c *Client) Resolve(ctx context.Context, server, fqdn, qtype string) Observation {
	obs := Observation{TS: time.Now().UTC(), Domain: fqdn, QType: qtype, Resolver: server}
	qt, ok := dns.StringToType[qtype]
	if !ok {
		obs.Rcode = RcodeNetErr
		obs.AnswerHash = AnswerHash(obs.Rcode, nil)
		return obs
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qt)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	start := time.Now()
	r, err := c.exchange(ctx, c.udp, m, server)
	if err == nil && r.Truncated {
		obs.Truncated = true
		if tr, terr := c.exchange(ctx, c.tcp, m, server); terr == nil {
			r = tr
		}
	}
	obs.LatencyMs = uint32(time.Since(start).Milliseconds())

	if err != nil {
		obs.Rcode = classifyErr(err)
		obs.AnswerHash = AnswerHash(obs.Rcode, nil)
		return obs
	}
	obs.Rcode = rcodeString(r.Rcode)
	obs.Rdata, obs.TTL = Extract(r, qt)
	obs.Answers = Answers(r)
	obs.AnswerHash = AnswerHash(obs.Rcode, obs.Rdata)
	if wire, perr := r.Pack(); perr == nil {
		obs.Wire = wire
	}
	return obs
}

func (c *Client) exchange(ctx context.Context, cl *dns.Client, m *dns.Msg, server string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	r, _, err := cl.ExchangeContext(ctx, m, server)
	return r, err
}

func classifyErr(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout()) {
		return RcodeTimeout
	}
	return RcodeNetErr
}

func rcodeString(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rc)
}

// Extract returns the sorted, deduplicated normalized rdata of the answer RRs
// matching qtype, and their minimum TTL.
func Extract(r *dns.Msg, qtype uint16) ([]string, uint32) {
	out := []string{}
	var ttl uint32
	for _, rr := range r.Answer {
		h := rr.Header()
		if h.Rrtype != qtype {
			continue
		}
		if len(out) == 0 || h.Ttl < ttl {
			ttl = h.Ttl
		}
		out = append(out, Normalize(rr))
	}
	slices.Sort(out)
	return slices.Compact(out), ttl
}

// Answers returns every RR of the answer section, CNAME chain included,
// sorted and deduplicated.
func Answers(r *dns.Msg) []Answer {
	out := make([]Answer, 0, len(r.Answer))
	for _, rr := range r.Answer {
		h := rr.Header()
		out = append(out, Answer{Name: Name(h.Name), Type: typeString(h.Rrtype), Value: Normalize(rr)})
	}
	slices.SortFunc(out, func(a, b Answer) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Type, b.Type), cmp.Compare(a.Value, b.Value))
	})
	return slices.Compact(out)
}

func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func Normalize(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return Name(v.Target)
	case *dns.NS:
		return Name(v.Ns)
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, Name(v.Mx))
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", Name(v.Ns), Name(v.Mbox), v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	default:
		return strings.TrimPrefix(rr.String(), rr.Header().String())
	}
}

func Name(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

func AnswerHash(rcode string, rdata []string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(rcode))
	for _, v := range slices.Sorted(slices.Values(rdata)) {
		h.Write([]byte{0})
		h.Write([]byte(v))
	}
	return h.Sum64()
}

func NormalizeFQDN(s string) (string, error) {
	n := Name(s)
	if n == "" || !strings.Contains(n, ".") || len(n) > 253 {
		return "", fmt.Errorf("invalid fqdn %q", s)
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "", fmt.Errorf("invalid fqdn %q", s)
		}
	}
	if _, ok := dns.IsDomainName(n); !ok {
		return "", fmt.Errorf("invalid fqdn %q", s)
	}
	return n, nil
}

func NormalizeServer(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = strings.Trim(addr, "[]"), "53"
	}
	if host == "" {
		return "", fmt.Errorf("invalid resolver address %q", addr)
	}
	return net.JoinHostPort(host, port), nil
}
