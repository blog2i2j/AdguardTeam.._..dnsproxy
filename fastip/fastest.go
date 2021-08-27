package fastip

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/cache"
	"github.com/miekg/dns"
)

// FastestAddr provides methods to determine the fastest network addresses.
type FastestAddr struct {
	// ipCacheLock protects ipCache.
	ipCacheLock sync.Mutex
	// ipCache caches fastest IP addresses.
	ipCache cache.Cache

	// pinger is the dialer with predefined timeout for pinging TCP
	// connections.
	pinger *net.Dialer

	// pingPorts are the ports to ping on.
	pingPorts []uint

	// PingWaitTimeout is the timeout for waiting all the resolved addresses
	// are pinged.  Any ping results received after it are cached but not
	// used at the moment.  It should be configured right after the
	// FastestAddr initialization since it isn't protected for concurrent
	// usage.
	PingWaitTimeout time.Duration
}

// NewFastestAddr initializes a new instance of the *FastestAddr.
func NewFastestAddr() (f *FastestAddr) {
	return &FastestAddr{
		ipCache: cache.New(cache.Config{
			MaxSize:   64 * 1024,
			EnableLRU: true,
		}),
		pingPorts:       []uint{80, 443},
		PingWaitTimeout: defaultPingWaitTimeout,
		pinger:          &net.Dialer{Timeout: pingTCPTimeout},
	}
}

// ExchangeFastest queries each specified upstream and returns a response with
// the fastest IP address.  The fastest IP address is cosidered to be the first
// one successfully dialed and other addresses are removed from the answer.
func (f *FastestAddr) ExchangeFastest(req *dns.Msg, ups []upstream.Upstream) (
	resp *dns.Msg,
	u upstream.Upstream,
	err error,
) {
	replies, err := upstream.ExchangeAll(ups, req)
	if err != nil {
		return nil, nil, err
	}

	host := strings.ToLower(req.Question[0].Name)
	ips := f.extractIPs(replies)

	if pingRes := f.pingAll(host, ips); pingRes != nil {
		return f.prepareReply(pingRes, replies)
	}

	log.Debug("%s: no fastest IP found, using the first response", host)

	return replies[0].Resp, replies[0].Upstream, nil
}

// prepareReply converts replies into the DNS answer message accoding to
// pingRes.  The returned upstreams is the one which replied with the fastest
// address.
func (f *FastestAddr) prepareReply(pingRes *pingResult, replies []upstream.ExchangeAllResult) (
	m *dns.Msg,
	u upstream.Upstream,
	err error,
) {
	ip := pingRes.ipp.IP
	for _, r := range replies {
		if hasAns(r.Resp, ip) {
			m = r.Resp
			u = r.Upstream

			break
		}
	}

	if m == nil {
		log.Error("found no replies with IP %s, most likely this is a bug", ip)

		return replies[0].Resp, replies[0].Upstream, nil
	}

	// Modify the message and keep only A and AAAA records containing the
	// fastest IP address.
	ans := make([]dns.RR, 0, len(m.Answer))
	for _, rr := range m.Answer {
		switch addr := rr.(type) {
		case *dns.A:
			if ip.Equal(addr.A.To4()) {
				ans = append(ans, rr)
			}

		case *dns.AAAA:
			if ip.Equal(addr.AAAA) {
				ans = append(ans, rr)
			}

		default:
			ans = append(ans, rr)
		}
	}

	// Set new answer.
	m.Answer = ans

	return m, u, nil
}

// hasAns returns true if m contains ip in its answer section.
func hasAns(m *dns.Msg, ip net.IP) (ok bool) {
	for _, rr := range m.Answer {
		respIP := proxyutil.GetIPFromDNSRecord(rr)
		if respIP != nil && respIP.Equal(ip) {
			return true
		}
	}

	return false
}

// extractIPs extracts all IP addresses from results.
func (f *FastestAddr) extractIPs(results []upstream.ExchangeAllResult) (ips []net.IP) {
	for _, r := range results {
		for _, rr := range r.Resp.Answer {
			ip := proxyutil.GetIPFromDNSRecord(rr)
			if ip != nil && !containsIP(ips, ip) {
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// containsIP returns true if ips contains the ip.
func containsIP(ips []net.IP, ip net.IP) (ok bool) {
	if len(ips) == 0 {
		return false
	}

	for _, i := range ips {
		if i.Equal(ip) {
			return true
		}
	}

	return false
}
