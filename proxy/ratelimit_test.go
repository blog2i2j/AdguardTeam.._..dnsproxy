package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRatelimitingProxy(t *testing.T) {
	// Prepare the proxy server
	upsConf, err := ParseUpstreamsConfig([]string{upstreamAddr}, &upstream.Options{
		Timeout: defaultTimeout,
	})
	require.NoError(t, err)

	dnsProxy := mustNew(t, &Config{
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		UpstreamConfig: upsConf,
		TrustedProxies: netutil.SliceSubnetSet{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::0/0"),
		},
		RatelimitSubnetLenIPv4: 24,
		RatelimitSubnetLenIPv6: 64,
		Ratelimit:              1,
	})

	// Start listening
	ctx := context.Background()
	err = dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Send the first message (not blocked)
	req := createTestMessage()

	r, _, err := client.Exchange(req, addr.String())
	if err != nil {
		t.Fatalf("error in the first request: %s", err)
	}
	requireResponse(t, req, r)

	// Send the second message (blocked)
	req = createTestMessage()

	_, _, err = client.Exchange(req, addr.String())
	if err == nil {
		t.Fatalf("second request was not blocked")
	}
}

func TestRatelimiting(t *testing.T) {
	// rate limit is 1 per sec
	p := Proxy{}
	p.Ratelimit = 1

	addr := netip.MustParseAddr("127.0.0.1")

	limited := p.isRatelimited(addr)

	if limited {
		t.Fatal("First request must have been allowed")
	}

	limited = p.isRatelimited(addr)

	if !limited {
		t.Fatal("Second request must have been ratelimited")
	}
}

func TestWhitelist(t *testing.T) {
	// rate limit is 1 per sec with whitelist
	p := Proxy{}
	p.Ratelimit = 1
	p.RatelimitWhitelist = []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("127.0.0.2"),
		netip.MustParseAddr("127.0.0.125"),
	}

	addr := netip.MustParseAddr("127.0.0.1")

	limited := p.isRatelimited(addr)

	if limited {
		t.Fatal("First request must have been allowed")
	}

	limited = p.isRatelimited(addr)

	if limited {
		t.Fatal("Second request must have been allowed due to whitelist")
	}
}
