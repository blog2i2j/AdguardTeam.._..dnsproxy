package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestUdpProxy(t *testing.T) {
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
	})

	// Start listening
	ctx := context.Background()
	err = dnsProxy.Start(ctx)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return dnsProxy.Shutdown(ctx) })

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	sendTestMessages(t, conn)
}
