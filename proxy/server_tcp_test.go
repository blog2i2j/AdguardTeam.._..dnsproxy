package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestTcpProxy(t *testing.T) {
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

	// Create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	sendTestMessages(t, conn)
}

func TestTlsProxy(t *testing.T) {
	// Prepare the proxy server
	serverConfig, caPem := createServerTLSConfig(t)

	upsConf, err := ParseUpstreamsConfig([]string{upstreamAddr}, &upstream.Options{
		Timeout: defaultTimeout,
	})
	require.NoError(t, err)

	dnsProxy := mustNew(t, &Config{
		TLSListenAddr:   []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		HTTPSListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		QUICListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TLSConfig:       serverConfig,
		UpstreamConfig:  upsConf,
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

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{ServerName: tlsServerName, RootCAs: roots}

	// Create a DNS-over-TLS client connection
	addr := dnsProxy.Addr(ProtoTLS)
	conn, err := dns.DialWithTLS("tcp-tls", addr.String(), tlsConfig)
	if err != nil {
		t.Fatalf("cannot connect to the proxy: %s", err)
	}

	sendTestMessages(t, conn)
}
