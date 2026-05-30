package socks5

import (
	"errors"
	"net"
	"testing"
)

// TestClientPerClientDialTCP verifies that a per-client DialTCP is used in
// preference to the package-level DialTCP, without affecting the global.
func TestClientPerClientDialTCP(t *testing.T) {
	sentinel := errors.New("per-client dialTCP called")
	var gotNetwork, gotRaddr string

	c := &Client{
		Server: "192.0.2.1:1080",
		DialTCP: func(network, laddr, raddr string) (net.Conn, error) {
			gotNetwork, gotRaddr = network, raddr
			return nil, sentinel
		},
	}

	err := c.Negotiate(nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected per-client DialTCP to be used, got err=%v", err)
	}
	if gotNetwork != "tcp" {
		t.Errorf("network = %q, want %q", gotNetwork, "tcp")
	}
	if gotRaddr != c.Server {
		t.Errorf("raddr = %q, want %q", gotRaddr, c.Server)
	}
}

// TestClientPerClientDialUDP verifies that a per-client DialUDP is used and is
// preserved through the struct rebuild that DialWithLocalAddr performs.
func TestClientPerClientDialUDP(t *testing.T) {
	sentinel := errors.New("per-client dialUDP called")

	// A per-client DialTCP feeds a scripted SOCKS5 negotiation/UDP-associate
	// reply so that DialWithLocalAddr reaches the DialUDP call.
	c := &Client{
		Server: "192.0.2.1:1080",
		DialTCP: func(network, laddr, raddr string) (net.Conn, error) {
			return newScriptedProxyConn(), nil
		},
		DialUDP: func(network, laddr, raddr string) (net.Conn, error) {
			return nil, sentinel
		},
	}

	_, err := c.DialWithLocalAddr("udp", "", "192.0.2.2:53", nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected per-client DialUDP to be used, got err=%v", err)
	}
}

// newScriptedProxyConn returns a net.Conn pre-loaded with the proxy-side bytes
// of a no-auth negotiation reply followed by a successful UDP-associate reply
// pointing at 192.0.2.3:1234. Writes from the client are discarded.
func newScriptedProxyConn() net.Conn {
	reply := []byte{
		// Negotiation reply: VER=5, METHOD=0 (no auth)
		Ver, MethodNone,
		// Request reply: VER=5, REP=0 (success), RSV=0, ATYP=1 (IPv4),
		// BND.ADDR=192.0.2.3, BND.PORT=1234
		Ver, RepSuccess, 0x00, ATYPIPv4, 192, 0, 2, 3, 0x04, 0xd2,
	}
	return &scriptedConn{r: reply}
}

type scriptedConn struct {
	net.Conn
	r   []byte
	off int
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	if c.off >= len(c.r) {
		return 0, errors.New("scriptedConn: no more data")
	}
	n := copy(b, c.r[c.off:])
	c.off += n
	return n, nil
}

func (c *scriptedConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *scriptedConn) Close() error                { return nil }
