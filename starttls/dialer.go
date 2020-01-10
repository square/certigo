package starttls

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/mwitkow/go-http-dialer"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Dialer is an interface for dialers (either net.Dialer, or http_dialer.HttpTunnel)
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// Internal copy of tls.DialWithDialer, adapter so it can work with HTTP CONNECT dialers.
// See: https://golang.org/pkg/crypto/tls/#DialWithDialer
func dialWithDialer(dialer Dialer, timeout time.Duration, network, addr string, config *tls.Config) (*tls.Conn, error) {
	var errChannel chan error
	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, config)
	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()

		err = <-errChannel
	}

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

func wrapDialerWithProxy(dialer Dialer, connectProxy *url.URL, tlsConfig *tls.Config) (Dialer, error) {
	dialerOpt := http_dialer.WithDialer(dialer.(*net.Dialer))
	tlsOpt := http_dialer.WithTls(tlsConfig)
	if connectProxy.User != nil {
		password, ok := connectProxy.User.Password()
		if !ok {
			return nil, fmt.Errorf("proxy username without password not currently supported")
		}
		auth := http_dialer.WithProxyAuth(http_dialer.AuthBasic(connectProxy.User.Username(), password))
		dialer = http_dialer.New(connectProxy, dialerOpt, tlsOpt, auth)
	} else {
		dialer = http_dialer.New(connectProxy, dialerOpt, tlsOpt)
	}
	return dialer, nil
}
