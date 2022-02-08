package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/square/certigo/lib"
)

type Options struct {
	Inspect      func(verification *lib.SimpleVerification, conn *tls.ConnectionState)
	Port         int
	Target       string
	ServerName   string
	CAPath       string
	CertPath     string
	KeyPath      string
	ExpectedName string
}

func ListenAndServe(opts *Options) error {
	// Load the TLS roots and client cert.
	var roots *x509.CertPool
	if opts.CAPath != "" {
		rootPEM, err := os.ReadFile(opts.CAPath)
		if err != nil {
			return err
		}
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM(rootPEM)
	}

	var clientCert []tls.Certificate
	if opts.CertPath != "" {
		keyPath := opts.KeyPath
		if keyPath == "" {
			keyPath = opts.CertPath
		}
		cert, err := tls.LoadX509KeyPair(opts.CertPath, opts.KeyPath)
		if err != nil {
			return err
		}
		clientCert = append(clientCert, cert)
	}

	// Start a goroutine to print verification results.
	type result struct {
		verification *lib.SimpleVerification
		state        *tls.ConnectionState
	}
	results := make(chan result)
	go func() {
		for result := range results {
			opts.Inspect(result.verification, result.state)
		}
	}()

	verify := func(conn tls.ConnectionState) error {
		verification := lib.VerifyChainWithPool(conn.PeerCertificates, conn.OCSPResponse, opts.ExpectedName, roots)
		results <- result{&verification, &conn}
		if verification.Error != "" {
			return errors.New(verification.Error)
		}
		return nil
	}

	// Create a reverse proxy to the target.
	url, err := url.Parse(opts.Target)
	if err != nil {
		return err
	}
	proxy := httputil.NewSingleHostReverseProxy(url)
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		// NewSingleHostReverseProxy doesn't overwrite Host. Do so now and
		// then forward to the original director...
		r.Host = ""
		director(r)
	}
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       clientCert,
			ServerName:         opts.ServerName,
			InsecureSkipVerify: true,
			VerifyConnection:   verify,
		},
	}
	return http.ListenAndServe(fmt.Sprintf(":%d", opts.Port), proxy)
}
