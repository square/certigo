package lib

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"text/template"

	"github.com/fatih/color"
)

// TLSDescription has the basic information about a TLS connection
type TLSDescription struct {
	Version string
	Cipher  string
}

var tlsLayout = `** TLS Connection **
Version: {{.Version}}
Cipher Suite: {{.Cipher}}`

func tlscolor(d description) string {
	c, ok := qualityColors[d.Quality]
	if !ok {
		return d.Name
	}
	return c.SprintFunc()(d.Name)
}

// EncodeTLSToText returns a human readable string, suitable for certigo console output.
func EncodeTLSToText(tcs *tls.ConnectionState) string {
	version := lookup(tlsVersions, tcs.Version)
	cipher := lookup(cipherSuites, tcs.CipherSuite)
	description := TLSDescription{
		Version: tlscolor(version),
		Cipher:  tlscolor(cipher),
	}
	t := template.New("TLS template")
	t, err := t.Parse(tlsLayout)
	if err != nil {
		// Should never happen
		panic(err)
	}
	var buffer bytes.Buffer
	w := bufio.NewWriter(&buffer)
	err = t.Execute(w, description)
	if err != nil {
		// Should never happen
		panic(err)
	}
	w.Flush()
	return string(buffer.Bytes())
}

// EncodeTLSToObject returns a JSON-marshallable description of a TLS connection
func EncodeTLSToObject(t *tls.ConnectionState) interface{} {
	version := lookup(tlsVersions, t.Version)
	cipher := lookup(cipherSuites, t.CipherSuite)
	return &TLSDescription{
		version.Slug,
		cipher.Slug,
	}
}

// Just a map lookup with a default
func lookup(descriptions map[uint16]description, what uint16) description {
	v, ok := descriptions[what]
	if !ok {
		unknown := fmt.Sprintf("UNKNOWN_%x", what)
		return description{unknown, unknown, 0}
	}
	return v
}

type description struct {
	Name    string // a human-friendly string
	Slug    string // a machine-friendly string
	Quality uint8  // 0 = insecure, 1 = ok, 2 = good
}

var qualityColors = map[uint8]*color.Color{
	0: red,
	1: yellow,
	2: green,
}

var tlsVersions = map[uint16]description{
	tls.VersionSSL30: {"SSL 3.0", "ssl_3_0", 0},
	tls.VersionTLS10: {"TLS 1.0", "tls_1_0", 0},
	tls.VersionTLS11: {"TLS 1.1", "tls_1_1", 1},
	tls.VersionTLS12: {"TLS 1.2", "tls_1_2", 2},
}

var cipherSuites = map[uint16]description{
	tls.TLS_RSA_WITH_RC4_128_SHA:                {"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_RC4_128_SHA", 0},
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           {"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            {"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", 1},
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            {"TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", 1},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         {"TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256", 1},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         {"TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", 1},
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         {"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384", 1},
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        {"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 1},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 1},
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          {"TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0},
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     {"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 1},
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 1},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 1},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 1},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 2},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 2},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 2},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 2},
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", 2},
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  {"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", 2},
}
