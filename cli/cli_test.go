package cli

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/square/certigo/cli/terminal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at Jan 29 16:00:00 2084 GMT.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)

const testCert string = `
-----BEGIN CERTIFICATE-----
MIIE1DCCArygAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMCVVMx
FzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMRcwFQYDVQQDDA5JbnRlcm1lZGlhZXRD
QTAeFw0xNzA3MTkxNjUwMjBaFw0xNzA3MjkxNjUwMjBaMDUxCzAJBgNVBAYTAlVT
MRcwFQYDVQQKDA50ZXN0MS5hY21lLmNvbTENMAsGA1UEAwwEYmxvZzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKm8P47lABp4+rz2nN+QYrxedbaFVWoF
FuoSkqcHsafMwbMrN+kI6wJVtlbwviDvxWFJ92q0H71QNFybTsmof3KUN/kYCp7P
+LKhBrN0ttWI5q6v5eDrjN0VdtVdnlZOYmJFbvETOgfK/qXKNRRM8HYW0tdqrtEw
CR5dIu53xVUSViBdwXpuy2c5W2mFn1gxTpdW+3hbZsL1pHrU9qPWLtTgl/KY8kjs
I7KW1cIcinE4SJomhB5L/4emhxKGY+kEa2+fN9IPjjvKSMOw9kiBKk1GHZcIY5EA
O3TIfUk3fysPzi5qA0su/bNtPQy1uXgXS10xUlV7pqRPvHjiNzgFkXUCAwEAAaOB
4zCB4DAJBgNVHRMEAjAAMB0GA1UdDgQWBBRVQ91jSOONzVr1VGBdJOlPN+3XxTBg
BgNVHSMEWTBXgBQ13bfx50rDZO3y2CZdHPgleFUEoKE7pDkwNzELMAkGA1UEBhMC
VVMxFzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMQ8wDQYDVQQDDAZSb290Q0GCAhAA
MA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAtBgNVHREEJjAk
hiJzcGlmZmU6Ly9kZXYuYWNtZS5jb20vcGF0aC9zZXJ2aWNlMA0GCSqGSIb3DQEB
CwUAA4ICAQBp2+rtUxt1VmNM/vi6PwoSoYzWFmQ2nc4OM7bsOG4uppU54wRYZ+T7
c42EcrpyBgWn+rWHT1Hi6SNcmloKHydaUTZ4pq3IlKKnBNqwivU5BzIxYLDrhR/U
wd9s1tgmLvADqkQa1XjjSFn5Auoj1R640ry4qpw8IOusdm6wVhru4ssRnHX4E2uR
jQe7b3ws38aZhjtL78Ip0BB4yPxWJRp/WmEoT33QP+cZhA4IYWECxNODr6DSJeq2
VNu/6JACGrNfM2Sjt4Wxz+nIa3cKDNCA6PR8StTUTcoQ6ZBzpn+n/Q1xSRIOJz6N
hgfkyb9O7HAMdAP+TxehjqG3gh5Ky2DgYMCIZOztVzsuOb1DGJe/kGUKeRJLl2/O
QwkctwUOcVIxckNu6OvclriFzvoXObqO77XeCI2V1Vef0wGTWlWNOdbFa4708Y7f
5UdwInYQUi87RFDnc1SDU4Jrsv4KzZiv9FCfDg8pCBIdWpWT7DAuI0d7i7PZ+iFt
ZZ6sb/YDkyiDXU4ar/dja0FDE2r7jsN9D+FfW49+iDvXr4ELQyhZpW3Zr1Ojwm58
CJzjZwbRYiVwPBRsKmiYfO1E7esvw3CmjK5chfz8c40f6/APDro9ZmYNBRv2CnJy
t/DtcM/GpAhBbLP9Tk7kPB41v5fRIxVDo50Iz/qvkr37pQ4RsejSFg==
-----END CERTIFICATE-----
`

const expectedVerbose string = `** CERTIFICATE 1 **
Input Format: PEM
Serial: 4096
Valid: 2017-07-19 16:50 UTC to 2017-07-29 16:50 UTC
Signature: SHA256-RSA
Subject Info:
	Country: US
	Organization: test1.acme.com
	CommonName: blog
Issuer Info:
	Country: US
	Organization: test1.acme.com
	CommonName: IntermediaetCA
Subject Key ID: 55:43:DD:63:48:E3:8D:CD:5A:F5:54:60:5D:24:E9:4F:37:ED:D7:C5
Authority Key ID: 35:DD:B7:F1:E7:4A:C3:64:ED:F2:D8:26:5D:1C:F8:25:78:55:04:A0
Basic Constraints: CA:false
Key Usage:
	Digital Signature
	Key Encipherment
	Key Agreement
Extended Key Usage:
	Server Auth
URI Names:
	spiffe://dev.acme.com/path/service

`

const expectedConnect string = `** TLS Connection **
Version: TLS 1.3
Cipher Suite: AES_128_GCM_SHA256 cipher

** CERTIFICATE 1 **
Serial: 64483185769360960274258770740570494187
Valid: 1970-01-01 00:00 UTC to 2084-01-29 16:00 UTC
Signature: SHA256-RSA (self-signed)
Subject Info:
	Organization: Acme Co
Issuer Info:
	Organization: Acme Co
Basic Constraints: CA:true
Key Usage:
	Digital Signature
	Key Encipherment
	Cert Sign
Extended Key Usage:
	Server Auth
DNS Names:
	example.com
IP Addresses:
	127.0.0.1, ::1
Warnings:
	Size of RSA key should be at least 2048 bits

Failed to verify certificate chain:
	x509: certificate signed by unknown authority
** TLS Connection **
Version: TLS 1.3
Cipher Suite: AES_128_GCM_SHA256 cipher

** CERTIFICATE 1 **
Serial: 64483185769360960274258770740570494187
Valid: 1970-01-01 00:00 UTC to 2084-01-29 16:00 UTC
Signature: SHA256-RSA (self-signed)
Subject Info:
	Organization: Acme Co
Issuer Info:
	Organization: Acme Co
Basic Constraints: CA:true
Key Usage:
	Digital Signature
	Key Encipherment
	Cert Sign
Extended Key Usage:
	Server Auth
DNS Names:
	example.com
IP Addresses:
	127.0.0.1, ::1
Warnings:
	Size of RSA key should be at least 2048 bits

Failed to verify certificate chain:
	x509: certificate signed by unknown authority
`

// Test basic dump functionality:  Dump a cert
func TestDump(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", t.Name())
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(testCert))
	require.NoError(t, err)

	args := []string{"dump", "--verbose", "--format", "PEM", tmpfile.Name()}
	testTerminal := terminal.TestTerminal{Width: 80}

	assert.EqualValues(t, 0, Run(args, &testTerminal), "process should exit 0")
	assert.Empty(t, testTerminal.ErrorBuf.Bytes(), "no error output expected")
	assert.EqualValues(t, expectedVerbose, testTerminal.OutputBuf.String())
}

func TestDumpMissingFile(t *testing.T) {
	testTerminal := terminal.TestTerminal{Width: 80}
	args := []string{"dump", "this-is-a-file-that-definitely-does-not-exist1111.pem"}
	assert.EqualValues(t, 2, Run(args, &testTerminal), "process should exit 0")
	const expected = "path 'this-is-a-file-that-definitely-does-not-exist1111.pem' does not exist, try --help\n"
	assert.Equal(t, expected, testTerminal.ErrorBuf.String())
	assert.Empty(t, testTerminal.OutputBuf.Bytes())
}

func TestConnect(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("X509KeyPair failed: %v", err)
	}
	ts.TLS.Certificates = []tls.Certificate{cert}

	defer ts.Close()

	args := []string{"connect", "--verbose", ts.URL[len("https://"):]}
	testTerminal := terminal.TestTerminal{Width: 80}
	Run(args, &testTerminal)
	assert.EqualValues(t, 0, Run(args, &testTerminal), "process should exit 0")
	assert.Empty(t, testTerminal.ErrorBuf.Bytes(), "no error output expected")
	assert.EqualValues(t, expectedConnect, testTerminal.OutputBuf.String())
}
