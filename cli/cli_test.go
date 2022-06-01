package cli

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/square/certigo/cli/terminal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certstrap init --curve P-256 --cn "Localhost Root" --expires "20 years"
var localhostRoot = []byte(`-----BEGIN CERTIFICATE-----
MIIBZzCCAQygAwIBAgIBATAKBggqhkjOPQQDAjAZMRcwFQYDVQQDEw5Mb2NhbGhv
c3QgUm9vdDAeFw0yMjA1MzEyMTIyNTRaFw00MjA1MzEyMTMyNTJaMBkxFzAVBgNV
BAMTDkxvY2FsaG9zdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFU5m
vrrtaf20iV8PtR9Vtri/AaOAFIDZGB24mXq8bAtqrpYJTmw4W9FXjuhF9I/hk4kb
VwkUJ/RPSQDo4WAYz6NFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFKmuTXHQnGbvxH+YrwLza85GBUT1MAoGCCqGSM49BAMC
A0kAMEYCIQDzxBz6YMWQv6kn+14Gsp+QB0q8AU+lP/Z0GJMl/SCs+QIhAPAWMOjc
mW2/VQQ+IRyDXj92xdJQ+953pBYY/inVjTBA
-----END CERTIFICATE-----`)

// certstrap request-cert --common-name localhost --curve P-256 --ip 127.0.0.1
// certstrap sign localhost --CA Localhost_Root --expires "20 years"
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBsDCCAVagAwIBAgIRAJ0DJ0Fq0oq1WrJVGOX8cyMwCgYIKoZIzj0EAwIwGTEX
MBUGA1UEAxMOTG9jYWxob3N0IFJvb3QwHhcNMjIwNTMxMjEyNDM4WhcNNDIwNTMx
MjEzMjUxWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATM99XdCMWptOjjx1INxFJSLhcqrFGIzXSfNNpL0EpPhsjkl2rLYBo7
mNvUBz2pSTMkHA8emmVeBGr748DsMQHGo4GDMIGAMA4GA1UdDwEB/wQEAwIDuDAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFEtGby8/yZBA
gfDySvtlSxqFqfZNMB8GA1UdIwQYMBaAFKmuTXHQnGbvxH+YrwLza85GBUT1MA8G
A1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0EAwIDSAAwRQIhAKoEpWBCX6HU4QQMU7B/
gPQR8oSxPa61OkaKz4He0ekjAiAVN8VtVouHHeWoq892Gbl508fST5wYKeLUdg2u
+v9Syg==
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoAW3yvL3JJBzaAdG
aPJ9zriULhC+a9ODMQTM1vWBGVahRANCAATM99XdCMWptOjjx1INxFJSLhcqrFGI
zXSfNNpL0EpPhsjkl2rLYBo7mNvUBz2pSTMkHA8emmVeBGr748DsMQHG
-----END PRIVATE KEY-----`)

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

// The ciphersuite negotiated can vary, so allow any in the expected connection result below.
var cipherSuiteRegex = regexp.MustCompile("(?m)^Cipher Suite: .*$")
var CipherSuiteRepl = "Cipher Suite: XXX"

const expectedConnect string = `** TLS Connection **
Version: TLS 1.3
Cipher Suite: XXX

** CERTIFICATE 1 **
Serial: 208705168425672442866264119814836220707
Valid: 2022-05-31 21:24 UTC to 2042-05-31 21:32 UTC
Signature: ECDSA-SHA256
Subject Info:
	CommonName: localhost
Issuer Info:
	CommonName: Localhost Root
Subject Key ID: 4B:46:6F:2F:3F:C9:90:40:81:F0:F2:4A:FB:65:4B:1A:85:A9:F6:4D
Authority Key ID: A9:AE:4D:71:D0:9C:66:EF:C4:7F:98:AF:02:F3:6B:CE:46:05:44:F5
Key Usage:
	Digital Signature
	Key Encipherment
	Data Encipherment
	Key Agreement
Extended Key Usage:
	Server Auth
	Client Auth
IP Addresses:
	127.0.0.1

Found 1 valid certificate chain(s):
[0] CN=localhost
	=> CN=Localhost Root [self-signed]
** TLS Connection **
Version: TLS 1.3
Cipher Suite: XXX

** CERTIFICATE 1 **
Serial: 208705168425672442866264119814836220707
Valid: 2022-05-31 21:24 UTC to 2042-05-31 21:32 UTC
Signature: ECDSA-SHA256
Subject Info:
	CommonName: localhost
Issuer Info:
	CommonName: Localhost Root
Subject Key ID: 4B:46:6F:2F:3F:C9:90:40:81:F0:F2:4A:FB:65:4B:1A:85:A9:F6:4D
Authority Key ID: A9:AE:4D:71:D0:9C:66:EF:C4:7F:98:AF:02:F3:6B:CE:46:05:44:F5
Key Usage:
	Digital Signature
	Key Encipherment
	Data Encipherment
	Key Agreement
Extended Key Usage:
	Server Auth
	Client Auth
IP Addresses:
	127.0.0.1

Found 1 valid certificate chain(s):
[0] CN=localhost
	=> CN=Localhost Root [self-signed]
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
	rootPath, err := ioutil.TempFile("", t.Name())
	require.NoError(t, err)
	defer os.Remove(rootPath.Name())

	_, err = rootPath.Write([]byte(localhostRoot))
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	require.NoError(t, err)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	ts.TLS.Certificates = []tls.Certificate{cert}

	args := []string{"connect", "--verbose", "--ca", rootPath.Name(), "--verify", "--expected-name", "127.0.0.1", ts.URL[len("https://"):]}
	testTerminal := terminal.TestTerminal{Width: 80}
	Run(args, &testTerminal)
	assert.EqualValues(t, 0, Run(args, &testTerminal), "process should exit 0")
	assert.Empty(t, testTerminal.ErrorBuf.Bytes(), "no error output expected")

	out := cipherSuiteRegex.ReplaceAllLiteralString(testTerminal.OutputBuf.String(), CipherSuiteRepl)
	assert.EqualValues(t, expectedConnect, out)
}
