/*-
 * Copyright 2016 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/color"
)

var layout = `Serial: {{.SerialNumber}}
Not Before: {{.NotBefore | certStart}}
Not After : {{.NotAfter | certEnd}}
Signature : {{.SignatureAlgorithm | algorithm}} {{if . | isSelfSigned}}(self-signed){{end}}
Subject Info: {{if .Subject.CommonName}}
	CommonName: {{.Subject.CommonName}}{{end}} {{if .Subject.Organization}}
	Organization: {{.Subject.Organization}} {{end}} {{if .Subject.OrganizationalUnit}}
	OrganizationalUnit: {{.Subject.OrganizationalUnit}} {{end}} {{if .Subject.Country}}
	Country: {{.Subject.Country}} {{end}} {{if .Subject.Locality}}
	Locality: {{.Subject.Locality}} {{end}}
Issuer Info: {{if .Issuer.CommonName}}
	CommonName: {{.Issuer.CommonName}} {{end}} {{if .Issuer.Organization}}
	Organization: {{.Issuer.Organization}} {{end}} {{if .Issuer.OrganizationalUnit}}
	OrganizationalUnit: {{.Issuer.OrganizationalUnit}} {{end}} {{if .Issuer.Country}}
	Country: {{.Issuer.Country}} {{end}} {{if .Issuer.Locality}}
	Locality: {{.Issuer.Locality}} {{end}} {{if .SubjectKeyId}} 
Subject Key ID   : {{.SubjectKeyId | hexify}} {{end}} {{if .AuthorityKeyId}}
Authority Key ID : {{.AuthorityKeyId | hexify}} {{end}} {{if .BasicConstraintsValid}}
Basic Constraints: CA:{{.IsCA}}{{if ge .MaxPathLen 0}}, pathlen:{{.MaxPathLen}}{{end}} {{end}} {{if .PermittedDNSDomains}}
Name Constraints {{if .PermittedDNSDomainsCritical}}(critical){{end}}: {{range .PermittedDNSDomains}}
	{{.}} {{end}} {{end}} {{if .KeyUsage | keyUsage}}
Key Usage: {{range .KeyUsage | keyUsage}}
	{{.}} {{end}} {{end}} {{if .ExtKeyUsage}}
Extended Key Usage: {{range .ExtKeyUsage}}
	{{. | extKeyUsage}} {{end}} {{end}} {{if .DNSNames}}
Alternate DNS Names: {{range .DNSNames}}
	{{.}} {{end}} {{end}} {{if .IPAddresses}}
Alternate IP Addresses: {{range .IPAddresses}}	
	{{.}} {{end}} {{end}} {{if .EmailAddresses}}
Email Addresses: {{range .EmailAddresses}}
	{{.}} {{end}} {{end}} {{if . | certWarnings}}
Warnings: {{range . | certWarnings}}
	{{.}} {{end}} {{end}}
`

type certWithName struct {
	name string
	file string
	cert *x509.Certificate
}

func displayCertFromPem(block *pem.Block) {
	raw, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading cert: %s", err)
		os.Exit(1)
	}

	cert := certWithName{cert: raw}
	if val, ok := block.Headers[nameHeader]; ok {
		cert.name = val
	}
	if val, ok := block.Headers[fileHeader]; ok {
		cert.file = val
	}

	displayCert(cert)
}

// displayCert takes in an x509.Certificate object and an alias
// (for jceks certs, blank otherwise), and prints out relevant
// information. Start and end dates are colored based on whether or not
// the certificate is expired, not expired, or close to expiring.
func displayCert(cert certWithName) {
	funcMap := template.FuncMap{
		"hexify":       hexify,
		"certStart":    certStart,
		"certEnd":      certEnd,
		"algorithm":    highlightAlgorithm,
		"keyUsage":     keyUsage,
		"extKeyUsage":  extKeyUsage,
		"certWarnings": certWarnings,
		"isSelfSigned": isSelfSigned,
	}
	t := template.New("Cert template").Funcs(funcMap)
	t, _ = t.Parse(layout)
	if cert.name != "" {
		fmt.Println("Alias :", cert.name)
	}
	t.Execute(os.Stdout, cert.cert)

}

var (
	green  = color.New(color.Bold, color.FgGreen)
	yellow = color.New(color.Bold, color.FgYellow)
	red    = color.New(color.Bold, color.FgRed)
)

var keyUsageStrings = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "Digital Signature",
	x509.KeyUsageContentCommitment: "Content Commitment",
	x509.KeyUsageKeyEncipherment:   "Key Encipherment",
	x509.KeyUsageDataEncipherment:  "Data Encipherment",
	x509.KeyUsageKeyAgreement:      "Key Agreement",
	x509.KeyUsageCertSign:          "Cert Sign",
	x509.KeyUsageCRLSign:           "CRL Sign",
	x509.KeyUsageEncipherOnly:      "Encipher Only",
	x509.KeyUsageDecipherOnly:      "Decipher Only",
}

var extKeyUsageStrings = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "Server Auth",
	x509.ExtKeyUsageClientAuth:                 "Client Auth",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSEC End System",
	x509.ExtKeyUsageIPSECTunnel:                "IPSEC Tunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSEC User",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft ServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape ServerGatedCrypto",
}

var algorithmColors = map[x509.SignatureAlgorithm]*color.Color{
	x509.MD2WithRSA:      red,
	x509.MD5WithRSA:      red,
	x509.SHA1WithRSA:     red,
	x509.SHA256WithRSA:   green,
	x509.SHA384WithRSA:   green,
	x509.SHA512WithRSA:   green,
	x509.DSAWithSHA1:     red,
	x509.DSAWithSHA256:   red,
	x509.ECDSAWithSHA1:   red,
	x509.ECDSAWithSHA256: green,
	x509.ECDSAWithSHA384: green,
	x509.ECDSAWithSHA512: green,
}

var algoName = [...]string{
	x509.MD2WithRSA:      "MD2-RSA",
	x509.MD5WithRSA:      "MD5-RSA",
	x509.SHA1WithRSA:     "SHA1-RSA",
	x509.SHA256WithRSA:   "SHA256-RSA",
	x509.SHA384WithRSA:   "SHA384-RSA",
	x509.SHA512WithRSA:   "SHA512-RSA",
	x509.DSAWithSHA1:     "DSA-SHA1",
	x509.DSAWithSHA256:   "DSA-SHA256",
	x509.ECDSAWithSHA1:   "ECDSA-SHA1",
	x509.ECDSAWithSHA256: "ECDSA-SHA256",
	x509.ECDSAWithSHA384: "ECDSA-SHA384",
	x509.ECDSAWithSHA512: "ECDSA-SHA512",
}

func algString(algo x509.SignatureAlgorithm) string {
	if 0 < algo && int(algo) < len(algoName) {
		return algoName[algo]
	}
	return strconv.Itoa(int(algo))
}

// highlightAlgorithm changes the color of the signing algorithm
// based on a set color map, e.g. to make SHA-1 show up red.
func highlightAlgorithm(sig x509.SignatureAlgorithm) string {
	color, ok := algorithmColors[sig]
	if !ok {
		return algString(sig)
	}
	return color.SprintFunc()(algString(sig))
}

// keyUsage decodes/prints key usage from a certificate.
func keyUsage(ku x509.KeyUsage) []string {
	out := []string{}
	for key, value := range keyUsageStrings {
		if ku&key > 0 {
			out = append(out, value)
		}
	}
	return out
}

// extKeyUsage decodes/prints extended key usage from a certificate.
func extKeyUsage(eku x509.ExtKeyUsage) string {
	val, ok := extKeyUsageStrings[eku]
	if ok {
		return val
	}
	return fmt.Sprintf("unknown:%d", eku)
}

// certStart takes a given start time for the validity of
// a certificate and returns that time colored properly
// based on how close it is to expiry. If it's more than
// a day after the certificate became valid the string will
// be green. If it has been less than a day the string will
// be yellow. If the certificate is not yet valid, the string
// will be red.
func certStart(start time.Time) string {
	now := time.Now()
	day, _ := time.ParseDuration("24h")
	threshold := start.Add(day)
	if now.After(threshold) {
		return green.SprintfFunc()(start.String())
	} else if now.After(start) {
		return yellow.SprintfFunc()(start.String())
	} else {
		return red.SprintfFunc()(start.String())
	}
}

// certEnd takes a given end time for the validity of
// a certificate and returns that time colored properly
// based on how close it is to expiry. If the certificate
// is more than a month away from expiring it returns a
// green string. If the certificate is less than a month
// from expiry it returns a yellow string. If the certificate
// is expired it returns a red string.
func certEnd(end time.Time) string {
	now := time.Now()
	month, _ := time.ParseDuration("720h")
	threshold := now.Add(month)
	if threshold.Before(end) {
		return green.SprintfFunc()(end.String())
	} else if now.Before(end) {
		return yellow.SprintfFunc()(end.String())
	} else {
		return red.SprintfFunc()(end.String())
	}
}

// hexify returns a colon separated, hexadecimal representation
// of a given byte array.
func hexify(arr []byte) string {
	var hexed bytes.Buffer
	for i := 0; i < len(arr); i++ {
		hexed.WriteString(strings.ToUpper(hex.EncodeToString(arr[i : i+1])))
		if i < len(arr)-1 {
			hexed.WriteString(":")
		}
	}
	return hexed.String()
}

var badSignatureAlgorithms = []x509.SignatureAlgorithm{
	x509.MD2WithRSA,
	x509.MD5WithRSA,
	x509.SHA1WithRSA,
	x509.DSAWithSHA1,
	x509.ECDSAWithSHA1,
}

// certWarnings prints a list of warnings to show common mistakes in certs.
func certWarnings(cert *x509.Certificate) (warnings []string) {
	if cert.SerialNumber.Sign() != 1 {
		warnings = append(warnings, red.SprintfFunc()("Serial number in cert appears to be zero/negative"))
	}

	if cert.SerialNumber.BitLen() > 160 {
		warnings = append(warnings, red.SprintfFunc()("Serial number too long; should be 20 bytes or less"))
	}

	if (cert.KeyUsage&x509.KeyUsageCertSign != 0) && !cert.IsCA {
		warnings = append(warnings, red.SprintfFunc()("Key usage 'cert sign' is set, but is not a CA cert"))
	}

	if (cert.KeyUsage&x509.KeyUsageCertSign == 0) && cert.IsCA {
		warnings = append(warnings, red.SprintfFunc()("Certificate is a CA cert, but key usage 'cert sign' missing"))
	}

	if cert.Version < 2 {
		warnings = append(warnings, red.SprintfFunc()("Certificate is not in X509v3 format (version is %d)", cert.Version+1))
	}

	if len(cert.UnhandledCriticalExtensions) > 0 {
		warnings = append(warnings, red.SprintfFunc()("Certificate has unhandled critical extensions"))
	}

	warnings = append(warnings, algWarnings(cert)...)

	return
}

// algWarnings checks key sizes, signature algorithms.
func algWarnings(cert *x509.Certificate) (warnings []string) {
	alg, size := decodeKey(cert.PublicKey)
	if (alg == "RSA" || alg == "DSA") && size < 2048 {
		warnings = append(warnings, red.SprintfFunc()("Size of %s key should be at least 2048 bits", alg))
	}
	if alg == "ECDSA" && size < 224 {
		warnings = append(warnings, red.SprintfFunc()("Size of %s key should be at least 224 bits", alg))
	}

	for _, alg := range badSignatureAlgorithms {
		if cert.SignatureAlgorithm == alg {
			warnings = append(warnings, red.SprintfFunc()("Using %s, which is an outdated signature algorithm", algString(alg)))
		}
	}

	if alg == "RSA" {
		key := cert.PublicKey.(*rsa.PublicKey)
		if key.E < 3 {
			warnings = append(warnings, red.SprintfFunc()("Public key exponent in RSA key is less than 3"))
		}
		if key.N.Sign() != 1 {
			warnings = append(warnings, red.SprintfFunc()("Public key modulus in RSA key appears to be zero/negative"))
		}
	}

	return
}

// decodeKey returns the algorithm and key size for a public key.
func decodeKey(publicKey interface{}) (string, int) {
	switch publicKey.(type) {
	case *dsa.PublicKey:
		return "DSA", publicKey.(*dsa.PublicKey).P.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", publicKey.(*ecdsa.PublicKey).Curve.Params().BitSize
	case *rsa.PublicKey:
		return "RSA", publicKey.(*rsa.PublicKey).N.BitLen()
	default:
		return "", 0
	}
}
