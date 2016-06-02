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
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/color"
)

var Layout = `Enable Date: {{.NotBefore | certStart}}
Expiry Date: {{.NotAfter | certEnd}}
Algorithm Type: {{.SignatureAlgorithm}}
Subject Info:
	CommonName: {{.Subject.CommonName}}
	Organization: {{.Subject.Organization}}
	OrganizationalUnit: {{.Subject.OrganizationalUnit}}
	Country: {{.Subject.Country}}
	Locality: {{.Subject.Locality}}
Issuer Info:
	CommonName: {{.Issuer.CommonName}}
	Organization: {{.Issuer.Organization}}
	OrganizationalUnit: {{.Issuer.OrganizationalUnit}}
	Country: {{.Issuer.Country}}
	Locality: {{.Issuer.Locality}}
Subject Key ID  : {{.SubjectKeyId | hexify}}
Authority Key ID: {{.AuthorityKeyId | hexify}}
Alternate DNS Names: {{.DNSNames}}
Serial Number: {{.SerialNumber}}
`

// displayCert takes in an x509 Certificate object and prints out relevant
// information. Start and end dates are colored based on whether or not
// the certificate is expired, not expired, or close to expiring.
func displayCert(cert *x509.Certificate) {
	funcMap := template.FuncMap{
		"hexify":    hexify,
		"certStart": certStart,
		"certEnd":   certEnd,
	}
	t := template.New("Cert template").Funcs(funcMap)
	t, _ = t.Parse(Layout)
	t.Execute(os.Stdout, cert)

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
		return color.GreenString(start.String())
	} else if now.After(start) {
		return color.YellowString(start.String())
	} else {
		return color.RedString(start.String())
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
		return color.GreenString(end.String())
	} else if now.Before(end) {
		return color.YellowString(end.String())
	} else {
		return color.RedString(end.String())
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
