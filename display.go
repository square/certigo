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
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/color"
)

/*
 * Template used to display certificate to standard output.
 */
var Layout = `Enable Date: {{.NotBefore | enable}}`+
`Expiry Date: {{.NotAfter | expire}}`+
`Algorithm Type: {{.SignatureAlgorithm}}
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

/*
 * Arguments: Certificate to display
 * Returns: N/A
 *
 * Function to display cert.
 * Initializes template and template functions, then executes template.
 */
func displayCert(cert *x509.Certificate) {
	funcMap := template.FuncMap{
		"hexify": hexify,
		"enable": enable,
		"expire": expire,
	}
	t := template.New("Cert template").Funcs(funcMap)
	t, _ = t.Parse(Layout)
	t.Execute(os.Stdout, cert)

}

/*
 * Arguments: Start date for certificate
 * Returns: Empty string for the template
 *
 * Used to print in color the date cert becomes active.
 * Prints date in green if cert enabled at least a day ago.
 * Prints date in yellow if cert enabled within last day.
 * Prints date in red if cert not yet valid.
 */
func enable(start time.Time) string {
	now := time.Now()
	day, _ := time.ParseDuration("24h")
	threshold := start.Add(day)
	if now.After(threshold) {
		color.Green(start.String())
	} else if now.After(start) {
		color.Yellow(start.String())
	} else {
		color.Red(start.String())
	}
	return ""
}

/*
 * Arguments: End date for certificate
 * Returns: Empty string for the template
 *
 * Used to print in color the date the cert expires.
 * Prints date in green if cert expires more than a month in the future.
 * Prints date in yellow if cert expires within a month.
 * Prints date in red if cert is expired.
 */
func expire(end time.Time) string {
	now := time.Now()
	month, _ := time.ParseDuration("720h")
	threshold := now.Add(month)
	if threshold.Before(end) {
		color.Green(end.String())
	} else if now.Before(end) {
		color.Yellow(end.String())
	} else {
		color.Red(end.String())
	}
	return ""
}

/*
 * Arguments: Byte array formatted key ID
 * Returns: String version of key ID
 *
 * Converts Subject Key ID and Authority Key ID from
 * byte arrays to a hex, colon separated format.
 */
func hexify(arr []byte) string {
	hexed := ""
	for i := 0; i < len(arr); i++ {
		hexed += strings.ToUpper(hex.EncodeToString(arr[i : i+1]))
		if i < len(arr)-1 {
			hexed += ":"
		}
	}
	return hexed
}
