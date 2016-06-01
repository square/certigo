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
)

var Layout = `Expiry Date: {{.NotAfter}}
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

func displayCert(cert *x509.Certificate) {

	funcMap := template.FuncMap{
		"hexify": hexify,
	}
	t := template.New("Cert template").Funcs(funcMap)
	t, _ = t.Parse(Layout)
	t.Execute(os.Stdout, cert)

}

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
