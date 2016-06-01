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
