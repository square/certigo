package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

func main() {
	file := os.Args[1]

	certs := getCerts(file)
	for i := range certs {
		displayCert(certs[i])
	}
}

func getCerts(file string) []*x509.Certificate {
	var certs []*x509.Certificate
	data, _ := ioutil.ReadFile(file)
	if strings.HasSuffix(file, "pem") {
		block, data := pem.Decode(data)
		for block != nil {
			cert, _ := x509.ParseCertificates(block.Bytes)
			certs = append(certs, cert[0])
			block, data = pem.Decode(data)
		}
	} else if strings.HasSuffix(file, "p12") {
		_, cert, _ := pkcs12.Decode(data, "password")
		certs = append(certs, cert)
	}
	return certs
}

func displayCert(cert *x509.Certificate) {

	//Expiry Date
	fmt.Println("Expiry Date:", cert.NotAfter)

	//Algorithm
	fmt.Println("Algorithm Type:", cert.SignatureAlgorithm)

	//Subject Info
	fmt.Println("Subject Info:")
	fmt.Println("	CommonName:", cert.Subject.CommonName)
	fmt.Println("	Organization:", cert.Subject.Organization)
	fmt.Println("	OrganizationalUnit:", cert.Subject.OrganizationalUnit)
	fmt.Println("	Country:", cert.Subject.Country)
	fmt.Println("	Locality:", cert.Subject.Locality)

	//Issuer Info
	fmt.Println("Issuer Info:")
	fmt.Println("	CommonName:", cert.Issuer.CommonName)
	fmt.Println("	Organization:", cert.Issuer.Organization)
	fmt.Println("	OrganizationalUnit:", cert.Issuer.OrganizationalUnit)
	fmt.Println("	Country:", cert.Issuer.Country)
	fmt.Println("	Locality:", cert.Issuer.Locality)

	//Subject Key ID
	fmt.Print("Subject Key ID: ")
	for i := 0; i < len(cert.SubjectKeyId); i++ {
		fmt.Print(hex.EncodeToString(cert.SubjectKeyId[i : i+1]))
		if i < len(cert.SubjectKeyId)-1 {
			fmt.Print(":")
		}
	}

	//Authority Key ID
	fmt.Print("\nAuthority Key ID: ")
	for i := 0; i < len(cert.AuthorityKeyId); i++ {
		fmt.Print(hex.EncodeToString(cert.AuthorityKeyId[i : i+1]))
		if i < len(cert.AuthorityKeyId)-1 {
			fmt.Print(":")
		}
	}

	//SANs, (alternate DNS Names)
	fmt.Println("\nAlternate DNS Names:", cert.DNSNames)

	//Serial Number
	fmt.Println("Serial Number:", cert.SerialNumber)
	fmt.Println("\n")
}
