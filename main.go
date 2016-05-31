package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/pkcs12"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("certigo", "A command line certificate examination utility.")

	dump     = app.Command("dump", "Display information about a certificate.")
	dumpFile = dump.Arg("file", "Certificate file to dump.").Required().String()
	dumpType = dump.Flag("format", "Format of given input. If unspecified, certigo guesses based on file extension").Short('f').String()
)

func main() {

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	//Dump Certificate
	case dump.FullCommand():
		certs, err := getCerts(*dumpFile, *dumpType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		for _, cert := range certs {
			displayCert(cert)
		}
	}
}

func getCerts(file, format string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	data, _ := ioutil.ReadFile(file)
	switch format {
	case "PEM":
		block, data := pem.Decode(data)
		for block != nil {
			cert, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert[0])
			block, data = pem.Decode(data)
		}
	case "PKCS12":
		_, cert, err := pkcs12.Decode(data, "password")
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	default:
		return nil, fmt.Errorf("unknown type %s", format)
	}
	return certs, nil
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
