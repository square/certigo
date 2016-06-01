package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/pkcs12"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("certigo", "A command line certificate examination utility.")

	dump     = app.Command("dump", "Display information about a certificate.")
	dumpFile = dump.Arg("file", "Certificate file to dump.").Required().String()
	dumpType = dump.Flag("format", "Format of given input. If unspecified, certigo guesses based on file extension").Default("guess").Short('f').String()
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
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
			block, data = pem.Decode(data)
		}
	case "PKCS12":
		scanner := bufio.NewReader(os.Stdin)
		fmt.Print("Enter password: ")
		password, _ := scanner.ReadString('\n')
		blocks, err := pkcs12.ToPEM(data, strings.TrimSuffix(password, "\n"))
		if err != nil {
			return nil, err
		}
		for _, block := range blocks {
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, err
				}
				certs = append(certs, cert)
			}
		}
	case "guess":
		if strings.HasSuffix(file, "pem") {
			return getCerts(file, "PEM")
		} else if strings.HasSuffix(file, "p12") || strings.HasSuffix(file, "pks") {
			return getCerts(file, "PKCS12")
		} else {
			return getCerts(file, ", couldn't guess format")
		}
	default:
		return nil, fmt.Errorf("unknown type %s", format)
	}
	return certs, nil
}
