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
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/square/certigo/jceks"
	"golang.org/x/crypto/pkcs12"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("certigo", "A command line certificate examination utility.")

	dump     = app.Command("dump", "Display information about a certificate.")
	dumpFile = dump.Arg("file", "Certificate file to dump.").Required().String()
	dumpType = dump.Flag("format", "Format of given input. If unspecified, certigo guesses based on file extension").Short('f').String()
)

var fileExtToFormat = map[string]string{
	".pem":   "PEM",
	".crt":   "PEM",
	".p12":   "PKCS12",
	".pfx":   "PKCS12",
	".jceks": "JCEKS",
}

type CertWithAlias struct {
	alias string
	cert  *x509.Certificate
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case dump.FullCommand(): // Dump certificate
		format, ok := formatForFile(*dumpFile, *dumpType)
		if !ok {
			fmt.Fprint(os.Stderr, "unable to guess file type\n")
			os.Exit(1)
		}

		certs, err := getCerts(*dumpFile, format)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		for i, cert := range certs {
			fmt.Println("CERTIFICATE", i+1)
			displayCert(cert)
			fmt.Println()
		}
	}
}

// formatForFile returns the file format (either from flags or
// based on file extension).
func formatForFile(filename, format string) (string, bool) {
	if format == "" {
		guess, ok := fileExtToFormat[strings.ToLower(filepath.Ext(filename))]
		return guess, ok
	}
	return format, true
}

// getCerts takes in a filename and format type and returns an
// array of all the certificates found in that file along with aliases
// for each cert if the format of the input was jceks. If no format
// is specified for the file, getCerts guesses what format was used
// based on the file extension used in the file name. If it can't
// guess based on this it returns and error.
func getCerts(file, format string) ([]CertWithAlias, error) {
	var certs []CertWithAlias
	data, _ := ioutil.ReadFile(file)
	switch format {
	case "PEM":
		block, data := pem.Decode(data)
		for block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, CertWithAlias{cert: cert})
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
				certs = append(certs, CertWithAlias{cert: cert})
			}
		}
	case "JCEKS":
		scanner := bufio.NewReader(os.Stdin)
		fmt.Print("Enter password: ")
		password, _ := scanner.ReadString('\n')
		keyStore, err := jceks.Load(file, []byte(strings.TrimSuffix(password, "\n")))
		if err != nil {
			return nil, err
		}
		for _, alias := range keyStore.ListCerts() {
			cert, _ := keyStore.GetCert(alias)
			if err != nil {
				return nil, err
			}
			certs = append(certs, CertWithAlias{cert: cert, alias: alias})
		}
		for _, alias := range keyStore.ListPrivateKeys() {
			fmt.Printf("Enter password for alias [%s]: ", alias)
			password, _ := scanner.ReadString('\n')
			_, certArr, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(strings.TrimSuffix(password, "\n")))
			if err != nil {
				return nil, err
			}
			for _, cert := range certArr {
				certs = append(certs, CertWithAlias{cert: cert, alias: alias})
			}
		}
	default:
		return nil, fmt.Errorf("unknown file type: %s", format)
	}
	return certs, nil
}
