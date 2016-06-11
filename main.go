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
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/square/certigo/jceks"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	app = kingpin.New("certigo", "A command line certificate examination utility.")

	dump      = app.Command("dump", "Display information about a certificate.")
	dumpFiles = dump.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFiles()
	dumpType  = dump.Flag("format", "Format of given input (heuristic guess if not specified).").String()
)

var fileExtToFormat = map[string]string{
	".pem":   "PEM",
	".crt":   "PEM",
	".p12":   "PKCS12",
	".pfx":   "PKCS12",
	".jceks": "JCEKS",
	".jks":   "JCEKS", // Only partially supported
	".der":   "DER",
}

type certWithAlias struct {
	alias string
	file  string
	cert  *x509.Certificate
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case dump.FullCommand(): // Dump certificate
		files := []*os.File{}
		if *dumpFiles != nil {
			for _, filename := range *dumpFiles {
				rawFile, err := os.Open(filename)
				if err != nil {
					fmt.Fprintf(os.Stderr, "unable to open file: %s\n", err)
					os.Exit(1)
				}
				files = append(files, rawFile)
				defer rawFile.Close()
			}
		} else {
			files = append(files, os.Stdin)
		}

		var certs []certWithAlias
		for _, file := range files {
			reader := bufio.NewReader(file)
			format, ok := formatForFile(reader, file.Name(), *dumpType)
			if !ok {
				fmt.Fprintf(os.Stderr, "unable to guess file type (for file %s)\n", file.Name())
				os.Exit(1)
			}

			parsed, err := getCerts(reader, file.Name(), format)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				os.Exit(1)
			}
			certs = append(certs, parsed...)
		}

		for i, cert := range certs {
			fmt.Printf("** CERTIFICATE %d **\n", i+1)
			if cert.file != "" && len(files) > 1 {
				fmt.Printf("File  : %s\n", path.Base(cert.file))
			}
			displayCert(cert)
			fmt.Println()
		}
	}
}

func readPassword(prompt string) (string, error) {
	var tty *os.File
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		tty = os.Stdin
	} else {
		defer tty.Close()
	}
	tty.WriteString(prompt)
	password, err := terminal.ReadPassword(int(tty.Fd()))
	tty.WriteString("\n")
	if err != nil {
		return "", err
	}
	return string(password), err
}

// formatForFile returns the file format (either from flags or
// based on file extension).
func formatForFile(file *bufio.Reader, filename, format string) (string, bool) {
	// First, honor --format flag we got from user
	if format != "" {
		return format, true
	}

	// Second, attempt to guess based on extension
	guess, ok := fileExtToFormat[strings.ToLower(filepath.Ext(filename))]
	if ok {
		return guess, true
	}

	// Third, attempt to guess based on first 4 bytes of input
	data, err := file.Peek(4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	// Heuristics for guessing -- best effort.
	magic := binary.BigEndian.Uint32(data)
	if magic == 0xCECECECE || magic == 0xFEEDFEED {
		// JCEKS/JKS files always start with this prefix
		return "JCEKS", true
	}
	if magic == 0x2D2D2D2D || magic == 0x434f4e4e {
		// Starts with '----' or 'CONN' (what s_client prints...)
		return "PEM", true
	}
	if magic&0xFFFF0000 == 0x30820000 {
		// Looks like the input is DER-encoded, so it's either PKCS12 or X.509.
		if magic&0x0000FF00 == 0x0300 {
			// Probably X.509
			return "DER", true
		}
		return "PKCS12", true
	}

	return "", false
}

// getCerts takes in a filename and format type and returns an
// array of all the certificates found in that file along with aliases
// for each cert if the format of the input was jceks. If no format
// is specified for the file, getCerts guesses what format was used
// based on the file extension used in the file name. If it can't
// guess based on this it returns and error.
func getCerts(reader io.Reader, filename string, format string) ([]certWithAlias, error) {
	var certs []certWithAlias
	switch format {
	case "PEM":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		block, data := pem.Decode(data)
		for block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, certWithAlias{file: filename, cert: cert})
			block, data = pem.Decode(data)
		}
	case "DER":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, err
		}
		certs = append(certs, certWithAlias{file: filename, cert: cert})
	case "PKCS12":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		password, err := readPassword("Enter password: ")
		if err != nil {
			return nil, err
		}
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
				certs = append(certs, certWithAlias{alias: block.Headers["friendlyName"], file: filename, cert: cert})
			}
		}
	case "JCEKS":
		password, err := readPassword("Enter password: ")
		if err != nil {
			return nil, err
		}
		keyStore, err := jceks.LoadFromReader(reader, []byte(strings.TrimSuffix(password, "\n")))
		if err != nil {
			return nil, err
		}
		for _, alias := range keyStore.ListCerts() {
			cert, _ := keyStore.GetCert(alias)
			if err != nil {
				return nil, err
			}
			certs = append(certs, certWithAlias{alias: alias, file: filename, cert: cert})
		}
		for _, alias := range keyStore.ListPrivateKeys() {
			password, err := readPassword(fmt.Sprintf("Enter password for alias [%s]: ", alias))
			if err != nil {
				return nil, err
			}
			_, certArr, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(strings.TrimSuffix(password, "\n")))
			if err != nil {
				return nil, err
			}
			for _, cert := range certArr {
				certs = append(certs, certWithAlias{alias: alias, file: filename, cert: cert})
			}
		}
	default:
		return nil, fmt.Errorf("unknown file type: %s", format)
	}
	return certs, nil
}
