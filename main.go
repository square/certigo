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
	"crypto/tls"
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
	"sync"

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

	connect     = app.Command("connect", "Connect to a server and print its certificate")
	connectTo   = connect.Arg("server:port", "Hostname or IP to connect to").String()
	connectName = connect.Flag("name", "Override the server name used for SNI").String()
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
	app.Version("1.0.1")

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

		wg := &sync.WaitGroup{}
		certs := make(chan certWithAlias, 1)

		go displayCerts(wg, certs, len(files) > 1)

		readCerts(wg, certs, files)

		wg.Wait()
	case connect.FullCommand(): // Get certs by connecting to a server
		conn, err := tls.Dial("tcp", *connectTo, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         *connectName,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()
		for i, cert := range conn.ConnectionState().PeerCertificates {
			fmt.Printf("** CERTIFICATE %d **\n", i+1)
			displayCert(certWithAlias{cert: cert})
		}
	}
}

func readCerts(wg *sync.WaitGroup, certs chan<- certWithAlias, files []*os.File) {
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		format, ok := formatForFile(reader, file.Name(), *dumpType)
		if !ok {
			fmt.Fprintf(os.Stderr, "unable to guess file type (for file %s)\n", file.Name())
			os.Exit(1)
		}

		readCertsFromFile(wg, reader, file.Name(), format, certs)
	}
}

func displayCerts(wg *sync.WaitGroup, certs <-chan certWithAlias, showFiles bool) {
	i := 1
	for cert := range certs {
		fmt.Printf("** CERTIFICATE %d **\n", i)
		if cert.file != "" && showFiles {
			fmt.Printf("File  : %s\n", path.Base(cert.file))
		}
		displayCert(cert)
		fmt.Println()
		wg.Done()
		i++
	}
}

func readPassword(prompt string) string {
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
		fmt.Fprintf(os.Stderr, "error reading password: %s", err)
		os.Exit(1)
	}

	return strings.TrimSuffix(string(password), "\n")
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

// pemScanner will return a bufio.Scanner that splits the input
// from the given reader into PEM blocks.
func pemScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)

	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		block, rest := pem.Decode(data)
		if block != nil {
			size := len(data) - len(rest)
			return size, data[:size], nil
		}

		return 0, nil, nil
	})

	return scanner
}

// readCertsFromFile takes in a filename and format type and returns an
// array of all the certificates found in that file along with aliases
// for each cert if the format of the input was jceks. If no format
// is specified for the file, readCertsFromFile guesses what format was used
// based on the file extension used in the file name. If it can't
// guess based on this it returns and error.
func readCertsFromFile(wg *sync.WaitGroup, reader io.Reader, filename string, format string, out chan<- certWithAlias) {
	switch format {
	case "PEM":
		scanner := pemScanner(reader)
		for scanner.Scan() {
			block, _ := pem.Decode(scanner.Bytes())
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error parsing certificate: %s", err)
				os.Exit(1)
			}
			wg.Add(1)
			out <- certWithAlias{file: filename, cert: cert}
		}
	case "DER":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading input: %s", err)
			os.Exit(1)
		}
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing certificate: %s", err)
			os.Exit(1)
		}
		wg.Add(1)
		out <- certWithAlias{file: filename, cert: cert}
	case "PKCS12":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading input: %s", err)
			os.Exit(1)
		}
		password := readPassword("Enter password: ")
		blocks, err := pkcs12.ToPEM(data, password)
		if err != nil || len(blocks) == 0 {
			fmt.Fprint(os.Stderr, "keystore appears to be empty or password was incorrect")
			os.Exit(1)
		}
		for _, block := range blocks {
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error parsing certificate: %s", err)
					os.Exit(1)
				}
				wg.Add(1)
				out <- certWithAlias{file: filename, cert: cert}
			}
		}
	case "JCEKS":
		password := readPassword("Enter password: ")
		keyStore, err := jceks.LoadFromReader(reader, []byte(password))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing keystore: %s", err)
			os.Exit(1)
		}
		for _, alias := range keyStore.ListCerts() {
			cert, _ := keyStore.GetCert(alias)
			wg.Add(1)
			out <- certWithAlias{file: filename, cert: cert}
		}
		for _, alias := range keyStore.ListPrivateKeys() {
			password := readPassword(fmt.Sprintf("Enter password for alias [%s]: ", alias))
			_, certArr, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(password))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error parsing keystore: %s", err)
				os.Exit(1)
			}
			for _, cert := range certArr {
				wg.Add(1)
				out <- certWithAlias{file: filename, cert: cert}
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown file type: %s", format)
		os.Exit(1)
	}
}
