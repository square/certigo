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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/square/certigo/jceks"
	"github.com/square/certigo/pkcs7"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	app = kingpin.New("certigo", "A command line certificate examination utility.")

	dump         = app.Command("dump", "Display information about a certificate from a file/stdin.")
	dumpFiles    = dump.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFiles()
	dumpType     = dump.Flag("format", "Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).").String()
	dumpPem      = dump.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Bool()
	dumpPassword = dump.Flag("password", "Password for PKCS12/JCEKS key stores (if required).").String()
	dumpJson     = dump.Flag("json", "Write output as machine-readable JSON format.").Bool()

	connect       = app.Command("connect", "Connect to a server and print its certificate(s).")
	connectTo     = connect.Arg("server:port", "Hostname or IP to connect to.").String()
	connectName   = connect.Flag("name", "Override the server name used for Server Name Indication (SNI).").String()
	connectCaPath = connect.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	connectPem    = connect.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Bool()
	connectJson   = connect.Flag("json", "Write output as machine-readable JSON format.").Bool()
)

const (
	nameHeader = "friendlyName"
	fileHeader = "originFile"
)

var fileExtToFormat = map[string]string{
	".pem":   "PEM",
	".crt":   "PEM",
	".p7b":   "PEM",
	".p7c":   "PEM",
	".p12":   "PKCS12",
	".pfx":   "PKCS12",
	".jceks": "JCEKS",
	".jks":   "JCEKS", // Only partially supported
	".der":   "DER",
}

func main() {
	app.Version("1.3.0")

	result := displayResult{}
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case dump.FullCommand(): // Dump certificate
		files := inputFiles(*dumpFiles)
		defer func() {
			for _, file := range files {
				file.Close()
			}
		}()

		readCerts(files, func(block *pem.Block) {
			if *dumpPem {
				block.Headers = nil
				pem.Encode(os.Stdout, block)
				return
			}

			switch block.Type {
			case "CERTIFICATE":
				result.Certificates = append(result.Certificates, createDisplayCertFromX509(block))
			case "PKCS7":
				certs, err := pkcs7.ExtractCertificates(block.Bytes)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error parsing PKCS7 block: %s\n", err)
					os.Exit(1)
				}
				for _, cert := range certs {
					result.Certificates = append(result.Certificates, createDisplayCert(certWithName{cert: cert}))
				}
			}
		})

		if *dumpJson {
			blob, _ := json.Marshal(result)
			fmt.Println(string(blob))
		} else {
			for i, cert := range result.Certificates {
				fmt.Printf("** CERTIFICATE %d **\n", i+1)
				displayCert(cert)
				fmt.Println()
			}
		}

	case connect.FullCommand(): // Get certs by connecting to a server
		conn, err := tls.Dial("tcp", *connectTo, &tls.Config{
			// We verify later manually so we can print results
			InsecureSkipVerify: true,
			ServerName:         *connectName,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error connecting: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()
		for _, cert := range conn.ConnectionState().PeerCertificates {
			if *connectPem {
				pem.Encode(os.Stdout, certToPem(cert, nil))
			} else {
				result.Certificates = append(result.Certificates, createDisplayCert(certWithName{cert: cert}))
			}
		}

		if !*connectPem {
			var hostname string
			if *connectName != "" {
				hostname = *connectName
			} else {
				hostname = strings.Split(*connectTo, ":")[0]
			}
			verifyResult := verifyChain(conn.ConnectionState().PeerCertificates, hostname, *connectCaPath)
			result.VerifyResult = &verifyResult
		}

		if *connectJson {
			blob, _ := json.Marshal(result)
			fmt.Println(string(blob))
		} else {
			for i, cert := range result.Certificates {
				fmt.Printf("** CERTIFICATE %d **\n", i+1)
				displayCert(cert)
				fmt.Println()
			}
			printVerifyResult(*result.VerifyResult)
		}
	}
}

func inputFiles(fileNames []string) []*os.File {
	files := []*os.File{}
	if fileNames != nil {
		for _, filename := range fileNames {
			rawFile, err := os.Open(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "unable to open file: %s\n", err)
				os.Exit(1)
			}
			files = append(files, rawFile)
		}
	} else {
		files = append(files, os.Stdin)
	}
	return files
}

func readCerts(files []*os.File, callback func(*pem.Block)) {
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		format, ok := formatForFile(reader, file.Name(), *dumpType)
		if !ok {
			fmt.Fprintf(os.Stderr, "unable to guess file type (for file %s)\n", file.Name())
			os.Exit(1)
		}

		readCertsFromFile(reader, file.Name(), format, callback)
	}
}

func readPassword(prompt string) string {
	if *dumpPassword != "" {
		return *dumpPassword
	}

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
		fmt.Fprintf(os.Stderr, "error reading password: %s\n", err)
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

// readCertsFromFile takes some input and converts it to PEM blocks.
func readCertsFromFile(reader io.Reader, filename string, format string, callback func(*pem.Block)) {
	headers := map[string]string{}
	if filename != "" && filename != os.Stdin.Name() {
		headers[fileHeader] = filename
	}

	switch format {
	case "PEM":
		scanner := pemScanner(reader)
		for scanner.Scan() {
			block, _ := pem.Decode(scanner.Bytes())
			block.Headers = mergeHeaders(block.Headers, headers)
			callback(block)
		}
	case "DER":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading input: %s\n", err)
			os.Exit(1)
		}
		x509Certs, err := x509.ParseCertificates(data)
		if err == nil {
			for _, cert := range x509Certs {
				callback(certToPem(cert, headers))
			}
			return
		}
		p7bBlocks, err := pkcs7.ParseSignedData(data)
		if err == nil {
			for _, block := range p7bBlocks {
				callback(pkcs7ToPem(block, headers))
			}
			return
		}
		fmt.Fprintf(os.Stderr, "error parsing certificates from DER data\n")
		os.Exit(1)
	case "PKCS12":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading input: %s\n", err)
			os.Exit(1)
		}
		password := readPassword("Enter password: ")
		blocks, err := pkcs12.ToPEM(data, password)
		if err != nil || len(blocks) == 0 {
			fmt.Fprint(os.Stderr, "keystore appears to be empty or password was incorrect\n")
			os.Exit(1)
		}
		for _, block := range blocks {
			block.Headers = mergeHeaders(block.Headers, headers)
			callback(block)
		}
	case "JCEKS":
		password := readPassword("Enter password: ")
		keyStore, err := jceks.LoadFromReader(reader, []byte(password))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing keystore: %s\n", err)
			os.Exit(1)
		}
		for _, alias := range keyStore.ListCerts() {
			cert, _ := keyStore.GetCert(alias)
			callback(certToPem(cert, mergeHeaders(headers, map[string]string{nameHeader: alias})))
		}
		for _, alias := range keyStore.ListPrivateKeys() {
			password := readPassword(fmt.Sprintf("Enter password for alias [%s]: ", alias))
			key, certs, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(password))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error parsing keystore: %s\n", err)
				os.Exit(1)
			}
			callback(keyToPem(key, mergeHeaders(headers, map[string]string{nameHeader: alias})))
			for _, cert := range certs {
				callback(certToPem(cert, mergeHeaders(headers, map[string]string{nameHeader: alias})))
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown file type: %s\n", format)
		os.Exit(1)
	}
}

func mergeHeaders(baseHeaders, extraHeaders map[string]string) (headers map[string]string) {
	headers = map[string]string{}
	for k, v := range baseHeaders {
		headers[k] = v
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	return
}

// Convert an X.509 cert into a PEM block for output.
func certToPem(cert *x509.Certificate, headers map[string]string) *pem.Block {
	return &pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   cert.Raw,
		Headers: headers,
	}
}

// Convert a PKCS7 envelope into a PEM block for output.
func pkcs7ToPem(block *pkcs7.SignedDataEnvelope, headers map[string]string) *pem.Block {
	return &pem.Block{
		Type:    "PKCS7",
		Bytes:   block.Raw,
		Headers: headers,
	}
}

// Convert a key into one or more PEM blocks for output.
func keyToPem(key crypto.PrivateKey, headers map[string]string) *pem.Block {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Bytes:   x509.MarshalPKCS1PrivateKey(k),
			Headers: headers,
		}
	case *ecdsa.PrivateKey:
		raw, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error marshaling key: %s\n", reflect.TypeOf(key))
			os.Exit(1)
		}
		return &pem.Block{
			Type:    "EC PRIVATE KEY",
			Bytes:   raw,
			Headers: headers,
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown key type: %s\n", reflect.TypeOf(key))
		os.Exit(1)
	}
	return nil
}
