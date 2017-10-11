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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/mattn/go-colorable"
	"github.com/square/certigo/lib"
	"github.com/square/certigo/starttls"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	app     = kingpin.New("certigo", "A command-line utility to examine and validate certificates to help with debugging SSL/TLS issues.")
	verbose = app.Flag("verbose", "Print verbose").Short('v').Bool()

	dump         = app.Command("dump", "Display information about a certificate from a file or stdin.")
	dumpFiles    = dump.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFiles()
	dumpType     = dump.Flag("format", "Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).").Short('f').String()
	dumpPassword = dump.Flag("password", "Password for PKCS12/JCEKS key stores (reads from TTY if missing).").Short('p').String()
	dumpPem      = dump.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Short('m').Bool()
	dumpJSON     = dump.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()

	connect         = app.Command("connect", "Connect to a server and print its certificate(s).")
	connectTo       = connect.Arg("server:port", "Hostname or IP to connect to.").String()
	connectName     = connect.Flag("name", "Override the server name used for Server Name Indication (SNI).").Short('n').String()
	connectCaPath   = connect.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	connectCert     = connect.Flag("cert", "Client certificate chain for connecting to server (PEM).").ExistingFile()
	connectKey      = connect.Flag("key", "Private key for client certificate, if not in same file (PEM).").ExistingFile()
	connectStartTLS = connect.Flag("start-tls", "Enable StartTLS protocol ('ldap', 'mysql', 'postgres', 'smtp' or 'ftp').").Short('t').PlaceHolder("PROTOCOL").Enum("mysql", "postgres", "psql", "smtp", "ldap", "ftp")
	connectIdentity = connect.Flag("identity", "With --start-tls, sets the DB user or SMTP EHLO name").Default("certigo").String()
	connectProxy    = connect.Flag("proxy", "Optional URI for HTTP(s) CONNECT proxy to dial connections with").URL()
	connectTimeout  = connect.Flag("timeout", "Timeout for connecting to remote server (can be '5m', '1s', etc).").Default("5s").Duration()
	connectPem      = connect.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Short('m').Bool()
	connectJSON     = connect.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()

	verify         = app.Command("verify", "Verify a certificate chain from file/stdin against a name.")
	verifyFile     = verify.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFile()
	verifyType     = verify.Flag("format", "Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).").Short('f').String()
	verifyPassword = verify.Flag("password", "Password for PKCS12/JCEKS key stores (reads from TTY if missing).").Short('p').String()
	verifyName     = verify.Flag("name", "Server name to verify certificate against.").Short('n').Required().String()
	verifyCaPath   = verify.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	verifyJSON     = verify.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
)

const minWidth = 60
const maxWidth = 80

func main() {
	app.Version("1.9.1")

	terminalWidth := determineTerminalWidth()

	stdout := colorable.NewColorableStdout()
	result := simpleResult{}
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case dump.FullCommand(): // Dump certificate
		files := inputFiles(*dumpFiles)
		defer func() {
			for _, file := range files {
				file.Close()
			}
		}()

		var err error
		if *dumpPem {
			err = lib.ReadAsPEMFromFiles(files, *dumpType, readPassword, func(block *pem.Block) {
				block.Headers = nil
				pem.Encode(os.Stdout, block)
			})
		} else {
			err = lib.ReadAsX509FromFiles(files, *dumpType, readPassword, func(cert *x509.Certificate, err error) {
				if err != nil {
					fmt.Fprintf(os.Stderr, "error parsing block: %s\n", strings.TrimSuffix(err.Error(), "\n"))
				} else {
					result.Certificates = append(result.Certificates, cert)
				}
			})

			if *dumpJSON {
				blob, _ := json.Marshal(result)
				fmt.Println(string(blob))
			} else {
				for i, cert := range result.Certificates {
					fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
					fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
				}
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", strings.TrimSuffix(err.Error(), "\n"))
			os.Exit(1)
		} else if len(result.Certificates) == 0 && !*dumpPem {
			fmt.Fprintf(os.Stderr, "warning: no certificates found in input\n")
		}

	case connect.FullCommand(): // Get certs by connecting to a server
		if connectStartTLS == nil && connectIdentity != nil {
			fmt.Fprintln(os.Stderr, "error: --identity can only be used with --start-tls")
			os.Exit(1)
		}
		connState, cri, err := starttls.GetConnectionState(
			*connectStartTLS, *connectName, *connectTo, *connectIdentity,
			*connectCert, *connectKey, *connectProxy, *connectTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", strings.TrimSuffix(err.Error(), "\n"))
			os.Exit(1)
		}
		result.TLSConnectionState = connState
		result.CertificateRequestInfo = cri
		for _, cert := range connState.PeerCertificates {
			if *connectPem {
				pem.Encode(os.Stdout, lib.EncodeX509ToPEM(cert, nil))
			} else {
				result.Certificates = append(result.Certificates, cert)
			}
		}

		if !*connectPem {
			var hostname string
			if *connectName != "" {
				hostname = *connectName
			} else {
				hostname = strings.Split(*connectTo, ":")[0]
			}
			verifyResult := verifyChain(connState.PeerCertificates, hostname, *connectCaPath)
			result.VerifyResult = &verifyResult
		}

		if *connectJSON {
			blob, _ := json.Marshal(result)
			fmt.Println(string(blob))
		} else if !*connectPem {
			fmt.Fprintf(
				stdout, "%s\n\n",
				lib.EncodeTLSInfoToText(result.TLSConnectionState, result.CertificateRequestInfo))

			for i, cert := range result.Certificates {
				fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
				fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
			}
			printVerifyResult(stdout, *result.VerifyResult)
		}
	case verify.FullCommand():
		file := inputFile(*verifyFile)
		defer file.Close()

		chain := []*x509.Certificate{}
		lib.ReadAsX509FromFiles([]*os.File{file}, *verifyType, readPassword, func(cert *x509.Certificate, err error) {
			if err != nil {
				fmt.Fprintf(os.Stderr, "error parsing block: %s\n", strings.TrimSuffix(err.Error(), "\n"))
			} else {
				chain = append(chain, cert)
			}
		})

		verifyResult := verifyChain(chain, *verifyName, *verifyCaPath)
		if *verifyJSON {
			blob, _ := json.Marshal(verifyResult)
			fmt.Println(string(blob))
		} else {
			printVerifyResult(stdout, verifyResult)
		}
		if verifyResult.Error != "" {
			os.Exit(1)
		}
	}
}

func inputFile(fileName string) *os.File {
	if fileName == "" {
		return os.Stdin
	}

	rawFile, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to open file: %s\n", err)
		os.Exit(1)
	}
	return rawFile
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

func determineTerminalWidth() (width int) {
	fd := int(os.Stdout.Fd())
	if terminal.IsTerminal(fd) {
		var err error
		width, _, err = terminal.GetSize(fd)
		if err != nil {
			width = minWidth
		}
	} else {
		width = minWidth
	}

	if width > maxWidth {
		width = maxWidth
	} else if width < minWidth {
		width = minWidth
	}
	return
}

func readPassword(alias string) string {
	if *dumpPassword != "" {
		return *dumpPassword
	}
	if *verifyPassword != "" {
		return *verifyPassword
	}

	var tty *os.File
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		tty = os.Stdin
	} else {
		defer tty.Close()
	}

	tty.WriteString("Enter password")
	if alias != "" {
		tty.WriteString(fmt.Sprintf(" for entry [%s]", alias))
	}
	tty.WriteString(": ")

	password, err := terminal.ReadPassword(int(tty.Fd()))
	tty.WriteString("\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading password: %s\n", err)
		os.Exit(1)
	}

	return strings.TrimSuffix(string(password), "\n")
}
