package cli

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/square/certigo/cli/terminal"
	"github.com/square/certigo/lib"
	"github.com/square/certigo/starttls"
	"gopkg.in/alecthomas/kingpin.v2"
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
	connectTo       = connect.Arg("server[:port]", "Hostname or IP to connect to, with optional port.").Required().String()
	connectName     = connect.Flag("name", "Override the server name used for Server Name Indication (SNI).").Short('n').String()
	connectCaPath   = connect.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	connectCert     = connect.Flag("cert", "Client certificate chain for connecting to server (PEM).").ExistingFile()
	connectKey      = connect.Flag("key", "Private key for client certificate, if not in same file (PEM).").ExistingFile()
	connectStartTLS = connect.Flag("start-tls", fmt.Sprintf("Enable StartTLS protocol; one of: %v.", starttls.Protocols)).Short('t').PlaceHolder("PROTOCOL").Enum(starttls.Protocols...)
	connectIdentity = connect.Flag("identity", "With --start-tls, sets the DB user or SMTP EHLO name").Default("certigo").String()
	connectProxy    = connect.Flag("proxy", "Optional URI for HTTP(s) CONNECT proxy to dial connections with").URL()
	connectTimeout  = connect.Flag("timeout", "Timeout for connecting to remote server (can be '5m', '1s', etc).").Default("5s").Duration()
	connectPem      = connect.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Short('m').Bool()
	connectJSON     = connect.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
	connectVerify   = connect.Flag("verify", "Verify certificate chain.").Bool()

	verify         = app.Command("verify", "Verify a certificate chain from file/stdin against a name.")
	verifyFile     = verify.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFile()
	verifyType     = verify.Flag("format", "Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).").Short('f').String()
	verifyPassword = verify.Flag("password", "Password for PKCS12/JCEKS key stores (reads from TTY if missing).").Short('p').String()
	verifyName     = verify.Flag("name", "Server name to verify certificate against.").Short('n').Required().String()
	verifyCaPath   = verify.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	verifyJSON     = verify.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
)

const (
	version = "1.12.0"
)

func Run(args []string, tty terminal.Terminal) int {
	terminalWidth := tty.DetermineWidth()
	stdout := tty.Output()
	errOut := tty.Error()

	printErr := func(format string, args ...interface{}) int {
		_, err := fmt.Fprintf(errOut, format, args...)
		if err != nil {
			// If we can't write the error, we bail with a different return code... not much good
			// we can do at this point
			return 3
		}
		return 2
	}
	app.Version(version)

	// Alias starttls to start-tls
	connect.Flag("starttls", "").Hidden().EnumVar(connectStartTLS, starttls.Protocols...)
	// Use long help because many useful flags are under subcommands
	app.UsageTemplate(kingpin.LongHelpTemplate)

	result := lib.SimpleResult{}
	command, err := app.Parse(args)
	if err != nil {
		return printErr("%s, try --help\n", err)
	}
	switch command {
	case dump.FullCommand(): // Dump certificate
		if dumpPassword != nil && *dumpPassword != "" {
			tty.SetDefaultPassword(*dumpPassword)
		}

		files, err := inputFiles(*dumpFiles)
		defer func() {
			for _, file := range files {
				file.Close()
			}
		}()

		if *dumpPem {
			err = lib.ReadAsPEMFromFiles(files, *dumpType, tty.ReadPassword, func(block *pem.Block, format string) error {
				block.Headers = nil
				return pem.Encode(stdout, block)
			})
		} else {
			err = lib.ReadAsX509FromFiles(files, *dumpType, tty.ReadPassword, func(cert *x509.Certificate, format string, err error) error {
				if err != nil {
					return fmt.Errorf("error parsing block: %s\n", strings.TrimSuffix(err.Error(), "\n"))
				} else {
					result.Certificates = append(result.Certificates, cert)
					result.Formats = append(result.Formats, format)
				}
				return nil
			})

			if *dumpJSON {
				blob, _ := json.Marshal(result)
				fmt.Println(string(blob))
			} else {
				for i, cert := range result.Certificates {
					fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
					fmt.Fprintf(stdout, "Input Format: %s\n", result.Formats[i])
					fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
				}
			}
		}
		if err != nil {
			return printErr("error: %s\n", strings.TrimSuffix(err.Error(), "\n"))
		} else if len(result.Certificates) == 0 && !*dumpPem {
			printErr("warning: no certificates found in input\n")
		}

	case connect.FullCommand(): // Get certs by connecting to a server
		if connectStartTLS == nil && connectIdentity != nil {
			return printErr("error: --identity can only be used with --start-tls")
		}
		connState, cri, err := starttls.GetConnectionState(
			*connectStartTLS, *connectName, *connectTo, *connectIdentity,
			*connectCert, *connectKey, *connectProxy, *connectTimeout)
		if err != nil {
			return printErr("%s\n", strings.TrimSuffix(err.Error(), "\n"))
		}
		result.TLSConnectionState = connState
		result.CertificateRequestInfo = cri
		for _, cert := range connState.PeerCertificates {
			if *connectPem {
				pem.Encode(stdout, lib.EncodeX509ToPEM(cert, nil))
			} else {
				result.Certificates = append(result.Certificates, cert)
			}
		}

		var hostname string
		if *connectName != "" {
			hostname = *connectName
		} else {
			hostname = strings.Split(*connectTo, ":")[0]
		}
		verifyResult := lib.VerifyChain(connState.PeerCertificates, connState.OCSPResponse, hostname, *connectCaPath)
		result.VerifyResult = &verifyResult

		if *connectJSON {
			blob, _ := json.Marshal(result)
			fmt.Println(string(blob))
		} else if !*connectPem {
			fmt.Fprintf(
				stdout, "%s\n\n",
				lib.EncodeTLSInfoToText(result.TLSConnectionState, result.CertificateRequestInfo))

			for i, cert := range result.Certificates {
				fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
				fmt.Fprintf(stdout, "Input Format: %s\n", result.Formats[i])
				fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
			}
			lib.PrintVerifyResult(stdout, *result.VerifyResult)
		}

		if *connectVerify && len(result.VerifyResult.Error) > 0 {
			return 1
		}
	case verify.FullCommand():
		if verifyPassword != nil && *verifyPassword != "" {
			tty.SetDefaultPassword(*verifyPassword)
		}

		file, err := inputFile(*verifyFile)
		if err != nil {
			return printErr("%s\n", err.Error())
		}
		defer file.Close()

		chain := []*x509.Certificate{}
		err = lib.ReadAsX509FromFiles([]*os.File{file}, *verifyType, tty.ReadPassword, func(cert *x509.Certificate, format string, err error) error {
			if err != nil {
				return err
			} else {
				chain = append(chain, cert)
			}
			return nil
		})
		if err != nil {
			return printErr("error parsing block: %s\n", strings.TrimSuffix(err.Error(), "\n"))
		}

		verifyResult := lib.VerifyChain(chain, nil, *verifyName, *verifyCaPath)
		if *verifyJSON {
			blob, _ := json.Marshal(verifyResult)
			fmt.Println(string(blob))
		} else {
			lib.PrintVerifyResult(stdout, verifyResult)
		}
		if verifyResult.Error != "" {
			return 1
		}
	}
	return 0
}

func inputFile(fileName string) (*os.File, error) {
	if fileName == "" {
		return os.Stdin, nil
	}

	rawFile, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %s\n", err)
	}
	return rawFile, nil
}

func inputFiles(fileNames []string) ([]*os.File, error) {
	var files []*os.File
	if fileNames != nil {
		for _, filename := range fileNames {
			rawFile, err := os.Open(filename)
			if err != nil {
				return nil, fmt.Errorf("unable to open file: %s\n", err)
			}
			files = append(files, rawFile)
		}
	} else {
		files = append(files, os.Stdin)
	}
	return files, nil
}
