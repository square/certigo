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

package lib

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/square/certigo/jceks"
	"github.com/square/certigo/pkcs7"
)

const (
	// nameHeader is the PEM header field for the friendly name/alias of the key in the key store.
	nameHeader = "friendlyName"

	// fileHeader is the origin file where the key came from (as in file on disk).
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

var badSignatureAlgorithms = [...]x509.SignatureAlgorithm{
	x509.MD2WithRSA,
	x509.MD5WithRSA,
	x509.SHA1WithRSA,
	x509.DSAWithSHA1,
	x509.ECDSAWithSHA1,
}

// TODO: replace misuse of error type in future version (errors should not act as multi-line output templates)
func errorFromErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	buffer := new(bytes.Buffer)
	buffer.WriteString("encountered multiple errors:\n")
	for _, err := range errs {
		buffer.WriteString("* ")
		buffer.WriteString(strings.TrimSuffix(err.Error(), "\n"))
		buffer.WriteString("\n")
	}
	return errors.New(buffer.String())
}

// ReadAsPEMFromFiles will read PEM blocks from the given set of inputs. Input
// data may be in plain-text PEM files, DER-encoded certificates or PKCS7
// envelopes, or PKCS12/JCEKS keystores. All inputs will be converted to PEM
// blocks and passed to the callback.
func ReadAsPEMFromFiles(files []*os.File, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	var errs []error
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		format, err := formatForFile(reader, file.Name(), format)
		if err != nil {
			return fmt.Errorf("unable to guess file type for file %s", file.Name())
		}

		err = readCertsFromStream(reader, file.Name(), format, password, callback)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errorFromErrors(errs)
}

// ReadAsPEM will read PEM blocks from the given set of inputs. Input data may
// be in plain-text PEM files, DER-encoded certificates or PKCS7 envelopes, or
// PKCS12/JCEKS keystores. All inputs will be converted to PEM blocks and
// passed to the callback.
func ReadAsPEM(readers []io.Reader, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	var errs []error
	for _, r := range readers {
		reader := bufio.NewReaderSize(r, 4)
		format, err := formatForFile(reader, "", format)
		if err != nil {
			return fmt.Errorf("unable to guess format for input stream")
		}

		err = readCertsFromStream(reader, "", format, password, callback)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errorFromErrors(errs)
}

// ReadAsX509FromFiles will read X.509 certificates from the given set of
// inputs. Input data may be in plain-text PEM files, DER-encoded certificates
// or PKCS7 envelopes, or PKCS12/JCEKS keystores. All inputs will be converted
// to X.509 certificates (private keys are skipped) and passed to the callback.
func ReadAsX509FromFiles(files []*os.File, format string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	var errs []error
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		format, err := formatForFile(reader, file.Name(), format)
		if err != nil {
			return fmt.Errorf("unable to guess file type for file %s, try adding --format flag", file.Name())
		}

		err = readCertsFromStream(reader, file.Name(), format, password, pemToX509(callback))
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errorFromErrors(errs)
}

// ReadAsX509 will read X.509 certificates from the given set of inputs. Input
// data may be in plain-text PEM files, DER-encoded certificates or PKCS7
// envelopes, or PKCS12/JCEKS keystores. All inputs will be converted to X.509
// certificates (private keys are skipped) and passed to the callback.
func ReadAsX509(readers []io.Reader, format string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	var errs []error
	for _, r := range readers {
		reader := bufio.NewReaderSize(r, 4)
		format, err := formatForFile(reader, "", format)
		if err != nil {
			return fmt.Errorf("unable to guess format for input stream")
		}

		err = readCertsFromStream(reader, "", format, password, pemToX509(callback))
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errorFromErrors(errs)
}

func pemToX509(callback func(*x509.Certificate, string, error) error) func(*pem.Block, string) error {
	return func(block *pem.Block, format string) error {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			return callback(cert, format, err)
		case "PKCS7":
			certs, err := pkcs7.ExtractCertificates(block.Bytes)
			if err == nil {
				for _, cert := range certs {
					return callback(cert, format, nil)
				}
			} else {
				return callback(nil, format, err)
			}
		case "CERTIFICATE REQUEST":
			fmt.Println(red.SprintfFunc()("warning: certificate requests are not supported"))
		}
		return nil
	}
}

// readCertsFromStream takes some input and converts it to PEM blocks.
func readCertsFromStream(reader io.Reader, filename string, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	headers := map[string]string{}
	if filename != "" && filename != os.Stdin.Name() {
		headers[fileHeader] = filename
	}

	format = strings.TrimSpace(format)
	switch format {
	case "PEM":
		scanner := pemScanner(reader)
		for scanner.Scan() {
			block, _ := pem.Decode(scanner.Bytes())
			block.Headers = mergeHeaders(block.Headers, headers)
			err := callback(block, format)
			if err != nil {
				return err
			}
		}
		return nil
	case "DER":
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("unable to read input: %s\n", err) //nolint:staticcheck // See errorFromErrors
		}
		x509Certs, err0 := x509.ParseCertificates(data)
		if err0 == nil {
			for _, cert := range x509Certs {
				err := callback(EncodeX509ToPEM(cert, headers), format)
				if err != nil {
					return err
				}
			}
			return nil
		}
		p7bBlocks, err1 := pkcs7.ParseSignedData(data)
		if err1 == nil {
			for _, block := range p7bBlocks {
				err := callback(pkcs7ToPem(block, headers), format)
				if err != nil {
					return err
				}
			}
			return nil
		}
		//nolint:staticcheck // See errorFromErrors
		return fmt.Errorf("unable to parse certificates from DER data\n* X.509 parser gave: %s\n* PKCS7 parser gave: %s\n", err0, err1)
	case "PKCS12":
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("unable to read input: %s\n", err) //nolint:staticcheck // See errorFromErrors
		}
		blocks, err := pkcs12ToPemBlocks(data, password(""))
		if err != nil {
			//nolint:staticcheck // See errorFromErrors
			return fmt.Errorf("unable to read keystore: %s\n", err)
		}
		if len(blocks) == 0 {
			//nolint:staticcheck // See errorFromErrors
			return fmt.Errorf("keystore appears to be empty or password was incorrect\n")
		}
		for _, block := range blocks {
			block.Headers = mergeHeaders(block.Headers, headers)
			err := callback(block, format)
			if err != nil {
				return err
			}
		}
		return nil
	case "JCEKS":
		keyStore, err := jceks.LoadFromReader(reader, []byte(password("")))
		if err != nil {
			return fmt.Errorf("unable to parse keystore: %s\n", err) //nolint:staticcheck // See errorFromErrors
		}
		for _, alias := range keyStore.ListCerts() {
			cert, _ := keyStore.GetCert(alias)
			err := callback(EncodeX509ToPEM(cert, mergeHeaders(headers, map[string]string{nameHeader: alias})), format)
			if err != nil {
				return err
			}
		}
		for _, alias := range keyStore.ListPrivateKeys() {
			key, certs, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(password(alias)))
			if err != nil {
				//nolint:staticcheck // See errorFromErrors
				return fmt.Errorf("unable to parse keystore: %s\n", err)
			}

			mergedHeaders := mergeHeaders(headers, map[string]string{nameHeader: alias})

			block, err := keyToPem(key, mergedHeaders)
			if err != nil {
				return fmt.Errorf("problem reading key: %s\n", err) //nolint:staticcheck // See errorFromErrors
			}

			if err := callback(block, format); err != nil {
				return err
			}

			for _, cert := range certs {
				if err = callback(EncodeX509ToPEM(cert, mergedHeaders), format); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return fmt.Errorf("unknown file type '%s'\n", format) //nolint:staticcheck // See errorFromErrors
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

// EncodeX509ToPEM converts an X.509 certificate into a PEM block for output.
func EncodeX509ToPEM(cert *x509.Certificate, headers map[string]string) *pem.Block {
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
func keyToPem(key crypto.PrivateKey, headers map[string]string) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Bytes:   x509.MarshalPKCS1PrivateKey(k),
			Headers: headers,
		}, nil
	case *ecdsa.PrivateKey:
		raw, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			//nolint:staticcheck // See errorFromErrors
			return nil, fmt.Errorf("error marshaling key: %s\n", reflect.TypeOf(key))
		}
		return &pem.Block{
			Type:    "EC PRIVATE KEY",
			Bytes:   raw,
			Headers: headers,
		}, nil
	}
	//nolint:staticcheck // See errorFromErrors
	return nil, fmt.Errorf("unknown key type: %s\n", reflect.TypeOf(key))
}

// pkcs12ToPemBlocks converts all PKCS#12 safe bags in data to PEM blocks.
func pkcs12ToPemBlocks(data []byte, password string) ([]*pem.Block, error) {
	// pkcs12.ToPEM is deprecated because it returns "PRIVATE KEY" PEM blocks that are not in PKCS#8 format, but rather
	// in a format specific to the key type. However, the pkcs12 package does not provide an equivalent replacement:
	// there is no other way to preserve the order of the safe bag contents or to preserve "friendlyName", "localKeyId",
	// and "Microsoft CSP Name" attributes that may be present in the PKCS#12 data. Therefore, this function calls the
	// deprecated function and then attempts to fix the invalid PEM blocks by giving them appropriate block types.
	//nolint:staticcheck // See comment
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12 data: %w", err)
	}
	for _, block := range blocks {
		if block.Type != "PRIVATE KEY" {
			continue
		}
		if _, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
			block.Type = "EC PRIVATE KEY"
			continue
		}
		if _, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
			block.Type = "RSA PRIVATE KEY"
			continue
		}

		//nolint:staticcheck // See errorFromErrors
		return nil, fmt.Errorf("PKCS#12 conversion produced unknown private key type\n")
	}

	return blocks, nil
}

// formatForFile returns the file format (either from flags or
// based on file extension).
func formatForFile(file *bufio.Reader, filename, format string) (string, error) {
	// First, honor --format flag we got from user
	if format != "" {
		return format, nil
	}

	// Second, attempt to guess based on extension
	guess, ok := fileExtToFormat[strings.ToLower(filepath.Ext(filename))]
	if ok {
		return guess, nil
	}

	// Third, attempt to guess based on first 4 bytes of input
	data, err := file.Peek(4)
	if err != nil {
		return "", fmt.Errorf("unable to read file: %s\n", err) //nolint:staticcheck // See errorFromErrors
	}

	// Heuristics for guessing -- best effort.
	magic := binary.BigEndian.Uint32(data)
	if magic == 0xCECECECE || magic == 0xFEEDFEED {
		// JCEKS/JKS files always start with this prefix
		return "JCEKS", nil
	}
	if magic == 0x2D2D2D2D || magic == 0x434f4e4e {
		// Starts with '----' or 'CONN' (what s_client prints...)
		return "PEM", nil
	}
	if magic&0xFFFF0000 == 0x30820000 {
		// Looks like the input is DER-encoded, so it's either PKCS12 or X.509.
		if magic&0x0000FF00 == 0x0300 {
			// Probably X.509
			return "DER", nil
		}
		return "PKCS12", nil
	}

	return "", fmt.Errorf("unable to guess file format")
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
