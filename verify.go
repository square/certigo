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
	"io"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/fatih/color"
	"github.com/square/certigo/lib"
)

var (
	green  = color.New(color.Bold, color.FgGreen)
	yellow = color.New(color.Bold, color.FgYellow)
	red    = color.New(color.Bold, color.FgRed)
)

var algoName = [...]string{
	x509.MD2WithRSA:      "MD2-RSA",
	x509.MD5WithRSA:      "MD5-RSA",
	x509.SHA1WithRSA:     "SHA1-RSA",
	x509.SHA256WithRSA:   "SHA256-RSA",
	x509.SHA384WithRSA:   "SHA384-RSA",
	x509.SHA512WithRSA:   "SHA512-RSA",
	x509.DSAWithSHA1:     "DSA-SHA1",
	x509.DSAWithSHA256:   "DSA-SHA256",
	x509.ECDSAWithSHA1:   "ECDSA-SHA1",
	x509.ECDSAWithSHA256: "ECDSA-SHA256",
	x509.ECDSAWithSHA384: "ECDSA-SHA384",
	x509.ECDSAWithSHA512: "ECDSA-SHA512",
}

var badSignatureAlgorithms = [...]x509.SignatureAlgorithm{
	x509.MD2WithRSA,
	x509.MD5WithRSA,
	x509.SHA1WithRSA,
	x509.DSAWithSHA1,
	x509.ECDSAWithSHA1,
}

type simpleVerifyCert struct {
	Name               string `json:"name"`
	IsSelfSigned       bool   `json:"is_self_signed"`
	PEM                string `json:"pem"`
	signatureAlgorithm x509.SignatureAlgorithm
}

type simpleVerification struct {
	Error  string               `json:"error,omitempty"`
	Chains [][]simpleVerifyCert `json:"chains"`
}

type simpleResult struct {
	Certificates []*x509.Certificate `json:"certificates"`
	VerifyResult *simpleVerification `json:"verify_result,omitempty"`
}

func (s simpleResult) MarshalJSON() ([]byte, error) {
	certs := make([]interface{}, len(s.Certificates))
	for i, c := range s.Certificates {
		certs[i] = lib.EncodeX509ToObject(c)
	}

	out := map[string]interface{}{}
	out["certificates"] = certs
	if s.VerifyResult != nil {
		out["verify_result"] = s.VerifyResult
	}
	return json.Marshal(out)
}

func caBundle(caPath string) *x509.CertPool {
	if caPath == "" {
		return nil
	}

	bundleBytes, err := ioutil.ReadFile(caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading CA bundle: %s\n", err)
		os.Exit(1)
	}

	bundle := x509.NewCertPool()
	bundle.AppendCertsFromPEM(bundleBytes)
	return bundle
}

func verifyChain(certs []*x509.Certificate, dnsName, caPath string) simpleVerification {
	result := simpleVerification{
		Chains: [][]simpleVerifyCert{},
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	opts := x509.VerifyOptions{
		DNSName:       dnsName,
		Roots:         caBundle(caPath),
		Intermediates: intermediates,
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		result.Error = fmt.Sprintf("%s", err)
		return result
	}

	for _, chain := range chains {
		aChain := []simpleVerifyCert{}
		for _, cert := range chain {
			aCert := simpleVerifyCert{
				IsSelfSigned:       lib.IsSelfSigned(cert),
				signatureAlgorithm: cert.SignatureAlgorithm,
				PEM:                string(pem.EncodeToMemory(lib.EncodeX509ToPEM(cert, nil))),
			}

			if cert.Subject.CommonName != "" {
				aCert.Name = cert.Subject.CommonName
			} else {
				aCert.Name = fmt.Sprintf("Serial #%s", cert.SerialNumber.String())
			}

			aChain = append(aChain, aCert)
		}
		result.Chains = append(result.Chains, aChain)
	}
	return result
}

func fmtCert(cert simpleVerifyCert) string {
	name := cert.Name
	if cert.IsSelfSigned {
		name += green.SprintfFunc()(" [self-signed]")
	}
	for _, alg := range badSignatureAlgorithms {
		if cert.signatureAlgorithm == alg {
			name += red.SprintfFunc()(" [%s]", algString(alg))
			break
		}
	}
	return name
}

func algString(algo x509.SignatureAlgorithm) string {
	if 0 < algo && int(algo) < len(algoName) {
		return algoName[algo]
	}
	return strconv.Itoa(int(algo))
}

func printVerifyResult(out io.Writer, result simpleVerification) {
	if result.Error != "" {
		fmt.Fprintf(out, red.SprintfFunc()("Failed to verify certificate chain:\n"))
		fmt.Fprintf(out, "\t%s\n", result.Error)
		return
	}
	fmt.Fprintf(out, green.SprintfFunc()("Found %d valid certificate chain(s):\n", len(result.Chains)))
	for i, chain := range result.Chains {
		fmt.Fprintf(out, "[%d] %s\n", i, fmtCert(chain[0]))
		for j, cert := range chain {
			if j == 0 {
				continue
			}
			fmt.Fprintf(out, "\t=> %s\n", fmtCert(cert))
		}
	}
}
