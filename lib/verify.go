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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"crypto/tls"

	"github.com/fatih/color"
	"golang.org/x/crypto/ocsp"
)

type simpleVerifyCert struct {
	Name               string `json:"name"`
	IsSelfSigned       bool   `json:"is_self_signed"`
	PEM                string `json:"pem"`
	signatureAlgorithm x509.SignatureAlgorithm
}

type SimpleVerification struct {
	Error      string               `json:"error,omitempty"`
	OCSPStatus *ocsp.Response       `json:"ocsp_response,omitempty"`
	OCSPError  string               `json:"ocsp_error,omitempty"`
	Chains     [][]simpleVerifyCert `json:"chains"`
}

type SimpleResult struct {
	Certificates           []*x509.Certificate `json:"certificates"`
	VerifyResult           *SimpleVerification `json:"verify_result,omitempty"`
	TLSConnectionState     *tls.ConnectionState
	CertificateRequestInfo *tls.CertificateRequestInfo
}

func (s SimpleResult) MarshalJSON() ([]byte, error) {
	certs := make([]interface{}, len(s.Certificates))
	for i, c := range s.Certificates {
		certs[i] = EncodeX509ToObject(c)
	}

	out := map[string]interface{}{}
	out["certificates"] = certs
	if s.VerifyResult != nil {
		out["verify_result"] = s.VerifyResult
	}
	if s.TLSConnectionState != nil {
		out["tls_connection"] = EncodeTLSToObject(s.TLSConnectionState)
	}
	if s.CertificateRequestInfo != nil {
		encoded, err := EncodeCRIToObject(s.CertificateRequestInfo)
		if err != nil {
			return nil, err
		}
		out["certificate_request_info"] = encoded
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

func VerifyChain(certs []*x509.Certificate, ocspStaple []byte, dnsName, caPath string) SimpleVerification {
	result := SimpleVerification{
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
		status, err := checkOCSP(chain, ocspStaple)
		if err == nil {
			result.OCSPStatus = status
		}
		if err != nil && err != skippedRevocationCheck {
			result.OCSPError = err.Error()
		}

		aChain := []simpleVerifyCert{}
		for _, cert := range chain {
			aCert := simpleVerifyCert{
				IsSelfSigned:       IsSelfSigned(cert),
				signatureAlgorithm: cert.SignatureAlgorithm,
				PEM:                string(pem.EncodeToMemory(EncodeX509ToPEM(cert, nil))),
			}

			aCert.Name = PrintCommonName(cert.Subject)
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

func PrintVerifyResult(out io.Writer, result SimpleVerification) {
	if result.Error != "" {
		fmt.Fprintf(out, red.SprintfFunc()("Failed to verify certificate chain:\n"))
		fmt.Fprintf(out, "\t%s\n", result.Error)
		return
	}
	if result.OCSPError != "" {
		fmt.Fprintf(out, red.SprintfFunc()("Certificate has OCSP servers, but was unable to check status:\n"))
		fmt.Fprintf(out, "\t%s\n\n", result.OCSPError)
	} else if result.OCSPStatus != nil {
		var text string
		var color *color.Color
		switch result.OCSPStatus.Status {
		case ocsp.Good:
			text = "Good"
			color = green
		case ocsp.Revoked:
			text = "Revoked"
			color = red
		default:
			text = "Unknown"
			color = yellow
		}
		fmt.Fprintf(out, color.SprintfFunc()("Checked OCSP status for certificate, got status:"))
		fmt.Fprintf(out, "\n\t%s (last update: %s)\n\n", text, result.OCSPStatus.ProducedAt.Format(time.UnixDate))
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
