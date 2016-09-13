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
	"fmt"
	"io/ioutil"
	"os"
)

type vCert struct {
	Name               string `json:"name"`
	IsSelfSigned       bool   `json:"is_self_signed"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	original           *x509.Certificate
}

type vChain struct {
	Certs []vCert `json:"chain"`
}

type vResult struct {
	Error  string   `json:"error,omitempty"`
	Chains []vChain `json:"chains"`
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

func verifyChain(certs []*x509.Certificate, dnsName, caPath string) vResult {
	result := vResult{}

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

	//green.Printf("Server certificates appear to be valid (found %d chains):\n", len(chains))
	for _, chain := range chains {
		aChain := vChain{}
		for _, cert := range chain {
			aCert := vCert{}
			if cert.Subject.CommonName != "" {
				aCert.Name = cert.Subject.CommonName
			} else {
				aCert.Name = fmt.Sprintf("Serial #%s", cert.SerialNumber.String())
			}
			aCert.IsSelfSigned = isSelfSigned(cert)
			aCert.SignatureAlgorithm = algString(cert.SignatureAlgorithm)
			aCert.original = cert
			aChain.Certs = append(aChain.Certs, aCert)
		}
		result.Chains = append(result.Chains, aChain)
	}
	return result
}

func fmtCert(cert vCert) string {
	name := cert.Name
	if cert.IsSelfSigned {
		name += green.SprintfFunc()(" [self-signed]")
	}
	for _, alg := range badSignatureAlgorithms {
		if cert.original.SignatureAlgorithm == alg {
			name += red.SprintfFunc()(" [%s]", algString(alg))
			break
		}
	}
	return name
}

func printVerifyResult(result vResult) {
	if result.Error != "" {
		red.Printf("Failed to verify certificate chain:\n")
		fmt.Printf("\t%s\n", result.Error)
		return
	}
	for i, chain := range result.Chains {
		fmt.Printf("[%d] %s", i, fmtCert(chain.Certs[0]))
		for j, cert := range chain.Certs {
			if j == 0 {
				continue
			}
			fmt.Printf("\n\t=> %s", fmtCert(cert))

		}
	}
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}
