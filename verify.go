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
	"strings"
)

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

func verifyChain(certs []*x509.Certificate, dnsName, caPath string) {
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
		red.Printf("Failed to verify certificate chain:\n")
		fmt.Printf("\t%s\n", err)
		return
	}

	green.Printf("Server certificates appear to be valid (found %d chains):\n", len(chains))
	for i, chain := range chains {
		names := []string{}
		for _, cert := range chain {
			var name string
			if cert.Subject.CommonName != "" {
				name = cert.Subject.CommonName
			} else {
				name = fmt.Sprintf("Serial #%s", cert.SerialNumber.String())
			}
			for _, alg := range badSignatureAlgorithms {
				if cert.SignatureAlgorithm == alg {
					name += red.SprintfFunc()(" [%s]", alg.String())
					break
				}
			}
			names = append(names, name)
		}
		fmt.Printf("\t[%d] %s\n", i, strings.Join(names, "\n\t\t=> "))
	}
}
