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

package pkcs7

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var signedDataIdentifier = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 2})

type signedDataEnvelope struct {
	Type       asn1.ObjectIdentifier
	SignedData signedData `asn1:"tag:0,explicit,optional"`
}

// Refer to RFC 2315, Section 9.1 for definition of this type.
type signedData struct {
	Version          int
	DigestAlgorithms []asn1.ObjectIdentifier `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     []asn1.RawValue `asn1:"tag:0,optional,set"`
	RevocationLists  []asn1.RawValue `asn1:"tag:1,optional,set"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// ExtractCertificates reads a SignedData type and returns the embedded
// certificates (if present in the structure).
func ExtractCertificates(data []byte) ([]*x509.Certificate, error) {
	var envelope signedDataEnvelope
	_, err := asn1.Unmarshal(data, &envelope)
	if err != nil {
		return nil, err
	}

	if !signedDataIdentifier.Equal(envelope.Type) {
		return nil, fmt.Errorf("unexpected object identifier (was %s, expecting %s)", envelope.Type.String(), signedDataIdentifier.String())
	}

	if envelope.SignedData.Version != 1 {
		return nil, fmt.Errorf("unknown version number in signed data block (was %d, expecting 1)", envelope.SignedData.Version)
	}

	certs := make([]*x509.Certificate, len(envelope.SignedData.Certificates))
	for i, raw := range envelope.SignedData.Certificates {
		certs[i], err = x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, err
		}
	}

	return certs, nil
}
