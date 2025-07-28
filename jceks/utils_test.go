// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jceks

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// LoadPEMKey extracts a private key from a PEM file.
func LoadPEMKey(filename string) (*rsa.PrivateKey, error) {
	keyPEMBlock, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key from %q: %w", filename, err)
	}

	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			return nil, fmt.Errorf("failed to parse key PEM data")
		}
		if keyDERBlock.Type == "PRIVATE KEY" ||
			strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}

	key, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %s", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS8 private key is not RSA")
	}

	return rsaKey, nil
}

// LoadPEMCert extracts a certificate from a PEM file.
func LoadPEMCert(filename string) (*x509.Certificate, error) {
	certPEMBlock, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key from %q: %w", filename, err)
	}

	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			return nil, fmt.Errorf("failed to parse certificate PEM data")
		}
		if certDERBlock.Type == "CERTIFICATE" {
			break
		}
	}

	return x509.ParseCertificate(certDERBlock.Bytes)
}
