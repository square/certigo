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
	"flag"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var keytoolTests = flag.Bool("jceks.keytool-tests", false, "run Keytool integration tests")

// TestIntegrationKeytoolPackageRead tests that a JCEKS file written by keytool can be read by this package.
func TestIntegrationKeytoolPackageRead(t *testing.T) {
	t.Parallel()

	if !*keytoolTests {
		t.Skip("keytool integration tests are not enabled")
	}

	p12Filename := filepath.Join(os.TempDir(), "jceks-test-"+strconv.FormatUint(rand.Uint64(), 16)+".p12")
	jceksFilename := filepath.Join(os.TempDir(), "jceks-test-"+strconv.FormatUint(rand.Uint64(), 16)+".jceks")
	defer func() {
		_ = os.Remove(p12Filename)
		_ = os.Remove(jceksFilename)
	}()

	// Generate a JCEKS file by using openssl to make a PKCS#12 file and then converting it to JCEKS with keytool

	err := exec.Command("openssl", "pkcs12",
		"-export",
		"-in", "testdata/private-key.crt",
		"-inkey", "testdata/private-key.key",
		"-certfile", "testdata/private-key-ca.crt",
		"-name", "test-private-key",
		"-passout", "pass:store-password",
		"-out", p12Filename,
	).Run()
	require.NoError(t, err)

	err = exec.Command("keytool", "-importkeystore",
		"-alias", "test-private-key",
		"-srckeystore", p12Filename,
		"-srcstoretype", "PKCS12",
		"-srcstorepass", "store-password",
		"-destkeystore", jceksFilename,
		"-storetype", "JCEKS",
		"-deststorepass", "store-password",
		"-destkeypass", "key-password",
	).Run()
	require.NoError(t, err)

	err = exec.Command("keytool", "-importcert",
		"-noprompt",
		"-alias", "test-trusted-cert",
		"-file", "testdata/trusted-cert.crt",
		"-destkeystore", jceksFilename,
		"-storetype", "JCEKS",
		"-deststorepass", "store-password",
	).Run()
	require.NoError(t, err)

	// Now load the JCEKS file with the package and make sure that the entries match the source material

	ks, err := LoadFromFile(jceksFilename, []byte("store-password"))
	require.NoError(t, err)

	privKey, certs, err := ks.GetPrivateKeyAndCerts("test-private-key", []byte("key-password"))
	require.NoError(t, err)
	require.NotNil(t, privKey)
	require.IsType(t, &rsa.PrivateKey{}, privKey)
	rsaKey := privKey.(*rsa.PrivateKey)

	expectedRSAKey, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	require.Equal(t, expectedRSAKey, rsaKey)
	require.True(t, rsaKey.Equal(expectedRSAKey))

	expectedLeafCert, err := LoadPEMCert("testdata/private-key.crt")
	require.NoError(t, err)
	expectedCACert, err := LoadPEMCert("testdata/private-key-ca.crt")
	require.NoError(t, err)

	require.Len(t, certs, 2)
	require.True(t, certs[0].Equal(expectedLeafCert))
	require.True(t, certs[1].Equal(expectedCACert))

	keyAliases := ks.ListPrivateKeys()
	require.Equal(t, []string{"test-private-key"}, keyAliases)

	cert, err := ks.GetCert("test-trusted-cert")
	require.NoError(t, err)

	expectedCert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	require.True(t, cert.Equal(expectedCert))

	certAliases := ks.ListCerts()
	require.Equal(t, []string{"test-trusted-cert"}, certAliases)
}

// TestIntegrationKeytoolPackageWrite tests that a JCEKS file written by this package can be read by keytool.
func TestIntegrationKeytoolPackageWrite(t *testing.T) {
	t.Parallel()

	if !*keytoolTests {
		t.Skip("keytool integration tests are not enabled")
	}

	rnd := sha3.NewShake128()
	now := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)

	p12Filename := filepath.Join(os.TempDir(), "jceks-test-"+strconv.FormatUint(rand.Uint64(), 16)+".p12")
	jceksFilename := filepath.Join(os.TempDir(), "jceks-test-"+strconv.FormatUint(rand.Uint64(), 16)+".jceks")
	pemFilename := filepath.Join(os.TempDir(), "jceks-test-"+strconv.FormatUint(rand.Uint64(), 16)+".pem")
	defer func() {
		_ = os.Remove(p12Filename)
		_ = os.Remove(jceksFilename)
		_ = os.Remove(pemFilename)
	}()

	// Create a JCEKS file from source material using this package

	rsaKey, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	leafCert, err := LoadPEMCert("testdata/private-key.crt")
	require.NoError(t, err)
	caCert, err := LoadPEMCert("testdata/private-key-ca.crt")
	require.NoError(t, err)
	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder

	err = enc.SetIntegrityPassword("store-password")
	require.NoError(t, err)

	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	cipher, err := PBEWithMD5AndDES3CBC([]byte("key-password"), rnd, 20)
	require.NoError(t, err)
	err = enc.AddPrivateKeyPKCS1("test-private-key", now, pkcs1, [][]byte{leafCert.Raw, caCert.Raw}, cipher)
	require.NoError(t, err)

	err = enc.AddTrustedCertificate("test-trusted-cert", now, cert.Raw)
	require.NoError(t, err)

	f, err := os.Create(jceksFilename)
	require.NoError(t, err)
	defer func() {
		_ = f.Close()
	}()
	_, err = enc.WriteTo(f)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)

	// Now convert the JCEKS file to PKCS#12 with keytool, and then use openssl to extract the certs and keys into PEM

	err = exec.Command("keytool", "-importkeystore",
		"-srckeystore", jceksFilename,
		"-srcstoretype", "JCEKS",
		"-srcstorepass", "store-password",
		"-destkeystore", p12Filename,
		"-storetype", "PKCS12",
		"-deststorepass", "store-password",
		"-alias", "test-private-key",
		"-srckeypass", "key-password",
		"-destkeypass", "store-password",
	).Run()
	require.NoError(t, err)

	err = exec.Command("keytool", "-importkeystore",
		"-srckeystore", jceksFilename,
		"-srcstoretype", "JCEKS",
		"-srcstorepass", "store-password",
		"-destkeystore", p12Filename,
		"-storetype", "PKCS12",
		"-deststorepass", "store-password",
		"-alias", "test-trusted-cert",
	).Run()
	require.NoError(t, err)

	err = exec.Command("openssl", "pkcs12",
		"-in", p12Filename,
		"-out", pemFilename,
		"-nodes",
		"-passin", "pass:store-password",
		"-legacy",
	).Run()
	require.NoError(t, err)

	// Finally, verify that the material that ended up in the PEM matches the source material

	pemData, err := os.ReadFile(pemFilename)
	require.NoError(t, err)

	var certsDER [][]byte
	var keysDER [][]byte
	for {
		var pemBlock *pem.Block
		pemBlock, pemData = pem.Decode(pemData)
		if pemBlock == nil {
			break
		}
		switch pemBlock.Type {
		case "CERTIFICATE":
			certsDER = append(certsDER, pemBlock.Bytes)
		case "PRIVATE KEY":
			keysDER = append(keysDER, pemBlock.Bytes)
		}
	}

	require.ElementsMatch(t, certsDER, [][]byte{leafCert.Raw, caCert.Raw, cert.Raw})

	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	require.ElementsMatch(t, keysDER, [][]byte{pkcs8})
}
