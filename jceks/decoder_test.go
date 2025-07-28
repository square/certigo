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
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:generate testdata/generate-jceks.sh private-key
//go:generate testdata/generate-jceks.sh trusted-cert

func TestPrivateKey(t *testing.T) {
	ks, err := LoadFromFile("testdata/private-key.jceks", []byte("store-password"))
	require.NoError(t, err)
	key, certs, err := ks.GetPrivateKeyAndCerts("private-key-some-alias", []byte("key-password"))
	require.NoError(t, err)
	require.NotNil(t, key)
	require.IsType(t, &rsa.PrivateKey{}, key)
	rsaKey := key.(*rsa.PrivateKey)

	expected, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	require.Equal(t, expected, rsaKey)
	require.True(t, rsaKey.Equal(expected))

	expectedLeafCert, err := LoadPEMCert("testdata/private-key.crt")
	require.NoError(t, err)
	expectedCACert, err := LoadPEMCert("testdata/private-key-ca.crt")
	require.NoError(t, err)

	require.Len(t, certs, 2)
	require.True(t, certs[0].Equal(expectedLeafCert))
	require.True(t, certs[1].Equal(expectedCACert))

	keyAliases := ks.ListPrivateKeys()
	require.Equal(t, []string{"private-key-some-alias"}, keyAliases)
}

func TestTrustedCert(t *testing.T) {
	ks, err := LoadFromFile("testdata/trusted-cert.jceks", []byte("store-password"))
	require.NoError(t, err)
	cert, err := ks.GetCert("trusted-cert-some-alias")
	require.NoError(t, err)
	require.NotNil(t, cert)

	expectedCert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	require.True(t, cert.Equal(expectedCert))

	certAliases := ks.ListCerts()
	require.Equal(t, []string{"trusted-cert-some-alias"}, certAliases)
}

func TestLoadFromReader(t *testing.T) {
	f, err := os.Open("testdata/trusted-cert.jceks")
	require.NoError(t, err)

	ks, err := LoadFromReader(f, []byte("store-password"))
	require.NoError(t, err)
	cert, err := ks.GetCert("trusted-cert-some-alias")
	require.NoError(t, err)
	require.NotNil(t, cert)

	err = f.Close()
	require.NoError(t, err)
}

func TestParseWithEmpty(t *testing.T) {
	f, err := os.Open("testdata/trusted-cert.jceks")
	require.NoError(t, err)

	var ks KeyStore
	err = ks.Parse(f, []byte("store-password"))
	require.NoError(t, err)
	cert, err := ks.GetCert("trusted-cert-some-alias")
	require.NoError(t, err)
	require.NotNil(t, cert)

	err = f.Close()
	require.NoError(t, err)
}

func TestEmptyKeyStoreReadyToUse(t *testing.T) {
	var ks KeyStore

	certs := ks.ListCerts()
	require.Empty(t, certs)

	keys := ks.ListPrivateKeys()
	require.Empty(t, keys)

	cert, err := ks.GetCert("non-existent")
	require.NoError(t, err)
	require.Nil(t, cert)

	sk, keyCerts, err := ks.GetPrivateKeyAndCerts("non-existent", []byte("password"))
	require.NoError(t, err)
	require.Nil(t, sk)
	require.Empty(t, keyCerts)
}
