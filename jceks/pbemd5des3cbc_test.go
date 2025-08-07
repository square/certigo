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
	"bytes"
	"compress/flate"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestPBEWithMD5AndDES3CBCKeyPasswords(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		password string
		ok       bool
	}{
		{
			name:     "Minimal",
			password: " ",
			ok:       true,
		},
		{
			name:     "Typical",
			password: "CHANGE",
			ok:       true,
		},
		{
			name:     "Long",
			password: strings.Repeat("~", 4096),
			ok:       true,
		},
		{
			name:     "InvalidLow",
			password: "CHA\x1fNGE",
		},
		{
			name:     "InvalidHigh",
			password: "CHA\x7fNGE",
		},
		{
			name: "InvalidEmpty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rnd := sha3.NewShake128()
			c, err := PBEWithMD5AndDES3CBC([]byte(tc.password), rnd, 1)
			if !tc.ok {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidKeyProtectionParams)
				require.ErrorIs(t, err, ErrInvalidPassword)
				require.Nil(t, c)

				return
			}
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}

func TestPBEWithMD5AndDES3CBCKeyIterations(t *testing.T) {
	t.Parallel()

	rnd := sha3.NewShake128()

	_, err := PBEWithMD5AndDES3CBC([]byte("CHANGE"), rnd, 0)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidKeyProtectionParams)

	_, err = PBEWithMD5AndDES3CBC([]byte("CHANGE"), rnd, math.MaxInt)
	require.NoError(t, err)
}

func TestPBEWithMD5AndDES3CBCDeriveParams(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string

		password   []byte
		salt       []byte
		iterations uint

		key []byte
		iv  []byte
	}{
		{
			name:       "TypicalKeytool-21-0-4",
			password:   []byte("CHANGE"),
			salt:       []byte{0x50, 0x7c, 0xab, 0xc3, 0xb6, 0x10, 0xc3, 0x7d},
			iterations: 200000,
			key:        []byte{0x9b, 0x7e, 0x77, 0x61, 0x6a, 0x6f, 0xb9, 0x6d, 0x65, 0xbb, 0xdf, 0xef, 0x42, 0x41, 0x4c, 0x35, 0x35, 0x19, 0x1b, 0xa8, 0x43, 0x37, 0x84, 0xe8},
			iv:         []byte{0x3f, 0xc, 0x89, 0x8, 0xd8, 0xe2, 0x26, 0x46},
		},
		{
			name:       "EdgeCaseCharsKeytool-21-0-4",
			password:   []byte("hmm~ ~"),
			salt:       []byte{0xe9, 0xe0, 0x5b, 0xd6, 0x7, 0xbd, 0x13, 0xfb},
			iterations: 200000,
			key:        []byte{0x9e, 0x69, 0x8e, 0xe5, 0x55, 0x1, 0xac, 0xd6, 0xda, 0x10, 0x5e, 0xed, 0x9d, 0xe4, 0x66, 0x48, 0xd, 0xe1, 0x65, 0xc6, 0x6c, 0xbe, 0x84, 0xd0},
			iv:         []byte{0x9b, 0xe8, 0x86, 0xd, 0x54, 0x17, 0x7b, 0x63},
		},
		{
			name:       "MinIteration",
			password:   []byte("CHANGE"),
			salt:       []byte{0x73, 0xed, 0xf4, 0x2f, 0xc0, 0x40, 0xf6, 0x8a},
			iterations: 1,
			key:        []byte{0x4c, 0xfe, 0x6a, 0x95, 0xd5, 0xb0, 0xd, 0x88, 0xe6, 0xf0, 0xc2, 0xbc, 0x86, 0x61, 0x52, 0xb1, 0x8d, 0xb9, 0xc6, 0xca, 0xcd, 0xe2, 0x4a, 0xe4},
			iv:         []byte{0x6d, 0xb0, 0x6c, 0xcc, 0x8b, 0xba, 0x70, 0x93},
		},
		{
			name:       "EqualSaltHalves",
			password:   []byte("changeit"),
			salt:       []byte{0x0, 0x1, 0x2, 0x3, 0x0, 0x1, 0x2, 0x3},
			iterations: 20,
			key:        []byte{0x68, 0xaf, 0x50, 0x65, 0x62, 0xef, 0x3e, 0x43, 0x70, 0x6, 0x0, 0x96, 0x7f, 0x98, 0x66, 0x98, 0xde, 0xde, 0xea, 0xdc, 0x55, 0x77, 0xcf, 0xae},
			iv:         []byte{0xa2, 0xd8, 0x77, 0x92, 0x1b, 0x55, 0xc3, 0xa7},
		},
		{
			name:       "InsecureSalt",
			password:   []byte("changeit"),
			salt:       []byte{0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7},
			iterations: 20,
			key:        []byte{0x32, 0x64, 0x13, 0xd1, 0x33, 0xbe, 0x9a, 0xb5, 0x85, 0xc1, 0x49, 0xbb, 0x93, 0x9c, 0x59, 0x53, 0x32, 0x64, 0x13, 0xd1, 0x33, 0xbe, 0x9a, 0xb5},
			iv:         []byte{0x85, 0xc1, 0x49, 0xbb, 0x93, 0x9c, 0x59, 0x53},
		},
		{
			name:       "CertigoExamplePrivateKey",
			password:   []byte("private-key-key-password"),
			salt:       []byte{0xba, 0x48, 0x13, 0x87, 0x94, 0x39, 0x5a, 0x3a},
			iterations: 20,
			key:        []byte{0x2, 0xc9, 0xdb, 0xbb, 0xfe, 0xc2, 0x53, 0xe8, 0x98, 0xb8, 0xb8, 0x60, 0x60, 0x65, 0x55, 0x5b, 0x33, 0x6a, 0xc6, 0x18, 0x6b, 0x22, 0xe4, 0xdb},
			iv:         []byte{0xad, 0xd5, 0x14, 0x4, 0x19, 0xc9, 0x26, 0x38},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key, iv := derivePBEWithMD5AndDES3CBCParams(tc.password, tc.salt, tc.iterations)
			require.Equal(t, tc.key, key)
			require.Equal(t, tc.iv, iv)
		})
	}
}

func TestPBEWithMD5AndDES3CBCEncryptPrivateKey(t *testing.T) {
	t.Parallel()

	rnd := sha3.NewShake128()

	// Hard-code an arbitrary key so that we don't waste time generating a key just for an unrelated test
	rsaPriv, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaPriv)

	c, err := PBEWithMD5AndDES3CBC([]byte("CHANGE"), rnd, 20)
	require.NoError(t, err)
	require.NotNil(t, c)

	encrypted, err := c.encryptPrivateKey(privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PrivateKey: pkcs1,
	})
	require.NoError(t, err)

	// Sanity check: if ciphertext is encrypted, it should be indistinguishable from random to a compression algorithm
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write(encrypted.EncryptedKey)
	require.NoError(t, err)
	err = w.Close()
	require.NoError(t, err)
	compressionFraction := float64(buf.Len()) / float64(len(pkcs1))
	require.Greater(t, compressionFraction, 0.99)
}

func TestPBEWithMD5AndDES3CBCPrivateKeyRoundTrip(t *testing.T) {
	t.Parallel()

	rnd := sha3.NewShake128()

	const password = "p@55w0rD"

	c, err := PBEWithMD5AndDES3CBC([]byte(password), rnd, 20)
	require.NoError(t, err)
	require.NotNil(t, c)

	privKey := privateKeyInfo{
		Version:    42,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 3, 7}},
		PrivateKey: []byte("Squeamish Ossifrage"),
	}
	expected := privateKeyInfo{
		Version:    privKey.Version,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: slices.Clone(privKey.Algo.Algorithm)},
		PrivateKey: bytes.Clone(privKey.PrivateKey),
	}

	protectedKeyInfo, err := c.encryptPrivateKey(privKey)
	require.NoError(t, err)

	decrypted, err := recoverPBEWithMD5AndDES3CBC(protectedKeyInfo, []byte(password))
	require.NoError(t, err)
	require.Equal(t, expected, decrypted)
}

func FuzzPBEWithMD5AndDES3CBCRecover(f *testing.F) {
	rnd := sha3.NewShake128()
	rsaPriv, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(f, err)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaPriv)
	c, err := PBEWithMD5AndDES3CBC([]byte("CHANGE"), rnd, 20)
	require.NoError(f, err)
	require.NotNil(f, c)
	encrypted, err := c.encryptPrivateKey(privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PrivateKey: pkcs1,
	})
	require.NoError(f, err)
	data, err := asn1.Marshal(encrypted)
	require.NoError(f, err)

	f.Add(data, []byte("CHANGE"))

	f.Fuzz(func(t *testing.T, data []byte, password []byte) {
		var protectedKeyInfo encryptedPrivateKeyInfo
		if _, err := asn1.Unmarshal(data, &protectedKeyInfo); err != nil {
			return
		}

		_, _ = recoverPBEWithMD5AndDES3CBC(protectedKeyInfo, password)
	})
}
