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
	"crypto/sha1"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	flag.Parse()
	m.Run()
}

func TestEncodeIntegrityPassword(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		password  string
		expected  []byte
		expectErr bool
	}{
		{
			name:     "BasicASCII",
			password: "Hi!",
			expected: []byte{0, 'H', 0, 'i', 0, '!'},
		},
		{
			name:     "BasicMultilingual",
			password: `¯\_(ツ)_/¯`,
			expected: []byte{0, 0xaf, 0, '\\', 0, '_', 0, '(', 0x30, 0xc4, 0, ')', 0, '_', 0, '/', 0, 0xaf},
		},
		{
			name:      "ErrTooShort",
			expectErr: true,
		},
		{
			name:      "ErrOutOfRange",
			password:  "\U00010000",
			expectErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual, err := encodeIntegrityPassword(tc.password)
			if tc.expectErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidPassword)

				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestMakeIntegrityHash(t *testing.T) {
	t.Parallel()

	h := makeIntegrityHash([]byte("changeit"))
	actual := h.Sum(nil)

	expected := sha1.Sum([]byte("changeit" + jceksIntegrityMagic))

	require.Equal(t, expected[:], actual)
}

func FuzzLoadFromReader(f *testing.F) {
	for filename, password := range map[string]string{
		"private-key.jceks":                    "store-password",
		"trusted-cert.jceks":                   "store-password",
		"encoder-private-store.jceks":          "changeit",
		"encoder-cert-store.jceks":             "changeit",
		"encoder-re-encode-private-key.jceks":  "changeit",
		"encoder-re-encode-trusted-cert.jceks": "changeit",
	} {
		data, err := os.ReadFile(filepath.Join("testdata", filename))
		require.NoError(f, err)
		f.Add(data, []byte(password))
	}

	f.Fuzz(func(t *testing.T, data []byte, password []byte) {
		var ks KeyStore
		err := ks.ParseWithOptions(bytes.NewReader(data), password,
			WithMaxCertificateBytes(20*1024), WithMaxPrivateKeyBytes(20*1024))
		if err != nil {
			for _, mightBe := range []error{
				ErrInvalidPassword,
				ErrInvalidJCEKSData,
				ErrUnsupportedJCEKSData,
				ErrIntegrityProtectionViolation,
			} {
				if errors.Is(err, mightBe) {
					return
				}
			}
			t.Fatal(err)
		}
	})
}
