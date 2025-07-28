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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKCS5PadUnpad(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in       []byte
		expected []byte
	}{
		{in: []byte{}, expected: []byte{8, 8, 8, 8, 8, 8, 8, 8}},
		{in: []byte{42}, expected: []byte{42, 7, 7, 7, 7, 7, 7, 7}},
		{in: []byte{42, 42}, expected: []byte{42, 42, 6, 6, 6, 6, 6, 6}},
		{in: []byte{42, 42, 42}, expected: []byte{42, 42, 42, 5, 5, 5, 5, 5}},
		{in: []byte{42, 42, 42, 42}, expected: []byte{42, 42, 42, 42, 4, 4, 4, 4}},
		{in: []byte{42, 42, 42, 42, 42}, expected: []byte{42, 42, 42, 42, 42, 3, 3, 3}},
		{in: []byte{42, 42, 42, 42, 42, 42}, expected: []byte{42, 42, 42, 42, 42, 42, 2, 2}},
		{in: []byte{42, 42, 42, 42, 42, 42, 42}, expected: []byte{42, 42, 42, 42, 42, 42, 42, 1}},
		{in: []byte{42, 42, 42, 42, 42, 42, 42, 42}, expected: []byte{42, 42, 42, 42, 42, 42, 42, 42, 8, 8, 8, 8, 8, 8, 8, 8}},
		{in: []byte{0}, expected: []byte{0, 7, 7, 7, 7, 7, 7, 7}},
		{in: []byte{1, 2, 3, 4, 5}, expected: []byte{1, 2, 3, 4, 5, 3, 3, 3}},
		{in: []byte{3, 3, 3, 3, 3}, expected: []byte{3, 3, 3, 3, 3, 3, 3, 3}},
	} {
		t.Run(fmt.Sprintf("In-%X", tc.in), func(t *testing.T) {
			t.Parallel()

			actual := pkcs5Pad(tc.in)
			require.Equal(t, tc.expected, actual)

			unpadded, err := pkcs5Unpad(actual)
			require.NoError(t, err)
			require.Equal(t, tc.in, unpadded)
		})
	}
}

func TestPKCS5UnpadFailures(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{name: "Empty", in: nil},
		{name: "TooShort", in: []byte{1, 2, 3, 4, 5, 6, 7}},
		{name: "PadExceedsBlockSize", in: []byte{9, 9, 9, 9, 9, 9, 9, 9, 9}},
		{name: "InvalidPadding", in: []byte{42, 7, 7, 7, 6, 7, 7, 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := pkcs5Unpad(tc.in)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidCiphertext)
		})
	}
}
