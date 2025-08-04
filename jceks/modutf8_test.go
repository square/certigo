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
	"errors"
	"io"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestWriteModifiedUTF8(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		str      string
		expected []byte
	}{
		{
			name:     "Empty",
			str:      "",
			expected: nil,
		},
		{
			name:     "BasicASCII",
			str:      "Hi! \x01\x7f",
			expected: []byte{'H', 'i', '!', ' ', 0x01, 0x7f},
		},
		{
			name:     "NUL",
			str:      "NUL=\x00!",
			expected: []byte{'N', 'U', 'L', '=', 0b110_00000, 0b10_000000, '!'},
		},
		{
			name:     "2Char",
			str:      "\u0080\u07ff",
			expected: []byte{0b110_00010, 0b10_000000, 0b110_11111, 0b10_111111},
		},
		{
			name:     "3Char",
			str:      "\u0800\uffff",
			expected: []byte{0b1110_0000, 0b10_100000, 0b10_000000, 0b1110_1111, 0b10_111111, 0b10_111111},
		},
		{
			name: "Surrogate",
			str:  "🤔",
			//U+D83E U+DD14
			expected: []byte{0b1110_1101, 0b10_100000, 0b10_111110, 0b1110_1101, 0b10_110100, 0b10_010100},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			err := writeModifiedUTF8(&buf, tc.str)
			require.NoError(t, err)
			require.Equal(t, tc.expected, buf.Bytes())
		})
	}
}

func TestReadModifiedUTF8(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		data        []byte
		expected    string
		expectedErr error
	}{
		{
			name:     "Empty",
			data:     nil,
			expected: "",
		},
		{
			name:     "BasicASCII",
			data:     []byte{'H', 'i', '!', ' ', 0x01, 0x7f},
			expected: "Hi! \x01\x7f",
		},
		{
			name:     "NUL",
			data:     []byte{'N', 'U', 'L', '=', 0b110_00000, 0b10_000000, '!'},
			expected: "NUL=\x00!",
		},
		{
			name:     "2Char",
			data:     []byte{0b110_00010, 0b10_000000, 0b110_11111, 0b10_111111},
			expected: "\u0080\u07ff",
		},
		{
			name:     "3Char",
			data:     []byte{0b1110_0000, 0b10_100000, 0b10_000000, 0b1110_1111, 0b10_111111, 0b10_111111},
			expected: "\u0800\uffff",
		},
		{
			name:     "Surrogate",
			data:     []byte{0b1110_1101, 0b10_100000, 0b10_111110, 0b1110_1101, 0b10_110100, 0b10_010100},
			expected: "🤔",
		},
		{
			name:        "InvalidByte1",
			data:        []byte{0b10_000000},
			expectedErr: errInvalidModifiedUTF8,
		},
		{
			name:        "MissingByte2",
			data:        []byte{0b110_00010},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name:        "UnmodifiedUTF8",
			data:        []byte("🤔"),
			expectedErr: errInvalidModifiedUTF8,
		},
		{
			name:        "MissingByte3",
			data:        []byte{0b1110_0000, 0b10_100000},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name:        "MissingSurrogateByte1",
			data:        []byte{0b1110_1101, 0b10_100000, 0b10_111110},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name:        "MissingSurrogateByte2",
			data:        []byte{0b1110_1101, 0b10_100000, 0b10_111110, 0b1110_1101},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name:        "MissingSurrogateByte3",
			data:        []byte{0b1110_1101, 0b10_100000, 0b10_111110, 0b1110_1101, 0b10_110100},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name:        "InvalidSurrogateByte1",
			data:        []byte{0b1110_1101, 0b10_100000, 0b10_111110, 0b1110_0000, 0b10_100000, 0b10_000000},
			expectedErr: errInvalidModifiedUTF8,
		},
		{
			name:        "InvalidSurrogateByte2",
			data:        []byte{0b1110_1101, 0b10_100000, 0b10_111110, 0b1110_1101, 0b10_000000, 0b10_000000},
			expectedErr: errInvalidModifiedUTF8,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual, err := readModifiedUTF8(bytes.NewReader(tc.data))
			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func FuzzReadModifiedUTF8(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		str, err := readModifiedUTF8(bytes.NewReader(data))
		if err != nil {
			if errors.Is(err, errInvalidModifiedUTF8) || errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}
			require.NoError(t, err)
		}

		var buf bytes.Buffer
		err = writeModifiedUTF8(&buf, str)
		require.NoError(t, err)

		expected := data
		if len(expected) < 1 {
			expected = nil
		}
		require.Equal(t, expected, buf.Bytes())
	})
}

func FuzzWriteModifiedUTF8(f *testing.F) {
	f.Fuzz(func(t *testing.T, str string) {
		if !utf8.ValidString(str) {
			return
		}

		var buf bytes.Buffer

		err := writeModifiedUTF8(&buf, str)
		require.NoError(t, err)

		recovered, err := readModifiedUTF8(&buf)
		require.NoError(t, err)

		require.Equal(t, str, recovered)
	})
}
