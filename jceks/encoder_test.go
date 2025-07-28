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
	"crypto/x509"
	"errors"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var writeReencoded = flag.Bool("jceks.write-reencoded", false, "write expected re-encoded JCEKS files")

func TestMain(m *testing.M) {
	flag.Parse()
	m.Run()
}

type discardErrWriter struct {
	err           error
	writeAfterErr int
}

func (dew *discardErrWriter) Write(p []byte) (int, error) {
	if dew.err != nil {
		dew.writeAfterErr++
		return 1, dew.err
	}

	return len(p), nil
}

func TestCounterWriter(t *testing.T) {
	t.Parallel()

	var dew discardErrWriter

	cw := &counterWriter{w: &dew}

	nn, err := cw.Write([]byte("Hello "))
	require.NoError(t, err)
	require.Equal(t, 6, nn)

	nn, err = cw.Write([]byte("World"))
	require.NoError(t, err)
	require.Equal(t, 5, nn)

	expectErr := errors.New("expected error")
	dew.err = expectErr

	nn, err = cw.Write([]byte("discarded"))
	require.NoError(t, err)
	require.Equal(t, 9, nn)

	nn, err = cw.Write([]byte("more"))
	require.NoError(t, err)
	require.Equal(t, 4, nn)

	n, err := cw.Results()
	require.Equal(t, expectErr, err)
	require.Equal(t, int64(6+5+1), n)
	require.Equal(t, 1, dew.writeAfterErr)
}

func TestJCEKSDigester(t *testing.T) {
	t.Parallel()

	jd := newJCEKSDigester([]byte("CHANGE"))
	_, err := jd.Write([]byte("Hello, "))
	require.NoError(t, err)
	_, err = jd.Write([]byte("World!"))
	require.NoError(t, err)

	var buf bytes.Buffer
	err = jd.WriteDigest(&buf)
	require.NoError(t, err)

	expected := sha1.Sum([]byte("CHANGEMighty AphroditeHello, World!"))

	require.Equal(t, expected[:], buf.Bytes())
}

func TestSetIntegrityPassword(t *testing.T) {
	t.Parallel()

	var enc Encoder
	require.False(t, enc.setIntegrityPassword)

	err := enc.SetIntegrityPassword("")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPassword)
	require.False(t, enc.setIntegrityPassword)

	err = enc.SetIntegrityPassword("123456")
	require.NoError(t, err)
	require.True(t, enc.setIntegrityPassword)
	require.Equal(t, []byte{0, '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6'}, enc.integrityPassword)
}

func TestEncodePrivateKeyStore(t *testing.T) {
	t.Parallel()

	rnd := sha3.NewShake128()
	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	rsaPriv, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaPriv)

	leafCert, err := LoadPEMCert("testdata/private-key.crt")
	require.NoError(t, err)
	caCert, err := LoadPEMCert("testdata/private-key-ca.crt")
	require.NoError(t, err)

	var enc Encoder

	cipher, err := PBEWithMD5AndDES3CBC([]byte("changeit"), rnd, 20)
	require.NoError(t, err)
	err = enc.AddPrivateKeyPKCS1("example.test", now, pkcs1, [][]byte{leafCert.Raw, caCert.Raw}, cipher)
	require.NoError(t, err)

	err = enc.SetIntegrityPassword("changeit")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	if *writeReencoded {
		err = os.WriteFile("testdata/encoder-private-store.jceks", buf.Bytes(), 0666)
		require.NoError(t, err)
	}

	expected, err := os.ReadFile("testdata/encoder-private-store.jceks")
	require.NoError(t, err)
	require.Equal(t, expected, buf.Bytes())
}

func TestEncodeTrustedCertificateStore(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder

	err = enc.AddTrustedCertificate("ca1", now, cert.Raw)
	require.NoError(t, err)

	err = enc.SetIntegrityPassword("changeit")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	if *writeReencoded {
		err = os.WriteFile("testdata/encoder-cert-store.jceks", buf.Bytes(), 0666)
		require.NoError(t, err)
	}

	expected, err := os.ReadFile("testdata/encoder-cert-store.jceks")
	require.NoError(t, err)
	require.Equal(t, expected, buf.Bytes())
}

func TestEncodeExistingPrivateKeyStore(t *testing.T) {
	t.Parallel()

	ks, err := LoadFromFile("testdata/private-key.jceks", []byte("store-password"))
	require.NoError(t, err)

	var enc Encoder
	err = enc.AddKeyStore(ks)
	require.NoError(t, err)
	err = enc.SetIntegrityPassword("changeit")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	if *writeReencoded {
		err = os.WriteFile("testdata/encoder-re-encode-private-key.jceks", buf.Bytes(), 0666)
		require.NoError(t, err)
	}

	expected, err := os.ReadFile("testdata/encoder-re-encode-private-key.jceks")
	require.NoError(t, err)
	require.Equal(t, expected, buf.Bytes())
}

func TestEncodeExistingTrustedCertificateStore(t *testing.T) {
	t.Parallel()

	ks, err := LoadFromFile("testdata/trusted-cert.jceks", []byte("store-password"))
	require.NoError(t, err)

	var enc Encoder
	err = enc.AddKeyStore(ks)
	require.NoError(t, err)
	err = enc.SetIntegrityPassword("changeit")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	if *writeReencoded {
		err = os.WriteFile("testdata/encoder-re-encode-trusted-cert.jceks", buf.Bytes(), 0666)
		require.NoError(t, err)
	}

	expected, err := os.ReadFile("testdata/encoder-re-encode-trusted-cert.jceks")
	require.NoError(t, err)
	require.Equal(t, expected, buf.Bytes())
}

func TestEncodeDuplicateAliases(t *testing.T) {
	t.Parallel()

	rnd := sha3.NewShake128()
	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	rsaPriv, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaPriv)

	privCert, err := LoadPEMCert("testdata/private-key.crt")
	require.NoError(t, err)

	otherCert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder

	cipher, err := PBEWithMD5AndDES3CBC([]byte("confusion"), rnd, 20)
	require.NoError(t, err)

	// Write private key entry as "foo" and cert as "bar"
	err = enc.AddPrivateKeyPKCS1("foo", now, pkcs1, [][]byte{privCert.Raw}, cipher)
	require.NoError(t, err)
	err = enc.AddTrustedCertificate("bar", now, otherCert.Raw)
	require.NoError(t, err)

	// Now write them again with opposite aliases, which should overwrite the previous ones
	err = enc.AddPrivateKeyPKCS1("bar", now, pkcs1, [][]byte{privCert.Raw}, cipher)
	require.NoError(t, err)
	err = enc.AddTrustedCertificate("foo", now, otherCert.Raw)
	require.NoError(t, err)

	err = enc.SetIntegrityPassword("confusion")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	reloaded, err := LoadFromReader(&buf, []byte("confusion"))
	require.NoError(t, err)

	require.Equal(t, []string{"foo"}, reloaded.ListCerts())
	require.Equal(t, []string{"bar"}, reloaded.ListPrivateKeys())
}

func TestProhibitDuplicateAliases(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder

	enc.SetProhibitDuplicateAliases(true)

	err = enc.AddTrustedCertificate("alias", now, cert.Raw)
	require.NoError(t, err)

	err = enc.AddTrustedCertificate("alias", now, cert.Raw)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDuplicateAlias)
}
