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

package jceks

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

var (
	generateTestData = flag.Bool("generate", false, "generate test data")
)

type testData struct {
	certFilename  string
	keyFilename   string
	p12Filename   string
	jceksFilename string
	storePassword string
	keyPassword   string
	alias         string
}

func newTestData(prefix string) *testData {
	return &testData{
		certFilename:  "testdata/" + prefix + ".crt",
		keyFilename:   "testdata/" + prefix + ".key",
		p12Filename:   "testdata/" + prefix + ".p12",
		jceksFilename: "testdata/" + prefix + ".jceks",
		storePassword: prefix + "-store-password",
		keyPassword:   prefix + "-key-password",
		alias:         prefix + "-some-alias",
	}
}

func (d *testData) cleanup() {
	os.Remove(d.certFilename)
	os.Remove(d.keyFilename)
	os.Remove(d.p12Filename)
	os.Remove(d.jceksFilename)
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.Bytes()
	if err != nil {
		return "", errors.New(string(out))
	}
	return string(out), nil
}

func (d *testData) generatePrivateKeyAndCert(t *testing.T) {
	_, err := runCommand("openssl", "req", "-x509",
		"-nodes", "-days", "365", "-newkey", "rsa:2048",
		"-subj", "/CN=Test User/O=Test Organization/C=US",
		"-extensions", "v3_req",
		"-keyout", d.keyFilename,
		"-out", d.certFilename)
	if err != nil {
		t.Fatal(err)
	}
}

func (d *testData) convertPrivateKeyAndCertToPkcs12(t *testing.T) {
	_, err := runCommand("openssl", "pkcs12", "-export",
		"-in", d.certFilename,
		"-inkey", d.keyFilename,
		"-name", d.alias,
		"-out", d.p12Filename,
		"-passout", fmt.Sprintf("pass:%s", d.storePassword))
	if err != nil {
		t.Fatal(err)
	}
}

func (d *testData) convertPkcs12ToJceks(t *testing.T) {
	_, err := runCommand("keytool", "-importkeystore",
		"-alias", d.alias,
		"-destkeypass", d.keyPassword,
		"-destkeystore", d.jceksFilename,
		"-deststorepass", d.storePassword,
		"-srckeystore", d.p12Filename,
		"-srcstoretype", "PKCS12",
		"-srcstorepass", d.storePassword,
		"-storetype", "JCEKS")
	if err != nil {
		t.Fatal(err)
	}
}

func (d *testData) importCertToJceks(t *testing.T) {
	_, err := runCommand("keytool", "-importcert", "-noprompt",
		"-alias", d.alias,
		"-file", d.certFilename,
		"-keystore", d.jceksFilename,
		"-storepass", d.storePassword,
		"-storetype", "JCEKS")
	if err != nil {
		t.Fatal(err)
	}
}

func equalRSAPublicKey(a, b *rsa.PublicKey) bool {
	if a.E != b.E {
		return false
	}
	return a.N.Cmp(b.N) == 0
}

func equalRSAPrivateKey(a, b *rsa.PrivateKey) bool {
	if !equalRSAPublicKey(&a.PublicKey, &b.PublicKey) {
		return false
	}
	if a.D.Cmp(b.D) != 0 {
		return false
	}
	if len(a.Primes) != len(b.Primes) {
		return false
	}
	for i := 0; i < len(a.Primes); i++ {
		if a.Primes[i].Cmp(b.Primes[i]) != 0 {
			return false
		}
	}
	return true
}

func TestPrivateKey(t *testing.T) {
	d := newTestData("private-key")
	if *generateTestData {
		d.cleanup()
		d.generatePrivateKeyAndCert(t)
		d.convertPrivateKeyAndCertToPkcs12(t)
		d.convertPkcs12ToJceks(t)
	}

	ks, err := Load(d.jceksFilename, []byte(d.storePassword))
	if err != nil {
		t.Fatal(err)
	}
	key, certs, err := ks.GetPrivateKeyAndCerts(d.alias, []byte(d.keyPassword))
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("unable to load key")
	}

	expected, err := LoadPEMKey(d.keyFilename)
	if err != nil {
		t.Fatal(err)
	}
	if !equalRSAPrivateKey(key, expected) {
		t.Fatalf("keys are not equal")
	}

	if len(certs) != 1 {
		t.Fatalf("unexpected number of certs: %d != 1", len(certs))
	}

	expectedCert, err := LoadPEMCert(d.certFilename)
	if err != nil {
		t.Fatal(err)
	}

	if !certs[0].Equal(expectedCert) {
		t.Fatalf("certs are not equal")
	}

	keyAliases := ks.ListPrivateKeys()
	if !reflect.DeepEqual(keyAliases, []string{d.alias}) {
		t.Fatalf("unexpected private key aliases: %s", keyAliases)
	}
}

func TestTrustedCert(t *testing.T) {
	d := newTestData("trusted-cert")
	if *generateTestData {
		d.cleanup()
		d.generatePrivateKeyAndCert(t)
		d.importCertToJceks(t)
	}

	ks, err := Load(d.jceksFilename, []byte(d.storePassword))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ks.GetCert(d.alias)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Fatal("unable to load cert")
	}

	expectedCert, err := LoadPEMCert(d.certFilename)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.Equal(expectedCert) {
		t.Fatalf("certs are not equal")
	}

	certAliases := ks.ListCerts()
	if !reflect.DeepEqual(certAliases, []string{d.alias}) {
		t.Fatalf("unexpected cert aliases: %s", certAliases)
	}
}
