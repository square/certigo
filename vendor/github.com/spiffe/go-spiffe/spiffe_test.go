package spiffe

import (
	"io/ioutil"
	"testing"
)

func getCertificateFromFile(t *testing.T, certFilePath string) string {
	certificateString, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		t.Fatal(err)
	}

	return string(certificateString)
}

func TestGetURINamesFromPEM(t *testing.T) {
	certPEM := getCertificateFromFile(t, "testdata/leaf.cert.pem")

	var golden = "spiffe://dev.acme.com/path/service"

	uris, err := GetURINamesFromPEM(string(certPEM))
	if err != nil {
		t.Error(err)
	}

	if len(uris) == 1 {
		if uris[0] != golden {
			t.Fatalf("Expected '%v' but got '%v'", golden, uris[0])
		}
	} else {
		t.Fatalf("Expected 1 URI but got '%v'", len(uris))
	}

	certPEM = getCertificateFromFile(t, "testdata/intermediate.cert.pem")
	uris, err = GetURINamesFromPEM(string(certPEM))
	if err == nil {
		t.Fatal("Expected to fail")
	}

	if len(uris) > 0 {
		t.Fatalf("Expected to have no URIs but got %v URIs", len(uris))
	}
}
