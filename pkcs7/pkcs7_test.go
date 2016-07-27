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

package pkcs7

import (
	"encoding/base64"
	"testing"
)

var testBlock, _ = base64.StdEncoding.DecodeString(`
MIICXAYJKoZIhvcNAQcCoIICTTCCAkkCAQExADALBgkqhkiG9w0BBwGgggIvMIIC
KzCCAZQCCQDHlr/u+lfb8jANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCQ0ExEDAOBgNVBAoTB2NlcnRpZ28xEDAOBgNVBAsTB2V4YW1wbGUx
GjAYBgNVBAMTEWV4YW1wbGUtc21hbGwta2V5MB4XDTE2MDYxMDIyMTQxMloXDTIz
MDQxNTIyMTQxMlowWjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQK
EwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRowGAYDVQQDExFleGFtcGxlLXNt
YWxsLWtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAlzyCIeP1T87k1rHV
MtbaGXIWpK/VQuvuXwig+e3ct1ajA4bw0BAInXZ37FEGGSCUix0k/CjH2NltGREt
wbahE0k5oTkVbA5XS4xkNs0M0poAFN5OiFKEAqZ014hqhvKnEUQ2oTe9SVORWw49
mLNg36AIEE2Fu2KQb/VT90cwwD0CAwEAATANBgkqhkiG9w0BAQsFAAOBgQBVsJ4V
b2L1ywLVeAxNqY0PZqS7a8Q2GLhNr5V+3hOoWn7bwqQ7L06UJGSrcLOPZeIHIWM2
0aOFHSTWbocd4f+m6s3llyXwBBlK2BPZbWv0OeAHgjN9AVav4flAZ4oD2GxAaJkG
AXmR9QzZNJLai5mv3L/B/p/NxeU3UGfaySxVv6EAMQA=`)

func TestExtract(t *testing.T) {
	certs, err := ExtractCertificates(testBlock)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 certs, but found %d", len(certs))
	}
}
