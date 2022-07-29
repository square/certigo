Set up test data.

  $ cat > example-small-key.crt <<EOF
  > -----BEGIN CERTIFICATE-----
  > MIICKzCCAZQCCQDHlr/u+lfb8jANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJV
  > UzELMAkGA1UECBMCQ0ExEDAOBgNVBAoTB2NlcnRpZ28xEDAOBgNVBAsTB2V4YW1w
  > bGUxGjAYBgNVBAMTEWV4YW1wbGUtc21hbGwta2V5MB4XDTE2MDYxMDIyMTQxMloX
  > DTIzMDQxNTIyMTQxMlowWjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYD
  > VQQKEwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRowGAYDVQQDExFleGFtcGxl
  > LXNtYWxsLWtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAlzyCIeP1T87k
  > 1rHVMtbaGXIWpK/VQuvuXwig+e3ct1ajA4bw0BAInXZ37FEGGSCUix0k/CjH2Nlt
  > GREtwbahE0k5oTkVbA5XS4xkNs0M0poAFN5OiFKEAqZ014hqhvKnEUQ2oTe9SVOR
  > Ww49mLNg36AIEE2Fu2KQb/VT90cwwD0CAwEAATANBgkqhkiG9w0BAQsFAAOBgQBV
  > sJ4Vb2L1ywLVeAxNqY0PZqS7a8Q2GLhNr5V+3hOoWn7bwqQ7L06UJGSrcLOPZeIH
  > IWM20aOFHSTWbocd4f+m6s3llyXwBBlK2BPZbWv0OeAHgjN9AVav4flAZ4oD2GxA
  > aJkGAXmR9QzZNJLai5mv3L/B/p/NxeU3UGfaySxVvw==
  > -----END CERTIFICATE-----
  > EOF

Dump an example certificate (example-leaf.crt) to JSON output

  $ certigo dump --json example-small-key.crt
  {"certificates":[{"serial":"14381893493177441266","not_before":"2016-06-10T22:14:12Z","not_after":"2023-04-15T22:14:12Z","signature_algorithm":"SHA256-RSA","is_self_signed":true,"subject":{"common_name":"example-small-key","country":["US"],"organization":["certigo"],"organizational_unit":["example"],"province":["CA"]},"issuer":{"common_name":"example-small-key","country":["US"],"organization":["certigo"],"organizational_unit":["example"],"province":["CA"]},"lints":["[RFC5280] Sub certificates SHOULD include Subject Key Identifier in end entity certs"],"pem":"-----BEGIN CERTIFICATE-----\nMIICKzCCAZQCCQDHlr/u+lfb8jANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJV\nUzELMAkGA1UECBMCQ0ExEDAOBgNVBAoTB2NlcnRpZ28xEDAOBgNVBAsTB2V4YW1w\nbGUxGjAYBgNVBAMTEWV4YW1wbGUtc21hbGwta2V5MB4XDTE2MDYxMDIyMTQxMloX\nDTIzMDQxNTIyMTQxMlowWjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYD\nVQQKEwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRowGAYDVQQDExFleGFtcGxl\nLXNtYWxsLWtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAlzyCIeP1T87k\n1rHVMtbaGXIWpK/VQuvuXwig+e3ct1ajA4bw0BAInXZ37FEGGSCUix0k/CjH2Nlt\nGREtwbahE0k5oTkVbA5XS4xkNs0M0poAFN5OiFKEAqZ014hqhvKnEUQ2oTe9SVOR\nWw49mLNg36AIEE2Fu2KQb/VT90cwwD0CAwEAATANBgkqhkiG9w0BAQsFAAOBgQBV\nsJ4Vb2L1ywLVeAxNqY0PZqS7a8Q2GLhNr5V+3hOoWn7bwqQ7L06UJGSrcLOPZeIH\nIWM20aOFHSTWbocd4f+m6s3llyXwBBlK2BPZbWv0OeAHgjN9AVav4flAZ4oD2GxA\naJkGAXmR9QzZNJLai5mv3L/B/p/NxeU3UGfaySxVvw==\n-----END CERTIFICATE-----\n"}]}
