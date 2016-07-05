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

Dump an example certificate (example-leaf.crt)

  $ certigo dump example-small-key.crt
  ** CERTIFICATE 1 **
  Serial: 14381893493177441266
  Not Before: 2016-06-10 22:14:12 +0000 UTC
  Not After : 2023-04-15 22:14:12 +0000 UTC
  Signature : SHA256-RSA (self-signed)
  Subject Info:
  \tCommonName: example-small-key (esc)
  \tOrganization: [certigo] (esc)
  \tOrganizationalUnit: [example] (esc)
  \tCountry: [US] (esc)
  Issuer Info:
  \tCommonName: example-small-key (esc)
  \tOrganization: [certigo] (esc)
  \tOrganizationalUnit: [example] (esc)
  \tCountry: [US] (esc)
  Warnings:
  \tCertificate is not in X509v3 format (version is 2) (esc)
  \tSize of RSA key should be at least 2048 bits (esc)
  
