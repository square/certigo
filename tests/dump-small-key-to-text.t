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

  $ certigo --verbose dump example-small-key.crt
  ** CERTIFICATE 1 **
  Input Format: PEM
  Serial: 14381893493177441266
  Valid: 2016-06-10 22:14 UTC to 2023-04-15 22:14 UTC
  Signature: SHA256-RSA (self-signed)
  Subject Info:
  \tCountry: US (esc)
  \tProvince: CA (esc)
  \tOrganization: certigo (esc)
  \tOrganizational Unit: example (esc)
  \tCommonName: example-small-key (esc)
  Issuer Info:
  \tCountry: US (esc)
  \tProvince: CA (esc)
  \tOrganization: certigo (esc)
  \tOrganizational Unit: example (esc)
  \tCommonName: example-small-key (esc)
  Warnings:
  \t[CABF_BR] Certificates MUST be of type X.590 v3 (esc)
  \t[CABF_BR] For certificates valid after 31 Dec 2013, all certificates using RSA public key algorithm MUST have 2048 bits of modulus (esc)
  \t[CABF_BR] Subscriber Certificate: authorityInformationAccess MUST be present. (esc)
  \t[CABF_BR] Subscriber Certificate: authorityInformationAccess MUST contain the HTTP URL of the Issuing CA's OSCP responder. (esc)
  \t[CABF_BR] Subscriber Certificate: certificatePolicies MUST be present and SHOULD NOT be marked critical. (esc)
  \t[CABF_BR] Subscriber certificates MUST contain the Subject Alternate Name extension (esc)
  \t[CABF_BR] Subscriber certificates MUST have the extended key usage extension present (esc)
  \t[CABF_BR] Subscriber certificates must contain at least one policy identifier that indicates adherence to CAB standards (esc)
  \t[CABF_BR] The common name field in subscriber certificates must include only names from the SAN extension (esc)
  \t[RFC5280] Sub certificates SHOULD include Subject Key Identifier in end entity certs (esc)
  