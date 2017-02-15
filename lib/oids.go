package lib

import "encoding/asn1"

// OidDescription returns a human-readable name, a snake_case slug suitable as a json key,
// and a boolean describing whether multiple copies can appear on an X509 cert.
type OidDescription struct {
	Name     string
	Slug     string
	Multiple bool
}

func describeOid(oid asn1.ObjectIdentifier) OidDescription {
	raw := oid.String()
	// Multiple should be true for any types that are []string in x509.pkix.Name. When in doubt, set it to true.
	names := map[string]OidDescription{
		"2.5.4.3":                  {"CommonName", "common_name", false},
		"2.5.4.5":                  {"EV Incorporation Registration Number", "ev_registration_number", false},
		"2.5.4.6":                  {"Country", "country", true},
		"2.5.4.7":                  {"Locality", "locality", true},
		"2.5.4.8":                  {"Province", "province", true},
		"2.5.4.10":                 {"Organization", "organization", true},
		"2.5.4.11":                 {"Organizational Unit", "organizational_unit", true},
		"2.5.4.15":                 {"Business Category", "business_category", true},
		"1.2.840.113549.1.9.1":     {"Email Address", "email_address", true},
		"1.3.6.1.4.1.311.60.2.1.1": {"EV Incorporation Locality", "ev_locality", true},
		"1.3.6.1.4.1.311.60.2.1.2": {"EV Incorporation Province", "ev_province", true},
		"1.3.6.1.4.1.311.60.2.1.3": {"EV Incorporation Country", "ev_country", true},
	}
	if description, ok := names[raw]; ok {
		return description
	}
	return OidDescription{raw, raw, true}
}
