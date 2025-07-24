package starttls

import (
	"crypto/tls"
	"slices"
)

// cipherSuitesPreferenceOrder is copied from the crypto/tls package and defines Go's internal client preferences. This
// should be kept up to date with new Go versions, but if it drifts out of date, it only affects negotiation preferences
// and not whether a particular cipher suite is supported.
var cipherSuitesPreferenceOrder = []uint16{
	// AEADs w/ ECDHE
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

	// CBC w/ ECDHE
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

	// AEADs w/o ECDHE
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,

	// CBC w/o ECDHE
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,

	// 3DES
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,

	// CBC_SHA256
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,

	// RC4
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_RC4_128_SHA,
}

func allSupportedCipherSuiteIDs() []uint16 {
	secureSuites := tls.CipherSuites()
	insecureSuites := tls.InsecureCipherSuites()

	suites := make([]uint16, 0, len(secureSuites)+len(insecureSuites))
	for _, suitesCategory := range [][]*tls.CipherSuite{secureSuites, insecureSuites} {
		for _, suite := range suitesCategory {
			suites = append(suites, suite.ID)
		}
	}

	ordering := make(map[uint16]int)
	for i, id := range cipherSuitesPreferenceOrder {
		ordering[id] = i
	}

	slices.SortFunc(suites, func(s1, s2 uint16) int {
		idx1, prefer1 := ordering[s1]
		idx2, prefer2 := ordering[s2]
		if prefer1 != prefer2 {
			if prefer1 {
				return -1
			}

			return 1
		}
		if prefer1 {
			if idx1 < idx2 {
				return -1
			} else if idx1 > idx2 {
				return 1
			}
		}

		return 0 // Equal or both not in the preference list (equally bad)
	})

	return suites
}
