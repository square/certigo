/*-
 * Copyright 2017 Square Inc.
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

package starttls

import (
	"crypto/tls"
	"fmt"
	"net/smtp"

	"github.com/square/certigo/starttls/ldap"
	"github.com/square/certigo/starttls/mysql"
	"github.com/square/certigo/starttls/psql"
)

func tlsConfigForConnect(connectName, clientCert, clientKey string) (*tls.Config, error) {
	conf := &tls.Config{
		// We verify later manually so we can print results
		InsecureSkipVerify: true,
		ServerName:         connectName,
		MinVersion:         tls.VersionSSL30,
	}

	if clientCert != "" {
		keyFile := clientCert
		if clientKey != "" {
			keyFile = clientKey
		}

		cert, err := tls.LoadX509KeyPair(clientCert, keyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read client certificate/key: %s\n", err)
		}

		conf.Certificates = []tls.Certificate{cert}
	}

	return conf, nil
}

// GetConnectionState connects to a TLS server, returning the connection state.
// Currently, startTLSType can be one of "mysql", "postgres" or "psql", or the empty string, which does a normal TLS
// connection.  connectTo specifies the address to connect to. connectName sets SNI.  connectCert and connectKey are
// client certs
func GetConnectionState(startTLSType, connectName, connectTo, clientCert, clientKey string) (*tls.ConnectionState, error) {
	var state *tls.ConnectionState
	var err error
	var tlsConfig *tls.Config

	switch startTLSType {
	case "postgres", "psql":
		// No tlsConfig needed for postgres, but all others do.
	default:
		tlsConfig, err = tlsConfigForConnect(connectName, clientCert, clientKey)
		if err != nil {
			return nil, err
		}
	}

	switch startTLSType {
	case "":
		conn, err := tls.Dial("tcp", connectTo, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("error connecting: %v\n", err)
		}
		defer conn.Close()
		s := conn.ConnectionState()
		state = &s
	case "ldap":
		l, err := ldap.Dial("tcp", connectTo)
		if err != nil {
			return nil, err
		}
		defer l.Close()

		err = l.StartTLS(tlsConfig)
		if err != nil {
			return nil, err
		}
		state, err = l.TLSConnectionState()
		if err != nil {
			panic(fmt.Sprintf("LDAP Connection isn't TLS after we successfully called StartTLS (%s)", err.Error()))
		}
	case "mysql":
		mysql.RegisterTLSConfig("certigo", tlsConfig)
		state, err = mysql.DumpTLS(fmt.Sprintf("certigo@tcp(%s)/?tls=certigo", connectTo))
	case "postgres", "psql":
		// Setting sslmode to "require" skips verification.
		url := fmt.Sprintf("postgres://certigo@%s/?sslmode=require", connectTo)
		if clientCert != "" {
			url += fmt.Sprintf("&sslcert=%s", clientCert)
		}
		if clientKey != "" {
			url += fmt.Sprintf("&sslkey=%s", clientCert)
		}
		state, err = pq.DumpTLS(url)
	case "smtp":
		client, err := smtp.Dial(connectTo)
		if err != nil {
			return nil, err
		}
		err = client.StartTLS(tlsConfig)
		if err != nil {
			return nil, err
		}
		smtpState, ok := client.TLSConnectionState()
		if !ok {
			panic("SMTP Connection isn't TLS after we successfully called StartTLS")
		}
		state = &smtpState
	default:
		return nil, fmt.Errorf("error connecting: unknown StartTLS protocol '%s'\n", startTLSType)
	}

	if err != nil {
		return nil, fmt.Errorf("error connecting: %v\n", err)
	}

	return state, nil
}
