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
	"os"

	"github.com/square/certigo/starttls/mysql"
	"github.com/square/certigo/starttls/psql"
)

func tlsConfigForConnect(connectName, connectCert, connectKey string) *tls.Config {
	conf := &tls.Config{
		// We verify later manually so we can print results
		InsecureSkipVerify: true,
		ServerName:         connectName,
	}

	if connectCert != "" {
		keyFile := connectCert
		if connectKey != "" {
			keyFile = connectKey
		}

		cert, err := tls.LoadX509KeyPair(connectCert, keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to read client certificate/key: %s\n", err)
			os.Exit(1)
		}

		conf.Certificates = []tls.Certificate{cert}
	}

	return conf
}

func GetConnectionState(connectStartTLS, connectName, connectTo, connectCert, connectKey string) *tls.ConnectionState {
	var state *tls.ConnectionState
	var err error

	switch connectStartTLS {
	case "":
		conn, err := tls.Dial("tcp", connectTo, tlsConfigForConnect(connectName, connectCert, connectKey))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error connecting: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()
		s := conn.ConnectionState()
		state = &s
	case "mysql":
		mysql.RegisterTLSConfig("certigo", tlsConfigForConnect(connectName, connectCert, connectKey))
		state, err = mysql.DumpTLS(fmt.Sprintf("certigo@tcp(%s)/?tls=certigo", connectTo))
	case "postgres", "psql":
		// Setting sslmode to "require" skips verification.
		url := fmt.Sprintf("postgres://certigo@%s/?sslmode=require", connectTo)
		if connectCert != "" {
			url += fmt.Sprintf("&sslcert=%s", connectCert)
		}
		if connectKey != "" {
			url += fmt.Sprintf("&sslkey=%s", connectCert)
		}
		state, err = pq.DumpTLS(url)
	default:
		fmt.Fprintf(os.Stderr, "error connecting: unknown StartTLS protocol '%s'\n", connectStartTLS)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting: %v\n", err)
		os.Exit(1)
	}

	return state
}
