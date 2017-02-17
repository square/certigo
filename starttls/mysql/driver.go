// Copyright 2012 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

// Package mysql provides a MySQL driver for Go's database/sql package
//
// The driver should be used via the database/sql package:
//
//  import "database/sql"
//  import _ "github.com/go-sql-driver/mysql"
//
//  db, err := sql.Open("mysql", "user:password@/dbname")
//
// See https://github.com/go-sql-driver/mysql#usage for details
package mysql

import (
	"crypto/tls"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
)

// MySQLDriver is exported to make the driver directly accessible.
// In general the driver is used via the database/sql package.
type MySQLDriver struct{}

// DialFunc is a function which can be used to establish the network connection.
// Custom dial functions must be registered with RegisterDial
type DialFunc func(addr string) (net.Conn, error)

var dials map[string]DialFunc

// RegisterDial registers a custom dial function. It can then be used by the
// network address mynet(addr), where mynet is the registered new network.
// addr is passed as a parameter to the dial function.
func RegisterDial(net string, dial DialFunc) {
	if dials == nil {
		dials = make(map[string]DialFunc)
	}
	dials[net] = dial
}

// Open new Connection.
// See https://github.com/go-sql-driver/mysql#dsn-data-source-name for how
// the DSN string is formated
func (d MySQLDriver) Open(dsn string) (driver.Conn, error) {
	var err error

	// New mysqlConn
	mc := &mysqlConn{
		maxAllowedPacket: maxPacketSize,
		maxWriteSize:     maxPacketSize - 1,
	}
	mc.cfg, err = ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	mc.parseTime = mc.cfg.ParseTime
	mc.strict = mc.cfg.Strict

	// Connect to Server
	if dial, ok := dials[mc.cfg.Net]; ok {
		mc.netConn, err = dial(mc.cfg.Addr)
	} else {
		nd := net.Dialer{Timeout: mc.cfg.Timeout}
		mc.netConn, err = nd.Dial(mc.cfg.Net, mc.cfg.Addr)
	}
	if err != nil {
		return nil, err
	}

	// Enable TCP Keepalives on TCP connections
	if tc, ok := mc.netConn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlive(true); err != nil {
			// Don't send COM_QUIT before handshake.
			mc.netConn.Close()
			mc.netConn = nil
			return nil, err
		}
	}

	mc.buf = newBuffer(mc.netConn)

	// Set I/O timeouts
	mc.buf.timeout = mc.cfg.ReadTimeout
	mc.writeTimeout = mc.cfg.WriteTimeout

	// Reading Handshake Initialization Packet
	cipher, err := mc.readInitPacket()
	if err != nil {
		mc.cleanup()
		return nil, err
	}

	// Send Client Authentication Packet
	if err = mc.writeAuthPacket(cipher); err != nil {
		mc.cleanup()
		return nil, err
	}

	// Handle response to auth packet, switch methods if possible
	if err = handleAuthResult(mc, cipher); err != nil {
		// Authentication failed and MySQL has already closed the connection
		// (https://dev.mysql.com/doc/internals/en/authentication-fails.html).
		// Do not send COM_QUIT, just cleanup and return the error.
		mc.cleanup()
		return nil, err
	}

	if mc.cfg.MaxAllowedPacket > 0 {
		mc.maxAllowedPacket = mc.cfg.MaxAllowedPacket
	} else {
		// Get max allowed packet size
		maxap, err := mc.getSystemVar("max_allowed_packet")
		if err != nil {
			mc.Close()
			return nil, err
		}
		mc.maxAllowedPacket = stringToInt(maxap) - 1
	}
	if mc.maxAllowedPacket < maxPacketSize {
		mc.maxWriteSize = mc.maxAllowedPacket
	}

	// Handle DSN Params
	err = mc.handleParams()
	if err != nil {
		mc.Close()
		return nil, err
	}

	return mc, nil
}

// DumpTLS returns a TLS context from a connection to the server. This was was
// added for use by Certigo in order to make it possible to dump TLS certificates
// from a MySQL server for debugging.
func DumpTLS(dsn string) (*tls.ConnectionState, error) {
	var err error

	// New mysqlConn
	mc := &mysqlConn{
		maxAllowedPacket: maxPacketSize,
		maxWriteSize:     maxPacketSize - 1,
	}
	mc.cfg, err = ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	mc.parseTime = mc.cfg.ParseTime
	mc.strict = mc.cfg.Strict

	if mc.cfg.tls == nil {
		return nil, errors.New("certigo/mysql error: TLS must be enabled to dump TLS data")
	}

	// Connect to Server
	if dial, ok := dials[mc.cfg.Net]; ok {
		mc.netConn, err = dial(mc.cfg.Addr)
	} else {
		nd := net.Dialer{Timeout: mc.cfg.Timeout}
		mc.netConn, err = nd.Dial(mc.cfg.Net, mc.cfg.Addr)
	}
	if err != nil {
		return nil, err
	}

	mc.buf = newBuffer(mc.netConn)

	// Set I/O timeouts
	mc.buf.timeout = mc.cfg.ReadTimeout
	mc.writeTimeout = mc.cfg.WriteTimeout

	// Reading Handshake Initialization Packet
	_, err = mc.readInitPacket()
	if err != nil {
		mc.cleanup()
		return nil, err
	}

	// Send Client Authentication Packet
	// Adjust client flags based on server support
	clientFlags := clientProtocol41 |
		clientSecureConn |
		clientLongPassword |
		clientTransactions |
		clientLocalFiles |
		clientPluginAuth |
		clientMultiResults |
		clientSSL |
		mc.flags&clientLongFlag

	if mc.cfg.ClientFoundRows {
		clientFlags |= clientFoundRows
	}

	if mc.cfg.MultiStatements {
		clientFlags |= clientMultiStatements
	}

	pktLen := 4 + 4 + 1 + 23

	// Calculate packet length and get buffer with that size
	data := mc.buf.takeSmallBuffer(pktLen + 4)
	if data == nil {
		// can not take the buffer. Something must be wrong with the connection
		return nil, driver.ErrBadConn
	}

	// ClientFlags [32 bit]
	data[4] = byte(clientFlags)
	data[5] = byte(clientFlags >> 8)
	data[6] = byte(clientFlags >> 16)
	data[7] = byte(clientFlags >> 24)

	// MaxPacketSize [32 bit] (none)
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x00

	// Charset [1 byte]
	var found bool
	data[12], found = collations[mc.cfg.Collation]
	if !found {
		// Note possibility for false negatives:
		// could be triggered  although the collation is valid if the
		// collations map does not contain entries the server supports.
		return nil, errors.New("mysql: unknown collation")
	}

	// SSL Connection Request Packet
	// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest

	// Send TLS / SSL request packet
	if err := mc.writePacket(data[:pktLen+4]); err != nil {
		return nil, fmt.Errorf("mysql: %s", err)
	}

	// Switch to TLS
	tlsConn := tls.Client(mc.netConn, mc.cfg.tls)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("mysql: %s", err)
	}

	state := tlsConn.ConnectionState()
	mc.netConn = tlsConn
	mc.buf.nc = tlsConn
	mc.cleanup()

	return &state, nil
}

func handleAuthResult(mc *mysqlConn, oldCipher []byte) error {
	// Read Result Packet
	cipher, err := mc.readResultOK()
	if err == nil {
		return nil // auth successful
	}

	if mc.cfg == nil {
		return err // auth failed and retry not possible
	}

	// Retry auth if configured to do so.
	if mc.cfg.AllowOldPasswords && err == ErrOldPassword {
		// Retry with old authentication method. Note: there are edge cases
		// where this should work but doesn't; this is currently "wontfix":
		// https://github.com/go-sql-driver/mysql/issues/184

		// If CLIENT_PLUGIN_AUTH capability is not supported, no new cipher is
		// sent and we have to keep using the cipher sent in the init packet.
		if cipher == nil {
			cipher = oldCipher
		}

		if err = mc.writeOldAuthPacket(cipher); err != nil {
			return err
		}
		_, err = mc.readResultOK()
	} else if mc.cfg.AllowCleartextPasswords && err == ErrCleartextPassword {
		// Retry with clear text password for
		// http://dev.mysql.com/doc/refman/5.7/en/cleartext-authentication-plugin.html
		// http://dev.mysql.com/doc/refman/5.7/en/pam-authentication-plugin.html
		if err = mc.writeClearAuthPacket(); err != nil {
			return err
		}
		_, err = mc.readResultOK()
	} else if mc.cfg.AllowNativePasswords && err == ErrNativePassword {
		if err = mc.writeNativeAuthPacket(cipher); err != nil {
			return err
		}
		_, err = mc.readResultOK()
	}
	return err
}
