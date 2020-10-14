package starttls

import (
	"crypto/tls"
	"database/sql"
	"net"

	mssql "github.com/denisenkom/go-mssqldb"
)

func mssqlDumpTLS(connectionString string, tlsConfig *tls.Config) (*tls.ConnectionState, error) {
	var tlsConn *tls.Conn

	connector, err := mssql.NewConnector(connectionString)
	if err != nil {
		return nil, err
	}

	connector.NewTLSConn = func(conn net.Conn, config *tls.Config) *tls.Conn {
		// NB we must copy the tls config settings required for the tls
		//    connection to work over the mssql tds connection.
		//    see https://github.com/denisenkom/go-mssqldb/blob/0f454e2ecd6ad8fb4691cdbf10e399e05ca03784/tds.go#L928-L933
		tlsConfig.DynamicRecordSizingDisabled = config.DynamicRecordSizingDisabled

		tlsConn = tls.Client(conn, tlsConfig)

		return tlsConn
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	// NB this is expected to fail with "invalid login" class of errors,
	//    so if we have a tlsConn, we ignore any error.
	err = db.Ping()
	if tlsConn == nil && err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()

	return &state, nil
}
