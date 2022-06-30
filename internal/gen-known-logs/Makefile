.PHONY: ctlogs

ctlogs:
	go run github.com/square/certigo/internal/gen-known-logs --package lib > ../../lib/ctlogs.go
	go fmt ../../lib/ctlogs.go
