.PHONY: ctlogs

lib/ctlogs.go:
	go run github.com/square/certigo/internal/gen-known-logs --package lib > lib/ctlogs.go
	go fmt lib/ctlogs.go

ctlogs: lib/ctlogs.go
