# Find all non-vendor source files
SOURCE_FILES = $(shell find . \( -name '*.go' -not -path './vendor*' \)) 

certigo: $(SOURCE_FILES)
	go build .

depends: glide.lock
	glide -q install

test:
	go test -v `glide novendor`

check:
	go vet -v `glide novendor`
	!(gofmt -d $(SOURCE_FILES) | grep .)

install: depends
	go build -o $(GOPATH)/bin/certigo .

.PHONY : default depends test check
