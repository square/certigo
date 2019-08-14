FROM golang:alpine AS builder

COPY . /src
WORKDIR /src
ENV CGO_ENABLED=0
RUN go build -mod=vendor -o /bin/certigo
RUN go vet -mod=vendor ./...
RUN go test -mod=vendor ./...

FROM python
RUN pip install cram

COPY --from=builder /bin/certigo /bin/certigo

COPY tests /tests
RUN cram -v /tests/*.t

FROM alpine
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
COPY --from=builder /bin/certigo /bin/certigo
ENTRYPOINT ["/bin/certigo"]
