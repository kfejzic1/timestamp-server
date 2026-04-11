FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download || true
COPY *.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -o /signer .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /signer /usr/local/bin/signer
RUN mkdir -p /data

EXPOSE 8081
CMD ["signer"]
