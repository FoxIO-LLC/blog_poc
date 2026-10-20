FROM golang:1.27.1-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o /server .
RUN mkdir -p /certs \
    && openssl req -x509 -newkey rsa:2048 -keyout /certs/server.key -out /certs/server.crt \
       -days 365 -nodes -subj /CN=localhost

FROM gcr.io/distroless/base-debian12
COPY --from=build /server /server
COPY --from=build /certs /app/certs
ENV SERVER_ADDR=:8081 \
    TLS_CERT_FILE=/app/certs/server.crt \
    TLS_KEY_FILE=/app/certs/server.key
EXPOSE 8081/udp
ENTRYPOINT ["/server"]
