FROM rust:1.88-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends git cmake clang libclang-dev pkg-config && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/hyperium/h3 /src \
    && cd /src && git checkout 43745ad87e95b0c035ac9c547aad467303213425
WORKDIR /src
RUN cargo build --release --example server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /certs \
    && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /certs/key.pem -out /certs/cert.pem -days 365 -nodes -subj /CN=localhost \
    && openssl x509 -in /certs/cert.pem -outform DER -out /certs/server.cert \
    && openssl pkcs8 -topk8 -nocrypt -in /certs/key.pem -outform DER -out /certs/server.key
COPY --from=build /src/target/release/examples/server /usr/local/bin/h3-server
EXPOSE 8088/udp
ENTRYPOINT ["h3-server", "--listen", "0.0.0.0:8088", "--cert", "/certs/server.cert", "--key", "/certs/server.key"]
