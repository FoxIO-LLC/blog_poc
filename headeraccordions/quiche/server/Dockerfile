FROM rust:1.88-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang libclang-dev perl && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 0.29.2 https://github.com/cloudflare/quiche /src
WORKDIR /src
RUN cargo build --release --bin quiche-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /certs \
    && openssl req -x509 -newkey rsa:2048 -keyout /certs/cert.key -out /certs/cert.crt \
       -days 365 -nodes -subj /CN=localhost
COPY --from=build /src/target/release/quiche-server /usr/local/bin/quiche-server
EXPOSE 4433/udp
ENTRYPOINT ["quiche-server", "--listen", "0.0.0.0:4433", "--cert", "/certs/cert.crt", "--key", "/certs/cert.key", "--no-retry", "--max-field-section-size", "1048576"]
