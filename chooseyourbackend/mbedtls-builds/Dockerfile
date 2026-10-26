FROM --platform=linux/amd64 debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential wget ca-certificates git cmake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG MBEDTLS_VERSION=3.6.6
RUN wget -q https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2 && \
    tar xjf mbedtls-${MBEDTLS_VERSION}.tar.bz2 && \
    cd mbedtls-${MBEDTLS_VERSION} && \
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=ON && \
    cmake --build build -j$(nproc) && \
    cmake --install build && \
    ldconfig

RUN git clone --depth 1 --branch v6.1.0 https://github.com/embedthis/goahead.git && \
    cd goahead && \
    sed -i \
        -e 's|#define ME_COM_MBEDTLS 0|#define ME_COM_MBEDTLS 1|' \
        -e 's|#define ME_COM_OPENSSL 1|#define ME_COM_OPENSSL 0|' \
        -e 's|#define ME_GOAHEAD_SSL_CERTIFICATE "self.crt"|#define ME_GOAHEAD_SSL_CERTIFICATE "/etc/goahead/certs/server.crt"|' \
        -e 's|#define ME_GOAHEAD_SSL_KEY "self.key"|#define ME_GOAHEAD_SSL_KEY "/etc/goahead/certs/server.key"|' \
        projects/goahead-linux-default-me.h && \
    make -f projects/goahead-linux-default.mk prep \
        ME_COM_MBEDTLS=1 ME_COM_OPENSSL=0 ME_COM_SSL=1 && \
    make -f projects/goahead-linux-default.mk \
        ME_COM_MBEDTLS=1 \
        ME_COM_OPENSSL=0 \
        ME_COM_SSL=1 \
        IFLAGS="-Ibuild/linux-x64-dev/inc -I/usr/local/include" \
        -j$(nproc)

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/libmbed* /usr/local/lib/
COPY --from=builder /build/goahead/build/linux-x64-dev/bin/ /usr/local/bin/
RUN ldconfig

COPY --from=builder /build/goahead/src/auth.txt /etc/goahead/auth.txt
COPY --from=builder /build/goahead/src/route.txt /etc/goahead/route.txt

RUN mkdir -p /var/www/goahead && \
    echo 'MUTUAL-TLS-PROTECTED-CONTENT' > /var/www/goahead/index.html

COPY setup-certs.sh /setup-certs.sh
RUN chmod +x /setup-certs.sh

EXPOSE 443
CMD ["/setup-certs.sh"]
