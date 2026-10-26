FROM --platform=linux/amd64 debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential perl wget ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG OPENSSL_VERSION=3.6.2
RUN wget -q https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar xzf openssl-${OPENSSL_VERSION}.tar.gz && \
    cd openssl-${OPENSSL_VERSION} && \
    ./Configure linux-x86_64 --prefix=/opt/openssl --openssldir=/opt/openssl no-tests shared && \
    make -j$(nproc) && \
    make install_sw

ARG GOAHEAD_VERSION=v6.1.0
RUN git clone --depth 1 --branch ${GOAHEAD_VERSION} https://github.com/embedthis/goahead.git && \
    cd goahead && \
    sed -i \
        -e 's|#define ME_GOAHEAD_SSL_AUTHORITY ""|#define ME_GOAHEAD_SSL_AUTHORITY "/etc/goahead/certs/ca.crt"|' \
        -e 's|#define ME_GOAHEAD_SSL_CERTIFICATE "self.crt"|#define ME_GOAHEAD_SSL_CERTIFICATE "/etc/goahead/certs/server.crt"|' \
        -e 's|#define ME_GOAHEAD_SSL_KEY "self.key"|#define ME_GOAHEAD_SSL_KEY "/etc/goahead/certs/server.key"|' \
        -e 's|#define ME_GOAHEAD_SSL_REVOKE ""|#define ME_GOAHEAD_SSL_REVOKE "/etc/goahead/certs/crl.pem"|' \
        -e 's|#define ME_GOAHEAD_SSL_VERIFY_PEER 0|#define ME_GOAHEAD_SSL_VERIFY_PEER 1|' \
        -e 's|#define ME_GOAHEAD_SSL_VERIFY_ISSUER 0|#define ME_GOAHEAD_SSL_VERIFY_ISSUER 1|' \
        projects/goahead-linux-default-me.h && \
    sed -i 's|subject\[0\] = issuer\[0\] = .\\0.;|subject[0] = issuer[0] = '"'"'\\0'"'"';\n    trace(0, "VERIFY_CB: preverify_ok=%d error=%d(%s) depth=%d", ok, X509_STORE_CTX_get_error(xContext), X509_verify_cert_error_string(X509_STORE_CTX_get_error(xContext)), X509_STORE_CTX_get_error_depth(xContext));|' src/openssl.c && \
    make -f projects/goahead-linux-default.mk prep \
        ME_COM_OPENSSL=1 ME_COM_MBEDTLS=0 ME_COM_SSL=1 && \
    make -f projects/goahead-linux-default.mk \
        ME_COM_OPENSSL=1 \
        ME_COM_MBEDTLS=0 \
        ME_COM_SSL=1 \
        IFLAGS="-Ibuild/linux-x64-dev/inc -I/opt/openssl/include" \
        LDFLAGS="-g -rdynamic -Wl,--enable-new-dtags -Wl,-rpath,/opt/openssl/lib64 -L/opt/openssl/lib64" \
        -j$(nproc)

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/openssl/lib64/ /opt/openssl/lib64/
ENV LD_LIBRARY_PATH=/usr/local/bin

COPY --from=builder /build/goahead/build/linux-x64-dev/bin/ /usr/local/bin/
COPY --from=builder /build/goahead/src/auth.txt /etc/goahead/auth.txt
COPY --from=builder /build/goahead/src/route.txt /etc/goahead/route.txt

RUN mkdir -p /var/www/goahead && \
    echo 'MUTUAL-TLS-PROTECTED-CONTENT' > /var/www/goahead/index.html

COPY setup-certs.sh /setup-certs.sh
RUN chmod +x /setup-certs.sh

EXPOSE 443
CMD ["/setup-certs.sh"]
