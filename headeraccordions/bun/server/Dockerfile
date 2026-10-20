FROM oven/bun:1.4.3
WORKDIR /app
RUN mkdir -p /certs \
    && apt-get update && apt-get install -y openssl \
    && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
         -keyout /certs/key.pem -out /certs/cert.pem \
         -days 365 -nodes -subj /CN=localhost \
    && apt-get remove -y openssl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY server.ts .
EXPOSE 443/tcp 443/udp
CMD ["bun", "run", "server.ts"]
