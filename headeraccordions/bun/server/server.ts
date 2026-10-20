import { readFileSync } from "fs";

Bun.serve({
  port: 443,
  tls: {
    cert: readFileSync("/certs/cert.pem"),
    key: readFileSync("/certs/key.pem"),
  },
  http3: true,
  fetch(req) {
    const hdrs = req.headers;
    let count = 0;
    for (const _ of hdrs) count++;
    return new Response(`ok headers=${count}\n`);
  },
});

console.log("Bun HTTP/3 server listening on :443");
