package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sync/atomic"

	"github.com/quic-go/quic-go/http3"
)

var (
	requests, headers atomic.Uint64
	held              []http.Header
)

func main() {
	addr := os.Getenv("SERVER_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		total := headers.Add(uint64(len(r.Header)))
		held = append(held, r.Header)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Printf("request=%d headers=%d total_headers=%d alloc=%dMB\n",
			n, len(r.Header), total, m.Alloc>>20)
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	})
	srv := &http3.Server{Addr: addr, Handler: mux, TLSConfig: &tls.Config{}}
	if err := srv.ListenAndServeTLS(os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
