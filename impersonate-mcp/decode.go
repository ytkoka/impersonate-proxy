package main

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// zstdMaxMemory bounds the decoder's window so a hostile frame can't make it
// allocate without limit.
const zstdMaxMemory = 64 << 20

// decodeBody undoes the response's Content-Encoding. fetch_url sends browser
// style Accept-Encoding headers (gzip, deflate, br, zstd), and Go only decodes
// by itself when it chose the header, so decoding is done here. The returned
// closer must be called when reading is done. decoded is false when the body
// was already plain, including when Go's transport had decoded it.
func decodeBody(resp *http.Response) (r io.Reader, closer func(), decoded bool, err error) {
	closer = func() {}
	var encodings []string
	for _, v := range resp.Header.Values("Content-Encoding") {
		for _, e := range strings.Split(v, ",") {
			if e = strings.ToLower(strings.TrimSpace(e)); e != "" && e != "identity" {
				encodings = append(encodings, e)
			}
		}
	}
	r = resp.Body
	// Encodings are listed in the order applied, so undo them last to first.
	for i := len(encodings) - 1; i >= 0; i-- {
		switch encodings[i] {
		case "gzip", "x-gzip":
			gz, err := gzip.NewReader(r)
			if err != nil {
				return nil, closer, false, fmt.Errorf("decoding gzip body: %w", err)
			}
			r = gz
		case "deflate":
			br := bufio.NewReader(r)
			head, _ := br.Peek(2)
			if len(head) == 2 && head[0]&0x0f == 8 && (uint(head[0])<<8|uint(head[1]))%31 == 0 {
				zr, err := zlib.NewReader(br) // the format HTTP means by "deflate"
				if err != nil {
					return nil, closer, false, fmt.Errorf("decoding deflate body: %w", err)
				}
				r = zr
			} else {
				r = flate.NewReader(br) // some servers send a bare deflate stream
			}
		case "br":
			r = brotli.NewReader(r)
		case "zstd":
			zd, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(zstdMaxMemory))
			if err != nil {
				return nil, closer, false, fmt.Errorf("decoding zstd body: %w", err)
			}
			prev := closer
			closer = func() { zd.Close(); prev() }
			r = zd
		default:
			return nil, closer, false, fmt.Errorf("unsupported Content-Encoding %q", encodings[i])
		}
	}
	return r, closer, len(encodings) > 0, nil
}
