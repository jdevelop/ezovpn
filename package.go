package ezovpn

import (
	"io"
	"os"
	"strings"
)

// CertFetcher abstracts certificate access.
type CertFetcher = func(string) (io.ReadCloser, error)

// defaultFetcher promotes os.Open as CertFetcher
var (
	DefaultCertFetcher CertFetcher = func(path string) (io.ReadCloser, error) { return os.Open(path) }
	crlf                           = []byte("\n")
)

func formatBase64(src string) string {
	const lineLimit = 76
	var (
		w strings.Builder
		i int
	)
	for i < len(src) {
		end := i + lineLimit
		if end > len(src) {
			end = len(src)
		}
		w.Write([]byte(src[i:end]))
		w.Write(crlf)
		i += lineLimit
	}
	return w.String()
}
