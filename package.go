package ezovpn

import (
	"io"
	"os"
)

// CertFetcher abstracts certificate access.
type CertFetcher = func(string) (io.ReadCloser, error)

// defaultFetcher promotes os.Open as CertFetcher
var DefaultCertFetcher CertFetcher = func(path string) (io.ReadCloser, error) { return os.Open(path) }
