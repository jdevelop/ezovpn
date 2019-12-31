package ezovpn

import (
	"bufio"
	"encoding/base64"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	caOpen    = "<ca>\n"
	caClose   = "</ca>\n"
	certOpen  = "<cert>\n"
	certClose = "</cert>\n"
	keyOpen   = "<key>\n"
	keyClose  = "</key>\n"
	taOpen    = "<tls-auth>\n"
	taClose   = "</tls-auth>\n"
	taKey     = "key-direction 1\n"
	pkcsOpen  = "<pkcs12>\n"
	pkcsClose = "</pkcs12>\n"
)

const (
	fileIdx = 7
)

var (
	filesMatcher = regexp.MustCompile(`^\s*((ca)|(cert)|(key)|(tls-auth)|(pkcs12))\s+?(\S+)`)
)

func resolvePath(prefix, path string, cf CertFetcher) (io.ReadCloser, error) {
	var r io.ReadCloser
	if filepath.IsAbs(path) {
		f, err := cf(path)
		if err != nil {
			return nil, err
		}
		r = f
	} else {
		f, err := cf(filepath.Join(prefix, path))
		if err != nil {
			return nil, err
		}
		r = f
	}
	return r, nil
}

// readFileIn detects if the path to a certificate, defined in VPN config - is absolute or relative.
//
// Reads the file and wraps it's content into the corresponding tags.
func readFileIn(prefix, path string, w io.Writer, tagOpen, tagClose string, contentFetch CertFetcher) error {
	r, err := resolvePath(prefix, path, contentFetch)
	if err != nil {
		return err
	}
	defer r.Close()
	if _, err := w.Write([]byte(tagOpen)); err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		return err
	}
	if _, err := w.Write([]byte(tagClose)); err != nil {
		return err
	}
	return nil
}

// ImportVPNConfig imports the configuration from the file, using pathPrefix to resolve paths to certificates, if they are not absolute.
//
// 	pathPrefix    prefix to the path for resolving relative certificate paths.
// 	rdr           read the original VPN config from.
// 	w             write the resulting VPN config into.
// 	contentFetch  reads the certificate content.
func ImportVPNConfig(pathPrefix string, rdr io.Reader, w io.Writer, contentFetch CertFetcher) error {
	var (
		s  strings.Builder
		br = bufio.NewReader(rdr)
	)
	readLine := func() (string, error) {
		s.Reset()
		for {
			b, prefix, err := br.ReadLine()
			switch err {
			case io.EOF:
				s.Write(b)
				return s.String(), err
			case nil:
				s.Write(b)
			default:
				return "", err
			}
			if !prefix {
				break
			}
		}
		return s.String(), nil
	}
	stop := false
loop:
	for !stop {
		l, err := readLine()
		switch err {
		case nil:
		case io.EOF:
			stop = true
			if l == "" {
				break loop
			}
		default:
			return err
		}
		if grps := filesMatcher.FindStringSubmatch(l); grps != nil {
			filename := grps[fileIdx]
			switch grps[1] {
			case "ca":
				readFileIn(pathPrefix, filename, w, caOpen, caClose, contentFetch)
			case "cert":
				readFileIn(pathPrefix, filename, w, certOpen, certClose, contentFetch)
			case "key":
				readFileIn(pathPrefix, filename, w, keyOpen, keyClose, contentFetch)
			case "tls-auth":
				w.Write([]byte(taKey))
				readFileIn(pathPrefix, filename, w, taOpen, taClose, contentFetch)
			case "pkcs12":
				var (
					s strings.Builder
				)
				r, err := resolvePath(pathPrefix, filename, contentFetch)
				if err != nil {
					return err
				}
				enc := base64.NewEncoder(base64.StdEncoding, &s)
				if _, err := io.Copy(enc, r); err != nil {
					return err
				}
				if err := r.Close(); err != nil {
					return err
				}
				if err := enc.Close(); err != nil {
					return err
				}
				if _, err := w.Write([]byte(pkcsOpen)); err != nil {
					return err
				}
				if _, err := w.Write([]byte(formatBase64(s.String()))); err != nil {
					return err
				}
				if _, err := w.Write([]byte(pkcsClose)); err != nil {
					return err
				}
			default:
				w.Write([]byte(l))
				w.Write(crlf)
			}
		} else {
			w.Write([]byte(l))
			w.Write(crlf)
		}
	}
	return nil
}
