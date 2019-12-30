package ezovpn

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"text/template"
)

type ovpnData struct {
	Ca         string
	Cert       string
	Key        string
	TlsAuth    *string
	RemoteHost string
	RemotePort int
}

const (
	ovpnTemplate = `client
dev tun
proto udp
remote {{.RemoteHost}} {{.RemotePort}}
nobind
persist-key
persist-tun
comp-lzo
<ca>
{{.Ca -}}
</ca>
<cert>
{{.Cert -}}
</cert>
<key>
{{.Key -}}
</key>
{{if .TlsAuth -}}
key-direction 1
<tls-auth>
{{.TlsAuth -}}
</tls-auth>
{{- end -}}`
)

// FileSpec defines the names of the certificates
type FileSpec struct {
	// CA file name
	CAFile string
	// Cert file name ( name.crt )
	CertFile string
	// Key file name ( name.key )
	KeyFile string
	// TLS Auth file name ( ta.key )
	TAFile string
}

// VpnSpec defines the VPN server
type VpnSpec struct {
	// VPN Server IP or DNS name
	Server string
	// VPN Server port
	Port int
}

// GenerateVPNConfig generates the simple VPN config and embeds the certificates.
//
// keysDir 		path to the key
func GenerateVPNConfig(keysDir string, files *FileSpec, vpn *VpnSpec, out io.Writer, fetcher CertFetcher) error {
	tpl, err := template.New("VPN").Parse(ovpnTemplate)
	if err != nil {
		log.Fatal(err)
	}
	vd := ovpnData{
		RemoteHost: vpn.Server,
		RemotePort: vpn.Port,
	}
	readFileIn := func(path string, dest *string) error {
		c, err := fetcher(path)
		if err != nil {
			return fmt.Errorf("can't read certificate %s : %w", path, err)
		}
		data, err := ioutil.ReadAll(c)
		if err != nil {
			return fmt.Errorf("can't read certificate %s : %w", path, err)
		}
		*dest = string(data)
		return nil
	}
	if err := filepath.Walk(
		keysDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			name := filepath.Base(path)
			switch name {
			case files.CertFile:
				if err := readFileIn(path, &vd.Cert); err != nil {
					return err
				}
			case files.KeyFile:
				if err := readFileIn(path, &vd.Key); err != nil {
					return err
				}
			case files.CAFile:
				if err := readFileIn(path, &vd.Ca); err != nil {
					return err
				}
			case files.TAFile:
				var v string
				if err := readFileIn(path, &v); err != nil {
					return err
				}
				vd.TlsAuth = &v
			}
			return nil
		},
	); err != nil {
		return err
	}
	return tpl.Execute(out, &vd)
}
