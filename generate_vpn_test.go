package ezovpn

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	vpnRendered = `client
dev tun
proto udp
remote vpn.server.here 1144
nobind
persist-key
persist-tun
comp-lzo
<ca>
CERT FILE
DATA
</ca>
<cert>
CRT FILE
DATA
</cert>
<key>
KEYS
XXXX
</key>
key-direction 1
<tls-auth>
TLS AUTH
DATA
KEY
</tls-auth>`
)

func TestVPNGeneration(t *testing.T) {
	var buf strings.Builder
	require.Nil(t, GenerateVPNConfig("testdir", &FileSpec{
		CAFile:   "ca.crt",
		CertFile: "ovpn.crt",
		KeyFile:  "ovpn.key",
		TAFile:   "tlsauth.key",
	}, &VpnSpec{
		Server: "vpn.server.here",
		Port:   1144,
	}, &buf, DefaultCertFetcher))
	require.Equal(t, vpnRendered, buf.String())

}
