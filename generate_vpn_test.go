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
	vpnRenderedPK12 = `client
dev tun
proto udp
remote vpn.server.here 1144
nobind
persist-key
persist-tun
comp-lzo
<pkcs12>
/deSj5Uh3JfIX2bhP0f+TNTIw1OZJgwK4aXTjOmuIjcz9YVmiRR1ZwWI59VWaGKxci/4er8ZN3YS
OIce8ddQqQ8Ub/CPeBCXrt04DhjTzB3x+4MZ+ZBGHHevySGWe9oHKcavfBZM1+kpg+qz8BbZDbYY
SRs=
</pkcs12>
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

func TestVPNGenerationPKCS12(t *testing.T) {
	var buf strings.Builder
	require.Nil(t, GenerateVPNConfig("testdir", &FileSpec{
		CAFile:   "ca.crt",
		CertFile: "ovpn.crt",
		KeyFile:  "ovpn.key",
		TAFile:   "tlsauth.key",
		PKCS12:   "pkcs12.p12",
	}, &VpnSpec{
		Server: "vpn.server.here",
		Port:   1144,
	}, &buf, DefaultCertFetcher))
	require.Equal(t, vpnRenderedPK12, buf.String())

}
