package ezovpn

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRegexResolver(t *testing.T) {
	testData := []struct {
		line  string
		match bool
		key   string
		value string
	}{
		{"remote my-server-1 1194", false, "", ""},
		{"cert 		client.crt	", true, "cert", "client.crt"},
		{" ca 		ca.crt  ", true, "ca", "ca.crt"},
		{"# cert 		client.crt	", false, "", ""},
		{"cert 		client.crt	", true, "cert", "client.crt"},
		{"tls-auth 		ta.key 	1", true, "tls-auth", "ta.key"},
		{"#tls-auth 		ta.key 	1", false, "tls-auth", "ta.key"},
		{" pkcs12 /etc/openvpn/client.p12", true, "pkcs12", "/etc/openvpn/client.p12"},
	}

	for _, test := range testData {
		arr := filesMatcher.FindStringSubmatch(test.line)
		if test.match {
			require.NotNil(t, arr, test)
			require.Equal(t, arr[1], test.key, test)
			require.Equal(t, arr[fileIdx], test.value, test)
		} else {
			require.Nil(t, arr, test)
		}
	}
}

func TestEmbed(t *testing.T) {
	const (
		sourceFile = `# Specify that we are a client and that we
# will be pulling certain config file directives
# from the server.
client
;dev tap
dev tun
;dev-node MyTap
proto udp
remote my-server-1 1194
;remote-random
resolv-retry infinite
# Downgrade privileges after initialization (non-Windows only)
;user nobody
;group nobody
# Try to preserve some state across restarts.
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
cipher AES-256-CBC
comp-lzo
# Silence repeating messages
;mute 20`
		targetFile = `# Specify that we are a client and that we
# will be pulling certain config file directives
# from the server.
client
;dev tap
dev tun
;dev-node MyTap
proto udp
remote my-server-1 1194
;remote-random
resolv-retry infinite
# Downgrade privileges after initialization (non-Windows only)
;user nobody
;group nobody
# Try to preserve some state across restarts.
persist-key
persist-tun
<ca>
CA cert here
1234
</ca>
<cert>
0000000
1111111
</cert>
<key>
2222222222222222222
2222233322222222222
</key>
key-direction 1
<tls-auth>
AUTH PACKET
DATA
</tls-auth>
cipher AES-256-CBC
comp-lzo
# Silence repeating messages
;mute 20
`
		sourceFilePkcs12 = `# Specify that we are a client and that we
# will be pulling certain config file directives
# from the server.
client
;dev tap
dev tun
;dev-node MyTap
proto udp
remote my-server-1 1194
;remote-random
resolv-retry infinite
# Downgrade privileges after initialization (non-Windows only)
;user nobody
;group nobody
# Try to preserve some state across restarts.
persist-key
persist-tun
pkcs12 pkcs12.p12
tls-auth ta.key 1
cipher AES-256-CBC
comp-lzo
# Silence repeating messages
;mute 20`
		targetFilePkcs12 = `# Specify that we are a client and that we
# will be pulling certain config file directives
# from the server.
client
;dev tap
dev tun
;dev-node MyTap
proto udp
remote my-server-1 1194
;remote-random
resolv-retry infinite
# Downgrade privileges after initialization (non-Windows only)
;user nobody
;group nobody
# Try to preserve some state across restarts.
persist-key
persist-tun
<pkcs12>
/deSj5Uh3JfIX2bhP0f+TNTIw1OZJgwK4aXTjOmuIjcz9YVmiRR1ZwWI59VWaGKxci/4er8ZN3YS
OIce8ddQqQ8Ub/CPeBCXrt04DhjTzB3x+4MZ+ZBGHHevySGWe9oHKcavfBZM1+kpg+qz8BbZDbYY
SRs=
</pkcs12>
key-direction 1
<tls-auth>
AUTH PACKET
DATA
</tls-auth>
cipher AES-256-CBC
comp-lzo
# Silence repeating messages
;mute 20
`
	)

	pkcsFileData, err := os.Open("./testdir/pkcs12.p12")
	require.Nil(t, err)

	defer pkcsFileData.Close()

	var (
		ca     = stringCloser{strings.NewReader("CA cert here\n1234\n")}
		cert   = stringCloser{strings.NewReader("0000000\n1111111\n")}
		key    = stringCloser{strings.NewReader("2222222222222222222\n2222233322222222222\n")}
		ta     stringCloser
		pkcs12 = pkcsFileData
		m      mck
		w      bytes.Buffer
	)

	m.On("Fetch", "/tmp/ca.crt").Once().Return(&ca, nil)
	m.On("Fetch", "/tmp/client.crt").Once().Return(&cert, nil)
	m.On("Fetch", "/tmp/client.key").Once().Return(&key, nil)
	m.On("Fetch", "/tmp/ta.key").Twice().Return(&ta, nil).Run(func(args mock.Arguments) {
		ta = stringCloser{strings.NewReader("AUTH PACKET\nDATA\n")}
	})
	m.On("Fetch", "/tmp/pkcs12.p12").Once().Return(pkcs12, nil)

	for _, td := range []struct {
		expected string
		src      string
	}{
		{expected: targetFile, src: sourceFile},
		{expected: targetFilePkcs12, src: sourceFilePkcs12},
	} {
		w.Reset()
		ImportVPNConfig("/tmp", strings.NewReader(td.src), &w, m.Fetch)
		require.Equal(t, td.expected, w.String())
	}
	m.AssertExpectations(t)
}

type stringCloser struct {
	io.Reader
}

func (s *stringCloser) Close() error {
	return nil
}

type mck struct {
	mock.Mock
}

func (x *mck) Fetch(s string) (io.ReadCloser, error) {
	arrs := x.Called(s)
	return arrs[0].(io.ReadCloser), nil
}
