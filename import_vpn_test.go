package ezovpn

import (
	"bytes"
	"io"
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
	}

	for _, test := range testData {
		arr := filesMatcher.FindStringSubmatch(test.line)
		if test.match {
			require.NotNil(t, arr, test)
			require.Equal(t, arr[1], test.key, test)
			require.Equal(t, arr[6], test.value, test)
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
	)
	var (
		ca   = stringCloser{strings.NewReader("CA cert here\n1234\n")}
		cert = stringCloser{strings.NewReader("0000000\n1111111\n")}
		key  = stringCloser{strings.NewReader("2222222222222222222\n2222233322222222222\n")}
		ta   = stringCloser{strings.NewReader("AUTH PACKET\nDATA\n")}
		m    mck
		w    bytes.Buffer
	)

	m.On("Fetch", "/tmp/ca.crt").Once().Return(&ca, nil)
	m.On("Fetch", "/tmp/client.crt").Once().Return(&cert, nil)
	m.On("Fetch", "/tmp/client.key").Once().Return(&key, nil)
	m.On("Fetch", "/tmp/ta.key").Once().Return(&ta, nil)

	ImportVPNConfig("/tmp", strings.NewReader(sourceFile), &w, m.Fetch)

	m.AssertExpectations(t)

	require.Equal(t, targetFile, w.String())
}

type stringCloser struct {
	*strings.Reader
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
