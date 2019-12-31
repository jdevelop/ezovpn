package ezovpn

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	longBase64     = `/deSj5Uh3JfIX2bhP0f+TNTIw1OZJgwK4aXTjOmuIjcz9YVmiRR1ZwWI59VWaGKxci/4er8ZN3YSOIce8ddQqQ8Ub/CPeBCXrt04DhjTzB3x+4MZ+ZBGHHevySGWe9oHKcavfBZM1+kpg+qz8BbZDbYYSRs=`
	expectedBase64 = `/deSj5Uh3JfIX2bhP0f+TNTIw1OZJgwK4aXTjOmuIjcz9YVmiRR1ZwWI59VWaGKxci/4er8ZN3YS
OIce8ddQqQ8Ub/CPeBCXrt04DhjTzB3x+4MZ+ZBGHHevySGWe9oHKcavfBZM1+kpg+qz8BbZDbYY
SRs=
`
)

func TestBase64Split(t *testing.T) {
	require.Equal(t, expectedBase64, formatBase64(longBase64))
}
