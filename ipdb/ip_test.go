package ipdb

import (
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestIPRangeDB(t *testing.T) {
	require.True(t, China.Contains(net.ParseIP("180.101.49.11")))
	require.False(t, Private.Contains(net.ParseIP("180.101.49.11")))
}
