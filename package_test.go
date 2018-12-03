package npmaudit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePackage(t *testing.T) {
	require := require.New(t)
	result, err := parsePackage([]byte(testPkgJSON))
	require.NoError(err)

	expected := &pkg{
		deps: map[string]dependencyInfo{
			"tough-cookie":           dependencyInfo{21, "<=2.2.0"},
			"tough-cookie-filestore": dependencyInfo{22, "0.0.1"},
		},
		devDeps: map[string]dependencyInfo{
			"serve-handler": dependencyInfo{25, "<5.0.3"},
		},
	}

	require.Equal(expected, result)
}
