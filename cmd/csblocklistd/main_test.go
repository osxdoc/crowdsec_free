package main

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version bool
		want    int
	}{
		{name: "version", version: true, want: 0},
		{name: "listen failure", want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, listener.Close()) })
			dir := t.TempDir()
			code := run(filepath.Join(dir, "missing.yaml"), listener.Addr().String(),
				filepath.Join(dir, "blocklist.db"), "error", tc.version, false, "", "")
			require.Equal(t, tc.want, code)
		})
	}
}
