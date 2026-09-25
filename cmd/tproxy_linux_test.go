//go:build linux

package cmd

import (
	"testing"

	"github.com/Diniboy1123/usque/internal"
)

func TestTProxyInitialPacketSizeDefault(t *testing.T) {
	packetSize, err := tproxyCmd.Flags().GetUint16("initial-packet-size")
	if err != nil {
		t.Fatal(err)
	}
	if packetSize != internal.DefaultInitialPacketSize {
		t.Fatalf("initial packet size = %d, want %d", packetSize, internal.DefaultInitialPacketSize)
	}
}
