//go:build !linux

package internal

import (
	"errors"
	"net"
	"net/netip"
)

func ListenTransparentTCP(string) (net.Listener, error) {
	return nil, errors.New("TPROXY is only supported on Linux")
}

func OriginalDestination(net.Conn) (string, error) {
	return "", errors.New("TPROXY is only supported on Linux")
}

func ListenTransparentUDP(string) (*net.UDPConn, error) {
	return nil, errors.New("TPROXY is only supported on Linux")
}

func ListenTransparentUDPWriteBack(string) (*net.UDPConn, error) {
	return nil, errors.New("TPROXY is only supported on Linux")
}

func OriginalUDPDestination([]byte) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("TPROXY is only supported on Linux")
}
