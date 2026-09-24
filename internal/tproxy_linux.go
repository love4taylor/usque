//go:build linux

package internal

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const originalDestinationSocketOption = unix.SO_ORIGINAL_DST

func ListenTransparentTCP(address string) (net.Listener, error) {
	var listenConfig net.ListenConfig
	network := transparentNetwork(address, "tcp")
	listenConfig.Control = func(network, _ string, rawConn syscall.RawConn) error {
		var controlErr error
		if err := rawConn.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if controlErr == nil {
				controlErr = setTransparentSocket(int(fd), network)
			}
		}); err != nil {
			return err
		}
		return controlErr
	}
	return listenConfig.Listen(nil, network, address)
}

func ListenTransparentUDP(address string) (*net.UDPConn, error) {
	var listenConfig net.ListenConfig
	network := transparentNetwork(address, "udp")
	listenConfig.Control = func(network, _ string, rawConn syscall.RawConn) error {
		var controlErr error
		if err := rawConn.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if controlErr == nil {
				controlErr = setTransparentSocket(int(fd), network)
			}
			if controlErr == nil && network == "udp4" {
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			}
			if controlErr == nil && network == "udp6" {
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
			}
		}); err != nil {
			return err
		}
		return controlErr
	}
	conn, err := listenConfig.ListenPacket(nil, network, address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// ListenTransparentUDPWriteBack creates a transparent UDP socket bound to the
// original destination address. Replies sent through it retain that source
// address and port instead of appearing to come from the proxy listener.
func ListenTransparentUDPWriteBack(address string) (*net.UDPConn, error) {
	var listenConfig net.ListenConfig
	network := transparentNetwork(address, "udp")
	listenConfig.Control = func(network, _ string, rawConn syscall.RawConn) error {
		var controlErr error
		if err := rawConn.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if controlErr == nil {
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
			if controlErr == nil {
				controlErr = setTransparentSocket(int(fd), network)
			}
		}); err != nil {
			return err
		}
		return controlErr
	}
	conn, err := listenConfig.ListenPacket(nil, network, address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

func transparentNetwork(address, protocol string) string {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err == nil && ip != nil && ip.To4() == nil {
		return protocol + "6"
	}
	return protocol + "4"
}

func setTransparentSocket(fd int, network string) error {
	if network == "tcp6" || network == "udp6" {
		return unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	}
	return unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
}

func OriginalDestination(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("transparent connection is %T, want *net.TCPConn", conn)
	}
	var destination string
	var controlErr error
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return "", err
	}
	if err := rawConn.Control(func(fd uintptr) {
		localAddr := tcpConn.LocalAddr().(*net.TCPAddr)
		if ip4 := localAddr.IP.To4(); ip4 != nil {
			address, err := originalDestination4(fd)
			if err != nil {
				controlErr = err
				return
			}
			destination = net.JoinHostPort(address.Addr().String(), strconv.Itoa(int(address.Port())))
			return
		}
		address, err := originalDestination6(fd)
		if err != nil {
			controlErr = err
			return
		}
		destination = net.JoinHostPort(address.Addr().String(), strconv.Itoa(int(address.Port())))
	}); err != nil {
		return "", err
	}
	if controlErr != nil {
		return "", fmt.Errorf("read original destination: %w", controlErr)
	}
	return destination, nil
}

func originalDestination4(fd uintptr) (netip.AddrPort, error) {
	address := unix.RawSockaddrInet4{}
	if err := getSocketOption(fd, unix.SOL_IP, originalDestinationSocketOption, unsafe.Pointer(&address), uint32(unsafe.Sizeof(address))); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(netip.AddrFrom4(address.Addr), binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&address.Port))[:])), nil
}

func originalDestination6(fd uintptr) (netip.AddrPort, error) {
	address := unix.RawSockaddrInet6{}
	if err := getSocketOption(fd, unix.SOL_IPV6, originalDestinationSocketOption, unsafe.Pointer(&address), uint32(unsafe.Sizeof(address))); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(netip.AddrFrom16(address.Addr), binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&address.Port))[:])), nil
}

func getSocketOption(fd uintptr, level, name int, address unsafe.Pointer, size uint32) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(level), uintptr(name), uintptr(address), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func OriginalUDPDestination(control []byte) (netip.AddrPort, error) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, message := range messages {
		if message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_ORIGDSTADDR && len(message.Data) >= 8 {
			port := binary.BigEndian.Uint16(message.Data[2:4])
			var address [4]byte
			copy(address[:], message.Data[4:8])
			return netip.AddrPortFrom(netip.AddrFrom4(address), port), nil
		}
		if message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_ORIGDSTADDR && len(message.Data) >= 28 {
			port := binary.BigEndian.Uint16(message.Data[2:4])
			var address [16]byte
			copy(address[:], message.Data[8:24])
			return netip.AddrPortFrom(netip.AddrFrom16(address), port), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("original destination control message not found")
}
