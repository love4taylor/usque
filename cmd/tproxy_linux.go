//go:build linux

package cmd

import (
	"context"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var tproxyCmd = &cobra.Command{
	Use:   "tproxy",
	Short: "Expose Warp as a Linux transparent TCP and UDP proxy",
	Long: "Accept TCP and UDP packets redirected by Linux netfilter TPROXY and forward them through the MASQUE tunnel. " +
		"This command requires root and external IPv4/IPv6 TPROXY rules.",
	Run: runTProxy,
}

func runTProxy(cmd *cobra.Command, _ []string) {
	if !config.ConfigLoaded {
		cmd.Println("Config not loaded. Please register first.")
		return
	}
	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		cmd.Printf("Failed to get private key: %v\n", err)
		return
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		cmd.Printf("Failed to get public key: %v\n", err)
		return
	}
	sni, _ := cmd.Flags().GetString("sni-address")
	insecure, _ := cmd.Flags().GetBool("insecure")
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		cmd.Printf("Failed to generate cert: %v\n", err)
		return
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
	if err != nil {
		cmd.Printf("Failed to prepare TLS config: %v\n", err)
		return
	}
	useHTTP2, _ := cmd.Flags().GetBool("http2")
	useIPv6, _ := cmd.Flags().GetBool("ipv6")
	connectPort, _ := cmd.Flags().GetInt("connect-port")
	tcpL4, _ := cmd.Flags().GetBool("tcp-l4")
	endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
	if err != nil {
		cmd.Printf("Failed to select endpoint: %v\n", err)
		return
	}
	keepalive, _ := cmd.Flags().GetDuration("keepalive-period")
	initialPacketSize, _ := cmd.Flags().GetUint16("initial-packet-size")
	mtu, _ := cmd.Flags().GetInt("mtu")
	reconnectDelay, _ := cmd.Flags().GetDuration("reconnect-delay")
	alwaysReconnect, _ := cmd.Flags().GetBool("always-reconnect")
	var tcpProxy *api.L4Proxy
	if tcpL4 {
		l4Cert, certErr := internal.GenerateCert(privKey, &privKey.PublicKey)
		if certErr != nil {
			cmd.Printf("Failed to generate L4 certificate: %v\n", certErr)
			return
		}
		l4TLSConfig, tlsErr := api.PrepareTlsConfig(privKey, peerPubKey, l4Cert, internal.L4ConnectSNI, insecure)
		if tlsErr != nil {
			cmd.Printf("Failed to prepare L4 TLS config: %v\n", tlsErr)
			return
		}
		l4EndpointAddr, endpointErr := config.SelectEndpointFromConfig(false, useIPv6, connectPort)
		if endpointErr != nil {
			cmd.Printf("Failed to select L4 endpoint: %v\n", endpointErr)
			return
		}
		l4Endpoint, endpointOK := l4EndpointAddr.(*net.UDPAddr)
		if !endpointOK {
			cmd.Printf("L4 TPROXY requires an HTTP/3 UDP endpoint\n")
			return
		}
		tcpProxy, err = api.NewL4Proxy(api.L4ProxyConfig{
			TLSConfig:      l4TLSConfig,
			QUICConfig:     l4QUICConfig(keepalive, initialPacketSize),
			Endpoint:       l4Endpoint,
			ResolveLocally: false,
		})
		if err != nil {
			cmd.Printf("Failed to create L4 TPROXY proxy: %v\n", err)
			return
		}
		defer tcpProxy.Close()
		log.Printf("TPROXY TCP forwarding uses L4 HTTP/3 CONNECT; UDP forwarding uses netstack")
	}
	noIPv4, _ := cmd.Flags().GetBool("no-tunnel-ipv4")
	noIPv6, _ := cmd.Flags().GetBool("no-tunnel-ipv6")
	addresses := make([]netip.Addr, 0, 2)
	if !noIPv4 {
		address, parseErr := netip.ParseAddr(config.AppConfig.IPv4)
		if parseErr != nil {
			cmd.Printf("Failed to parse IPv4: %v\n", parseErr)
			return
		}
		addresses = append(addresses, address)
	}
	if !noIPv6 {
		address, parseErr := netip.ParseAddr(config.AppConfig.IPv6)
		if parseErr != nil {
			cmd.Printf("Failed to parse IPv6: %v\n", parseErr)
			return
		}
		addresses = append(addresses, address)
	}
	tunDev, tunNet, err := netstack.CreateNetTUN(addresses, nil, mtu)
	if err != nil {
		cmd.Printf("Failed to create tunnel network stack: %v\n", err)
		return
	}
	defer tunDev.Close()
	go api.MaintainTunnel(context.Background(), api.MaintainTunnelConfig{
		TLSConfig: tlsConfig, KeepalivePeriod: keepalive, InitialPacketSize: initialPacketSize,
		Endpoint: endpoint, Device: api.NewNetstackAdapter(tunDev), MTU: mtu,
		ReconnectDelay: reconnectDelay, AlwaysReconnect: alwaysReconnect, UseHTTP2: useHTTP2,
		HookEnv: map[string]string{"USQUE_MODE": "tproxy", "USQUE_IPV4": config.AppConfig.IPv4, "USQUE_IPV6": config.AppConfig.IPv6},
	})

	bind, _ := cmd.Flags().GetString("bind")
	bindV6, _ := cmd.Flags().GetString("bind-v6")
	port, _ := cmd.Flags().GetString("port")
	listenAddresses := []string{net.JoinHostPort(bind, port)}
	if bindV6 != "" {
		listenAddresses = append(listenAddresses, net.JoinHostPort(bindV6, port))
	}
	tcpListeners := make([]net.Listener, 0, len(listenAddresses))
	for _, address := range listenAddresses {
		tcpListener, listenErr := internal.ListenTransparentTCP(address)
		if listenErr != nil {
			for _, listener := range tcpListeners {
				_ = listener.Close()
			}
			cmd.Printf("Failed to create transparent TCP listener on %s: %v\n", address, listenErr)
			return
		}
		tcpListeners = append(tcpListeners, tcpListener)
	}
	defer func() {
		for _, listener := range tcpListeners {
			_ = listener.Close()
		}
	}()
	udpListeners := make([]*net.UDPConn, 0, len(listenAddresses))
	for _, address := range listenAddresses {
		udpConn, listenErr := internal.ListenTransparentUDP(address)
		if listenErr != nil {
			for _, listener := range udpListeners {
				_ = listener.Close()
			}
			for _, listener := range tcpListeners {
				_ = listener.Close()
			}
			cmd.Printf("Failed to create transparent UDP listener on %s: %v\n", address, listenErr)
			return
		}
		udpListeners = append(udpListeners, udpConn)
	}
	defer func() {
		for _, listener := range udpListeners {
			_ = listener.Close()
		}
	}()
	udpTimeout, _ := cmd.Flags().GetDuration("udp-timeout")
	log.Printf("TPROXY TCP and UDP listeners listening on %s", listenAddresses)
	for _, listener := range tcpListeners {
		go acceptTransparentTCP(cmd.Context(), listener, tunNet, tcpProxy)
	}
	for _, listener := range udpListeners {
		go serveTransparentUDP(cmd.Context(), listener, tunNet, udpTimeout)
	}
	select {}
}

func acceptTransparentTCP(ctx context.Context, listener net.Listener, tunNet *netstack.Net, tcpProxy *api.L4Proxy) {
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				log.Printf("TPROXY TCP accept loop stopped: %v", ctx.Err())
				return
			}
			log.Printf("TPROXY TCP accept failed: %v", err)
			continue
		}
		go proxyTransparentTCP(ctx, client, tunNet, tcpProxy)
	}
}

func proxyTransparentTCP(ctx context.Context, client net.Conn, tunNet *netstack.Net, tcpProxy *api.L4Proxy) {
	defer client.Close()
	destination, err := internal.OriginalDestination(client)
	if err != nil {
		if localAddr := client.LocalAddr(); localAddr != nil {
			destination = localAddr.String()
		}
	}
	if destination == "" {
		log.Printf("Failed to determine original TCP destination: %v", err)
		return
	}
	var remote net.Conn
	if tcpProxy != nil {
		remote, err = tcpProxy.DialContext(ctx, destination)
	} else {
		remote, err = tunNet.DialContext(ctx, "tcp", destination)
	}
	if err != nil {
		log.Printf("Failed to connect to %s: %v", destination, err)
		return
	}
	defer remote.Close()
	api.RelayTCP(client, remote)
}

type transparentUDPFlow struct {
	client    netip.AddrPort
	remote    net.Conn
	writer    *net.UDPConn
	closeOnce sync.Once
}

func (flow *transparentUDPFlow) close() {
	flow.closeOnce.Do(func() {
		_ = flow.remote.Close()
		_ = flow.writer.Close()
	})
}

type transparentUDPFlows struct {
	mu    sync.Mutex
	items map[string]*transparentUDPFlow
}

func (flows *transparentUDPFlows) remove(key string, flow *transparentUDPFlow) {
	flows.mu.Lock()
	if flows.items[key] == flow {
		delete(flows.items, key)
	}
	flows.mu.Unlock()
}

func (flows *transparentUDPFlows) closeAll() {
	flows.mu.Lock()
	items := make([]*transparentUDPFlow, 0, len(flows.items))
	for key, flow := range flows.items {
		delete(flows.items, key)
		items = append(items, flow)
	}
	flows.mu.Unlock()
	for _, flow := range items {
		flow.close()
	}
}

func serveTransparentUDP(ctx context.Context, listener *net.UDPConn, tunNet *netstack.Net, timeout time.Duration) {
	flows := &transparentUDPFlows{items: make(map[string]*transparentUDPFlow)}
	buffer := make([]byte, 64*1024)
	controlBuffer := make([]byte, 256)
	listenerDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-listenerDone:
		}
	}()
	defer close(listenerDone)
	defer flows.closeAll()
	for {
		n, controlSize, _, client, err := listener.ReadMsgUDPAddrPort(buffer, controlBuffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("TPROXY UDP read failed: %v", err)
			continue
		}
		control := controlBuffer[:controlSize]
		destination, err := internal.OriginalUDPDestination(control)
		if err != nil {
			log.Printf("Failed to determine original UDP destination: %v", err)
			continue
		}
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
		key := client.String() + "|" + destination.String()
		flows.mu.Lock()
		flow := flows.items[key]
		flows.mu.Unlock()
		if flow == nil {
			remote, dialErr := tunNet.DialContext(ctx, "udp", destination.String())
			if dialErr != nil {
				log.Printf("Failed to connect UDP %s: %v", destination.String(), dialErr)
				continue
			}
			writer, writeBackErr := internal.ListenTransparentUDPWriteBack(destination.String())
			if writeBackErr != nil {
				_ = remote.Close()
				log.Printf("Failed to create UDP write-back socket %s: %v", destination.String(), writeBackErr)
				continue
			}
			candidate := &transparentUDPFlow{client: client, remote: remote, writer: writer}
			flows.mu.Lock()
			flow = flows.items[key]
			if flow == nil {
				flow = candidate
				flows.items[key] = flow
				go relayTransparentUDP(flow, key, flows, timeout)
			} else {
				candidate.close()
			}
			flows.mu.Unlock()
		}
		if timeout > 0 {
			_ = flow.remote.SetReadDeadline(time.Now().Add(timeout))
		}
		_, writeErr := flow.remote.Write(buffer[:n])
		if writeErr != nil {
			log.Printf("Failed to write UDP %s: %v", destination.String(), writeErr)
		}
	}
}

func relayTransparentUDP(flow *transparentUDPFlow, key string, flows *transparentUDPFlows, timeout time.Duration) {
	buffer := make([]byte, 64*1024)
	for {
		if timeout > 0 {
			_ = flow.remote.SetReadDeadline(time.Now().Add(timeout))
		}
		n, err := flow.remote.Read(buffer)
		if err != nil {
			break
		}
		if _, err = flow.writer.WriteToUDPAddrPort(buffer[:n], flow.client); err != nil {
			break
		}
	}
	flow.close()
	flows.remove(key, flow)
}

func init() {
	tproxyCmd.Flags().StringP("bind", "b", "0.0.0.0", "TPROXY listen address")
	tproxyCmd.Flags().String("bind-v6", "", "Additional IPv6 TPROXY listen address")
	tproxyCmd.Flags().StringP("port", "p", "12345", "TPROXY listen port for TCP and UDP")
	tproxyCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	tproxyCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	tproxyCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	tproxyCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	tproxyCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	tproxyCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection")
	tproxyCmd.Flags().DurationP("reconnect-delay", "r", time.Second, "Delay between reconnect attempts")
	tproxyCmd.Flags().Duration("udp-timeout", 60*time.Second, "Idle timeout for transparent UDP flows")
	tproxyCmd.Flags().Bool("always-reconnect", true, "Always reconnect after tunnel loss")
	tproxyCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC")
	tproxyCmd.Flags().Bool("tcp-l4", false, "Forward TCP through an HTTP/3 L4 CONNECT stream instead of netstack")
	tproxyCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning")
	tproxyCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	tproxyCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	rootCmd.AddCommand(tproxyCmd)
}
