package radius

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"strings"
	"strconv"
	"syscall"
	"encoding/binary"
	"unsafe"
	"bytes"
	"os"
	"math/rand"
	"time"
	"log"
)

type packetResponseWriter struct {
	// listener that received the packet
	conn net.UDPConn
	addr *net.UDPAddr
	localAddr *net.UDPAddr
}

func udpAddrToSocketAddr(addr *net.UDPAddr) (syscall.Sockaddr, error) {
	switch {
	case addr.IP.To4() != nil:
		ip := [4]byte{}
		copy(ip[:], addr.IP.To4())

		return &syscall.SockaddrInet4{Addr: ip, Port: addr.Port}, nil

	default:
		ip := [16]byte{}
		copy(ip[:], addr.IP.To16())

		zoneID, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			return nil, err
		}

		return &syscall.SockaddrInet6{Addr: ip, Port: addr.Port, ZoneId: uint32(zoneID)}, nil
	}
}

func udpAddrFamily(net string, laddr, raddr *net.UDPAddr) int {
	switch net[len(net)-1] {
	case '4':
		return syscall.AF_INET
	case '6':
		return syscall.AF_INET6
	}

	if (laddr == nil || laddr.IP.To4() != nil) &&
		(raddr == nil || raddr.IP.To4() != nil) {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func dialUDP(network string, laddr *net.UDPAddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	//log.Printf("DialUDP %s -> %s\n", laddr.String(), raddr.String())
	remoteSocketAddress, err := udpAddrToSocketAddr(raddr)
	if err != nil {
		return nil, err
	}
	
	localSocketAddress, err := udpAddrToSocketAddr(laddr)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(udpAddrFamily(network, laddr, raddr), syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	log.Println("syscall.Socket() finish")

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	log.Println("syscall.SetsockoptInt() SO_REUSEADDR finish")

	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	log.Println("syscall.SetsockoptInt() IP_TRANSPARENT finish")

	if err := syscall.Bind(fd, localSocketAddress); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	log.Println("syscall.Bind() finish")

	if err := syscall.Connect(fd, remoteSocketAddress); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	log.Println("syscall.Connect() finish")

	f := os.NewFile(uintptr(fd), string(rand.NewSource(time.Now().UnixNano()).Int63()))
	defer f.Close()

	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

func (r *packetResponseWriter) Write(packet *Packet) error {
	encoded, err := packet.Encode()
	if err != nil {
		return err
	}
	//conn, err := dialUDP(r.addr.Network(), r.localAddr, r.addr)
	//if err != nil {
	//	return err
	//}

	if _, err := r.conn.WriteToUDP(encoded, r.addr); err != nil {
		return err
	}
	return nil
}

// PacketServer listens for RADIUS requests on a packet-based protocols (e.g.
// UDP).
type PacketServer struct {
	// The address on which the server listens. Defaults to :1812.
	Addr string

	// The network on which the server listens. Defaults to udp.
	Network string

	// The source from which the secret is obtained for parsing and validating
	// the request.
	SecretSource SecretSource

	// Handler which is called to process the request.
	Handler Handler

	// Skip incoming packet authenticity validation.
	// This should only be set to true for debugging purposes.
	InsecureSkipVerify bool

	shutdownRequested int32

	mu          sync.Mutex
	ctx         context.Context
	ctxDone     context.CancelFunc
	listeners   map[net.UDPConn]uint
	lastActive  chan struct{} // closed when the last active item finishes
	activeCount int32
}

func (s *PacketServer) initLocked() {
	if s.ctx == nil {
		s.ctx, s.ctxDone = context.WithCancel(context.Background())
		s.listeners = make(map[net.UDPConn]uint)
		s.lastActive = make(chan struct{})
	}
}

func (s *PacketServer) activeAdd() {
	atomic.AddInt32(&s.activeCount, 1)
}

func (s *PacketServer) activeDone() {
	if atomic.AddInt32(&s.activeCount, -1) == -1 {
		close(s.lastActive)
	}
}

// TODO: logger on PacketServer

// Serve accepts incoming connections on conn.
func (s *PacketServer) Serve(conn net.UDPConn) error {
	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}
	if s.SecretSource == nil {
		return errors.New("radius: nil SecretSource")
	}

	s.mu.Lock()
	s.initLocked()
	if atomic.LoadInt32(&s.shutdownRequested) == 1 {
		s.mu.Unlock()
		return ErrServerShutdown
	}

	s.listeners[conn]++
	s.mu.Unlock()

	type requestKey struct {
		IP         string
		Identifier byte
	}

	var (
		requestsLock sync.Mutex
		requests     = map[requestKey]struct{}{}
	)

	s.activeAdd()
	defer func() {
		s.mu.Lock()
		s.listeners[conn]--
		if s.listeners[conn] == 0 {
			delete(s.listeners, conn)
		}
		s.mu.Unlock()
		s.activeDone()
	}()

	var buff [MaxPacketLength]byte
	for {
		oob := make([]byte, 1024)
		n, oobn, _, remoteaddr, err := conn.ReadMsgUDP(buff[:], oob)
		if err != nil {
			return err
		}
		
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return err
		}
		var originalDst *net.UDPAddr
		for _, msg := range msgs {
			if msg.Header.Level != syscall.SOL_IP || msg.Header.Type != syscall.IP_RECVORIGDSTADDR {
				continue
			}
			originalDstRaw := &syscall.RawSockaddrInet4{}
			if err := binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return err
			}
			switch originalDstRaw.Family {
			case syscall.AF_INET:
				pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(originalDstRaw))
				p := (*[2]byte)(unsafe.Pointer(&pp.Port))
				originalDst = &net.UDPAddr{
					IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
					Port: int(p[0])<<8 + int(p[1]),
				}
			case syscall.AF_INET6:
				pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(originalDstRaw))
				p := (*[2]byte)(unsafe.Pointer(&pp.Port))
				originalDst = &net.UDPAddr{
					IP:   net.IP(pp.Addr[:]),
					Port: int(p[0])<<8 + int(p[1]),
					Zone: strconv.Itoa(int(pp.Scope_id)),
				}
			default:
				return nil
			}
		}
		//if originalDst == nil {
		//	return 0, nil, nil, nil
		//}

		//fmt.Printf("ReadFromUDP originalDst:%s\n", originalDst.String())

		s.activeAdd()
		go func(buff []byte, remoteAddr net.Addr, localAddr net.Addr) {
			defer s.activeDone()

			secret, err := s.SecretSource.RADIUSSecret(s.ctx, remoteAddr)
			if err != nil {
				return
			}
			if len(secret) == 0 {
				return
			}

			if !s.InsecureSkipVerify && !IsAuthenticRequest(buff, secret) {
				return
			}

			packet, err := Parse(buff, secret)
			if err != nil {
				return
			}

			key := requestKey{
				IP:         remoteAddr.String(),
				Identifier: packet.Identifier,
			}
			requestsLock.Lock()
			if _, ok := requests[key]; ok {
				requestsLock.Unlock()
				return
			}
			requests[key] = struct{}{}
			requestsLock.Unlock()

			response := packetResponseWriter{
				conn: conn,
				addr: remoteaddr,
				localAddr: originalDst, 
			}

			defer func() {
				requestsLock.Lock()
				delete(requests, key)
				requestsLock.Unlock()
			}()

			request := Request{
				LocalAddr:  localAddr, //conn.LocalAddr(),
				RemoteAddr: remoteAddr,
				Packet:     packet,
				ctx:        s.ctx,
			}

			s.Handler.ServeRADIUS(&response, &request)
		}(append([]byte(nil), buff[:n]...), remoteaddr, originalDst)
	}
}

// ListenAndServe starts a RADIUS server on the address given in s.
func (s *PacketServer) ListenAndServe() error {
	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}
	if s.SecretSource == nil {
		return errors.New("radius: nil SecretSource")
	}

	addrStr := ":1812"
	if s.Addr != "" {
		addrStr = s.Addr
	}

	network := "udp"
	if s.Network != "" {
		network = s.Network
	}

	ip := net.ParseIP(strings.Split(addrStr, ":")[0])
	port,_ := strconv.Atoi(strings.Split(addrStr, ":")[1])

	addr := &net.UDPAddr{
		IP:   ip,
		Port: port,
	}

	pc, err := net.ListenUDP(network, addr)
	if err != nil {
		return err
	}

	f, err := pc.File()
	if err != nil {
		return err
	}
	defer f.Close()

	fd := int(f.Fd())
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		return err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1); err != nil {
		return err
	}

	defer pc.Close()
	return s.Serve(*pc)
}

// Shutdown gracefully stops the server. It first closes all listeners and then
// waits for any running handlers to complete.
//
// Shutdown returns after nil all handlers have completed. ctx.Err() is
// returned if ctx is canceled.
//
// Any Serve methods return ErrShutdown after Shutdown is called.
func (s *PacketServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.initLocked()
	if atomic.CompareAndSwapInt32(&s.shutdownRequested, 0, 1) {
		for listener := range s.listeners {
			listener.Close()
		}

		s.ctxDone()
		s.activeDone()
	}
	s.mu.Unlock()

	select {
	case <-s.lastActive:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
