package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/Blocked233/middleware/proto"

	"google.golang.org/grpc"
)

var (
	GrpcServer *grpc.Server

	trojanPasswordLenth = 56
	crlf                = []byte{'\r', '\n'}
)

type MessageService struct {
	proto.MessageServer
}

func init() {

	GrpcServer = grpc.NewServer(grpc.InitialConnWindowSize(1024 * 1024 * 10))
	proto.RegisterMessageServer(GrpcServer, new(MessageService))

}

func (h MessageService) Tun(stream proto.Message_TunServer) error {

	defer stream.Context().Done()

	rcvBytes := tunBytesPool.Get().(*proto.TunByte)
	defer tunBytesPool.Put(rcvBytes)

	//First data

	err := stream.RecvMsg(rcvBytes)
	if err != nil {
		return err
	}

	cmd := rcvBytes.Data[trojanPasswordLenth+len(crlf)]
	addr := SplitAddr(rcvBytes.Data[trojanPasswordLenth+len(crlf)+1:])

	if addr == nil {
		return errors.New("wrong addr")
	}

	if cmd == 1 {
		return stdtcpProcess(stream, addr, rcvBytes)
	}
	if cmd == 3 {
		return stdudpProcess(stream, addr, rcvBytes)
	}
	return errors.New("wrong cmd")
}

func stdtcpProcess(stream proto.Message_TunServer, addr Addr, rcvBytes *proto.TunByte) error {

	payload := rcvBytes.Data[trojanPasswordLenth+len(crlf)+1+len(addr)+len(crlf):]

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		return err
	}

	conn.Write(payload)

	// client <-- destination

	go func() {
		buf := bufferPool.Get().(*byteReuse)
		defer bufferPool.Put(buf)

		sendBytes := tunBytesPool.Get().(*proto.TunByte)
		defer tunBytesPool.Put(sendBytes)

		for {

			n, err := conn.Read(buf.buf)
			if err != nil {
				return
			}

			sendBytes.Data = buf.buf[:n]

			err = stream.Send(sendBytes)
			if err != nil {
				return
			}
		}
	}()

	//client --> destination

	for {
		err := stream.RecvMsg(rcvBytes)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		_, err = conn.Write(rcvBytes.Data)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

	}
}

func stdudpProcess(stream proto.Message_TunServer, addr Addr, rcvBytes *proto.TunByte) error {

	udpListen, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}

	err = stream.RecvMsg(rcvBytes)
	if err != nil {
		return err
	}

	firstRecvAddr := SplitAddr(rcvBytes.Data)
	if firstRecvAddr == nil {
		return nil
	}

	firstUdpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return err
	}

	udpListen.WriteToUDP(rcvBytes.Data[len(firstRecvAddr)+4:], firstUdpAddr)

	// client <-- destination

	go func() {

		udpHeaderBuf := bufferPool.Get().(*byteReuse)
		defer bufferPool.Put(udpHeaderBuf)

		payload := bufferPool.Get().(*byteReuse)
		defer bufferPool.Put(payload)

		sendBytes := tunBytesPool.Get().(*proto.TunByte)
		defer tunBytesPool.Put(sendBytes)

		for {

			n, udpAddr, err := udpListen.ReadFromUDP(payload.buf)
			if err != nil {
				return
			}

			// Protocol: addr len(payload) crlf payload
			udpHeaderBuf.buf = udpHeaderBuf.buf[:0]

			if udpAddr.IP.Equal(firstUdpAddr.IP) && udpAddr.Port == firstUdpAddr.Port {
				udpHeaderBuf.buf = append(udpHeaderBuf.buf, firstRecvAddr...)
			} else {
				udpHeaderBuf.buf = append(udpHeaderBuf.buf, ParseAddrToSocksAddr(udpAddr)...)
			}

			udpHeaderBuf.buf = binary.BigEndian.AppendUint16(udpHeaderBuf.buf, uint16(n))
			udpHeaderBuf.buf = append(udpHeaderBuf.buf, crlf...)
			udpHeaderBuf.buf = append(udpHeaderBuf.buf, payload.buf[:n]...)

			sendBytes.Data = udpHeaderBuf.buf

			err = stream.Send(sendBytes)
			if err != nil {
				return
			}

		}
	}()

	//client --> destination

	for {
		err := stream.RecvMsg(rcvBytes)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		recvAddr := SplitAddr(rcvBytes.Data)
		if string(recvAddr) == string(firstRecvAddr) {
			_, err = udpListen.WriteToUDP(rcvBytes.Data[len(recvAddr)+4:], firstUdpAddr)
		} else {
			_, err = udpListen.WriteToUDP(rcvBytes.Data[len(recvAddr)+4:], recvAddr.UDPAddr())
		}

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

	}
}
