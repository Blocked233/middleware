package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"net"
)

/*
+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+

where Trojan Request is a SOCKS5-like request:

+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+

each UDP packet has the following format:

+------+----------+----------+--------+---------+----------+
| ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
+------+----------+----------+--------+---------+----------+
|  1   | Variable |    2     |   2    | X'0D0A' | Variable |
+------+----------+----------+--------+---------+----------+
*/

var (
	psd = hexSha224([]byte("1234"))
)

func HandleTrojan(tlsConn net.Conn) {

	connData := bufferPool.Get().(*byteReuse)
	defer bufferPool.Put(connData)

	n, err := tlsConn.Read(connData.buf)
	if err != nil {
		log.Println(err)
		return
	}

	rcvPsd := connData.buf[:trojanPasswordLenth]

	if string(rcvPsd) != string(psd) {
		return
	}

	cmd := connData.buf[trojanPasswordLenth+len(crlf)]
	addr := SplitAddr(connData.buf[trojanPasswordLenth+len(crlf)+1:])

	if addr == nil {
		return
	}

	switch cmd {
	case 1:
		tcpProcess(tlsConn, addr, connData, n)
	case 3:
		udpProcess(tlsConn, addr, connData)
	default:

	}

}

func tcpProcess(tlsConn net.Conn, addr Addr, connData *byteReuse, n int) {

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		log.Println(err)
		return
	}

	payload := connData.buf[trojanPasswordLenth+len(crlf)+1+len(addr)+len(crlf) : n]

	conn.Write(payload)

	go io.CopyBuffer(tlsConn, conn, connData.buf)

	// zero copy
	io.CopyBuffer(conn, tlsConn, connData.buf)
}

func udpProcess(tlsConn net.Conn, addr Addr, connData *byteReuse) {

	udpListen, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}

	firstUdpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		log.Println(err)
		return
	}

	n, err := tlsConn.Read(connData.buf)
	if err != nil {
		return
	}

	firstRecvAddr := SplitAddr(connData.buf[:n])
	if firstRecvAddr == nil {
		return
	}

	_, err = udpListen.WriteToUDP(connData.buf[len(firstRecvAddr)+4:n], firstUdpAddr)
	if err != nil {
		log.Println(err)
		return
	}

	// client <-- destination

	go func() {

		udpHeaderBuf := bufferPool.Get().(*byteReuse)
		defer bufferPool.Put(udpHeaderBuf)

		payload := bufferPool.Get().(*byteReuse)
		defer bufferPool.Put(payload)

		for {

			n, udpAddr, err := udpListen.ReadFromUDP(payload.buf)
			if err != nil {
				log.Println(err)
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

			_, err = tlsConn.Write(udpHeaderBuf.buf)

			if err != nil {
				log.Println(err)
				return
			}

		}
	}()

	//client --> destination

	for {
		n, err := tlsConn.Read(connData.buf)
		if err != nil {
			return
		}

		recvAddr := SplitAddr(connData.buf[:n])

		if string(recvAddr) == string(firstRecvAddr) {
			_, err = udpListen.WriteToUDP(connData.buf[len(recvAddr)+4:n], firstUdpAddr)
		} else {
			_, err = udpListen.WriteToUDP(connData.buf[len(recvAddr)+4:n], recvAddr.UDPAddr())
		}

		if err != nil {
			return
		}

	}
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
