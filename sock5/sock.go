package sock5

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"ffw/constant"
	"ffw/crypto"
	"ffw/packet"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/fasthttp/websocket"
	"github.com/google/uuid"
)

var (
	Commands = []string{"CONNECT", "BIND", "UDP ASSOCIATE"}
	AddrType = []string{"", "IPv4", "", "Domain", "IPv6"}

	errVer = errors.New("socks version not supported")
)

const (
	socksVer5       = 0x05
	socksCmdConnect = 0x01
)

type Tunnel struct {
	TCPAddr net.TCPAddr
	Url     string
	Mode    string
}

type Sock struct {
	TunnelServer    Tunnel
	fakeHost        string
	aesKey          []byte
	pubKey          []byte
	whileListDomain map[string]string
}

func New(fakeHost, tunnelServer, whileList, mode, prefix string, ssl bool) (*Sock, error) {
	var (
		sock Sock
	)

	pubKey, err := getPublicKey(tunnelServer, fakeHost, prefix, ssl)
	if err != nil {
		return nil, fmt.Errorf("get public key error: %v", err)
	}

	schema := ""
	if ssl {
		schema = "s"
	}

	t := url.URL{Scheme: "ws" + schema, Host: tunnelServer, Path: prefix + constant.DEFAULT_ENDPOINT_FFW}
	if mode == constant.MODE_HTTP {
		t = url.URL{Scheme: "http" + schema, Host: tunnelServer, Path: prefix + constant.DEFAULT_ENDPOINT_HTTP}
	}
	sock.TunnelServer.Url = t.String()
	sock.TunnelServer.Mode = mode
	port, _ := strconv.Atoi(t.Port())
	sock.TunnelServer.TCPAddr = net.TCPAddr{
		IP:   net.ParseIP(strings.Replace(t.Host, ":"+t.Port(), "", 1)),
		Port: port,
		Zone: "ip4",
	}
	sock.fakeHost = fakeHost
	sock.aesKey = []byte(strings.ReplaceAll(uuid.New().String(), "-", ""))
	sock.pubKey = pubKey

	if len(whileList) > 0 {
		sock.whileListDomain = make(map[string]string, 0)
		noProxy := strings.Split(whileList, ",")
		for _, i := range noProxy {
			i = strings.TrimSpace(i)
			i = strings.ToLower(i)
			index := strings.Index(strings.TrimSpace(i), ".")
			if index > 0 {
				sock.whileListDomain[i[index+1:]] = i[:index]
			}
		}
	}

	return &sock, nil
}

func getPublicKey(server, host, prefix string, ssl bool) (key []byte, err error) {
	headers := http.Header{}
	if len(host) > 0 {
		headers["Host"] = []string{host}
	}

	schema := "http://"
	if ssl {
		schema = "https://"
	}

	key, statusCode, err := packet.MakeHTTPRequest(schema+server+prefix+constant.DEFAULT_ENDPOINT_KEY, http.MethodGet, headers, nil)
	if err != nil {
		return
	}

	if statusCode != http.StatusOK {
		err = fmt.Errorf("error status code: %v", statusCode)
		return
	}
	return
}

func (s *Sock) isWhileList(domain string) bool {
	if s.whileListDomain == nil {
		return false
	}

	index := strings.Index(domain, ".")
	if index > 0 {
		value, found := s.whileListDomain[domain[index+1:]]
		if !found {
			return false
		}

		if value == "*" {
			return true
		}

		return value == domain[:index]
	}
	return false
}

func (s *Sock) handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)

	buf := make([]byte, 258)

	var n int

	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}

	if buf[idVer] != socksVer5 {
		return errVer
	}

	nmethod := int(buf[idNmethod]) //  client support auth mode
	msgLen := nmethod + 2          //  auth msg length
	if n == msgLen {               // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errors.New("socks authentication get extra data")
	}
	/*
	   X'00' NO AUTHENTICATION REQUIRED
	   X'01' GSSAPI
	   X'02' USERNAME/PASSWORD
	   X'03' to X'7F' IANA ASSIGNED
	   X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	   X'FF' NO ACCEPTABLE METHODS
	*/
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func (s *Sock) parseTarget(conn net.Conn) (host string, port string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int

	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}

	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}

	/*
	   CONNECT X'01'
	   BIND X'02'
	   UDP ASSOCIATE X'03'
	*/

	if buf[idCmd] > 0x03 || buf[idCmd] == 0x00 {
		err = fmt.Errorf("unknown command %v", buf[idCmd])
		return
	}

	if buf[idCmd] != socksCmdConnect { //  only support CONNECT mode
		err = errors.New("socks only support connect command")
		return
	}

	// read target address
	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm: // domain name
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errors.New("socks addr type not supported")
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errors.New("socks request get extra data")
		return
	}

	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	port = strconv.Itoa(int(binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])))

	return
}

func (s *Sock) proxyPassHTTP(conn net.Conn, target string) error {
	defer conn.Close()
	keyEn, err := crypto.RsaEncrypt(s.pubKey, s.aesKey)
	if err != nil {
		return fmt.Errorf("rsa encrypt key: %v", err)
	}

	headers := http.Header{
		"Host":                  []string{s.fakeHost},
		"ETag":                  []string{base64.URLEncoding.EncodeToString(keyEn)},
		constant.DEFAULT_HEADER: []string{target},
		"X-Id":                  []string{uuid.New().String()},
	}

	//create stream
	err = packet.CreateTunnel(s.TunnelServer.Url, headers)
	if err != nil {
		return fmt.Errorf("dial tunnel: %v", err)
	}

	tcpAddr := &s.TunnelServer.TCPAddr

	err = s.sendOK(conn, tcpAddr)
	if err != nil {
		return fmt.Errorf("send ok: %v", err)
	}

	// Transfer data
	go packet.CopyTunnel(s.TunnelServer.Url, headers, conn, s.aesKey)
	return packet.ForwardTunnel(s.TunnelServer.Url, headers, conn, s.aesKey)
}

func (s *Sock) proxyPassWebSocket(conn net.Conn, target string) error {
	defer conn.Close()
	keyEn, err := crypto.RsaEncrypt(s.pubKey, s.aesKey)
	if err != nil {
		return fmt.Errorf("rsa encrypt key: %v", err)
	}

	dest, _, err := websocket.DefaultDialer.Dial(s.TunnelServer.Url, http.Header{
		"Host":                  []string{s.fakeHost},
		"ETag":                  []string{base64.URLEncoding.EncodeToString(keyEn)},
		constant.DEFAULT_HEADER: []string{target},
	})

	if err != nil {
		return fmt.Errorf("dial: %v", err)
	}
	defer dest.Close()

	tcpAddr := &s.TunnelServer.TCPAddr

	err = s.sendOK(conn, tcpAddr)
	if err != nil {
		return fmt.Errorf("send ok: %v", err)
	}

	// Transfer data
	go packet.CopyWebSocket(dest, conn, s.aesKey)
	packet.ForwardWebSocket(conn, dest, s.aesKey)
	return nil
}

func (s *Sock) proxyPassWhileList(conn net.Conn, target string) error {
	defer conn.Close()
	dest, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("connect remote: %v", err)
	}
	defer dest.Close()

	tcpAddr := dest.LocalAddr().(*net.TCPAddr)
	if tcpAddr.Zone == "" {
		if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
			tcpAddr.Zone = "ip4"
		} else {
			tcpAddr.Zone = "ip6"
		}
	}

	err = s.sendOK(conn, tcpAddr)
	if err != nil {
		return fmt.Errorf("send ok: %v", err)
	}

	// Transfer data
	go io.Copy(dest, conn)
	io.Copy(conn, dest)
	return nil
}

func (s *Sock) sendOK(conn net.Conn, tcpAddr *net.TCPAddr) error {
	rep := make([]byte, 256)
	rep[0] = 0x05
	rep[1] = 0x00 // success
	rep[2] = 0x00 //RSV

	//IP
	if tcpAddr.Zone == "ip6" {
		rep[3] = 0x04 //IPv6
	} else {
		rep[3] = 0x01 //IPv4
	}

	var ip net.IP
	if tcpAddr.Zone == "ip6" {
		ip = tcpAddr.IP.To16()
	} else {
		ip = tcpAddr.IP.To4()
	}
	pindex := 4
	for _, b := range ip {
		rep[pindex] = b
		pindex += 1
	}
	rep[pindex] = byte((tcpAddr.Port >> 8) & 0xff)
	rep[pindex+1] = byte(tcpAddr.Port & 0xff)
	_, err := conn.Write(rep[0 : pindex+2])
	return err
}

func (s *Sock) handleConnection(conn net.Conn) {
	if err := s.handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	host, port, err := s.parseTarget(conn)
	if err != nil {
		log.Println("socks consult transfer mode or parse target:", err)
		return
	}

	if s.isWhileList(host) {
		err = s.proxyPassWhileList(conn, net.JoinHostPort(host, port))
	} else {
		if s.TunnelServer.Mode == constant.MODE_HTTP {
			err = s.proxyPassHTTP(conn, net.JoinHostPort(host, port))
		} else {
			err = s.proxyPassWebSocket(conn, net.JoinHostPort(host, port))
		}
	}

	if err != nil {
		log.Println("forward tcp error:", err)
		return
	}
}

func (s *Sock) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	log.Printf("[http-tunnel %s] Listening %s \n", constant.VERSION, addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("client connect error: ", err)
			conn.Close()
			continue
		}

		go s.handleConnection(conn)
	}
}
