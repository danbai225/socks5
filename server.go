package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

type Server struct {
	listen  net.Listener
	Config  Config
	UserMap map[string]string
}
type User struct {
	Name     []byte
	Password []byte
}
type Config struct {
	host      string
	port      uint16
	BlackList []string
	AuthList  []uint8
}

func (s *Server) Start() (err error) {
	s.listen, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.Config.host, s.Config.port))
	if err != nil {
		return err
	}
	for s.listen != nil {
		accept, err := s.listen.Accept()
		if err == nil {
			go s.newConn(accept)
		}
	}
	return nil
}
func (s *Server) newConn(conn net.Conn) {
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	err2 := s.auth(conn)
	if err2 != nil {
		log.Println(err2)
		return
	}
	bytes := make([]byte, 1024)
	read, err := conn.Read(bytes)
	if err != nil {
		return
	}
	bytes = bytes[:read]
	if len(bytes) < 5 {
		return
	}
	cmd := bytes[1]
	array, err2 := addressResolutionFormByteArray(bytes[4:], bytes[3])
	if err2 != nil {
		return
	}

	switch cmd {
	case Connect:
		dial, err2 := net.Dial("tcp", array)
		if err2 != nil {
			return
		}
		addr := dial.LocalAddr().String()
		split := strings.Split(addr, ":")
		port := split[len(split)-1]
		parseUint, _ := strconv.ParseUint(port, 10, 16)
		Type, host, _ := addressResolution(strings.Join(split[:len(split)-1], ":"))
		p := make([]byte, 2)
		binary.BigEndian.PutUint16(p, uint16(parseUint))
		data := []byte{Version, Zero, Zero, Type}
		data = append(data, host...)
		data = append(data, p...)
		conn.Write(data)
		ioCopy(conn, dial)
	case Bind:
	case UDP:
	}
}
func (s *Server) auth(conn net.Conn) error {
	bytes := make([]byte, 16)
	read, err := conn.Read(bytes)
	if err != nil {
		return err
	}
	bytes = bytes[:read]
	if len(bytes) < 3 {
		return errors.New("认证数据长度不符")
	}
	if bytes[0] != Version {
		return errors.New("协议不符合")
	}
	//支持的认证方法
	moth := uint8(Zero)
	for _, u := range s.Config.AuthList {
		for _, b := range bytes[2:] {
			if u == b {
				moth = u
				if moth == Zero {
					conn.Write([]byte{Version, Zero})
					return nil
				}
				break
			}
		}
	}
	if moth == Zero {
		return errors.New("没有支持的认证方法")
	}
	_, err = conn.Write([]byte{Version, moth})
	if err != nil {
		return err
	}
	switch moth {
	case NoAuthenticationRequired:
		return nil
	case AccountPasswordAuthentication:
		bytes = make([]byte, 1024)
		n, err := conn.Read(bytes)
		if err != nil {
			return err
		}
		bytes = bytes[:n]
		if len(bytes) < 3 {
			return errors.New("认证数据长度不符")
		}
		if bytes[0] != 0x01 {
			return errors.New("认证协议不符合")
		}
		username := bytes[2 : 2+bytes[1]]
		password := bytes[3+bytes[1]:]
		if pas, has := s.UserMap[string(username)]; has {
			if pas == string(password) {
				conn.Write([]byte{0x01, Zero})
				return nil
			}
		}
	}
	return nil
}
