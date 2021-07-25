package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"unicode"
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

const Zero = 0x0
const (
	// Version 协议版本
	Version = 0x05
)

//认证方法
const (
	// NoAuthenticationRequired 不需要认证
	NoAuthenticationRequired = 0x00
	// AccountPasswordAuthentication 账号密码认证
	AccountPasswordAuthentication = 0x02
)

//命令
const (
	// Connect 连接上游服务器
	Connect = iota + 1
	//Bind 绑定请求
	Bind
	// UDP 转发
	UDP
)

//目标地址类型
const (
	//IPV4 DST.ADDR部分4字节长度
	IPV4 = 0x01
	// Com 域名
	Com = 0x03
	// IPV6 16个字节长度
	IPV6 = 0x04
)

type AuthPackage struct {
	methodsCount uint8
	methods      []byte
}

func (t *AuthPackage) toData() []byte {
	return append([]byte{Version, t.methodsCount}, t.methods...)
}
func (t *AuthPackage) addMethod(methods ...uint8) {
	t.methods = append(t.methods, methods...)
	t.methodsCount += uint8(len(methods))
}

type ClientRequest struct {
	command     uint8
	RSV         uint8
	addressType uint8
	addr        []byte
}

func addressResolution(host string) (uint8, []byte, error) {
	var Type uint8
	addr := make([]byte, 0)
	if strings.Contains(host, ":") {
		Type = IPV6
		//ipv6 地址转16位uint
		if strings.Contains(host, "[") {
			host = host[1 : len(host)-1]
		}
		split := strings.Split(host, ":")
		for _, s := range split {
			if s == "" {
				addr = append(addr, Zero)
				continue
			}
			num, err := strconv.ParseUint(s, 16, 16)
			if err != nil {
				return Zero, nil, err
			}
			bytes := make([]byte, 2)
			binary.BigEndian.PutUint16(bytes, uint16(num))
			addr = append(addr, bytes...)
		}
	}
	runes := []rune(host)
	if Type == Zero && unicode.IsNumber(runes[len(runes)-1]) {
		Type = IPV4
		split := strings.Split(host, ".")
		for _, s := range split {
			num, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return Zero, nil, err
			}
			addr = append(addr, uint8(num))
		}
	}
	if Type == Zero && unicode.IsLetter(runes[len(runes)-1]) {
		Type = Com
		addr = append(addr, uint8(len(host)))
		addr = append(addr, []byte(host)...)
	}
	if Type == Zero {
		return Zero, nil, errors.New("地址类型错误")
	}
	return Type, addr, nil
}

//从[]byte 数据中解析主机地址和端口
func addressResolutionFormByteArray(ipdata []byte, Type uint8) (string, error) {
	if len(ipdata) < 6 || Type == Zero {
		return "", errors.New(fmt.Sprintf("解析地址数据有误,%v %x", ipdata, Type))
	}
	addr := ""
	var portBytes []byte
	switch Type {
	case IPV4:
		for i, b := range ipdata[:4] {
			addr += strconv.Itoa(int(b))
			if i != 3 {
				addr += "."
			}
		}
		portBytes = ipdata[4:6]
	case IPV6:
		if len(ipdata) < 18 {
			return "", errors.New("数据长度不足18字节")
		}
		for i := 0; i < 16; i += 2 {
			u := binary.BigEndian.Uint16(ipdata[i : i+2])
			s := strconv.FormatUint(uint64(u), 16)
			addr += s
			if i != 14 {
				addr += ":"
			}
		}
		portBytes = ipdata[16:18]
	case Com:
		l := ipdata[0]
		if int(l)+3 < len(ipdata) {
			return "", errors.New("数据长度不足")
		}
		bytes := ipdata[1 : int(l)+1]
		addr += string(bytes)
		portBytes = ipdata[int(l)+1 : int(l)+3]
	}
	addr += ":" + strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))
	return addr, nil
}

func portToBytes(port uint16) []byte {
	//写入端口
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return buf
}

type UdpProxy struct {
	conn net.Conn
	host string
	port uint16
}

func (u *UdpProxy) Write(bytes []byte) (n int, err error) {
	data, err := u.addHead(u.host, u.port, bytes)
	if err != nil {
		return 0, err
	}
	_, err = u.conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}
func (u *UdpProxy) SpecifyWrite(host string, port uint16, bytes []byte) (n int, err error) {
	data, err := u.addHead(host, port, bytes)
	if err != nil {
		return 0, err
	}
	_, err = u.conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}
func (u *UdpProxy) Read(bytes []byte) (host string, port uint16, n int, err error) {
	l, err := u.conn.Read(bytes)
	if err != nil {
		return "", 0, 0, err
	}
	host, port, data, err := u.removeHead(bytes[:l])
	if err != nil {
		return "", 0, 0, err
	}
	copy(bytes, data)
	n = len(data)
	return
}
func (u UdpProxy) removeHead(bytes []byte) (host string, port uint16, data []byte, err error) {
	if len(bytes) < 10 {
		return "", 0, nil, errors.New("错误的头数据")
	}
	Type := bytes[3]
	addr, err := addressResolutionFormByteArray(bytes[4:], Type)
	if err != nil {
		return "", 0, nil, err
	}
	//切分host 端口
	split := strings.Split(addr, ":")
	parseUint, err := strconv.ParseUint(split[len(split)-1], 10, 16)
	port = uint16(parseUint)
	if Type == IPV6 {
		host = strings.Join(split[:len(split)-1], ":")
	}
	host = split[0]
	//获取数据
	switch Type {
	case IPV4:
		data = append(bytes[10:])
	case IPV6:
		data = append(bytes[22:])
	case Com:
		data = append(bytes[7+len(host):])
	}
	return
}
func (u UdpProxy) addHead(host string, port uint16, bytes []byte) ([]byte, error) {
	data := make([]byte, len(bytes)+128)
	Type, b, err := addressResolution(host)
	if err != nil {
		return bytes, err
	}
	data = []byte{Zero, Zero, Zero, Type}
	data = append(data, b...)
	data = append(data, portToBytes(port)...)
	data = append(data, bytes...)
	return data, nil
}
func ioCopy(conn1 net.Conn, conn2 net.Conn) {
	defer func() {
		conn1.Close()
		conn2.Close()
	}()
	go io.Copy(conn1, conn2)
	io.Copy(conn2, conn1)
}
