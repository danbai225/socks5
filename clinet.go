package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	Host     string
	Port     string
	UserName string
	Password string
}

//连接
func (c *Client) conn() (net.Conn, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", c.Host, c.Port))
	if err != nil {
		return nil, err
	}
	err = c.auth(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

//认证
func (c *Client) auth(conn net.Conn) error {
	//组织发送支持的认证方法
	authPackage := AuthPackage{}
	if c.UserName != "" && c.Password != "" {
		authPackage.addMethod(AccountPasswordAuthentication)
	}
	authPackage.addMethod(NoAuthenticationRequired)
	_, err := conn.Write(authPackage.toData())
	if err != nil {
		return err
	}
	data := make([]byte, 2)
	l, err := conn.Read(data)
	if err != nil {
		return err
	}
	if l != 2 {
		return errors.New("返回数据有误非两个字节")
	}
	if data[0] != Version {
		return errors.New("当前协议Socks5与服务端协议不匹配")
	}
	buffer := bytes.Buffer{}
	switch data[1] {
	case NoAuthenticationRequired:
		return nil
	case AccountPasswordAuthentication:
		//认证协议 0x01
		buffer.WriteByte(0x01)
		//用户名长度
		buffer.WriteByte(byte(len(c.UserName)))
		//用户名
		buffer.WriteString(c.UserName)
		//密码长度
		buffer.WriteByte(byte(len(c.Password)))
		//密码
		buffer.WriteString(c.Password)
	}
	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		return err
	}
	l, err = conn.Read(data)
	if err != nil {
		return err
	}
	if l != 2 {
		return errors.New("返回数据有误非两个字节")
	}
	if data[0] != 0x01 {
		return errors.New("当前认证协议Socks5与服务端协议不匹配")
	}
	if data[1] > 0 {
		return errors.New("认证失败")
	}
	return nil
}

//向服务器发送连接请求
func (c *Client) requisition(conn net.Conn, host string, port uint16, cmd uint8) (net.Conn, error) {
	Type, addr, err := addressResolution(host)
	if err != nil {
		return nil, err
	}
	buffer := bytes.Buffer{}
	buffer.Write([]byte{Version, cmd, Zero, Type})
	buffer.Write(addr)
	//写入端口
	buffer.Write(portToBytes(port))
	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		return nil, err
	}
	read, err := conn.Read(addr)
	if err != nil {
		return nil, err
	}
	rdata := addr[:read]
	if rdata[1] != Zero {
		return nil, errors.New(fmt.Sprintf("请求错误:%x", rdata[1]))
	}
	if cmd == UDP {
		ipdata := make([]byte, 1024)
		if len(rdata) == 4 {
			n, err := conn.Read(ipdata)
			if err != nil {
				return nil, err
			}
			ipdata = ipdata[:n]
		} else {
			ipdata = rdata[4:]
		}
		addr, err := addressResolutionFormByteArray(ipdata, rdata[3])
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
		dial, err := net.Dial("udp", addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return dial, nil
	}
	return nil, nil
}
func (c *Client) udp(conn net.Conn, host string, port uint16) (net.Conn, error) {
	return c.requisition(conn, host, port, UDP)
}
func (c *Client) bind(conn net.Conn, host string, port uint16) error {
	_, err := c.requisition(conn, host, port, Bind)
	return err
}
func (c *Client) tcp(conn net.Conn, host string, port uint16) error {
	_, err := c.requisition(conn, host, port, Connect)
	return err
}
func (c *Client) TcpProxy(host string, port uint16) (net.Conn, error) {
	conn, err := c.conn()
	if err != nil {
		return nil, err
	}
	return conn, c.tcp(conn, host, port)
}
func (c *Client) GetHttpProxyClient() *http.Client {
	httpTransport := &http.Transport{}
	httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		split := strings.Split(addr, ":")
		if len(split) < 2 {
			return c.TcpProxy(split[0], 80)
		}
		port, err := strconv.Atoi(split[1])
		if err != nil {
			return nil, err
		}
		return c.TcpProxy(split[0], uint16(port))
	}
	return &http.Client{Transport: httpTransport}
}
func (c *Client) GetHttpProxyClientSpecify(transport *http.Transport, jar http.CookieJar, CheckRedirect func(req *http.Request, via []*http.Request) error, Timeout time.Duration) *http.Client {
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		split := strings.Split(addr, ":")
		if len(split) < 2 {
			return c.TcpProxy(split[0], 80)
		}
		port, err := strconv.Atoi(split[1])
		if err != nil {
			return nil, err
		}
		return c.TcpProxy(split[0], uint16(port))
	}
	return &http.Client{Transport: transport, Jar: jar, CheckRedirect: CheckRedirect, Timeout: Timeout}
}
func (c *Client) UdpProxy(host string, port uint16) (*UdpProxy, error) {
	conn, err := c.conn()
	if err != nil {
		return nil, err
	}
	udp, err := c.udp(conn, "0.0.0.0", 0)
	if err != nil {
		return nil, err
	}
	proxy := UdpProxy{udp, host, port}
	return &proxy, nil
}
