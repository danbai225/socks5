package socks5

import (
	"io/ioutil"
	"log"
	"testing"
)

func TestClient_TcpProxy(t *testing.T) {
	client := Client{Host: "164.155.79.89", Port: "6532", UserName: "danbai", Password: "hjj225"}
	proxy, err := client.TcpProxy("39.108.110.44", 2251)
	if err == nil {
		proxy.Write([]byte("testFormSocks5"))
		bytes := make([]byte, 1024)
		read, err := proxy.Read(bytes)
		if err == nil {
			log.Println(bytes[:read])
		}
	} else {
		log.Println(err.Error())
	}
}
func TestClient_HTTPProxy(t *testing.T) {
	client := Client{Host: "164.155.79.89", Port: "38080", UserName: "danbai", Password: "hjj225"}
	proxyClient := client.GetHttpProxyClient()
	get, err := proxyClient.Get("https://api.ip.sb/ip")
	if err == nil {
		all, err := ioutil.ReadAll(get.Body)
		if err == nil {
			log.Println(string(all))
		}
	}
	get, err = proxyClient.Get("https://google.com")
	if err == nil {
		all, err := ioutil.ReadAll(get.Body)
		if err == nil {
			log.Println(string(all))
		}
	}
}
func TestClient_UdpProxy(t *testing.T) {
	client := Client{Host: "192.168.0.2", Port: "7891", UserName: "danbai", Password: "hjj225"}
	//proxy, err2 := client.UdpProxy("0.0.0.0", 0)
	//go func() {
	//	//bytes := make([]byte, 1024)
	//	//var err error
	//	//var read int
	//	//for err==nil {
	//	//	read, err = proxy.Read(bytes)
	//	//	log.Println(bytes[:read])
	//	//}
	//}()
	//bytes := []byte("testFormSocks5 UDP")
	//if err2==nil{
	//	data := []byte{Zero, Zero, Zero, IPV4, 192, 168, 0, 118, 8, 204}
	//	data=append(data,bytes...)
	//	go func() {
	//		bytes := make([]byte, 1024)
	//		var err error
	//		var read int
	//		for err==nil {
	//			read, err = proxy.Read(bytes)
	//			log.Println(bytes[:read])
	//		}
	//	}()
	//	proxy.Write(data)
	//}else {
	//	log.Println(err2)
	//}
	//select {
	//
	//}
	proxy, err2 := client.UdpProxy("192.168.0.118", 2252)
	if err2 == nil {
		log.Println("正常")
		go func() {
			bytes := make([]byte, 1024)
			for {
				host, port, n, err := proxy.Read(bytes)
				if err != nil {
					log.Println(err)
					break
				}
				log.Println(host, port, bytes[:n])
			}
		}()
		proxy.Write([]byte("test"))
	}
	select {}
}
