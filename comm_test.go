package socks5

import (
	"log"
	"testing"
)

func TestAddressResolutionFormByteArray(t *testing.T) {
	log.Println(addressResolutionFormByteArray([]byte{164, 155, 79, 89, 170, 120, 0}, IPV4))
	_, bytes, err := addressResolution("1050:0:0:0:5:600:300c:326b")
	if err == nil {
		bytes = append(bytes, []byte{0x0, 0x80}...)
		log.Println(addressResolutionFormByteArray(bytes, IPV6))
	}
	_, bytes, err = addressResolution("www.baidu.com")
	if err == nil {
		bytes = append(bytes, []byte{0x0, 0x80}...)
		log.Println(addressResolutionFormByteArray(bytes, Com))
	}
	log.Println(addressResolutionFormByteArray([]byte{192, 168, 0, 118, 8, 204, 49}, IPV4))
}
