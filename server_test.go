package socks5

import "testing"

func TestServer(t *testing.T) {
	server := Server{Config: Config{host: "0.0.0.0", port: 2252,
		AuthList: []uint8{NoAuthenticationRequired, AccountPasswordAuthentication}},
		UserMap: map[string]string{
			"danbai": "hjj225",
		}}
	server.Start()
}
