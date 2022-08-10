package main

import (
	"ffw/constant"
	"ffw/sock5"
	"flag"
	"fmt"
	"log"
	"runtime"
)

var (
	addr   string
	server string
	host   string
	ignore string
	mode   string
	prefix string
	ssl    bool
)

func main() {
	if mode != constant.MODE_HTTP && mode != constant.MODE_WEBSOCKET {
		fmt.Println("Unknown Mode. Use 'ws' or 'http' ")
		return
	}

	s, err := sock5.New(host, server, ignore, mode, prefix, ssl)
	if err != nil {
		log.Panic(err)
	}

	err = s.Start(addr)
	if err != nil {
		log.Panic(err)
	}
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.StringVar(&addr, "addr", "127.0.0.1:1995", "Listening SOCKS IP and Port address (ip:port)")
	flag.StringVar(&server, "server", "127.0.0.1:80", "Upstream HTTP Proxies")
	flag.StringVar(&host, "host", "", "Fake host header to bypass")
	flag.StringVar(&ignore, "ignore", "", "No proxy for. Example: 127.0.0.1,*.google.com")
	flag.StringVar(&mode, "mode", "ws", "Tunnel mode 'ws' for websocket OR 'http' for http protocol")
	flag.StringVar(&prefix, "prefix", "", "Prefix server url")
	flag.BoolVar(&ssl, "ssl", false, "use ssl")

	flag.Parse()
}
