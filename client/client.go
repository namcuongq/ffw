package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"

	"github.com/namcuongq/ffw/constant"
	"github.com/namcuongq/ffw/sock5"
)

type Config struct {
	Addr   string
	Server string
	Host   string
	Ignore string
	Mode   string
	Prefix string
	Ssl    bool
}

var config Config

func main() {
	if config.Mode != constant.MODE_HTTP && config.Mode != constant.MODE_WEBSOCKET {
		fmt.Println("Unknown Mode. Use 'ws' or 'http' ")
		return
	}

	s, err := sock5.New(config.Host, config.Server, config.Ignore, config.Mode, config.Prefix, config.Ssl)
	if err != nil {
		log.Panic(err)
	}

	err = s.Start(config.Addr)
	if err != nil {
		log.Panic(err)
	}
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.StringVar(&config.Addr, "addr", "127.0.0.1:1995", "Listening SOCKS IP and Port address (ip:port)")
	flag.StringVar(&config.Server, "server", "127.0.0.1:80", "Upstream HTTP Proxies")
	flag.StringVar(&config.Host, "host", "", "Fake host header to bypass")
	flag.StringVar(&config.Ignore, "ignore", "", "No proxy for. Example: 127.0.0.1,*.google.com")
	flag.StringVar(&config.Mode, "mode", "ws", "Tunnel mode 'ws' for websocket OR 'http' for http protocol")
	flag.StringVar(&config.Prefix, "prefix", "", "Prefix server url")
	flag.BoolVar(&config.Ssl, "ssl", false, "enable https")

	flag.Parse()
}
