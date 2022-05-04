package main

import (
	"ffw/sock5"
	"flag"
	"log"
	"runtime"
)

var (
	addr   string
	server string
	host   string
	ignore string
)

func main() {
	s, err := sock5.New(host, server, ignore)
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
	flag.StringVar(&host, "host", "google.com", "Fake host header to bypass")
	flag.StringVar(&ignore, "ignore", "", "No proxy for. Example: 127.0.0.1,*.google.com")
	flag.Parse()
}
