package main

import (
	"encoding/base64"
	"ffw/constant"
	"ffw/crypto"
	"ffw/packet"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/fasthttp/websocket"
)

/*
openssl genrsa -out key.pem
openssl rsa -in key.pem  -pubout > key-pub.pem
*/
var privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwEvjwH002eYWWX72JkhbuGyBIyjFx0Y35FY/QWlOQs9KYVRC
4tL6WIW1xpKS6uxMfAmYAFB2FUNl0EuAhcG0o11Pd0vYTKZi0Y0s1wN34aOKWoN/
EQTDbF8Rx6hb441TtkomRlb0EfIp2IPo6dgu/BBqsaPzlMhoT3eBFBBGI5CmCskn
JyMskMaP9wMN87NaQiMqs7MOcW5fcpzhcahi4a46jSajeMqswNB+d/gq5u0Py2oL
QtBc47AiPfhKAoSuh6cYlGiHwwX6S+q7daWj2Eko2O7mAFkiS2DG0f+vfYorJfHr
57DXMShEEb458ZKuoou8N8jZ1gBpwcl4lvm1DwIDAQABAoIBAF20nYdvfBGyzbFO
7SQ6nneAaG15sOcqkJH0dV6qsjhcSyKirPVbWiNJBQt+4ZkZDSxkgG2mx+QUs8iN
AlQr0JrLHa5Eh2LSsdTrtq4QQprx1rnE2mawq4pjyYZBxIVemSx7datRNB6Ko1me
7iEF999dIKDwBAK8phgTZBMi2wr42K8Hg5tZS5Ddn2Rf9TCbFBj8brl9U4D7jak7
5Epn7p8i4WsXZy2fngKnRmsZ7mwusSL2ylFUe6K88gBv3eyYdt9nJyw5NjpMd0bo
ZHjtxUnIYUhh7UVp5iXII4znisIcmM7RiDKFvvhAbm6/tbHLpo8cBZCA36wul2jP
MWIMLgECgYEA9HbIZLJcTMCohFvhzJkQeNVGyznvK/A5QVIkkfVDGbQRtht3EzKP
jFydvC8BxswTc15mP9u9AuPNWfZaLr0Q8CUwn6rhdnWkr7bXt8XVccfRs5Ho/eHc
87Agv53j6R22jYPSunw2Xc9UOUxMdEQTJxKUjoTo29PkgNTD5kNmPBMCgYEAyV7n
NyWKBncIn9rAFqPeWphV5fghJsAwYhB9VRQnQ/3CehJSC9+SP2lJQmTrabL8QwSM
7CvUqJAbDIiAG45g/Y1Q9/zDVBiESvCm7mK2jv1gBtersnLy2tuFNju3CDiFa4WQ
5nxL57LkJhiyomUmlK/Aocx5g4v/qiYr1q1gCpUCgYEApx2AVh37rNhTGtA45oWI
ViHuGEVNc6rvaPD/YOvZ5/tJ1ESoPO5mZRx3E8rKmxys+0QAAA12A0C5A5O+CI9k
wdWajLvjDvjTEO+cPdu20uY3O1s2fD/nrIqtiHAl+hk+zzTbXHJHNA/kUpsO9LgI
o8A238qJ6KTMYymPlZxjihMCgYAedX1xyPrUuYKTc2okwoqql2o+y8Zv7xgibS4Y
BWFfFm4pOsYwR5P+hXVwVoWJSmp/1JtgSczz5kBBKBCAmouvLoX1zMTa3o58K2SE
oGfOvyKcRlkRN/PmCNhgeK3Zz3rW5bAiPODaXiPGY2v5xmUMjn0LvDsRG8cDPJza
7wSc9QKBgCODUTNFzyBujazUPHwBD8AJTtLFNFawDcW/xovLEnpKetHP3EuGvJ90
/1sgGlrtdXI2jTZDLB1ymAC85ipSa7ohGoSMaLZ6+/DXBxlXVc06TjQkJuq4PRvm
vuxA4VAznt+m9Oyb22ZRwPOTnsFrcAicQ+m+GjNEOwUurjjQgQn/
-----END RSA PRIVATE KEY-----
`)
var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwEvjwH002eYWWX72Jkhb
uGyBIyjFx0Y35FY/QWlOQs9KYVRC4tL6WIW1xpKS6uxMfAmYAFB2FUNl0EuAhcG0
o11Pd0vYTKZi0Y0s1wN34aOKWoN/EQTDbF8Rx6hb441TtkomRlb0EfIp2IPo6dgu
/BBqsaPzlMhoT3eBFBBGI5CmCsknJyMskMaP9wMN87NaQiMqs7MOcW5fcpzhcahi
4a46jSajeMqswNB+d/gq5u0Py2oLQtBc47AiPfhKAoSuh6cYlGiHwwX6S+q7daWj
2Eko2O7mAFkiS2DG0f+vfYorJfHr57DXMShEEb458ZKuoou8N8jZ1gBpwcl4lvm1
DwIDAQAB
-----END PUBLIC KEY-----
`)

var (
	addr    string
	pubKey  string
	privKey string
)

func main() {
	if len(privKey) > 0 {
		var err error
		if len(pubKey) < 1 {
			panic("path to public key ???")
		}
		privateKey, err = os.ReadFile(privKey)
		if err != nil {
			panic(err)
		}

		publicKey, err = os.ReadFile(pubKey)
		if err != nil {
			panic(err)
		}
	}

	var upgrader = websocket.Upgrader{}
	var channelTCP = make(map[string]*packet.ChannelTCPData, 0)

	// clear data old
	go func() {
		for k, v := range channelTCP {
			if time.Now().After(v.Date.Add(15 * time.Minute)) {
				delete(channelTCP, k)
			}
		}
	}()

	http.HandleFunc(constant.DEFAULT_ENDPOINT_KEY, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, string(publicKey))
	})

	http.HandleFunc(constant.DEFAULT_ENDPOINT_HTTP, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			id := r.Header.Get("X-Id")
			if len(id) < 1 {
				http.NotFound(w, r)
				return
			}

			channelData, found := channelTCP[id]
			if !found {
				http.NotFound(w, r)
				return
			}

			select {
			case body := <-channelData.IO:
				w.Write(body)
				return
			case <-time.After(10 * time.Second):
				w.Write([]byte(""))
				return
			}
		} else if r.Method == http.MethodDelete {
			id := r.Header.Get("X-Id")
			if len(id) > 0 {
				channelData, found := channelTCP[id]
				if found {
					channelData.Dst.Close()
					delete(channelTCP, id)
				}
			}
			w.Write([]byte("OK"))
			return
		} else if r.Method == http.MethodPut {
			id := r.Header.Get("X-Id")
			if len(id) < 1 {
				http.NotFound(w, r)
				return
			}

			channelData, found := channelTCP[id]
			if !found {
				http.NotFound(w, r)
				return
			}

			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.NotFound(w, r)
				return
			}

			packet.ForwardHTTP(channelData, body)
			w.Write([]byte("OK"))
			return
		} else if r.Method == http.MethodPost {
			target := r.Header.Get("For")
			if len(target) < 1 {
				http.NotFound(w, r)
				return
			}

			keyStr := r.Header.Get("Etag")
			if len(keyStr) < 1 {
				http.NotFound(w, r)
				return
			}

			id := r.Header.Get("X-Id")
			if len(id) < 1 {
				http.NotFound(w, r)
				return
			}

			_, found := channelTCP[id]
			if found {
				http.NotFound(w, r)
				return
			}
			var newChannel = &packet.ChannelTCPData{}
			newChannel.IO = make(chan []byte, 10)
			newChannel.Date = time.Now()

			ciphertext, err := base64.URLEncoding.DecodeString(keyStr)
			if err != nil {
				http.NotFound(w, r)
				return
			}

			keyAES, err := crypto.RsaDecrypt(privateKey, ciphertext)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			newChannel.Key = keyAES
			remoteConn, err := net.Dial("tcp", target)
			if err != nil {
				log.Printf("Error: %s", err.Error())
				return
			}
			newChannel.Dst = remoteConn
			channelTCP[id] = newChannel
			go packet.CopyHTTP(channelTCP[id], remoteConn)
			w.Write([]byte("OK"))
			return
		}
	})

	http.HandleFunc(constant.DEFAULT_ENDPOINT_FFW, func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("For")
		if len(target) < 1 {
			http.NotFound(w, r)
			return
		}

		keyStr := r.Header.Get("Etag")
		if len(keyStr) < 1 {
			http.NotFound(w, r)
			return
		}

		currentConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Print("upgrade:", err)
			return
		}
		defer currentConn.Close()

		ciphertext, err := base64.URLEncoding.DecodeString(keyStr)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		keyAES, err := crypto.RsaDecrypt(privateKey, ciphertext)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		remoteConn, err := net.Dial("tcp", target)
		if err != nil {
			log.Printf("Error: %s", err.Error())
			return
		}
		defer remoteConn.Close()

		go packet.ForwardWebSocket(remoteConn, currentConn, keyAES)
		packet.CopyWebSocket(currentConn, remoteConn, keyAES)
	})
	log.Printf("[http-tunnel %s] Server run on: %s\n", constant.VERSION, addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.StringVar(&addr, "addr", "127.0.0.1:80", "Listening HTTP IP and Port address (ip:port)")
	flag.StringVar(&pubKey, "pub", "", "Path to public key")
	flag.StringVar(&privKey, "priv", "", "Path to private key")
	flag.Parse()
}
