package packet

import (
	"bytes"
	"crypto/tls"
	"ffw/crypto"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fasthttp/websocket"
)

type ChannelTCPData struct {
	IO   chan []byte
	Date time.Time
	Key  []byte
	Dst  net.Conn
}

func ForwardWebSocket(dst io.Writer, src *websocket.Conn, keyEn []byte) (written int64, err error) {
	for {
		_, message, err := src.ReadMessage()
		if err != nil {
			break
		}

		message, err = crypto.AESDecrypt(keyEn, message)
		if err != nil {
			break
		}

		_, err = dst.Write(message)
		if err != nil {
			break
		}
	}
	return written, err
}

func CopyWebSocket(dst *websocket.Conn, src io.Reader, keyEn []byte) (written int64, err error) {
	size := 32 * 1024
	buf := make([]byte, size)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			payload := buf[0:nr]
			payload, err = crypto.AESEncrypt(keyEn, payload)
			if err != nil {
				return
			}

			ew := dst.WriteMessage(websocket.BinaryMessage, payload)
			if ew != nil {
				err = ew
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func CopyHTTP(dst *ChannelTCPData, src io.Reader) (written int64, err error) {
	size := 32 * 1024
	buf := make([]byte, size)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			payload := buf[0:nr]
			payload, err = crypto.AESEncrypt(dst.Key, payload)
			if err != nil {
				return
			}
			dst.IO <- payload
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func ForwardHTTP(dst *ChannelTCPData, message []byte) (written int, err error) {
	message, err = crypto.AESDecrypt(dst.Key, message)
	if err != nil {
		return
	}

	written, err = dst.Dst.Write(message)
	dst.Date = time.Now()
	return
}

func CreateTunnel(url string, headers http.Header) (err error) {
	_, _, err = MakeHTTPRequest(url, http.MethodPost, headers, nil)
	return
}

func CopyTunnel(url string, headers http.Header, conn net.Conn, key []byte) {
	for {
		message, statusCode, err := MakeHTTPRequest(url, http.MethodGet, headers, nil)
		if err != nil {
			log.Printf("recv data: %v", err)
			break
		}

		if len(message) <= 0 {
			continue
		}

		if statusCode == http.StatusNotFound {
			break
		}

		messageDe, err := crypto.AESDecrypt(key, message)
		if err != nil {
			log.Printf("decrypt data: %v", err)
			break
		}

		_, err = conn.Write(messageDe)
		if err != nil {
			log.Printf("write data: %v", err)
			break
		}
	}
}

func ForwardTunnel(url string, headers http.Header, conn net.Conn, key []byte) (err error) {
	size := 32 * 1024
	buf := make([]byte, size)
	for {
		nr, er := conn.Read(buf)
		if nr > 0 {
			payload := buf[0:nr]
			payload, er = crypto.AESEncrypt(key, payload)
			if err != nil {
				err = fmt.Errorf("encrypt data: %v", er)
				break
			}

			_, _, er = MakeHTTPRequest(url, http.MethodPut, headers, payload)
			if err != nil {
				err = fmt.Errorf("send data: %v", er)
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				if !strings.Contains(er.Error(), "An existing connection was forcibly closed by the remote host") {
					err = fmt.Errorf("read data from client: %v", er)
				}
			}
			break
		}
	}

	_, _, err = MakeHTTPRequest(url, http.MethodDelete, headers, nil)
	if err != nil {
		err = fmt.Errorf("close data: %v", err)
	}
	return
}

func MakeHTTPRequest(url, method string, headers http.Header, payload []byte) ([]byte, int, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   time.Second * 15,
		Transport: tr,
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v[0])
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 OPR/89.0.4447.6")

	response, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, 0, err
	}

	return body, response.StatusCode, err
}
