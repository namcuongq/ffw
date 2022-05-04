package packet

import (
	"ffw/crypto"
	"io"

	"github.com/fasthttp/websocket"
)

func Forward(dst io.Writer, src *websocket.Conn, keyEn []byte) (written int64, err error) {
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

func Copy(dst *websocket.Conn, src io.Reader, keyEn []byte) (written int64, err error) {
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
