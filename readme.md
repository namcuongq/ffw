# Go FFW (F*** Firewall) - HTTP tunnel v2.0

Go FFW is a reverse tunnel based on [fasthttp](https://github.com/valyala/fasthttp) and [websocket](https://github.com/fasthttp/websocket). It comes in to play by acting as a middle man in relaying the traffic between your blocked applications using http which is normally not blocked and to the destination server, effectively bypassing the restrictions on firewall.

Features:

* Sock5 proxy
* TCP proxy
* All data is encrypted
* Easy to use CLI
* Support websocket or http request

Common use cases:

* Bypass Blocked Sites
* Bypass blocked protocols (ssh,ftp,...)
* Get reverse Shell - Bypass firewall
* Pivot network

## How it works

How it works is based on the following model

![model](https://github.com/namcuongq/ffw/raw/main/images/work.png)

## Running

There are two executables:

* [ffwd](https://github.com/namcuongq/ffw/releases) - the tunnel server, to be run on publicly available host like VPS
* [ffwc](https://github.com/namcuongq/ffw/releases) - the tunnel client, to be run on your local machine or in your private network

To get help on the command parameters run ffwd -h or ffwc -h.

An encrypted tunnel requires the generation of public and private keys

```bash
$ openssl genrsa -out key.pem
$ openssl rsa -in key.pem -pubout > key-pub.pem
```

On server:

```bash
$ ffwd --addr 0.0.0.0:80 --priv key.pem --pub key-pub.pem
```

This will run HTTP server on port `80`.

On client:

```bash
$ ffwc --addr 127.0.0.1:1995 --server 127.0.0.1:80 --ignore 127.0.0.1,*.google.com --mode http
```

This will run SOCK5 proxy server on port `1995`. Configuring your application to use socks proxy.

## Donation

A GitHub star is always appreciated!
