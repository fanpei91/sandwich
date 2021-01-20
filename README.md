# sandwich

A fucking simple, smart, and tun-based(powered by gVisor TCP/IP stack) transparent proxy for the people in China Mainland.

# Server
1. compile from source code for your Linux server:
```bash
GOOS=linux GOARCH=amd64 go build -o ~/sandwich-amd64-linux .
```
2. use [acme.sh](https://github.com/acmesh-official/acme.sh) to ask for the certificate of Let's Encrypt.
3. execute the command on the server:
```bash
~/sandwich-amd64-linux -cert-file=/root/.acme.sh/<youdomain.com>/fullchain.cer 
 -private-key-file=/root/.acme.sh/<youdomain.com>/<youdomain.com>.key
 -listen-addr=:443 
 -server-mode=true
 -secret-key=key
```

# Client(macOS only)
1. compile from source code for your macOS:
```bash
go build -o ~/sandwich-amd64-darwin .
```

2. execute the command on your macOS:

```bash
sudo ~/sandwich-amd64-darwin -server-addr=<yourdomain:443> -secret-key=key
```

# Credits
* [gVisor](https://github.com/google/gvisor)
* [Clash](https://github.com/Dreamacro/clash)
* [tun2socks](https://github.com/xjasonlyu/tun2socks)
