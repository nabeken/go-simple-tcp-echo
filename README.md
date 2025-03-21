# go-simple-tcp-echo

`go-simple-tcp-echo` is a simple TCP + TLS echo server in Go to test networking stack including TLS stack.

```
go-simple-tcp-echo is a simple TCP echo server written in Go.

Usage:
  go-simple-tcp-echo [flags] IP_ADDR:PORT

Flags:
      --cert string               specify a path to load public SSL certificate
      --disable-greeting          disable a greeting message on new connection
      --disable-session-tickets   specify to disable TLS Session Tickets
  -h, --help                      help for go-simple-tcp-echo
      --key string                specify a path to load private SSL certificate
      --server-name string        specify a server name (default "node.example.com")
      --use-key-log               specify to use TLS Key Log
      --use-tls12                 specify to use TLS 1.2 only
```

## Generate a cert

You can use the script in Go's distribution:
```console
go run $(go env GOROOT)/src/crypto/tls/generate_cert.go --host localhost
```

You can find a test cert in `cert.pem` and its key in `key.pem`.
