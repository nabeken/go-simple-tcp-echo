package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	stdslog "log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	if err := realmain(); err != nil {
		stdslog.Error(err.Error())
		os.Exit(1)
	}
}

type sessionState int

func realmain() error {
	var serverName string
	var certPath string
	var keyPath string
	var useTLS12 bool
	var useKeyLog bool
	var disableSessionTickets bool
	var disableGreeting bool

	rootCmd := &cobra.Command{
		Use:   "go-simple-tcp-echo [flags] IP_ADDR:PORT",
		Short: "go-simple-tcp-echo is a simple TCP echo server written in Go.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]

			stdslog.Info(fmt.Sprintf("Listening to %s...", addr))

			srv, err := NewServer(
				serverName,
				certPath, keyPath,
				useTLS12, useKeyLog, disableSessionTickets, disableGreeting,
			)
			if err != nil {
				return fmt.Errorf("creating a server: %w", err)
			}

			l, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listening to: %w", err)
			}

			defer l.Close()

			for {
				conn, err := l.Accept()
				if err != nil {
					return fmt.Errorf("accepting a new connection: %w", err)
				}

				srv.serveConn(conn)
			}
		},
	}

	rootCmd.Flags().StringVar(
		&serverName,
		"server-name",
		"node.example.com",
		"specify a server name",
	)

	rootCmd.Flags().StringVar(
		&certPath,
		"cert",
		"",
		"specify a path to load public SSL certificate",
	)
	rootCmd.Flags().StringVar(
		&keyPath,
		"key",
		"",
		"specify a path to load private SSL certificate",
	)
	rootCmd.Flags().BoolVar(
		&useTLS12,
		"use-tls12",
		false,
		"specify to use TLS 1.2 only",
	)
	rootCmd.Flags().BoolVar(
		&useKeyLog,
		"use-key-log",
		false,
		"specify to use TLS Key Log",
	)
	rootCmd.Flags().BoolVar(
		&disableSessionTickets,
		"disable-session-tickets",
		false,
		"specify to disable TLS Session Tickets",
	)
	rootCmd.Flags().BoolVar(
		&disableGreeting,
		"disable-greeting",
		false,
		"disable a greeting message on new connection",
	)
	return rootCmd.Execute()
}

type server struct {
	hostname  string
	tlsConfig *tls.Config

	useKeyLog       bool
	disableGreeting bool
}

func NewServer(hostname, certPath, keyPath string, useTLS12, useKeyLog, disableSessionTickets, disableGreeting bool) (*server, error) {
	srv := server{hostname: hostname, useKeyLog: useKeyLog}

	if certPath == "" || keyPath == "" {
		stdslog.Info("Skipped loading cert and key")
		return &srv, nil
	}

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading the certificates: %w", err)
	}

	tlsConfig := tls.Config{
		Certificates:           []tls.Certificate{tlsCert},
		SessionTicketsDisabled: disableSessionTickets,
	}

	if useTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
	}

	return &server{
		hostname:  hostname,
		tlsConfig: &tlsConfig,

		useKeyLog:       useKeyLog,
		disableGreeting: disableGreeting,
	}, nil
}

func (s *server) serveConn(conn net.Conn) {
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	l := stdslog.With(
		"remote_addr", conn.RemoteAddr(),
	)

	defer func() {
		l.Info("Closing the connection...")
		conn.Close()
	}()

	// start TLS handshake if requested
	if s.tlsConfig != nil {
		l.Info("Starting TLS handshake...")

		tlsConn := tls.Server(conn, s.tlsConfig)
		err := tlsConn.Handshake()

		connState := tlsConn.ConnectionState()
		l = stdslog.With(
			"connection_state", stdslog.GroupValue(
				stdslog.String("version", tls.VersionName(connState.Version)),
				stdslog.Bool("handshake_complete", connState.HandshakeComplete),
				stdslog.Bool("did_resume", connState.DidResume),
				stdslog.String("cipher_suite", tls.CipherSuiteName(connState.CipherSuite)),
				stdslog.String("negotiated_protocol", connState.NegotiatedProtocol),
				stdslog.String("server_name", connState.ServerName),
			),
		)

		if err != nil {
			l.Info("TLS handshake failed",
				"error", err,
			)
			return

		} else {
			l = l.With("in_tls", true)

			l.Info("TLS handshake completed successfully",
				"error", err,
			)

			// reinstall bw and br
			conn = tlsConn
			br = bufio.NewReader(conn)
			bw = bufio.NewWriter(conn)
		}
	}

	dumpPrefix := fmt.Sprintf("%d-%s", time.Now().UTC().Unix(), conn)

	tlsConfig := s.tlsConfig.Clone()

	if s.useKeyLog {
		keyLogFn := fmt.Sprintf("%s-keylog.txt", dumpPrefix)
		f, err := os.Create(keyLogFn)
		if err != nil {
			l.Error("Failed to create a key log file", "error", err.Error())
			return
		}
		defer f.Close()

		l.Info("Writing key log file", "file", f.Name())

		tlsConfig.KeyLogWriter = f
	}

	if !s.disableGreeting {
		writeReplyAndFlush(l, bw, fmt.Sprintf("%s is ready to say hi to %s", s.hostname, conn.RemoteAddr()))
	}

	for {
		line, err := readLine(br)

		if err != nil {
			l.Error("Failed to read a line", "error", err.Error())
			break
		}

		writeReplyAndFlush(l, bw, line)
	}
}

func writeReplyAndFlush(l *stdslog.Logger, bw *bufio.Writer, reply string) {
	fmt.Fprintf(bw, "%s\n", reply)

	if err := bw.Flush(); err != nil {
		l.Info("Failed to flush the write", "error", err.Error())
	}
}

func readLine(br *bufio.Reader) (string, error) {
	l_, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.Trim(strings.Trim(l_, "\n"), "\r"), nil
}
