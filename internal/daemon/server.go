package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sshwebdoor/internal/config"
	"sshwebdoor/internal/web"
)

type Server struct {
	cfg       *config.Config
	tlsConfig *tls.Config
	attempts  *attemptManager
	logger    *log.Logger
}

func NewServer(cfg *config.Config, logger *log.Logger) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificates: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		cfg:       cfg,
		tlsConfig: tlsCfg,
		attempts:  newAttemptManager(cfg),
		logger:    logger,
	}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.ListenAddress, err)
	}
	defer listener.Close()
	s.logger.Printf("listening on %s and forwarding SSH to %s", s.cfg.ListenAddress, s.cfg.SSHForward)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				s.logger.Printf("temporary accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("accept connection: %w", err)
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remoteHost := remoteOnly(conn.RemoteAddr())
	buf := bufio.NewReader(conn)
	if looksLikeTLS(buf) {
		s.logger.Printf("connection from %s detected as HTTPS", remoteHost)
		if err := s.handleHTTPS(conn, buf, remoteHost); err != nil && !errors.Is(err, io.EOF) {
			s.logger.Printf("https handler error for %s: %v", remoteHost, err)
		}
		return
	}
	s.logger.Printf("connection from %s treated as SSH", remoteHost)
	if err := s.handleSSH(conn, buf); err != nil && !errors.Is(err, io.EOF) {
		s.logger.Printf("ssh proxy error for %s: %v", remoteHost, err)
	}
}

func (s *Server) handleHTTPS(conn net.Conn, buf *bufio.Reader, remote string) error {
	bconn := &bufferedConn{Conn: conn, reader: buf}
	tlsConn := tls.Server(bconn, s.tlsConfig.Clone())
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}

	reader := bufio.NewReader(tlsConn)
	writer := bufio.NewWriter(tlsConn)

	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	defer req.Body.Close()

	var body string
	status := http.StatusOK

	locked, remaining, unlock := s.attempts.status(remote)
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/":
		if locked {
			remainingLock := int(time.Until(unlock).Seconds())
			if remainingLock < 0 {
				remainingLock = 0
			}
			body, err = web.RenderPage(web.PageData{Locked: true, LockSeconds: remainingLock})
		} else {
			body, err = web.RenderPage(web.PageData{Remaining: remaining})
		}
	case req.Method == http.MethodPost && req.URL.Path == "/login":
		if err := req.ParseForm(); err != nil {
			status = http.StatusBadRequest
			body, _ = web.RenderPage(web.PageData{Message: "invalid form submission"})
			break
		}
		if locked {
			remainingLock := int(time.Until(unlock).Seconds())
			if remainingLock < 0 {
				remainingLock = 0
			}
			body, err = web.RenderPage(web.PageData{Locked: true, LockSeconds: remainingLock})
			break
		}
		password := req.PostFormValue("password")
		if err := bcrypt.CompareHashAndPassword([]byte(s.cfg.PasswordHash), []byte(password)); err != nil {
			remaining, lockUntil := s.attempts.recordFailure(remote)
			if !lockUntil.IsZero() {
				remainingLock := int(time.Until(lockUntil).Seconds())
				if remainingLock < 0 {
					remainingLock = 0
				}
				body, err = web.RenderPage(web.PageData{Locked: true, LockSeconds: remainingLock, Message: "Too many incorrect attempts."})
			} else {
				body, err = web.RenderPage(web.PageData{Remaining: remaining, Message: "Incorrect password."})
			}
			break
		}
		s.attempts.recordSuccess(remote)
		body, err = web.RenderPage(web.PageData{Success: true, Message: "Authentication successful."})
	default:
		status = http.StatusNotFound
		body = "Not Found"
	}

	if err != nil {
		return fmt.Errorf("render page: %w", err)
	}

	if status != http.StatusOK && !strings.HasPrefix(body, "<") {
		body = fmt.Sprintf("<html><body><h1>%d %s</h1><p>%s</p></body></html>", status, http.StatusText(status), body)
	}

	if err := writeResponse(writer, status, body); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	return nil
}

func (s *Server) handleSSH(conn net.Conn, buf *bufio.Reader) error {
	upstream, err := net.DialTimeout("tcp", s.cfg.SSHForward, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial upstream ssh: %w", err)
	}
	defer upstream.Close()

	bconn := &bufferedConn{Conn: conn, reader: buf}

	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(upstream, bconn)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(conn, upstream)
		errCh <- err
	}()

	if err := <-errCh; err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func writeResponse(w *bufio.Writer, status int, body string) error {
	if body == "" {
		body = http.StatusText(status)
	}
	header := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", status, http.StatusText(status), len(body))
	if _, err := w.WriteString(header); err != nil {
		return err
	}
	if _, err := w.WriteString(body); err != nil {
		return err
	}
	return w.Flush()
}

func looksLikeTLS(reader *bufio.Reader) bool {
	b, err := reader.Peek(1)
	if err != nil {
		return false
	}
	if b[0] != 0x16 {
		return false
	}
	header, err := reader.Peek(3)
	if err != nil {
		return false
	}
	version := header[1]
	return version == 0x03
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func remoteOnly(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
