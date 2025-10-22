package server

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sshwebdoor/internal/config"
)

//go:embed templates/login.html
var loginPage string

type Server struct {
	cfg     config.Config
	tracker *attemptTracker
	tmpl    *template.Template
	logger  *log.Logger
	tlsConf *tls.Config
}

// New constructs a server instance ready to accept connections.
func New(cfg config.Config) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}

	tmpl, err := template.New("login").Parse(loginPage)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	srv := &Server{
		cfg:     cfg,
		tracker: newAttemptTracker(cfg.MaxAttempts, time.Duration(cfg.LockoutSeconds)*time.Second, time.Duration(cfg.AttemptWindowSeconds)*time.Second),
		tmpl:    tmpl,
		logger:  log.New(os.Stdout, "sshwebdoor: ", log.LstdFlags),
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	return srv, nil
}

// Serve starts accepting connections until the context is cancelled or an unrecoverable error occurs.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	s.logger.Printf("listening on %s and forwarding SSH to %s", s.cfg.ListenAddress, s.cfg.SSHForward)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Printf("accept error: %v", err)
			return err
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	header := make([]byte, 5)
	n, err := io.ReadAtLeast(conn, header, 5)
	if err != nil {
		s.logger.Printf("read header: %v", err)
		return
	}
	header = header[:n]

	if isTLSRecord(header) {
		s.handleTLSConnection(conn, header)
		return
	}
	s.handleSSHConnection(conn, header)
}

func (s *Server) handleTLSConnection(conn net.Conn, header []byte) {
	pc := newPeekConn(conn, header)
	tlsConn := tls.Server(pc, s.tlsConf)
	defer tlsConn.Close()

	handler := &webHandler{
		tmpl:    s.tmpl,
		tracker: s.tracker,
		hash:    s.cfg.PasswordHash,
		logger:  s.logger,
	}

	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       15 * time.Second,
	}

	l := &singleConnListener{conn: tlsConn}
	if err := httpServer.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Printf("http serve error: %v", err)
	}
}

func (s *Server) handleSSHConnection(client net.Conn, header []byte) {
	backend, err := net.DialTimeout("tcp", s.cfg.SSHForward, 10*time.Second)
	if err != nil {
		s.logger.Printf("ssh dial error: %v", err)
		return
	}
	defer backend.Close()

	if _, err := backend.Write(header); err != nil {
		s.logger.Printf("ssh write header: %v", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(backend, client)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, backend)
	}()

	wg.Wait()
}

func isTLSRecord(header []byte) bool {
	if len(header) < 3 {
		return false
	}
	if header[0] != 0x16 {
		return false
	}
	if header[1] != 0x03 {
		return false
	}
	// Accept TLS 1.0 - 1.3
	if header[2] < 0x00 || header[2] > 0x03 {
		return false
	}
	return true
}

type peekConn struct {
	net.Conn
	reader io.Reader
}

func newPeekConn(conn net.Conn, header []byte) net.Conn {
	return &peekConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(header), conn),
	}
}

func (p *peekConn) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
	err  error
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = l.conn
		l.conn = nil
	})
	if c == nil {
		return nil, io.EOF
	}
	return c, nil
}

func (l *singleConnListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

type webHandler struct {
	tmpl    *template.Template
	tracker *attemptTracker
	hash    string
	logger  *log.Logger
}

func (h *webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, ip)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			h.render(w, pageData{Message: "Failed to parse form."})
			return
		}
		password := r.FormValue("password")
		h.handlePost(w, ip, password)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *webHandler) handleGet(w http.ResponseWriter, ip string) {
	locked, remaining, attempts := h.tracker.status(ip)
	data := pageData{
		AttemptsLeft: attempts,
	}
	if locked {
		data.Locked = true
		data.LockoutRemainingSeconds = int(remaining.Seconds())
		data.Message = fmt.Sprintf("Too many attempts. Try again in %d seconds.", int(remaining.Seconds()))
	}
	h.render(w, data)
}

func (h *webHandler) handlePost(w http.ResponseWriter, ip, password string) {
	locked, remaining, _ := h.tracker.status(ip)
	if locked {
		data := pageData{
			Locked:                  true,
			LockoutRemainingSeconds: int(remaining.Seconds()),
			Message:                 fmt.Sprintf("Too many attempts. Try again in %d seconds.", int(remaining.Seconds())),
		}
		h.render(w, data)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(h.hash), []byte(password)); err == nil {
		h.tracker.recordSuccess(ip)
		h.render(w, pageData{Message: "Access granted.", Success: true})
		return
	}

	attemptsLeft, nowLocked, lockout := h.tracker.recordFailure(ip)
	data := pageData{
		Message:      "Incorrect password.",
		AttemptsLeft: attemptsLeft,
	}
	if nowLocked {
		data.Locked = true
		data.LockoutRemainingSeconds = int(lockout.Seconds())
		data.Message = fmt.Sprintf("Too many attempts. Locked for %d seconds.", int(lockout.Seconds()))
	}
	h.render(w, data)
}

func (h *webHandler) render(w http.ResponseWriter, data pageData) {
	if err := h.tmpl.Execute(w, data); err != nil {
		h.logger.Printf("template execute: %v", err)
	}
}

type pageData struct {
	Message                 string
	Success                 bool
	Locked                  bool
	AttemptsLeft            int
	LockoutRemainingSeconds int
}
