package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sshwebdoor/internal/config"
	"sshwebdoor/internal/web"
)

type Server struct {
	cfg       config.Config
	tracker   *AttemptTracker
	tlsConfig *tls.Config
	logger    *log.Logger
}

func New(cfg config.Config, logger *log.Logger) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load tls certificate: %w", err)
	}
	cfg.ApplyDefaults()
	return &Server{
		cfg:     cfg,
		tracker: NewAttemptTracker(cfg.MaxAttempts, time.Duration(cfg.AttemptWindowSeconds)*time.Second, time.Duration(cfg.LockoutSeconds)*time.Second),
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		logger: logger,
	}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.logger.Printf("listening on %s", s.cfg.ListenAddress)

	var wg sync.WaitGroup
	acceptErr := make(chan error, 1)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					s.logger.Printf("temporary accept error: %v", err)
					continue
				}
				acceptErr <- err
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				s.handleConnection(ctx, c)
			}(conn)
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Printf("context canceled, shutting down listener")
	case err := <-acceptErr:
		if !errors.Is(err, net.ErrClosed) {
			ln.Close()
			wg.Wait()
			return err
		}
	}

	ln.Close()
	wg.Wait()
	return nil
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	remote := stripPort(conn.RemoteAddr().String())
	reader := bufio.NewReader(conn)
	bufConn := &bufferedConn{Conn: conn, reader: reader}

	if isTLS(reader) {
		if err := s.serveHTTPS(bufConn, remote); err != nil && !errors.Is(err, io.EOF) {
			s.logger.Printf("https handling failed for %s: %v", remote, err)
		}
		return
	}
	if err := s.proxySSH(ctx, bufConn, remote); err != nil && !errors.Is(err, io.EOF) {
		s.logger.Printf("ssh proxy failed for %s: %v", remote, err)
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func isTLS(reader *bufio.Reader) bool {
	header, err := reader.Peek(5)
	if err != nil {
		return false
	}
	if header[0] != 0x16 {
		return false
	}
	version := uint16(header[1])<<8 | uint16(header[2])
	return version >= 0x0301 && version <= 0x0304
}

func (s *Server) serveHTTPS(conn net.Conn, remote string) error {
	tlsConn := tls.Server(conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()

	tpl, err := web.LoginTemplate()
	if err != nil {
		return fmt.Errorf("load template: %w", err)
	}

	handler := &portalHandler{
		cfg:        s.cfg,
		tracker:    s.tracker,
		template:   tpl,
		remoteAddr: remote,
		logger:     s.logger,
	}

	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	listener := &singleConnListener{conn: tlsConn}
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (s *Server) proxySSH(ctx context.Context, clientConn net.Conn, remote string) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	backendConn, err := dialer.DialContext(ctx, "tcp", s.cfg.SSHForward)
	if err != nil {
		return fmt.Errorf("dial backend ssh %s: %w", s.cfg.SSHForward, err)
	}
	defer backendConn.Close()

	s.logger.Printf("forwarding ssh session from %s to %s", remote, s.cfg.SSHForward)

	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(backendConn, clientConn)
		if tcp, ok := backendConn.(*net.TCPConn); ok {
			tcp.CloseWrite()
		} else {
			backendConn.Close()
		}
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(clientConn, backendConn)
		if tcp, ok := clientConn.(*net.TCPConn); ok {
			tcp.CloseWrite()
		} else {
			clientConn.Close()
		}
		done <- struct{}{}
	}()

	<-done
	return nil
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
	used bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() {
		conn = l.conn
		l.used = true
	})
	if conn != nil {
		return conn, nil
	}
	return nil, io.EOF
}

func (l *singleConnListener) Close() error {
	if l.used {
		return nil
	}
	l.used = true
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func stripPort(addr string) string {
	if i := strings.LastIndex(addr, ":"); i != -1 {
		return addr[:i]
	}
	return addr
}

type portalHandler struct {
	cfg        config.Config
	tracker    *AttemptTracker
	template   *template.Template
	remoteAddr string
	logger     *log.Logger
}

func (h *portalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	remaining, lockoutUntil := h.tracker.AttemptsRemaining(h.remoteAddr)
	if lockoutUntil.After(time.Now()) {
		h.render(w, http.StatusTooManyRequests, templateData{
			Locked:            true,
			LockoutRemaining:  formatDuration(time.Until(lockoutUntil)),
			AttemptsRemaining: 0,
			Message:           "Too many failed attempts. Please wait before trying again.",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.render(w, http.StatusOK, templateData{AttemptsRemaining: remaining})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			h.render(w, http.StatusBadRequest, templateData{
				AttemptsRemaining: remaining,
				Message:           "Invalid form submission.",
			})
			return
		}
		password := r.FormValue("password")
		if err := bcrypt.CompareHashAndPassword([]byte(h.cfg.PasswordHash), []byte(password)); err != nil {
			remaining, locked := h.tracker.RegisterFailure(h.remoteAddr)
			if !locked.IsZero() {
				h.render(w, http.StatusTooManyRequests, templateData{
					Locked:            true,
					LockoutRemaining:  formatDuration(time.Until(locked)),
					AttemptsRemaining: 0,
					Message:           "Password incorrect. Access temporarily locked.",
				})
				return
			}
			h.render(w, http.StatusUnauthorized, templateData{
				AttemptsRemaining: remaining,
				Message:           "Password incorrect.",
			})
			return
		}

		h.tracker.RegisterSuccess(h.remoteAddr)
		h.render(w, http.StatusOK, templateData{
			AttemptsRemaining: h.cfg.MaxAttempts,
			Success:           true,
			Message:           "Access granted. You may proceed with SSH or administrative tasks.",
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type templateData struct {
	AttemptsRemaining int
	Locked            bool
	LockoutRemaining  string
	Message           string
	Success           bool
}

func (h *portalHandler) render(w http.ResponseWriter, status int, data templateData) {
	w.WriteHeader(status)
	if err := h.template.Execute(w, data); err != nil {
		h.logger.Printf("template execute error: %v", err)
	}
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Minute {
		seconds := int(d.Seconds())
		if seconds <= 0 {
			seconds = 1
		}
		return fmt.Sprintf("%ds", seconds)
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	if seconds == 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%dm %ds", minutes, seconds)
}
