package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sshwebdoor/config"
)

//go:embed login.html
var loginHTML embed.FS

type Server struct {
	cfg      config.Config
	attempts *attemptTracker
	handler  http.Handler
	certMu   sync.Mutex
	tlsConf  *tls.Config
}

func New(cfg config.Config) (*Server, error) {
	tplBytes, err := loginHTML.ReadFile("login.html")
	if err != nil {
		return nil, fmt.Errorf("load login template: %w", err)
	}
	tpl, err := template.New("login").Parse(string(tplBytes))
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}

	attempts := newAttemptTracker(cfg.MaxAttempts, cfg.LockoutSeconds, cfg.AttemptWindowSeconds)
	s := &Server{
		cfg:      cfg,
		attempts: attempts,
	}

	h := &loginHandler{
		cfg:      cfg,
		attempts: attempts,
		tpl:      tpl,
	}
	s.handler = h

	return s, nil
}

func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	log.Printf("listening on %s", s.cfg.ListenAddress)
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("temporary accept error: %v", err)
				continue
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	peek, err := reader.Peek(1)
	if err != nil {
		return
	}
	if len(peek) > 0 && peek[0] == 0x16 {
		s.handleHTTPS(reader, conn)
		return
	}
	s.handleSSH(reader, conn)
}

func (s *Server) handleHTTPS(reader *bufio.Reader, conn net.Conn) {
	tlsConf, err := s.tlsConfig()
	if err != nil {
		log.Printf("tls config error: %v", err)
		return
	}
	tlsConn := tls.Server(&bufferedConn{Conn: conn, Reader: reader}, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("tls handshake error: %v", err)
		return
	}
	defer tlsConn.Close()

	srv := &http.Server{
		Handler: s.handler,
	}
	if err := srv.Serve(&singleConnListener{conn: tlsConn}); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("http serve error: %v", err)
	}
}

func (s *Server) handleSSH(reader *bufio.Reader, conn net.Conn) {
	target, err := net.DialTimeout("tcp", s.cfg.SSHForward, 5*time.Second)
	if err != nil {
		log.Printf("ssh forward dial error: %v", err)
		return
	}
	defer target.Close()

	sshConn := &bufferedConn{Conn: conn, Reader: reader}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		proxyCopy(target, sshConn)
	}()
	go func() {
		defer wg.Done()
		proxyCopy(sshConn, target)
	}()
	wg.Wait()
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if s.tlsConf != nil {
		return s.tlsConf, nil
	}
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	s.tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}}
	return s.tlsConf, nil
}

// loginHandler implements the HTTPS password flow.
type loginHandler struct {
	cfg      config.Config
	attempts *attemptTracker
	tpl      *template.Template
}

type templateData struct {
	AttemptsRemaining int
	Locked            bool
	LockoutRemaining  int
	Message           string
	MessageClass      string
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := time.Now()

	if r.Method == http.MethodPost {
		h.handlePost(w, r, host, now)
		return
	}
	h.render(w, host, now, "", "")
}

func (h *loginHandler) handlePost(w http.ResponseWriter, r *http.Request, host string, now time.Time) {
	if err := r.ParseForm(); err != nil {
		h.render(w, host, now, "failed to parse form", "error")
		return
	}
	remaining, locked, unlockIn := h.attempts.remaining(host, now)
	if locked {
		h.renderLockout(w, unlockIn)
		return
	}
	password := r.FormValue("password")
	if err := bcrypt.CompareHashAndPassword([]byte(h.cfg.PasswordHash), []byte(password)); err != nil {
		remaining, locked, unlockIn = h.attempts.recordFailure(host, now)
		if locked {
			h.renderLockout(w, unlockIn)
			return
		}
		h.render(w, host, now, fmt.Sprintf("invalid password (%d attempts remaining)", remaining), "error")
		return
	}

	h.attempts.clear(host)
	h.renderSuccess(w)
}

func (h *loginHandler) render(w http.ResponseWriter, host string, now time.Time, message, class string) {
	remaining, locked, unlockIn := h.attempts.remaining(host, now)
	if locked {
		h.renderLockout(w, unlockIn)
		return
	}
	data := templateData{
		AttemptsRemaining: remaining,
		Locked:            false,
		LockoutRemaining:  0,
		Message:           message,
		MessageClass:      class,
	}
	h.executeTemplate(w, data)
}

func (h *loginHandler) renderLockout(w http.ResponseWriter, unlockIn time.Duration) {
	data := templateData{
		AttemptsRemaining: 0,
		Locked:            true,
		LockoutRemaining:  int(unlockIn / time.Second),
		Message:           "",
		MessageClass:      "error",
	}
	h.executeTemplate(w, data)
}

func (h *loginHandler) renderSuccess(w http.ResponseWriter) {
	data := templateData{
		AttemptsRemaining: 0,
		Locked:            false,
		Message:           "Access granted. You may close this window.",
		MessageClass:      "success",
	}
	h.executeTemplate(w, data)
}

func (h *loginHandler) executeTemplate(w http.ResponseWriter, data templateData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tpl.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func proxyCopy(dst io.Writer, src io.Reader) {
	if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("proxy copy error: %v", err)
	}
}

type singleConnListener struct {
	conn net.Conn
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	c := l.conn
	l.conn = nil
	return c, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type bufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.Reader.Read(p)
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "sshwebdoor"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ConfigureSSHLoopback writes a minimal sshd drop-in file restricting sshd to
// loopback and reloads the service.
func ConfigureSSHLoopback() error {
	dropInDir := "/etc/ssh/sshd_config.d"
	dropInPath := dropInDir + "/sshwebdoor.conf"
	content := "ListenAddress 127.0.0.1\nPort 22\n"
	if err := os.MkdirAll(dropInDir, 0o755); err != nil {
		return fmt.Errorf("create sshd drop-in dir: %w", err)
	}
	if err := os.WriteFile(dropInPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write sshd drop-in: %w", err)
	}
	cmd := exec.Command("systemctl", "reload", detectSSHService())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reload sshd: %w", err)
	}
	return nil
}

func detectSSHService() string {
	if _, err := os.Stat("/lib/systemd/system/ssh.service"); err == nil {
		return "ssh.service"
	}
	return "sshd.service"
}

// RestoreSSHConfiguration removes the sshwebdoor drop-in file.
func RestoreSSHConfiguration() error {
	dropInPath := "/etc/ssh/sshd_config.d/sshwebdoor.conf"
	if err := os.Remove(dropInPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// TLSFingerprint returns a SHA256 fingerprint of the generated certificate to
// help operators trust the self-signed cert.
func (s *Server) TLSFingerprint() (string, error) {
	tlsConf, err := s.tlsConfig()
	if err != nil {
		return "", err
	}
	if len(tlsConf.Certificates) == 0 {
		return "", errors.New("no certificate configured")
	}
	cert := tlsConf.Certificates[0]
	if len(cert.Certificate) == 0 {
		return "", errors.New("certificate not parsed")
	}
	xcert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", err
	}
	fingerprint := xcert.Subject.CommonName + " " + strings.ToUpper(fmt.Sprintf("%x", xcert.SerialNumber))
	return fingerprint, nil
}
