// Package smtpd implements a basic SMTP server.
package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	rcptToRE   = regexp.MustCompile(`[Tt][Oo]:<(.+)>`)
	mailFromRE = regexp.MustCompile(`[Ff][Rr][Oo][Mm]:<(.*)>(\s(.*))?`) // Delivery Status Notifications are sent with "MAIL FROM:<>"
	mailSizeRE = regexp.MustCompile(`[Ss][Ii][Zz][Ee]=(\d+)`)
)

// Handler function called upon successful receipt of an email.
type Handler func(remoteAddr net.Addr, from string, to []string, data []byte)

// HandlerRcpt function called on RCPT. Return accept status.
type HandlerRcpt func(remoteAddr net.Addr, from string, to string) bool

// AuthHandler function called when a login attempt is performed. Returns true if credentials are correct.
type AuthHandler func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error)

// ErrHandler is when an error happens in a connection
type ErrHandler func(remoteAddr net.Addr, err error)

// DebugHandler is used for debugging
type DebugHandler func(remoteAddr net.Addr, verb string, text string)

// ListenAndServe listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections.
func ListenAndServe(handler Handler, opts ...OptionSetter) error {
	srv, err := NewServer(handler, opts...)
	if err != nil {
		return err
	}
	return srv.ListenAndServe()
}

type maxSizeExceededError struct {
	limit int
}

func maxSizeExceeded(limit int) maxSizeExceededError {
	return maxSizeExceededError{limit}
}

// Error uses the RFC 5321 response message in preference to RFC 1870.
// RFC 3463 defines enhanced status code x.3.4 as "Message too big for system".
func (err maxSizeExceededError) Error() string {
	return fmt.Sprintf("552 5.3.4 Requested mail action aborted: exceeded storage allocation (%d)", err.limit)
}

// OptionSetter is used to handle the options in the server
type OptionSetter func(*Server) error

// WithAddress is for setting the address, the default is :25
func WithAddress(addr string) OptionSetter {
	return func(server *Server) error {
		// TODO : validate the address
		server.addr = addr
		return nil
	}
}

// WithAppName is for setting the app name, the default is smtpd
func WithAppName(app string) OptionSetter {
	return func(server *Server) error {
		server.appName = app
		return nil
	}
}

// WithAuthHandler set the authentication handler and if the authentication is required
func WithAuthHandler(handler AuthHandler, required bool) OptionSetter {
	return func(server *Server) error {
		server.authRequired = required
		server.authHandler = handler
		return nil
	}
}

// AllowAuthMechanisms to overwrite the authentication mechanism
func AllowAuthMechanisms(mehc string, allow bool) OptionSetter {
	return func(server *Server) error {
		server.authMechs[mehc] = allow
		return nil
	}
}

// WithRcptHandler add a RCPT handler to the server
func WithRcptHandler(handler HandlerRcpt) OptionSetter {
	return func(server *Server) error {
		server.handlerRcpt = handler
		return nil
	}
}

// WithHostname set the host name, default value is the os hostname
func WithHostname(host string) OptionSetter {
	return func(server *Server) error {
		server.hostname = host
		return nil
	}
}

// WithDebug is the debug handler
func WithDebug(dh DebugHandler) OptionSetter {
	return func(server *Server) error {
		server.debug = dh
		return nil
	}
}

func WithErrHandler(eh ErrHandler) OptionSetter {
	return func(server *Server) error {
		server.errHandler = eh
		return nil
	}
}

// WithMaxSize Maximum message size allowed, in bytes
func WithMaxSize(in int) OptionSetter {
	return func(server *Server) error {
		server.maxSize = in
		return nil
	}
}

// WithTimeout set the timeout on the connection
func WithTimeout(t time.Duration) OptionSetter {
	return func(server *Server) error {
		server.timeout = t
		return nil
	}
}

// WithTLS is for setting the TLS
func WithTLS(certFile string, keyFile string) OptionSetter {
	return func(server *Server) error {
		return server.configureTLS(certFile, keyFile)
	}
}

// WithTLSPassphrase is for setting the TLS with password
func WithTLSPassphrase(certFile string, keyFile string, pass string) OptionSetter {
	return func(server *Server) error {
		return server.configureTLSWithPassphrase(certFile, keyFile, pass)
	}
}

// RequireTLS Require TLS for every command except NOOP, EHLO, STARTTLS, or QUIT
// as per RFC 3207. Ignored if TLS is not configured.
func RequireTLS() OptionSetter {
	return func(server *Server) error {
		server.tlsRequired = true
		return nil
	}
}

// OnlyTLS Listen for incoming TLS connections only
// (not recommended as it may reduce compatibility). Ignored if TLS is not configured.
func OnlyTLS() OptionSetter {
	return func(server *Server) error {
		server.tlsListener = true
		return nil
	}
}

// Server is an SMTP server.
type Server struct {
	addr         string // TCP address to listen on, defaults to ":25" (all addresses, port 25) if empty
	appName      string
	authHandler  AuthHandler
	authMechs    map[string]bool // Override list of allowed authentication mechanisms. Currently supported: LOGIN, PLAIN, CRAM-MD5. Enabling LOGIN and PLAIN will reduce RFC 4954 compliance.
	authRequired bool            // Require authentication for every command except AUTH, EHLO, HELO, NOOP, RSET or QUIT as per RFC 4954. Ignored if AuthHandler is not configured.
	handler      Handler
	handlerRcpt  HandlerRcpt
	hostname     string
	maxSize      int
	timeout      time.Duration
	tlsConfig    *tls.Config
	tlsListener  bool
	tlsRequired  bool
	debug        DebugHandler
	errHandler   ErrHandler
}

// NewServer creates a new server, the options are available using the option pattern
func NewServer(handler Handler, opts ...OptionSetter) (*Server, error) {
	host, _ := os.Hostname()
	s := &Server{
		addr:         ":25",
		appName:      "smtpd",
		authHandler:  nil,
		authMechs:    make(map[string]bool),
		authRequired: false,
		handler:      handler,
		handlerRcpt:  nil,
		hostname:     host,
		maxSize:      1024 * 1024,
		timeout:      5 * time.Minute,
		tlsConfig:    nil,
		tlsListener:  false,
		tlsRequired:  false,
		errHandler:   nil,
		debug:        nil,
	}

	for i := range opts {
		if err := opts[i](s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// configureTLS creates a TLS configuration from certificate and key files.
func (srv *Server) configureTLS(certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	srv.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	return nil
}

// configureTLSWithPassphrase creates a TLS configuration from a certificate,
// an encrypted key file and the associated passphrase:
func (srv *Server) configureTLSWithPassphrase(
	certFile string,
	keyFile string,
	passphrase string,
) error {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	keyPEMDecrypted, err := x509.DecryptPEMBlock(keyDERBlock, []byte(passphrase))
	if err != nil {
		return err
	}
	var pemBlock pem.Block
	pemBlock.Type = keyDERBlock.Type
	pemBlock.Bytes = keyPEMDecrypted
	keyPEMBlock = pem.EncodeToMemory(&pemBlock)
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	srv.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	return nil
}

// ListenAndServeContext listens on the TCP network address srv.Addr and then
// calls Serve to handle requests on incoming connections.  If
// srv.Addr is blank, ":25" is used.
func (srv *Server) ListenAndServeContext(ctx context.Context) error {
	var ln net.Listener
	var err error

	// If tlsListener is enabled, listen for TLS connections only.
	if srv.tlsConfig != nil && srv.tlsListener {
		ln, err = tls.Listen("tcp", srv.addr, srv.tlsConfig)
	} else {
		ln, err = net.Listen("tcp", srv.addr)
	}
	if err != nil {
		return err
	}
	return srv.ServeContext(ctx, ln)
}

// ListenAndServe is the ListenAndServeContext with context background
func (srv *Server) ListenAndServe() error {
	return srv.ListenAndServeContext(context.Background())
}

// Serve creates a new SMTP session after a network connection is established,
// it uses the the context background
func (srv *Server) Serve(ln net.Listener) error {
	return srv.ServeContext(context.Background(), ln)
}

// ServeContext creates a new SMTP session after a network connection is established.
func (srv *Server) ServeContext(ctx context.Context, ln net.Listener) error {
	defer func() {
		_ = ln.Close()
	}()
	errChan := make(chan error)
	connChan := make(chan net.Conn)

	fn := func() {
		conn, err := ln.Accept()
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}
	for {
		go fn()
		select {
		case err := <-errChan:
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			return err
		case conn := <-connChan:
			session := srv.newSession(conn)
			go session.serve(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

type session struct {
	srv           *Server
	conn          net.Conn
	br            *bufio.Reader
	bw            *bufio.Writer
	remoteIP      string // Remote IP address
	remoteHost    string // Remote hostname according to reverse DNS lookup
	remoteName    string // Remote hostname as supplied with EHLO
	tls           bool
	authenticated bool
	from          string
	gotFrom       bool
	to            []string
	buffer        bytes.Buffer
}

// Create new session from connection.
func (srv *Server) newSession(conn net.Conn) (s *session) {
	s = &session{
		srv:  srv,
		conn: conn,
		br:   bufio.NewReader(conn),
		bw:   bufio.NewWriter(conn),
	}

	// Get remote end info for the Received header.
	s.remoteIP, _, _ = net.SplitHostPort(s.conn.RemoteAddr().String())
	names, err := net.LookupAddr(s.remoteIP)
	if err == nil && len(names) > 0 {
		s.remoteHost = names[0]
	} else {
		s.remoteHost = "unknown"
	}

	// Set tls = true if TLS is already in use.
	_, s.tls = s.conn.(*tls.Conn)

	return
}

func (s *session) logErr(err error) {
	if s.srv.errHandler != nil {
		s.srv.errHandler(s.conn.RemoteAddr(), err)
	}
}

func (s *session) reset() {
	s.from = ""
	s.gotFrom = false
	s.to = nil
	s.buffer.Reset()
}

// Function called to handle connection requests.
func (s *session) serve(ctx context.Context) {
	defer s.conn.Close()
	for fn := initFn; fn != nil; fn = fn(ctx, s) {
	}
}

// Wrapper function for writing a complete line to the socket.
func (s *session) writef(format string, args ...interface{}) error {
	if s.srv.timeout > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(s.srv.timeout)); err != nil {
			s.logErr(err)
			return err
		}
	}

	line := fmt.Sprintf(format, args...)
	_, err := fmt.Fprintf(s.bw, line+"\r\n")
	if err != nil {
		s.logErr(err)
		return err
	}
	err = s.bw.Flush()
	if err != nil {
		s.logErr(err)
		return err
	}

	if s.srv.debug != nil {
		s.srv.debug(s.conn.RemoteAddr(), "WRITE", line)
	}

	return nil
}

// Read a complete line from the socket.
func (s *session) readLine() (string, error) {
	if s.srv.timeout > 0 {
		if err := s.conn.SetReadDeadline(time.Now().Add(s.srv.timeout)); err != nil {
			return "", err
		}
	}

	line, err := s.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line) // Strip trailing \r\n

	if s.srv.debug != nil {
		s.srv.debug(s.conn.RemoteAddr(), "READ", line)
	}

	return line, err
}

// Parse a line read from the socket.
func (s *session) parseLine(line string) (verb string, args string) {
	if idx := strings.Index(line, " "); idx != -1 {
		verb = strings.ToUpper(line[:idx])
		args = strings.TrimSpace(line[idx+1:])
	} else {
		verb = strings.ToUpper(line)
		args = ""
	}
	return verb, args
}

// Read the message data following a DATA command.
func (s *session) readData() ([]byte, error) {
	var data []byte
	for {
		if s.srv.timeout > 0 {
			if err := s.conn.SetReadDeadline(time.Now().Add(s.srv.timeout)); err != nil {
				return nil, err
			}
		}

		line, err := s.br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		// Handle end of data denoted by lone period (\r\n.\r\n)
		if bytes.Equal(line, []byte(".\r\n")) {
			break
		}
		// Remove leading period (RFC 5321 section 4.5.2)
		if line[0] == '.' {
			line = line[1:]
		}

		// Enforce the maximum message size limit.
		if s.srv.maxSize > 0 {
			if len(data)+len(line) > s.srv.maxSize {
				_, _ = s.br.Discard(s.br.Buffered()) // Discard the buffer remnants.
				return nil, maxSizeExceeded(s.srv.maxSize)
			}
		}

		data = append(data, line...)
	}
	return data, nil
}

// Create the Received header to comply with RFC 2821 section 3.8.2.
// TODO: Work out what to do with multiple to addresses.
func (s *session) makeHeaders(to []string) []byte {
	var buffer bytes.Buffer
	now := time.Now().Format("Mon, _2 Jan 2006 15:04:05 -0700 (MST)")
	buffer.WriteString(fmt.Sprintf("Received: from %s (%s [%s])\r\n", s.remoteName, s.remoteHost, s.remoteIP))
	buffer.WriteString(fmt.Sprintf("        by %s (%s) with SMTP\r\n", s.srv.hostname, s.srv.appName))
	buffer.WriteString(fmt.Sprintf("        for <%s>; %s\r\n", to[0], now))
	return buffer.Bytes()
}

// Determine allowed authentication mechanisms.
// RFC 4954 specifies that plaintext authentication mechanisms such as LOGIN and PLAIN require a TLS connection.
// This can be explicitly overridden e.g. setting s.srv.AuthMechs["LOGIN"] = true.
func (s *session) authMechs() (mechs map[string]bool) {
	mechs = map[string]bool{"LOGIN": s.tls, "PLAIN": s.tls, "CRAM-MD5": true}

	for mech := range mechs {
		allowed, found := s.srv.authMechs[mech]
		if found {
			mechs[mech] = allowed
		}
	}

	return
}

// Create the greeting string sent in response to an EHLO command.
func (s *session) makeEHLOResponse() (response string) {
	response = fmt.Sprintf("250-%s greets %s\r\n", s.srv.hostname, s.remoteName)

	// RFC 1870 specifies that "SIZE 0" indicates no maximum size is in force.
	response += fmt.Sprintf("250-SIZE %d\r\n", s.srv.maxSize)

	// Only list STARTTLS if TLS is configured, but not currently in use.
	if s.srv.tlsConfig != nil && !s.tls {
		response += "250-STARTTLS\r\n"
	}

	// Only list AUTH if an AuthHandler is configured and at least one mechanism is allowed.
	if s.srv.authHandler != nil {
		var mechs []string
		for mech, allowed := range s.authMechs() {
			if allowed {
				mechs = append(mechs, mech)
			}
		}
		if len(mechs) > 0 {
			response += "250-AUTH " + strings.Join(mechs, " ") + "\r\n"
		}
	}

	response += "250 ENHANCEDSTATUSCODES"
	return
}
