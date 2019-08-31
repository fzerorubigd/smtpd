package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

type stateFn func(ctx context.Context, sess *session) stateFn

func readLine(ctx context.Context, sess *session) (string, error) {
	errChan := make(chan error, 1)
	lineChan := make(chan string, 1)

	go func() {
		// Attempt to read a line from the socket.
		// On timeout, send a timeout message and return from serve().
		// On error, assume the client has gone away i.e. return from serve().
		line, err := sess.readLine()
		if err != nil {
			errChan <- err
			return
		}
		lineChan <- line
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case err := <-errChan:
		return "", err
	case ln := <-lineChan:
		return ln, nil
	}
}

func nextState(sess *session, nextState stateFn, err error) stateFn {
	if err == nil {
		return nextState
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		_ = sess.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded",
			sess.srv.hostname,
			sess.srv.appName)
	}

	return nil
}

func closeConn(sess *session, err error) stateFn {
	return nextState(sess, nil, err)
}

func nexCommand(sess *session, format string, args ...interface{}) stateFn {
	return nextState(sess, dispatch, sess.writef(format, args...))
}

func initFn(_ context.Context, sess *session) stateFn {
	return nexCommand(sess, "220 %s %s ESMTP Service ready", sess.srv.hostname, sess.srv.appName)
}

func dispatch(ctx context.Context, sess *session) stateFn {
	ln, err := readLine(ctx, sess)
	if err != nil {
		return closeConn(sess, err)
	}

	verb, args := sess.parseLine(ln)
	switch verb {
	case "HELO":
		return fnHELO(args)
	case "EHLO":
		return fnEHLO(args)
	case "MAIL":
		return fnMAIL(args)
	case "RCPT":
		return fnRCPT(args)
	case "DATA":
		return fnDATA(args)
	case "QUIT":
		return fnQUIT(args)
	case "RSET":
		return fnRSET(args)
	case "NOOP":
		return fnNOOP(args)
	case "HELP", "VRFY", "EXPN":
		return fnNotImplemented(args)
	case "STARTTLS":
		return fnSTARTTLS(args)
	case "AUTH":
		return fnAUTH(args)
	default:
		return fnSyntaxError(args)
	}
}

func fnHELO(args string) stateFn {
	return func(ctx context.Context, sess *session) stateFn {
		sess.remoteHost = args
		// RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET, so reset for HELO too.
		sess.reset()
		return nexCommand(sess, "250 %s greets %s", sess.srv.hostname, sess.remoteName)
	}
}

func fnEHLO(args string) stateFn {
	return func(ctx context.Context, sess *session) stateFn {
		sess.remoteName = args
		// RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET.
		sess.reset()
		return nexCommand(sess, sess.makeEHLOResponse())
	}
}

func fnValidate(sess *session, auth bool) stateFn {
	if sess.srv.tlsConfig != nil && sess.srv.tlsRequired && !sess.tls {
		return nexCommand(sess, "530 5.7.0 Must issue a STARTTLS command first")
	}
	if auth && sess.srv.authHandler != nil && sess.srv.authRequired && !sess.authenticated {
		return nexCommand(sess, "530 5.7.0 Authentication required")
	}

	return nil
}

func fnMAIL(args string) stateFn {
	return func(ctx context.Context, sess *session) stateFn {
		if fn := fnValidate(sess, true); fn != nil {
			return fn
		}
		sess.to = nil
		sess.buffer.Reset()

		match := mailFromRE.FindStringSubmatch(args)
		if match == nil {
			return nexCommand(sess, "501 5.5.4 Syntax error in parameters or arguments (invalid FROM parameter)")
		}

		if len(match[2]) > 2 {
			return fnMailSize(match[1], match[2])
			// Valid size is available
		}

		return fnMailSimple(match[1])
	}
}

func fnMailSize(from string, size string) stateFn {
	return func(ctx context.Context, sess *session) stateFn {
		sizeMatch := mailSizeRE.FindStringSubmatch(size)
		if sizeMatch == nil {
			return nexCommand(
				sess,
				"501 5.5.4 Syntax error in parameters or arguments (invalid SIZE parameter)")
		}
		// Enforce the maximum message size if one is set.
		size, err := strconv.Atoi(sizeMatch[1])
		if err != nil { // Bad SIZE parameter
			return nexCommand(sess, "501 5.5.4 Syntax error in parameters or arguments (invalid SIZE parameter)")
		}
		if sess.srv.maxSize > 0 && size > sess.srv.maxSize { // SIZE above maximum size, if set
			return nexCommand(sess, maxSizeExceeded(sess.srv.maxSize).Error())
		}
		// SIZE ok
		return fnMailSimple(from)
	}
}

func fnMailSimple(from string) stateFn {
	return func(ctx context.Context, sess *session) stateFn {
		sess.from = from
		sess.gotFrom = true
		return nexCommand(sess, "250 2.1.0 Ok")
	}
}

func fnRCPT(args string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		if fn := fnValidate(s, true); fn != nil {
			return fn
		}

		if !s.gotFrom {
			return nexCommand(s, "503 5.5.1 Bad sequence of commands (MAIL required before RCPT)")
		}

		match := rcptToRE.FindStringSubmatch(args)
		if match == nil {
			return nexCommand(s, "501 5.5.4 Syntax error in parameters or arguments (invalid TO parameter)")
		}

		// RFC 5321 specifies 100 minimum recipients
		if len(s.to) == 100 {
			return nexCommand(s, "452 4.5.3 Too many recipients")
		}

		accept := true
		if s.srv.handlerRcpt != nil {
			accept = s.srv.handlerRcpt(s.conn.RemoteAddr(), s.from, match[1])
		}

		if accept {
			s.to = append(s.to, match[1])
			return nexCommand(s, "250 2.1.5 Ok")
		}
		return nexCommand(s, "550 5.1.0 Requested action not taken: mailbox unavailable")
	}
}

func fnDATA(_ string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		if fn := fnValidate(s, true); fn != nil {
			return fn
		}

		if !s.gotFrom || len(s.to) == 0 {
			return nexCommand(s, "503 5.5.1 Bad sequence of commands (MAIL & RCPT required before DATA)")
		}

		return nextState(s, fnReadData, s.writef("354 Start mail input; end with <CR><LF>.<CR><LF>"))
	}
}

func fnReadData(ctx context.Context, s *session) stateFn {
	// Attempt to read message body from the socket.
	// On timeout, send a timeout message and return from serve().
	// On net.Error, assume the client has gone away i.e. return from serve().
	// On other errors, allow the client to try again.
	dataChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		data, err := s.readData()
		if err != nil {
			errChan <- err
			return
		}
		dataChan <- data
	}()
	select {
	case <-ctx.Done():
		return closeConn(s, ctx.Err())
	case err := <-errChan:
		switch err.(type) {
		case net.Error:
			if err.(net.Error).Timeout() {
				return closeConn(
					s,
					s.writef(
						"421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded",
						s.srv.hostname,
						s.srv.appName,
					),
				)
			}
		case maxSizeExceededError:
			return nexCommand(s, err.Error())
		}
		return nexCommand(s, "451 4.3.0 Requested action aborted: local error in processing")
	case data := <-dataChan:
		// Create Received header & write message body into buffer.
		s.buffer.Reset()
		s.buffer.Write(s.makeHeaders(s.to))
		s.buffer.Write(data)
		if err := s.writef("250 2.0.0 Ok: queued"); err != nil {
			return closeConn(s, err)
		}

		// Pass mail on to handler.
		if s.srv.handler != nil {
			go s.srv.handler(s.conn.RemoteAddr(), s.from, s.to, s.buffer.Bytes())
		}

		s.reset()
		return dispatch
	}
}

func fnQUIT(_ string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		return closeConn(s, s.writef("221 2.0.0 %s %s ESMTP Service closing transmission channel", s.srv.hostname, s.srv.appName))
	}
}

func fnRSET(_ string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		if fn := fnValidate(s, false); fn != nil {
			return fn
		}
		s.reset()
		return nexCommand(s, "250 2.0.0 Ok")
	}
}

func fnNOOP(args string) stateFn {
	return func(ctx context.Context, sess *session) stateFn {
		return nexCommand(sess, "250 2.0.0 Ok")
	}
}

func fnNotImplemented(_ string) stateFn {
	return func(ctx context.Context, sess *session) stateFn {
		return nexCommand(sess, "502 5.5.1 Command not implemented")
	}
}

func fnSTARTTLS(args string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		// Parameters are not allowed (RFC 3207 section 4).
		if args != "" {
			return nexCommand(s, "501 5.5.2 Syntax error (no parameters allowed)")
		}

		// Handle case where TLS is requested but not configured (and therefore not listed as a service extension).
		if s.srv.tlsConfig == nil {
			return nexCommand(s, "502 5.5.1 Command not implemented")
		}

		// Handle case where STARTTLS is received when TLS is already in use.
		if s.tls {
			return nexCommand(s, "503 5.5.1 Bad sequence of commands (TLS already in use)")
		}

		return nextState(s, fnTLSConnect, s.writef("220 2.0.0 Ready to start TLS"))
	}
}

func fnTLSConnect(_ context.Context, s *session) stateFn {
	// Establish a TLS connection with the client.
	tlsConn := tls.Server(s.conn, s.srv.tlsConfig)
	err := tlsConn.Handshake()
	if err != nil {
		return nexCommand(s, "403 4.7.0 TLS handshake failed")
	}

	// TLS handshake succeeded, switch to using the TLS connection.
	s.conn = tlsConn
	s.br = textproto.NewReader(bufio.NewReader(s.conn))
	s.bw = textproto.NewWriter(bufio.NewWriter(s.conn))
	s.tls = true

	// RFC 3207 specifies that the server must discard any prior knowledge obtained from the client.
	s.remoteName = ""
	s.reset()

	return dispatch
}

func fnAUTH(args string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		if fn := fnValidate(s, false); fn != nil {
			return fn
		}

		// Handle case where AUTH is requested but not configured (and therefore not listed as a service extension).
		if s.srv.authHandler == nil {
			return fnNotImplemented("")
		}

		// Handle case where AUTH is received when already authenticated.
		if s.authenticated {
			return nexCommand(s, "503 5.5.1 Bad sequence of commands (already authenticated for this session)")
		}

		// RFC 4954 specifies that AUTH is not permitted during mail transactions.
		if s.gotFrom || len(s.to) > 0 {
			return nexCommand(s, "503 5.5.1 Bad sequence of commands (AUTH not permitted during mail transaction)")
		}

		// RFC 4954 requires a mechanism parameter.
		authType, authArgs := s.parseLine(args)
		if authType == "" {
			return nexCommand(s, "501 5.5.4 Malformed AUTH input (argument required)")
		}

		// RFC 4954 requires rejecting unsupported authentication mechanisms with a 504 response.
		allowedAuth := s.authMechs()
		if allowed, found := allowedAuth[authType]; !found || !allowed {
			return nexCommand(s, "504 5.5.4 Unrecognized authentication type")
		}
		// RFC 4954 also specifies that ESMTP code 5.5.4 ("Invalid command arguments") should be returned
		// when attempting to use an unsupported authentication type.
		// Many servers return 5.7.4 ("Security features not supported") instead.
		switch authType {
		case "PLAIN":
			return handleAuthPlain(authArgs)
		case "LOGIN":
			return handleAuthLogin(authArgs)
		case "CRAM-MD5":
			return handleAuthCramMD5()
		default:
			return fnNotImplemented("")
		}
	}
}

func handleAuthPlain(arg string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		var err error
		// If fast mode (AUTH PLAIN [arg]) is not used, prompt for credentials.
		if arg == "" {
			if err := s.writef("334 "); err != nil {
				return nextState(s, nil, err)
			}

			arg, err = readLine(ctx, s)
			if err != nil {
				return nextState(s, nil, err)
			}
		}

		data, err := base64.StdEncoding.DecodeString(arg)
		if err != nil {
			return nexCommand(s, "501 5.5.2 Syntax error (unable to decode)")
		}

		parts := bytes.Split(data, []byte{0})
		if len(parts) != 3 {
			return nexCommand(s, "501 5.5.2 Syntax error (unable to parse)")
		}

		return fnCallSrvHandler("PLAIN", parts[1], parts[2], nil)
	}
}

func handleAuthLogin(arg string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		var err error
		if arg == "" {
			if err := s.writef("334 " + base64.StdEncoding.EncodeToString([]byte("Username:"))); err != nil {
				return closeConn(s, err)
			}

			arg, err = readLine(ctx, s)
			if err != nil {
				return closeConn(s, err)
			}
		}

		username, err := base64.StdEncoding.DecodeString(arg)
		if err != nil {
			return nexCommand(s, "501 5.5.2 Syntax error (unable to decode)")
		}

		if err := s.writef("334 " + base64.StdEncoding.EncodeToString([]byte("Password:"))); err != nil {
			return closeConn(s, err)
		}

		line, err := readLine(ctx, s)
		if err != nil {
			return closeConn(s, err)
		}

		password, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nexCommand(s, "501 5.5.2 Syntax error (unable to decode)")
		}

		return fnCallSrvHandler("LOGIN", username, password, nil)
	}
}

func handleAuthCramMD5() stateFn {
	return func(ctx context.Context, s *session) stateFn {
		shared := "<" + strconv.Itoa(os.Getpid()) + "." + strconv.Itoa(time.Now().Nanosecond()) + "@" + s.srv.hostname + ">"
		if err := s.writef("334 " + base64.StdEncoding.EncodeToString([]byte(shared))); err != nil {
			return closeConn(s, err)
		}

		data, err := readLine(ctx, s)
		if err != nil {
			return closeConn(s, err)
		}

		if data == "*" {
			return nexCommand(s, "501 5.7.0 Authentication cancelled")
		}

		buf, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nexCommand(s, "501 5.5.2 Syntax error (unable to decode)")
		}

		fields := strings.Split(string(buf), " ")
		if len(fields) < 2 {
			return nexCommand(s, "501 5.5.2 Syntax error (unable to parse)")
		}

		return fnCallSrvHandler("CRAM-MD5", []byte(fields[0]), []byte(fields[1]), []byte(shared))
	}
}

func fnCallSrvHandler(method string, user, pass, shared []byte, ) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		// Validate credentials.
		authenticated, err := s.srv.authHandler(s.conn.RemoteAddr(), method, user, pass, shared)
		if err != nil {
			return closeConn(s, err)
		}

		s.authenticated = authenticated
		if s.authenticated {
			return nexCommand(s, "235 2.7.0 Authentication successful")
		}
		return nexCommand(s, "535 5.7.8 Authentication credentials invalid")
	}
}

func fnSyntaxError(_ string) stateFn {
	return func(ctx context.Context, s *session) stateFn {
		// See RFC 5321 section 4.2.4 for usage of 500 & 502 response codes.
		return nexCommand(s, "500 5.5.2 Syntax error, command unrecognized")
	}
}
