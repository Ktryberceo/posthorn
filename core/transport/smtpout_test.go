package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Fake SMTP server fixture ---

// fakeSMTPServer is a tiny stand-in for an upstream SMTP relay. Not
// production-grade — just enough behavior to exercise SMTPOutTransport.
// Configured via the exported knobs before tests run a transaction.
type fakeSMTPServer struct {
	listener net.Listener
	Addr     string

	// Behavior knobs (read before Accept; no concurrent mutation).
	AdvertiseSTARTTLS  bool        // EHLO response includes 250-STARTTLS
	STARTTLSConfig     *tls.Config // when set, STARTTLS upgrades the session with this server config
	AdvertiseAUTH      bool        // EHLO response includes 250-AUTH PLAIN
	AuthShouldFail     bool
	RejectMailCode     int // 0 means accept; 4xx/5xx code rejects
	RejectMailMsg      string
	RejectRcptCode     int
	RejectRcptMsg      string
	RejectDataInitCode int // rejects the DATA command itself
	RejectDataInitMsg  string

	mu       sync.Mutex
	Sessions []*fakeSession // one per connection
}

// fakeSession captures everything the fake server saw during one
// connection — used by tests to assert wire-level shape.
type fakeSession struct {
	EHLOArg         string
	AuthPlainBase64 string
	MailFrom        string
	RcptTo          []string
	Data            []byte
	QuitSeen        bool
	STARTTLSSeen    bool
}

func startFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveFakeSMTP(t, l)
}

// startFakeSMTPServerTLS serves implicit TLS: the listener is wrapped so
// the handshake happens before the greeting, as on port 465.
func startFakeSMTPServerTLS(t *testing.T, cfg *tls.Config) *fakeSMTPServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveFakeSMTP(t, tls.NewListener(l, cfg))
}

func serveFakeSMTP(t *testing.T, l net.Listener) *fakeSMTPServer {
	t.Helper()
	s := &fakeSMTPServer{
		listener:      l,
		Addr:          l.Addr().String(),
		AdvertiseAUTH: true, // most tests want auth working
	}
	go s.acceptLoop()
	t.Cleanup(func() { _ = l.Close() })
	return s
}

func (s *fakeSMTPServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(s.Addr)
	if err != nil {
		t.Fatalf("split host:port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func (s *fakeSMTPServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	session := &fakeSession{}
	s.mu.Lock()
	s.Sessions = append(s.Sessions, session)
	s.mu.Unlock()

	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 fake.smtp.test ready")

	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd, arg := splitCommand(line)
		switch strings.ToUpper(cmd) {
		case "EHLO", "HELO":
			session.EHLOArg = arg
			lines := []string{"fake.smtp.test"}
			if s.AdvertiseSTARTTLS {
				lines = append(lines, "STARTTLS")
			}
			if s.AdvertiseAUTH {
				lines = append(lines, "AUTH PLAIN")
			}
			writeMultilineResponse(tp, 250, lines)
		case "AUTH":
			// Expect "AUTH PLAIN <base64>" (single-line form).
			parts := strings.SplitN(arg, " ", 2)
			if len(parts) == 2 {
				session.AuthPlainBase64 = parts[1]
			}
			if s.AuthShouldFail {
				_ = tp.PrintfLine("535 5.7.8 Authentication failed")
			} else {
				_ = tp.PrintfLine("235 2.7.0 OK")
			}
		case "MAIL":
			// "MAIL FROM:<addr>" — strip the FROM: prefix so tests assert
			// on the address only.
			session.MailFrom = stripSMTPArgPrefix(arg, "FROM:")
			if s.RejectMailCode != 0 {
				_ = tp.PrintfLine("%d %s", s.RejectMailCode, s.RejectMailMsg)
				continue
			}
			_ = tp.PrintfLine("250 2.1.0 OK")
		case "RCPT":
			session.RcptTo = append(session.RcptTo, stripSMTPArgPrefix(arg, "TO:"))
			if s.RejectRcptCode != 0 {
				_ = tp.PrintfLine("%d %s", s.RejectRcptCode, s.RejectRcptMsg)
				continue
			}
			_ = tp.PrintfLine("250 2.1.5 OK")
		case "DATA":
			if s.RejectDataInitCode != 0 {
				_ = tp.PrintfLine("%d %s", s.RejectDataInitCode, s.RejectDataInitMsg)
				continue
			}
			_ = tp.PrintfLine("354 End data with <CR><LF>.<CR><LF>")
			body, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			session.Data = body
			_ = tp.PrintfLine("250 2.0.0 OK: queued as ABC123")
		case "STARTTLS":
			if s.STARTTLSConfig == nil {
				_ = tp.PrintfLine("454 4.7.0 TLS not available")
				continue
			}
			_ = tp.PrintfLine("220 2.0.0 Ready to start TLS")
			tlsConn := tls.Server(conn, s.STARTTLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			tp = textproto.NewConn(conn)
			session.STARTTLSSeen = true
		case "QUIT":
			session.QuitSeen = true
			_ = tp.PrintfLine("221 2.0.0 Bye")
			return
		case "NOOP":
			_ = tp.PrintfLine("250 2.0.0 OK")
		case "RSET":
			_ = tp.PrintfLine("250 2.0.0 OK")
		default:
			_ = tp.PrintfLine("500 5.5.1 Command unrecognized")
		}
	}
}

func splitCommand(line string) (cmd, arg string) {
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		return line, ""
	}
	return line[:idx], line[idx+1:]
}

// stripSMTPArgPrefix removes the "FROM:" / "TO:" prefix from a MAIL/RCPT
// argument (case-insensitive on the prefix; address portion preserved
// verbatim). Returns the input unchanged if the prefix isn't there.
func stripSMTPArgPrefix(arg, prefix string) string {
	if len(arg) >= len(prefix) && strings.EqualFold(arg[:len(prefix)], prefix) {
		return arg[len(prefix):]
	}
	return arg
}

func writeMultilineResponse(tp *textproto.Conn, code int, lines []string) {
	for i, line := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		_ = tp.PrintfLine("%d%s%s", code, sep, line)
	}
}

// --- Tests ---

func goodSMTPMessage() Message {
	return Message{
		From:     "noreply@example.com",
		To:       []string{"craig@example.com"},
		Subject:  "Hello",
		BodyText: "Body text.",
	}
}

func newSMTPTestTransport(t *testing.T, srv *fakeSMTPServer, mode TLSMode) *SMTPOutTransport {
	t.Helper()
	host, port := srv.hostPort(t)
	tp := NewSMTPOutTransport(host, port, "user", "pass", mode)
	tp.now = func() time.Time { return time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC) }
	return tp
}

func TestSMTPOut_Success_NoTLS(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if len(srv.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(srv.Sessions))
	}
	sess := srv.Sessions[0]
	if sess.EHLOArg != "localhost" {
		t.Errorf("EHLO argument = %q, want %q", sess.EHLOArg, "localhost")
	}
	if !sess.QuitSeen {
		t.Error("QUIT not seen")
	}
	if sess.MailFrom != "<noreply@example.com>" {
		t.Errorf("MAIL FROM = %q, want %q", sess.MailFrom, "<noreply@example.com>")
	}
	if len(sess.RcptTo) != 1 || sess.RcptTo[0] != "<craig@example.com>" {
		t.Errorf("RCPT TO = %v", sess.RcptTo)
	}
	if len(sess.Data) == 0 {
		t.Error("no DATA captured")
	}
	if !bytes.Contains(sess.Data, []byte("Subject: Hello")) {
		t.Errorf("DATA missing Subject header: %s", sess.Data)
	}
	if !bytes.Contains(sess.Data, []byte("Body text.")) {
		t.Errorf("DATA missing body text: %s", sess.Data)
	}
}

func TestSMTPOut_CustomHelloHostname(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	tp.HelloHostname = "mail.example.com"

	if _, err := tp.Send(context.Background(), goodSMTPMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got := srv.Sessions[0].EHLOArg; got != "mail.example.com" {
		t.Errorf("EHLO argument = %q, want %q", got, "mail.example.com")
	}
}

func TestSMTPOut_Success_MultipleRecipients(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	msg := Message{
		From:     "from@example.com",
		To:       []string{"a@example.com", "b@example.com", "c@example.com"},
		Subject:  "S",
		BodyText: "B",
	}
	if _, err := tp.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	sess := srv.Sessions[0]
	if len(sess.RcptTo) != 3 {
		t.Errorf("RCPT TO count = %d, want 3", len(sess.RcptTo))
	}
}

func TestSMTPOut_Success_ReplyTo(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	msg := goodSMTPMessage()
	msg.ReplyTo = "reply@example.com"
	if _, err := tp.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !bytes.Contains(srv.Sessions[0].Data, []byte("Reply-To: reply@example.com")) {
		t.Errorf("DATA missing Reply-To header: %s", srv.Sessions[0].Data)
	}
}

func TestSMTPOut_OmitsEmptyReplyTo(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	msg := goodSMTPMessage()
	msg.ReplyTo = ""
	if _, err := tp.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if bytes.Contains(srv.Sessions[0].Data, []byte("Reply-To:")) {
		t.Errorf("Reply-To present when message field empty: %s", srv.Sessions[0].Data)
	}
}

func TestSMTPOut_DialFailure_Transient(t *testing.T) {
	// Use a port we're confident is closed. Bind, get the port, close.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	_ = l.Close()

	tp := NewSMTPOutTransport(host, port, "u", "p", TLSNone)
	tp.now = func() time.Time { return time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC) }

	_, err = tp.Send(context.Background(), goodSMTPMessage())
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	if te.Class != ErrTransient {
		t.Errorf("Class = %v, want ErrTransient", te.Class)
	}
}

func TestSMTPOut_RequireTLS_NotAdvertised_Terminal(t *testing.T) {
	srv := startFakeSMTPServer(t)
	srv.AdvertiseSTARTTLS = false // server doesn't advertise STARTTLS
	tp := newSMTPTestTransport(t, srv, TLSStartTLS)

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	if te.Class != ErrTerminal {
		t.Errorf("Class = %v, want ErrTerminal", te.Class)
	}
	if !strings.Contains(te.Message, "STARTTLS") {
		t.Errorf("Message should mention STARTTLS: %q", te.Message)
	}
}

func TestSMTPOut_AuthFailure_Terminal(t *testing.T) {
	srv := startFakeSMTPServer(t)
	srv.AuthShouldFail = true
	tp := newSMTPTestTransport(t, srv, TLSNone)

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	if te.Class != ErrTerminal {
		t.Errorf("Class = %v, want ErrTerminal", te.Class)
	}
	if te.Status != 535 {
		t.Errorf("Status = %d, want 535", te.Status)
	}
}

func TestSMTPOut_MailRejected_5xx_Terminal(t *testing.T) {
	srv := startFakeSMTPServer(t)
	srv.RejectMailCode = 550
	srv.RejectMailMsg = "5.7.1 Sender not authorized"
	tp := newSMTPTestTransport(t, srv, TLSNone)

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	if te.Class != ErrTerminal {
		t.Errorf("Class = %v, want ErrTerminal", te.Class)
	}
}

func TestSMTPOut_RcptRejected_4xx_Transient(t *testing.T) {
	srv := startFakeSMTPServer(t)
	srv.RejectRcptCode = 450
	srv.RejectRcptMsg = "4.7.1 Greylisting"
	tp := newSMTPTestTransport(t, srv, TLSNone)

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	if te.Class != ErrTransient {
		t.Errorf("Class = %v, want ErrTransient (greylisting is transient)", te.Class)
	}
}

func TestSMTPOut_RcptRejected_5xx_Terminal(t *testing.T) {
	srv := startFakeSMTPServer(t)
	srv.RejectRcptCode = 550
	srv.RejectRcptMsg = "5.1.1 Recipient unknown"
	tp := newSMTPTestTransport(t, srv, TLSNone)

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	if te.Class != ErrTerminal {
		t.Errorf("Class = %v, want ErrTerminal", te.Class)
	}
}

func TestSMTPOut_DataInitRejected_Terminal(t *testing.T) {
	srv := startFakeSMTPServer(t)
	srv.RejectDataInitCode = 552
	srv.RejectDataInitMsg = "5.3.4 Message too big"
	tp := newSMTPTestTransport(t, srv, TLSNone)

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	if te.Class != ErrTerminal {
		t.Errorf("Class = %v, want ErrTerminal", te.Class)
	}
}

func TestSMTPOut_RFC5322Headers(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	msg := Message{
		From:     "noreply@example.com",
		To:       []string{"a@example.com", "b@example.com"},
		ReplyTo:  "reply@example.com",
		Subject:  "Test Subject",
		BodyText: "Hello, World!",
	}
	if _, err := tp.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// textproto.ReadDotBytes normalizes wire CRLF to LF; assertions use \n.
	data := string(srv.Sessions[0].Data)
	required := []string{
		"From: noreply@example.com\n",
		"To: a@example.com, b@example.com\n",
		"Reply-To: reply@example.com\n",
		"Subject: Test Subject\n",
		"Date: Mon, 15 Jan 2024 12:00:00 +0000\n",
		"MIME-Version: 1.0\n",
		"Content-Type: text/plain; charset=\"utf-8\"\n",
		"Content-Transfer-Encoding: 8bit\n",
		"\nHello, World!", // blank line separates headers from body
	}
	for _, want := range required {
		if !strings.Contains(data, want) {
			t.Errorf("DATA missing %q\nFull DATA:\n%s", want, data)
		}
	}
}

// TestSMTPOut_HeaderInjection is the NFR1 / FR52 acceptance test for the
// SMTP transport. CRLF in a header value would let an attacker inject
// sibling headers (e.g., Bcc:) into the outbound message. We reject at
// the validation step before the wire conversation begins.
func TestSMTPOut_HeaderInjection(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{"crlf_in_from", Message{
			From: "attacker@evil.com\r\nBcc: victim@target.com",
			To:   []string{"r@example.com"}, Subject: "s", BodyText: "b",
		}},
		{"lf_in_from", Message{
			From: "attacker@evil.com\nBcc: victim@target.com",
			To:   []string{"r@example.com"}, Subject: "s", BodyText: "b",
		}},
		{"crlf_in_subject", Message{
			From: "f@example.com", To: []string{"r@example.com"},
			Subject: "Hello\r\nBcc: victim@target.com", BodyText: "b",
		}},
		{"crlf_in_replyto", Message{
			From: "f@example.com", To: []string{"r@example.com"},
			ReplyTo: "x@x.com\r\nBcc: victim@target.com",
			Subject: "s", BodyText: "b",
		}},
		{"crlf_in_to_recipient", Message{
			From:    "f@example.com",
			To:      []string{"r@example.com\r\nBcc: victim@target.com"},
			Subject: "s", BodyText: "b",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startFakeSMTPServer(t)
			tp := newSMTPTestTransport(t, srv, TLSNone)

			_, err := tp.Send(context.Background(), tt.msg)
			var te *TransportError
			if !errors.As(err, &te) {
				t.Fatalf("not a *TransportError: %v", err)
			}
			if te.Class != ErrTerminal {
				t.Errorf("Class = %v, want ErrTerminal (header injection)", te.Class)
			}
			// Confirm we never wrote anything over the wire — no session
			// captured means we rejected before dialing.
			//
			// Actually we dial+EHLO+STARTTLS+AUTH before validation in the
			// current flow... wait, we validate FIRST. Let me re-check.
			// Yes: validateNoHeaderCRLF runs at the top of Send, before
			// dial. So no session is recorded.
			if len(srv.Sessions) > 0 && len(srv.Sessions[0].Data) > 0 {
				t.Errorf("DATA was written despite injection attempt: %s", srv.Sessions[0].Data)
			}
		})
	}
}

// TestSMTPOut_MIMESubjectEncoding pins the RFC 2047 encoding behavior:
// non-ASCII subjects get B-encoded so they survive the wire.
func TestSMTPOut_MIMESubjectEncoding(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	msg := goodSMTPMessage()
	msg.Subject = "café résumé"
	if _, err := tp.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	data := string(srv.Sessions[0].Data)
	// B-encoded subjects start with =?utf-8?b? or =?UTF-8?B?
	if !strings.Contains(strings.ToLower(data), "=?utf-8?b?") {
		t.Errorf("non-ASCII subject not B-encoded; DATA:\n%s", data)
	}
	// And the literal non-ASCII characters should not appear unencoded.
	if strings.Contains(data, "café") {
		t.Errorf("non-ASCII subject leaked unencoded: %s", data)
	}
}

func TestSMTPOut_MIMESubject_ASCIIPassthrough(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	msg := goodSMTPMessage()
	msg.Subject = "Plain ASCII Subject"
	if _, err := tp.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string(srv.Sessions[0].Data), "Subject: Plain ASCII Subject\n") {
		t.Errorf("ASCII subject not passed through unchanged: %s", srv.Sessions[0].Data)
	}
}

// TestSMTPOut_PasswordNotInErrorMessages is the NFR3 surface for SMTP.
// The password legitimately crosses the wire as base64(AUTH PLAIN), so
// "not on the wire" is not the invariant. Instead: the literal password
// must not appear in any error message the operator might log.
func TestSMTPOut_PasswordNotInErrorMessages(t *testing.T) {
	const sentinel = "sentinel-smtp-password-do-not-leak"
	srv := startFakeSMTPServer(t)
	srv.AuthShouldFail = true

	host, port := srv.hostPort(t)
	tp := NewSMTPOutTransport(host, port, "user", sentinel, TLSNone)
	tp.now = func() time.Time { return time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC) }

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	if err == nil {
		t.Fatal("expected error from failed auth")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("password %q leaked in error message: %v", sentinel, err)
	}
}

func TestSMTPOut_EnvelopeAddress_StripsDisplayName(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	msg := Message{
		From:     "Display Name <noreply@example.com>",
		To:       []string{"Some User <user@example.com>"},
		Subject:  "S",
		BodyText: "B",
	}
	if _, err := tp.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	sess := srv.Sessions[0]
	if sess.MailFrom != "<noreply@example.com>" {
		t.Errorf("MAIL FROM = %q, want %q (display name stripped)", sess.MailFrom, "<noreply@example.com>")
	}
	if sess.RcptTo[0] != "<user@example.com>" {
		t.Errorf("RCPT TO = %q, want %q", sess.RcptTo[0], "<user@example.com>")
	}
	// But the From: HEADER (inside DATA) keeps the display name.
	if !strings.Contains(string(sess.Data), "From: Display Name <noreply@example.com>") {
		t.Errorf("From header should keep display name: %s", sess.Data)
	}
}

func TestSMTPOut_DotStuffing(t *testing.T) {
	// A line in the body starting with '.' must be dot-stuffed by
	// textproto.DotWriter — otherwise it'd prematurely terminate the
	// DATA section. The fake server's ReadDotBytes undoes the stuffing,
	// so the captured body should equal the input.
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)
	msg := goodSMTPMessage()
	msg.BodyText = "Line one\n. Line two starts with a dot\nLine three"
	if _, err := tp.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !bytes.Contains(srv.Sessions[0].Data, []byte(". Line two starts with a dot")) {
		t.Errorf("Dot-prefixed line corrupted by stuffing/destuffing roundtrip: %s", srv.Sessions[0].Data)
	}
}

func TestSMTPOut_ContextCancelled_Transient(t *testing.T) {
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSNone)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Send

	_, err := tp.Send(ctx, goodSMTPMessage())
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	if te.Class != ErrTransient {
		t.Errorf("Class = %v, want ErrTransient (cancelled context)", te.Class)
	}
}

// --- Registry integration ---

func TestSMTPOut_RegisteredAtPackageLoad(t *testing.T) {
	reg, ok := Lookup("smtp")
	if !ok {
		t.Fatal("smtp not registered after package init")
	}

	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{"empty", map[string]any{}, true},
		{"missing_port", map[string]any{"host": "h", "username": "u", "password": "p"}, true},
		{"missing_host", map[string]any{"port": 587, "username": "u", "password": "p"}, true},
		{"missing_username", map[string]any{"host": "h", "port": 587, "password": "p"}, true},
		{"missing_password", map[string]any{"host": "h", "port": 587, "username": "u"}, true},
		{"port_out_of_range", map[string]any{"host": "h", "port": 99999, "username": "u", "password": "p"}, true},
		{"empty_hello_hostname", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p", "hello_hostname": ""}, true},
		{"non_string_hello_hostname", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p", "hello_hostname": 123}, true},
		{"crlf_hello_hostname", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p", "hello_hostname": "mail.example.com\r\nX-INJECTED"}, true},
		{"trailing_space_hello_hostname", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p", "hello_hostname": "mail.example.com "}, true},
		{"internal_space_hello_hostname", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p", "hello_hostname": "mail example.com"}, true},
		{"tls_unknown_value", map[string]any{"host": "h", "port": 465, "username": "u", "password": "p", "tls": "ssl"}, true},
		{"tls_non_string", map[string]any{"host": "h", "port": 465, "username": "u", "password": "p", "tls": true}, true},
		{"tls_and_require_tls", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p", "tls": "starttls", "require_tls": true}, true},
		{"require_tls_non_bool", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p", "require_tls": "yes"}, true},
		{"valid_tls_implicit", map[string]any{"host": "h", "port": 465, "username": "u", "password": "p", "tls": "implicit"}, false},
		{"valid_tls_none", map[string]any{"host": "h", "port": 25, "username": "u", "password": "p", "tls": "none"}, false},
		{"valid_int_port", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p"}, false},
		{"valid_int64_port", map[string]any{"host": "h", "port": int64(587), "username": "u", "password": "p"}, false},
		{"valid_hello_hostname", map[string]any{"host": "h", "port": 587, "username": "u", "password": "p", "hello_hostname": "mail.example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reg.Validate(tt.settings)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%v) error = %v, wantErr %v", tt.settings, err, tt.wantErr)
			}
		})
	}

	tp, err := reg.Build(map[string]any{
		"host": "smtp.example.com", "port": 587,
		"username": "u", "password": "p",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := tp.(*SMTPOutTransport); !ok {
		t.Errorf("Build returned %T, want *SMTPOutTransport", tp)
	}
}

// TestSMTPOut_Build_TLSMode pins the settings.tls enum and the mapping of
// the older require_tls boolean onto it: omitted means STARTTLS, so a
// config written before implicit TLS existed behaves exactly as before.
func TestSMTPOut_Build_TLSMode(t *testing.T) {
	reg, _ := Lookup("smtp")
	base := func(extra map[string]any) map[string]any {
		m := map[string]any{"host": "h", "port": 587, "username": "u", "password": "p"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name     string
		settings map[string]any
		want     TLSMode
	}{
		{"default_starttls", base(nil), TLSStartTLS},
		{"require_tls_true", base(map[string]any{"require_tls": true}), TLSStartTLS},
		{"require_tls_false", base(map[string]any{"require_tls": false}), TLSNone},
		{"tls_starttls", base(map[string]any{"tls": "starttls"}), TLSStartTLS},
		{"tls_implicit", base(map[string]any{"tls": "implicit"}), TLSImplicit},
		{"tls_none", base(map[string]any{"tls": "none"}), TLSNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, err := reg.Build(tt.settings)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if got := tp.(*SMTPOutTransport).TLS; got != tt.want {
				t.Errorf("TLS = %q, want %q", got, tt.want)
			}
		})
	}
	if _, err := reg.Build(base(map[string]any{"tls": "implicit", "require_tls": true})); err == nil {
		t.Error("Build should refuse tls together with require_tls")
	}
}

func TestSMTPOut_Build_OptionalHelloHostname(t *testing.T) {
	reg, _ := Lookup("smtp")
	tp, err := reg.Build(map[string]any{
		"host": "h", "port": 587, "username": "u", "password": "p",
		"hello_hostname": "mail.example.com",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := tp.(*SMTPOutTransport).HelloHostname; got != "mail.example.com" {
		t.Errorf("HelloHostname = %q, want %q", got, "mail.example.com")
	}
}

// --- TLS modes (FR50: tls = "starttls" | "implicit" | "none") ---

// testTLSConfig generates a self-signed certificate for 127.0.0.1 and
// returns the server-side config plus a root pool that trusts it, so the
// transport verifies the fake server the way it would a real relay.
func testTLSConfig(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake.smtp.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
	}
	return srvCfg, pool
}

func (s *fakeSMTPServer) sessionAt(t *testing.T, i int) *fakeSession {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Sessions) <= i {
		t.Fatalf("want session %d, server saw %d", i, len(s.Sessions))
	}
	return s.Sessions[i]
}

func tlsTestErr(t *testing.T, err error) *TransportError {
	t.Helper()
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("not a *TransportError: %v", err)
	}
	return te
}

func TestSMTPOut_ImplicitTLS_Success(t *testing.T) {
	srvCfg, pool := testTLSConfig(t)
	srv := startFakeSMTPServerTLS(t, srvCfg)
	tp := newSMTPTestTransport(t, srv, TLSImplicit)
	tp.rootCAs = pool

	if _, err := tp.Send(context.Background(), goodSMTPMessage()); err != nil {
		t.Fatalf("Send over implicit TLS: %v", err)
	}
	sess := srv.sessionAt(t, 0)
	if sess.STARTTLSSeen {
		t.Error("implicit mode must not issue STARTTLS")
	}
	if sess.AuthPlainBase64 == "" {
		t.Error("AUTH PLAIN should have been sent over the TLS connection")
	}
	if sess.MailFrom != "<noreply@example.com>" {
		t.Errorf("MAIL FROM = %q", sess.MailFrom)
	}
	if !bytes.Contains(sess.Data, []byte("Subject: Hello")) {
		t.Errorf("DATA missing subject:\n%s", sess.Data)
	}
	if !sess.QuitSeen {
		t.Error("QUIT not seen")
	}
}

func TestSMTPOut_ImplicitTLS_UnknownCA_Terminal(t *testing.T) {
	srvCfg, _ := testTLSConfig(t)
	srv := startFakeSMTPServerTLS(t, srvCfg)
	tp := newSMTPTestTransport(t, srv, TLSImplicit) // system roots don't know the fake cert

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	te := tlsTestErr(t, err)
	if te.Class != ErrTerminal {
		t.Errorf("Class = %v, want ErrTerminal (certificate verification is a config problem)", te.Class)
	}
	if !strings.Contains(te.Message, "TLS handshake failed") {
		t.Errorf("Message = %q", te.Message)
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(te.Cause, &unknown) {
		t.Errorf("Cause = %v, want x509.UnknownAuthorityError", te.Cause)
	}
}

func TestSMTPOut_ImplicitTLS_SkipVerify(t *testing.T) {
	srvCfg, _ := testTLSConfig(t)
	srv := startFakeSMTPServerTLS(t, srvCfg)
	tp := newSMTPTestTransport(t, srv, TLSImplicit)
	tp.TLSInsecureSkipVerify = true

	if _, err := tp.Send(context.Background(), goodSMTPMessage()); err != nil {
		t.Fatalf("Send with tls_insecure_skip_verify: %v", err)
	}
}

// Implicit mode pointed at a STARTTLS port: the server greets in
// plaintext, the TLS client reads "220 " as a record header, and the
// operator gets told which mode the port probably wants.
func TestSMTPOut_ImplicitTLS_AgainstPlaintextPort_Terminal(t *testing.T) {
	_, pool := testTLSConfig(t)
	srv := startFakeSMTPServer(t)
	tp := newSMTPTestTransport(t, srv, TLSImplicit)
	tp.rootCAs = pool

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	te := tlsTestErr(t, err)
	if te.Class != ErrTerminal {
		t.Errorf("Class = %v, want ErrTerminal", te.Class)
	}
	if !strings.Contains(te.Message, `tls = "starttls"`) || !strings.Contains(te.Message, strconv.Itoa(tp.Port)) {
		t.Errorf("Message = %q, want the starttls hint naming the port", te.Message)
	}
}

// STARTTLS mode pointed at an implicit-TLS port: both sides wait for the
// other to speak first. The per-Send deadline must end it, and the
// error must say no greeting arrived rather than hang the request.
func TestSMTPOut_STARTTLS_AgainstImplicitPort_NoGreeting(t *testing.T) {
	srvCfg, pool := testTLSConfig(t)
	srv := startFakeSMTPServerTLS(t, srvCfg)
	tp := newSMTPTestTransport(t, srv, TLSStartTLS)
	tp.rootCAs = pool

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := tp.Send(ctx, goodSMTPMessage())
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Send took %v; the deadline was not applied to the socket", elapsed)
	}
	te := tlsTestErr(t, err)
	if te.Class != ErrTransient {
		t.Errorf("Class = %v, want ErrTransient", te.Class)
	}
	if !strings.Contains(te.Message, "no SMTP greeting") {
		t.Errorf("Message = %q", te.Message)
	}
}

func TestSMTPOut_GreetingHint_Port465(t *testing.T) {
	timeout := &greetingError{err: errors.New("i/o timeout")}

	tp := &SMTPOutTransport{Port: 465, TLS: TLSStartTLS}
	if te := tp.classifyDialError(timeout); !strings.Contains(te.Message, `tls = "implicit"`) {
		t.Errorf("starttls on 465: Message = %q, want the implicit hint", te.Message)
	}
	tp = &SMTPOutTransport{Port: 465, TLS: TLSImplicit}
	if te := tp.classifyDialError(timeout); strings.Contains(te.Message, `tls = "implicit"`) {
		t.Errorf("implicit on 465: Message = %q, hint makes no sense here", te.Message)
	}
	tp = &SMTPOutTransport{Port: 587, TLS: TLSStartTLS}
	if te := tp.classifyDialError(timeout); strings.Contains(te.Message, "465") {
		t.Errorf("starttls on 587: Message = %q, no 465 hint expected", te.Message)
	}
}

func TestSMTPOut_STARTTLS_Upgrade_Success(t *testing.T) {
	srvCfg, pool := testTLSConfig(t)
	srv := startFakeSMTPServer(t)
	srv.AdvertiseSTARTTLS = true
	srv.STARTTLSConfig = srvCfg
	tp := newSMTPTestTransport(t, srv, TLSStartTLS)
	tp.rootCAs = pool

	if _, err := tp.Send(context.Background(), goodSMTPMessage()); err != nil {
		t.Fatalf("Send with STARTTLS upgrade: %v", err)
	}
	sess := srv.sessionAt(t, 0)
	if !sess.STARTTLSSeen {
		t.Fatal("server never saw STARTTLS")
	}
	if sess.AuthPlainBase64 == "" {
		t.Error("AUTH PLAIN should follow the upgrade")
	}
	if !bytes.Contains(sess.Data, []byte("Subject: Hello")) {
		t.Errorf("DATA missing subject:\n%s", sess.Data)
	}
}

func TestSMTPOut_STARTTLS_UnknownCA_Terminal(t *testing.T) {
	srvCfg, _ := testTLSConfig(t)
	srv := startFakeSMTPServer(t)
	srv.AdvertiseSTARTTLS = true
	srv.STARTTLSConfig = srvCfg
	tp := newSMTPTestTransport(t, srv, TLSStartTLS) // no rootCAs

	_, err := tp.Send(context.Background(), goodSMTPMessage())
	te := tlsTestErr(t, err)
	if te.Class != ErrTerminal {
		t.Errorf("Class = %v, want ErrTerminal", te.Class)
	}
	if !strings.Contains(te.Message, "STARTTLS handshake failed") {
		t.Errorf("Message = %q", te.Message)
	}
}

func TestSMTPOut_PlaintextMode_SkipsSTARTTLS(t *testing.T) {
	srv := startFakeSMTPServer(t)
	srv.AdvertiseSTARTTLS = true // offered, deliberately not taken
	tp := newSMTPTestTransport(t, srv, TLSNone)

	if _, err := tp.Send(context.Background(), goodSMTPMessage()); err != nil {
		t.Fatalf("Send in plaintext mode: %v", err)
	}
	if srv.sessionAt(t, 0).STARTTLSSeen {
		t.Error("tls = \"none\" must not issue STARTTLS")
	}
}
