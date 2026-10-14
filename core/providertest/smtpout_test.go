package providertest

// Outbound-SMTP transport e2e. Unlike the HTTP transports (which encode
// a CRLF payload safely and still send), smtpout enforces NFR1 by
// REJECTING a CRLF-in-header message at its edge — so an injection
// payload results in no delivery rather than a neutralized delivery.
// Both are injection-safe; this test locks in that smtpout takes the
// reject path. It reuses the shared Scenario/DeliveredMail/battery but
// needs a fake SMTP *server* as the sink, so it has its own runner.

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/craigmccaskill/posthorn/gateway"
	"github.com/craigmccaskill/posthorn/transport"
)

// fakeSMTPServer accepts one-shot SMTP sessions (no TLS, no AUTH — which
// is what NewSMTPOutTransport(..., TLSNone, no creds) drives) and
// records each delivered message's envelope + DATA blob.
type fakeSMTPServer struct {
	ln net.Listener

	mu       sync.Mutex
	messages []deliveredSMTP
}

type deliveredSMTP struct {
	mailFrom string
	rcptTo   []string
	data     string
}

func startFakeSMTP(t *testing.T) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTPServer{ln: ln}
	go s.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeSMTPServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(s.ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}
	return host, port
}

func (s *fakeSMTPServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	wr := bufio.NewWriter(conn)
	reply := func(line string) {
		_, _ = wr.WriteString(line + "\r\n")
		_ = wr.Flush()
	}
	reply("220 fake.smtp.test ready")

	var msg deliveredSMTP
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			reply("250 fake.smtp.test") // single line: no extensions → no STARTTLS/AUTH
		case strings.HasPrefix(cmd, "MAIL FROM"):
			msg.mailFrom = extractAngle(line)
			reply("250 2.1.0 OK")
		case strings.HasPrefix(cmd, "RCPT TO"):
			msg.rcptTo = append(msg.rcptTo, extractAngle(line))
			reply("250 2.1.5 OK")
		case strings.HasPrefix(cmd, "DATA"):
			reply("354 End data with <CR><LF>.<CR><LF>")
			var b strings.Builder
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" || dl == ".\n" {
					break
				}
				// Un-dot-stuff a leading ".".
				if strings.HasPrefix(dl, "..") {
					dl = dl[1:]
				}
				b.WriteString(dl)
			}
			msg.data = b.String()
			s.mu.Lock()
			s.messages = append(s.messages, msg)
			s.mu.Unlock()
			msg = deliveredSMTP{}
			reply("250 2.0.0 OK: queued")
		case strings.HasPrefix(cmd, "QUIT"):
			reply("221 2.0.0 Bye")
			return
		case strings.HasPrefix(cmd, "RSET"):
			msg = deliveredSMTP{}
			reply("250 2.0.0 OK")
		case strings.HasPrefix(cmd, "NOOP"):
			reply("250 2.0.0 OK")
		default:
			reply("250 2.0.0 OK")
		}
	}
}

func (s *fakeSMTPServer) delivered() []deliveredSMTP {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]deliveredSMTP, len(s.messages))
	copy(out, s.messages)
	return out
}

// smtpOutEndpoint builds the same contact endpoint but for a scenario
// driven into the SMTP transport supplied by the runner.
func smtpOutForm(t *testing.T, host string, port int, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	ep := contactEndpoint()
	tp := transport.NewSMTPOutTransport(host, port, "", "", transport.TLSNone)
	h, err := gateway.New(ep, tp)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, ep.Path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestE2E_SMTPOut_FormToWire_HappyPath(t *testing.T) {
	srv := startFakeSMTP(t)
	host, port := srv.hostPort(t)

	rec := smtpOutForm(t, host, port, url.Values{"name": {"Alice"}, "message": {"Hello there"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	msgs := srv.delivered()
	if len(msgs) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(msgs))
	}
	if got := msgs[0].mailFrom; !strings.Contains(got, "noreply@example.com") {
		t.Errorf("MAIL FROM = %q, want the endpoint from", got)
	}
	if len(msgs[0].rcptTo) != 1 || !strings.Contains(msgs[0].rcptTo[0], "ops@example.com") {
		t.Errorf("RCPT TO = %v, want [ops@example.com]", msgs[0].rcptTo)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(msgs[0].data))
	if err != nil {
		t.Fatalf("parse DATA: %v\n%s", err, msgs[0].data)
	}
	if got := parsed.Header.Get("Subject"); got != "Contact from Alice" {
		t.Errorf("Subject header = %q", got)
	}
}

func TestE2E_SMTPOut_FormToWire_InjectionRejectedAtEdge(t *testing.T) {
	// smtpout enforces NFR1 by refusing a CRLF-in-header message. For each
	// injection payload the send must fail (no delivery) — never a
	// delivered message carrying a smuggled header.
	for _, payload := range InjectionValues() {
		if !strings.ContainsAny(payload, "\r\n") {
			continue // only the CRLF-bearing payloads exercise the reject path
		}
		t.Run(SanitizeName(payload), func(t *testing.T) {
			srv := startFakeSMTP(t)
			host, port := srv.hostPort(t)

			rec := smtpOutForm(t, host, port, url.Values{"name": {payload}, "message": {"body"}})
			if rec.Code == http.StatusOK {
				t.Errorf("status = 200 for a CRLF payload; smtpout should reject at the edge")
			}
			for _, m := range srv.delivered() {
				assertNoSmuggledHeader(t, m.data)
			}
		})
	}
}

// assertNoSmuggledHeader parses a delivered DATA blob and fails if a
// header the submitter tried to inject appears.
func assertNoSmuggledHeader(t *testing.T, data string) {
	t.Helper()
	parsed, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		return // unparseable → nothing smuggled into a real header
	}
	for _, banned := range []string{"Bcc", "X-Injected"} {
		if v := parsed.Header.Get(banned); v != "" {
			t.Errorf("smuggled header %s: %q in delivered message", banned, v)
		}
	}
}

func extractAngle(line string) string {
	i := strings.IndexByte(line, '<')
	j := strings.IndexByte(line, '>')
	if i >= 0 && j > i {
		return line[i+1 : j]
	}
	return strings.TrimSpace(line)
}
