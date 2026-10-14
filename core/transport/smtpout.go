package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// Outbound SMTP transport (FR50, ADR-17).
//
// Implements the Transport interface against an upstream SMTP relay
// (Mailgun's SMTP gateway, a self-hosted Postfix relay, Mailtrap, etc.)
// using stdlib `net/smtp` primitives — no third-party SMTP library
// dependency. STARTTLS by default; implicit TLS (port 465) or plaintext
// by configuration (TLSMode). SMTP AUTH PLAIN.
//
// Each Send opens a fresh TCP connection, runs the full SMTP transaction
// (TLS handshake first in implicit mode; EHLO → STARTTLS → AUTH → MAIL →
// RCPT → DATA → QUIT), then closes. Connection reuse is a v2 optimization once we have
// async sending and persistent state.
//
// NFR1 enforcement: SMTP transport hand-writes the RFC 5322 message
// envelope (From, To, Subject, Reply-To headers) into the DATA section
// because there's no JSON struct to lean on. The structural defense is
// (a) pre-write validation that submitter-controlled header values
// contain no CR/LF (rejects header-injection attempts at Send time with
// ErrTerminal), (b) stdlib net/smtp's own validateLine check on MAIL FROM
// and RCPT TO (CRLF rejected at the protocol level), and (c) net/textproto
// dot-stuffing inside Data() which translates `\n` → `\r\n` and escapes
// lone `.` lines to `..` so body content can't smuggle headers via the
// data-end terminator.

const (
	// smtpRequestTimeout is the per-Send hard cap on the SMTP transaction.
	// Longer than HTTP transports because SMTP often has slower greeting
	// and DATA-acceptance round trips.
	smtpRequestTimeout = 30 * time.Second
)

// TLSMode selects how the connection to the relay is secured. Configured
// as settings.tls (FR50); the older settings.require_tls boolean maps onto
// it (true → TLSStartTLS, false → TLSNone).
type TLSMode string

const (
	// TLSStartTLS connects in plaintext and upgrades with STARTTLS before
	// AUTH. The server must advertise the extension; when it doesn't,
	// Send fails closed. The default.
	TLSStartTLS TLSMode = "starttls"

	// TLSImplicit wraps the TCP connection in TLS before the SMTP greeting
	// (RFC 8314 implicit TLS, conventionally port 465).
	TLSImplicit TLSMode = "implicit"

	// TLSNone sends in plaintext. net/smtp refuses to send AUTH PLAIN over
	// plaintext to anything but localhost, so this is for local testing
	// and trusted internal networks only.
	TLSNone TLSMode = "none"
)

// ParseTLSMode validates a settings.tls value.
func ParseTLSMode(s string) (TLSMode, bool) {
	switch TLSMode(s) {
	case TLSStartTLS, TLSImplicit, TLSNone:
		return TLSMode(s), true
	}
	return "", false
}

// SMTPOutTransport implements Transport against an upstream SMTP relay.
type SMTPOutTransport struct {
	Host     string
	Port     int
	Username string
	Password string

	// HelloHostname is announced in EHLO/HELO. Some relays require it to
	// identify the client; the default is localhost for compatibility.
	HelloHostname string

	// TLS selects plaintext, STARTTLS upgrade, or implicit TLS from the
	// first byte. Default TLSStartTLS. In STARTTLS mode a server that
	// doesn't advertise the extension fails Send with ErrTerminal — a
	// misconfiguration the operator must fix, never a silent downgrade.
	TLS TLSMode

	// TLSInsecureSkipVerify disables certificate validation in both TLS
	// modes. Test-only escape hatch for self-signed certs in local
	// development; production operators must leave this false and use a
	// real cert.
	TLSInsecureSkipVerify bool

	// rootCAs overrides the system roots for certificate verification.
	// Tests inject the fake server's self-signed cert; production leaves
	// it nil.
	rootCAs *x509.CertPool

	// dial is the connection factory. Production: net.Dialer.DialContext,
	// the per-Send deadline applied to the socket, an implicit-TLS
	// handshake when tlsConfig is non-nil, then smtp.NewClient (which
	// reads the greeting). Tests inject a function that returns a client
	// connected to a fake SMTP server.
	dial func(ctx context.Context, addr string, tlsConfig *tls.Config) (*smtp.Client, error)

	// now is injectable for deterministic Date headers in tests.
	now func() time.Time
}

// NewSMTPOutTransport constructs an outbound SMTP transport. host and port
// identify the upstream relay; username/password are the SMTP AUTH PLAIN
// credentials; mode selects plaintext, STARTTLS, or implicit TLS (an
// empty mode means TLSStartTLS).
func NewSMTPOutTransport(host string, port int, username, password string, mode TLSMode) *SMTPOutTransport {
	if mode == "" {
		mode = TLSStartTLS
	}
	return &SMTPOutTransport{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		TLS:      mode,
		dial:     defaultSMTPDial,
		now:      time.Now,
	}
}

// tlsHandshakeError marks a failed implicit-TLS handshake so Send can
// classify it as terminal: a certificate or configuration problem, not a
// transient network fault.
type tlsHandshakeError struct{ err error }

func (e *tlsHandshakeError) Error() string { return "tls handshake: " + e.err.Error() }
func (e *tlsHandshakeError) Unwrap() error { return e.err }

// greetingError marks a connection that opened but produced no usable
// SMTP greeting: a hung relay, or STARTTLS mode pointed at an
// implicit-TLS port, which looks identical from this side.
type greetingError struct{ err error }

func (e *greetingError) Error() string { return "greeting: " + e.err.Error() }
func (e *greetingError) Unwrap() error { return e.err }

// defaultSMTPDial is the production dial: open TCP, apply the per-Send
// deadline to the socket so no protocol step can stall past it, wrap in
// TLS when tlsConfig is set (implicit mode), then hand the connection to
// smtp.Client, which reads the server greeting.
func defaultSMTPDial(ctx context.Context, addr string, tlsConfig *tls.Config) (*smtp.Client, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if tlsConfig != nil {
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, &tlsHandshakeError{err: err}
		}
		conn = tlsConn
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, &greetingError{err: err}
	}
	return c, nil
}

// tlsConfig builds the client TLS configuration shared by STARTTLS and
// implicit mode: verify the relay's certificate against the system roots
// (or the injected test roots) for the configured host name.
func (s *SMTPOutTransport) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         s.Host,
		InsecureSkipVerify: s.TLSInsecureSkipVerify,
		RootCAs:            s.rootCAs,
	}
}

// Send implements Transport.
//
// Error class mapping:
//
//	connect/network/timeout         → ErrTransient
//	no greeting before the deadline → ErrTransient (hint when port is 465)
//	TLS handshake failure           → ErrTerminal (cert, or wrong mode for the port)
//	STARTTLS missing when required  → ErrTerminal (config bug, not transient)
//	AUTH rejected                   → ErrTerminal (bad creds)
//	MAIL/RCPT/DATA 4xx              → ErrTransient (greylisting, temporary)
//	MAIL/RCPT/DATA 5xx              → ErrTerminal (relay-rejected, bad address)
//	CRLF in header value            → ErrTerminal (NFR1 reject at our edge)
func (s *SMTPOutTransport) Send(ctx context.Context, msg Message) (SendResult, error) {
	// Passthrough headers become literal header lines in buildRFC5322
	// (FR99). The ingress already refused bad values; this is the layer
	// that must not trust that (NFR32). checkHeaders holds each name to
	// the allowlist and each value to one line of printable ASCII within
	// RFC 5322's line limit, so they can be written as they are.
	if err := checkHeaders(msg); err != nil {
		return SendResult{}, err
	}
	// NFR1: reject CRLF in submitter-controlled header values before we
	// hand-write them into the DATA blob. Catches header-injection
	// payloads at our edge with a clear error.
	if err := validateNoHeaderCRLF(msg); err != nil {
		return SendResult{}, &TransportError{
			Class:   ErrTerminal,
			Cause:   err,
			Message: "smtp: header injection attempt rejected",
		}
	}

	// Establish per-request deadline. The operator's per-endpoint timeout
	// (FR22) is the outer bound; smtpRequestTimeout is the safety net for
	// unbounded protocol stalls.
	deadlineCtx, cancel := context.WithTimeout(ctx, smtpRequestTimeout)
	defer cancel()

	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	var implicitTLS *tls.Config
	if s.TLS == TLSImplicit {
		implicitTLS = s.tlsConfig()
	}
	c, err := s.dial(deadlineCtx, addr, implicitTLS)
	if err != nil {
		return SendResult{}, s.classifyDialError(err)
	}
	defer func() { _ = c.Close() }()

	// EHLO/HELO — required before any other command. Some relays use the
	// announced hostname for client authorization; localhost remains the
	// compatibility default when no hostname is configured.
	helloHostname := s.HelloHostname
	if helloHostname == "" {
		helloHostname = "localhost"
	}
	if err := c.Hello(helloHostname); err != nil {
		return SendResult{}, classifySMTPError(err, "smtp: EHLO failed")
	}

	// STARTTLS upgrade (TLSStartTLS). If the server doesn't advertise the
	// extension we refuse to continue: plaintext is an operator-side
	// config error, not a transient fault, and never a silent downgrade.
	// Implicit mode is already encrypted; plaintext mode skips this.
	if s.TLS == TLSStartTLS {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			return SendResult{}, &TransportError{
				Class:   ErrTerminal,
				Message: "smtp: server does not advertise STARTTLS (tls = \"starttls\" requires it)",
			}
		}
		if err := c.StartTLS(s.tlsConfig()); err != nil {
			return SendResult{}, classifyStartTLSError(err)
		}
	}

	// AUTH PLAIN. stdlib's PlainAuth refuses to send credentials over an
	// unencrypted link unless the server explicitly advertises AUTH PLAIN,
	// and verifies the server hostname matches what we configured.
	if s.Username != "" || s.Password != "" {
		auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)
		if err := c.Auth(auth); err != nil {
			// Auth errors are typically bad creds; classify as terminal.
			return SendResult{}, classifySMTPError(err, "smtp: AUTH failed")
		}
	}

	// Envelope: MAIL FROM uses the address-only portion (no display name).
	envFrom, err := envelopeAddress(msg.From)
	if err != nil {
		return SendResult{}, &TransportError{Class: ErrTerminal, Cause: err, Message: "smtp: invalid from address"}
	}
	if err := c.Mail(envFrom); err != nil {
		return SendResult{}, classifySMTPError(err, "smtp: MAIL FROM rejected")
	}
	for _, to := range msg.To {
		envTo, err := envelopeAddress(to)
		if err != nil {
			return SendResult{}, &TransportError{Class: ErrTerminal, Cause: err, Message: "smtp: invalid to address"}
		}
		if err := c.Rcpt(envTo); err != nil {
			return SendResult{}, classifySMTPError(err, "smtp: RCPT TO rejected")
		}
	}

	// DATA: write the full RFC 5322 message (headers + body). textproto's
	// DotWriter handles dot-stuffing and \n→\r\n translation automatically.
	w, err := c.Data()
	if err != nil {
		return SendResult{}, classifySMTPError(err, "smtp: DATA command rejected")
	}
	payload := s.buildRFC5322(msg)
	if _, err := w.Write(payload); err != nil {
		return SendResult{}, &TransportError{Class: ErrTransient, Cause: err, Message: "smtp: write payload failed"}
	}
	if err := w.Close(); err != nil {
		return SendResult{}, classifySMTPError(err, "smtp: DATA finalize failed")
	}

	// QUIT is best-effort. A failed QUIT after a successful DATA-close
	// doesn't mean the message wasn't accepted — the server already
	// returned 250 to the dot.
	_ = c.Quit()

	// MessageID: stdlib net/smtp doesn't expose the server's
	// "queued as <id>" response, so SendResult.MessageID stays empty for
	// SMTP — the operator must correlate via timestamp + recipient in the
	// relay's own logs.
	return SendResult{}, nil
}

// validateNoHeaderCRLF rejects any submitter-controlled header value that
// contains a CR or LF — the structural defense against header injection in
// the hand-written RFC 5322 DATA blob (NFR1).
func validateNoHeaderCRLF(msg Message) error {
	if strings.ContainsAny(msg.From, "\r\n") {
		return errors.New("from contains CR or LF")
	}
	if strings.ContainsAny(msg.ReplyTo, "\r\n") {
		return errors.New("reply-to contains CR or LF")
	}
	if strings.ContainsAny(msg.Subject, "\r\n") {
		return errors.New("subject contains CR or LF")
	}
	for i, to := range msg.To {
		if strings.ContainsAny(to, "\r\n") {
			return fmt.Errorf("to[%d] contains CR or LF", i)
		}
	}
	return nil
}

// envelopeAddress extracts the bare email portion of an RFC 5322 address
// for use in SMTP MAIL FROM / RCPT TO. The display name is dropped — the
// envelope address is just the addr-spec.
//
// Examples:
//
//	"craig@example.com"               → "craig@example.com"
//	"Craig <craig@example.com>"       → "craig@example.com"
//	"\"Craig Mc\" <craig@example.com>" → "craig@example.com"
func envelopeAddress(addr string) (string, error) {
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return "", fmt.Errorf("parse address %q: %w", addr, err)
	}
	return parsed.Address, nil
}

// buildRFC5322 constructs the message body sent in DATA. Headers use
// CRLF line endings (RFC 5322); the body's line endings are converted
// by textproto.DotWriter inside Data().
//
// Text-only messages keep the v1.x single-part wire format unchanged.
// When BodyHTML is set (FR74), the body becomes multipart/alternative
// with the text part first — RFC 2046 §5.1.4 orders parts by increasing
// preference, so HTML-capable clients render the HTML part and
// text-only clients fall back to the text part.
func (s *SMTPOutTransport) buildRFC5322(msg Message) []byte {
	var buf bytes.Buffer
	writeHeader(&buf, "From", msg.From)
	writeHeader(&buf, "To", strings.Join(msg.To, ", "))
	if msg.ReplyTo != "" {
		writeHeader(&buf, "Reply-To", msg.ReplyTo)
	}
	writeHeader(&buf, "Subject", encodeMIMESubject(msg.Subject))
	for _, h := range msg.Headers {
		writeHeader(&buf, h.Name, h.Value) // validated by checkHeaders in Send
	}
	writeHeader(&buf, "Date", s.now().UTC().Format(time.RFC1123Z))
	writeHeader(&buf, "MIME-Version", "1.0")

	if msg.BodyHTML == "" && len(msg.Attachments) == 0 {
		writeHeader(&buf, "Content-Type", "text/plain; charset=\"utf-8\"")
		writeHeader(&buf, "Content-Transfer-Encoding", "8bit")
		buf.WriteString("\r\n")
		buf.WriteString(msg.BodyText)
		return buf.Bytes()
	}

	if len(msg.Attachments) == 0 {
		// HTML, no files: multipart/alternative at the top level.
		var parts bytes.Buffer
		mw := multipart.NewWriter(&parts)
		writeHeader(&buf, "Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
		buf.WriteString("\r\n")
		writeAlternativeParts(mw, msg)
		_ = mw.Close()
		buf.Write(parts.Bytes())
		return buf.Bytes()
	}

	// Attachments present (FR92): multipart/mixed wraps the body — a
	// plain text part, or a nested multipart/alternative for HTML —
	// followed by one base64 part per file. All boundaries are
	// generated by multipart.Writer, never content-derived.
	var parts bytes.Buffer
	mixed := multipart.NewWriter(&parts)
	writeHeader(&buf, "Content-Type", `multipart/mixed; boundary="`+mixed.Boundary()+`"`)
	buf.WriteString("\r\n")

	if msg.BodyHTML == "" {
		textPart, _ := mixed.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {`text/plain; charset="utf-8"`},
			"Content-Transfer-Encoding": {"8bit"},
		})
		_, _ = textPart.Write([]byte(msg.BodyText))
	} else {
		var altBuf bytes.Buffer
		alt := multipart.NewWriter(&altBuf)
		writeAlternativeParts(alt, msg)
		_ = alt.Close()
		altPart, _ := mixed.CreatePart(textproto.MIMEHeader{
			"Content-Type": {`multipart/alternative; boundary="` + alt.Boundary() + `"`},
		})
		_, _ = altPart.Write(altBuf.Bytes())
	}

	for _, a := range msg.Attachments {
		// Filename crosses only as a MIME parameter via FormatMediaType
		// (structural quoting/encoding — NFR1); CR/LF are stripped
		// defensively even though ingestion already sanitized.
		name := strings.NewReplacer("\r", "", "\n", "").Replace(a.Filename)
		part, _ := mixed.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {a.ContentType},
			"Content-Disposition":       {mime.FormatMediaType("attachment", map[string]string{"filename": name})},
			"Content-Transfer-Encoding": {"base64"},
		})
		_, _ = part.Write(wrapBase64(a.Data))
	}
	_ = mixed.Close()
	buf.Write(parts.Bytes())
	return buf.Bytes()
}

// writeAlternativeParts emits the text and HTML parts in RFC 2046
// §5.1.4 order (increasing preference).
func writeAlternativeParts(mw *multipart.Writer, msg Message) {
	textPart, _ := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {`text/plain; charset="utf-8"`},
		"Content-Transfer-Encoding": {"8bit"},
	})
	_, _ = textPart.Write([]byte(msg.BodyText))
	htmlPart, _ := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {`text/html; charset="utf-8"`},
		"Content-Transfer-Encoding": {"8bit"},
	})
	_, _ = htmlPart.Write([]byte(msg.BodyHTML))
}

// wrapBase64 encodes data with RFC 2045 76-column line wrapping.
func wrapBase64(data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	var out bytes.Buffer
	for len(enc) > 76 {
		out.WriteString(enc[:76])
		out.WriteString("\r\n")
		enc = enc[76:]
	}
	out.WriteString(enc)
	return out.Bytes()
}

// writeHeader writes a single `Name: Value\r\n` header line. Caller has
// already CRLF-validated the value (validateNoHeaderCRLF).
func writeHeader(buf *bytes.Buffer, name, value string) {
	buf.WriteString(name)
	buf.WriteString(": ")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

// encodeMIMESubject applies RFC 2047 B-encoding when the subject contains
// non-ASCII bytes. ASCII-only subjects pass through unchanged. The
// encoder handles word-splitting per the 76-character soft limit.
func encodeMIMESubject(subject string) string {
	if !needsMIMEEncoding(subject) {
		return subject
	}
	return mime.BEncoding.Encode("utf-8", subject)
}

func needsMIMEEncoding(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return true
		}
	}
	return false
}

// classifyDialError maps a dial failure to a TransportError. Network
// faults are transient. A failed TLS handshake is terminal: the cert
// didn't verify, or the server spoke plaintext, which means tls =
// "implicit" is pointed at a STARTTLS port. A connection that opened but
// never produced a greeting is transient (a hung relay), with a hint
// when the port is 465, because STARTTLS mode against an implicit-TLS
// port looks exactly like a hung relay from this side.
func (s *SMTPOutTransport) classifyDialError(err error) *TransportError {
	var hs *tlsHandshakeError
	if errors.As(err, &hs) {
		msg := "smtp: TLS handshake failed"
		var rhe tls.RecordHeaderError
		if errors.As(err, &rhe) {
			msg = fmt.Sprintf("smtp: TLS handshake failed: server answered in plaintext, so port %d probably expects tls = \"starttls\"", s.Port)
		}
		return &TransportError{Class: ErrTerminal, Cause: err, Message: msg}
	}
	var ge *greetingError
	if errors.As(err, &ge) {
		var tperr *textproto.Error
		if errors.As(ge.err, &tperr) {
			return classifySMTPError(ge.err, "smtp: server refused the connection in its greeting")
		}
		msg := "smtp: connected but no SMTP greeting arrived"
		if s.TLS != TLSImplicit && s.Port == 465 {
			msg += " (port 465 usually expects tls = \"implicit\")"
		}
		return &TransportError{Class: ErrTransient, Cause: err, Message: msg}
	}
	return &TransportError{Class: ErrTransient, Cause: err, Message: "smtp: dial failed"}
}

// classifyStartTLSError maps a StartTLS failure. An SMTP reply code
// (the server refused the command) classifies by code; anything else is
// the handshake itself failing — certificate verification, protocol
// mismatch — which is a configuration problem, so terminal.
func classifyStartTLSError(err error) *TransportError {
	var tperr *textproto.Error
	if errors.As(err, &tperr) {
		return classifySMTPError(err, "smtp: STARTTLS command rejected")
	}
	return &TransportError{Class: ErrTerminal, Cause: err, Message: "smtp: STARTTLS handshake failed"}
}

// classifySMTPError maps an error from a net/smtp.Client command to a
// TransportError with the right ErrorClass. SMTP protocol errors come
// back as *textproto.Error which exposes the response code directly.
//
// Mapping:
//
//	4xx codes  → ErrTransient (server-side temporary; greylisting, etc.)
//	5xx codes  → ErrTerminal  (relay-rejected, bad address, AUTH failure)
//	non-SMTP   → ErrTransient (network/timeout/EOF; retry once)
func classifySMTPError(err error, contextMsg string) *TransportError {
	if err == nil {
		return nil
	}
	var tperr *textproto.Error
	if errors.As(err, &tperr) {
		class := ErrTransient
		if tperr.Code >= 500 {
			class = ErrTerminal
		}
		return &TransportError{
			Class:   class,
			Status:  tperr.Code,
			Cause:   err,
			Message: contextMsg,
		}
	}
	// I/O error, connection drop, timeout — transient.
	return &TransportError{
		Class:   ErrTransient,
		Cause:   err,
		Message: contextMsg,
	}
}

var _ Transport = (*SMTPOutTransport)(nil)

// Registry registration.
func init() {
	Register(Registration{
		Type:           "smtp",
		Validate:       validateSMTPOutSettings,
		Build:          buildSMTPOutFromSettings,
		CarriesHeaders: true,
	})
}

func validateSMTPOutSettings(settings map[string]any) error {
	host, ok := settings["host"].(string)
	if !ok || host == "" {
		return fmt.Errorf("smtp transport requires settings.host")
	}
	// port can be int or int64 depending on TOML's parse; accept either.
	portRaw, ok := settings["port"]
	if !ok {
		return fmt.Errorf("smtp transport requires settings.port")
	}
	port, ok := coerceInt(portRaw)
	if !ok || port <= 0 || port > 65535 {
		return fmt.Errorf("smtp transport settings.port must be 1-65535, got %v", portRaw)
	}
	if username, ok := settings["username"].(string); !ok || username == "" {
		return fmt.Errorf("smtp transport requires settings.username")
	}
	if password, ok := settings["password"].(string); !ok || password == "" {
		return fmt.Errorf("smtp transport requires settings.password")
	}
	if helloHostnameRaw, exists := settings["hello_hostname"]; exists {
		helloHostname, ok := helloHostnameRaw.(string)
		if !ok || helloHostname == "" || strings.ContainsAny(helloHostname, " \t\r\n\v\f") {
			return fmt.Errorf("smtp transport settings.hello_hostname must be a non-empty string with no whitespace")
		}
	}
	if _, err := smtpTLSModeFromSettings(settings); err != nil {
		return err
	}
	return nil
}

// smtpTLSModeFromSettings resolves settings.tls, falling back to the
// older settings.require_tls boolean. Both keys together is an error so
// a config can't say two different things about the same connection.
func smtpTLSModeFromSettings(settings map[string]any) (TLSMode, error) {
	tlsRaw, hasTLS := settings["tls"]
	reqRaw, hasReq := settings["require_tls"]
	switch {
	case hasTLS && hasReq:
		return "", fmt.Errorf("smtp transport: set settings.tls or settings.require_tls, not both")
	case hasTLS:
		str, isString := tlsRaw.(string)
		mode, valid := ParseTLSMode(str)
		if !isString || !valid {
			return "", fmt.Errorf(`smtp transport settings.tls must be "starttls", "implicit", or "none", got %v`, tlsRaw)
		}
		return mode, nil
	case hasReq:
		b, isBool := reqRaw.(bool)
		if !isBool {
			return "", fmt.Errorf("smtp transport settings.require_tls must be true or false, got %v", reqRaw)
		}
		if b {
			return TLSStartTLS, nil
		}
		return TLSNone, nil
	}
	return TLSStartTLS, nil
}

func buildSMTPOutFromSettings(settings map[string]any) (Transport, error) {
	host, _ := settings["host"].(string)
	port, _ := coerceInt(settings["port"])
	username, _ := settings["username"].(string)
	password, _ := settings["password"].(string)
	helloHostname, _ := settings["hello_hostname"].(string)
	mode, err := smtpTLSModeFromSettings(settings)
	if err != nil {
		return nil, err
	}
	insecureSkipVerify := false
	if v, ok := settings["tls_insecure_skip_verify"].(bool); ok {
		insecureSkipVerify = v
	}
	if host == "" || port <= 0 || username == "" || password == "" {
		return nil, fmt.Errorf("smtp: host, port, username, password all required")
	}
	tp := NewSMTPOutTransport(host, port, username, password, mode)
	tp.HelloHostname = helloHostname
	tp.TLSInsecureSkipVerify = insecureSkipVerify
	return tp, nil
}

// coerceInt handles the int / int64 / float64 polymorphism TOML decoders
// can produce depending on the value's representation in the file.
func coerceInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}
