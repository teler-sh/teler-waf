// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"bytes"
	"errors"
	"html"
	"io"
	"net"
	"regexp"
	"strings"

	"net/http"
	"net/url"

	"github.com/dwisiswant0/clientip"
	"github.com/expr-lang/expr/vm"
	"github.com/teler-sh/teler-waf/request"
	"github.com/teler-sh/teler-waf/threat"
	"github.com/patrickmn/go-cache"
	"github.com/twharmon/gouid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
)

// inThreatIndex checks if the given substring is in specific threat datasets
func (t *Teler) inThreatIndex(kind threat.Threat, substr string) bool {
	if i := strings.Index(t.threat.data[kind], substr); i >= 0 {
		return true
	}

	return false
}

// inThreatRegexp checks if the given pattern 'p' is match against threat datasets
func (t *Teler) inThreatRegexp(kind threat.Threat, p string) (bool, error) {
	var pattern strings.Builder
	pattern.WriteString("(?m)^")
	pattern.WriteString(regexp.QuoteMeta(p))
	pattern.WriteString("$")

	return regexp.MatchString(pattern.String(), t.threat.data[kind])
}

// setDSLRequestEnv will set DSL environment based on the incoming request information.
func (t *Teler) setDSLRequestEnv(r *http.Request) {
	// Converts map of headers to RAW string
	headers := headersToRawString(r.Header)

	// Decode the URL-encoded and unescape HTML entities request URI of the URL
	uri := stringDeUnescape(r.URL.RequestURI())

	// Declare byte slice for request body.
	var body string

	// Check if the request has a body
	if r.Body != nil {
		// Initialize buffer to hold request body.
		buf := &bytes.Buffer{}

		// NOTE(dwisiswant0): I think we should limit the r.Body
		// reader (w/ io.LimitedReader) before copying it.

		// Use io.Copy to copy the request body to the buffer.
		_, err := io.Copy(buf, r.Body)
		if err == nil {
			// If the read not fails, replace the request body
			// with a new io.ReadCloser that reads from the buffer.
			r.Body = io.NopCloser(buf)

			// Convert the buffer to a string.
			body = buf.String()
		}

		// Decode the URL-encoded and unescape HTML entities of body
		body = stringDeUnescape(body)
	}

	// Set DSL requests environment
	t.env.Requests = map[string]interface{}{
		"URI":     uri,
		"Headers": headers,
		"Body":    body,
		"Method":  r.Method,
		"IP":      clientip.FromRequest(r).String(),
	}
}

// headersToRawString converts a map of http.Header to
// multiline string, example:
// from,
//
//	Header = map[string][]string{
//		"Accept-Encoding": {"gzip, deflate"},
//		"Accept-Language": {"en-us"},
//		"Foo": {"Bar", "two"},
//	}
//
// to
//
//	Host: example.com
//	accept-encoding: gzip, deflate
//	Accept-Language: en-us
//	fOO: Bar
//	foo: two
func headersToRawString(headers http.Header) string {
	var h strings.Builder

	// Iterate over the request headers and append each key-value pair to the builder
	for key, values := range headers {
		for _, value := range values {
			h.WriteString(urldecode(key))
			h.WriteString(": ")
			h.WriteString(urldecode(value))
		}
	}

	// Returns the accumulated string of builder
	return h.String()
}

// unescapeHTML to unescapes any HTML entities, i.e. &aacute;"
// unescapes to "á", as does "&#225;" and "&#xE1;".
func unescapeHTML(s string) string {
	return html.UnescapeString(s)
}

// urldecode decodes a URL-encoded string by replacing
// percent-encoded characters with their corresponding ASCII
// characters, handling '+' as a space character.
func urldecode(s string) string {
	var out strings.Builder

	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			decoded := (hexValue(s[i+1]) << 4) | hexValue(s[i+2])
			out.WriteByte(decoded)
			i += 3
		} else if s[i] == '+' {
			out.WriteByte(' ')
			i++
		} else {
			out.WriteByte(s[i])
			i++
		}
	}

	return out.String()
}

// isHexDigit checks if a byte `c` represents a hex digit (0-9, a-f, A-F).
func isHexDigit(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// hexValue returns the decimal value of a hex digit `c`.
func hexValue(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

// stringDeUnescape to decode URL-decoded characters, and
// unescapes any HTML entities
func stringDeUnescape(s string) string {
	s = urldecode(s)
	return unescapeHTML(s)
}

// isValidMethod check if the given request.Method is valid
func isValidMethod(method request.Method) bool {
	switch method {
	case request.GET, request.HEAD, request.POST, request.PUT, request.PATCH:
	case request.DELETE, request.CONNECT, request.OPTIONS, request.TRACE, request.ALL:
	case "":
		return true
	}

	return false
}

// normalizeRawStringReader trim double-quotes of HTTP raw string,
// replace double-escape of CR and LF, and double it in the end, and
// returning as pointer of strings.Reader
func normalizeRawStringReader(raw string) *strings.Reader {
	var builder strings.Builder

	raw = strings.Trim(raw, `"`)
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	raw = strings.ReplaceAll(raw, "\\r", "\r")
	builder.WriteString(raw)
	builder.WriteString("\r\n\r\n")

	return strings.NewReader(builder.String())
}

// setCustomHeader to set custom header to the response writer
func setCustomHeader(w http.ResponseWriter, key, value string) {
	w.Header().Set(key, value)
}

// getUID to get unique ID
func getUID() string {
	// Generate a unique ID using the gouid package.
	id := gouid.Bytes(10)

	return id.String()
}

// removeSpecialChars to remove special characters with empty string
// includes line feed/newline, horizontal tab, backspace & form feed
func removeSpecialChars(str string) string {
	str = strings.Replace(str, "\n", "", -1) // Replace all newline
	str = strings.Replace(str, "\r", "", -1) // Replace all carriage return
	str = strings.Replace(str, "\t", "", -1) // Replace all horizontal tab
	str = strings.Replace(str, "\b", "", -1) // Replace all backspace
	str = strings.Replace(str, "\f", "", -1) // Replace all form feed

	return str
}

// getCache returns the cached error value for the given key.
// If the key is not found in the cache or the value is nil, it returns nil, false.
// When development flag is not set it will always return nil, false
func (t *Teler) getCache(key string) (error, bool) {
	if t.opt.Development {
		return nil, false
	}

	if msg, ok := t.cache.Get(key); ok {
		if msg == nil {
			return nil, ok
		}

		return msg.(error), ok
	}

	return nil, false
}

// setCache sets the error value for the given key in the cache.
// if msg is empty it sets a nil error, otherwise it creates a new error with the msg.
// When development flag is not set it will return without setting anything in the cache
func (t *Teler) setCache(key string, msg string) {
	if t.opt.Development {
		return
	}

	var err error

	if msg != "" {
		err = errors.New(msg)
	} else {
		err = nil
	}

	t.cache.Set(key, err, cache.DefaultExpiration)
}

// isDSLProgramTrue checks if the given compiled DSL expression (program) is true.
func (t *Teler) isDSLProgramTrue(program *vm.Program) bool {
	dslEval, err := t.env.Run(program)
	if err != nil {
		return false
	}

	return dslEval.(bool)
}

// setCache sets the error message to logs.
func (t *Teler) error(level zapcore.Level, msg string) {
	log := t.log.WithOptions(zap.WithCaller(true), zap.AddCallerSkip(1))

	switch level {
	case zapcore.ErrorLevel:
		log.Error(msg)
	case zapcore.PanicLevel:
		log.Panic(msg)
		// case zapcore.FatalLevel:
		// 	log.Fatal(msg)
	}
}

// isValidReferrer checks if a given referrer URL is a valid domain.
// It returns a boolean indicating validity, the extracted hostname,
// and an error if parsing or processing fails.
func isValidReferrer(ref string) (bool, string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return false, "", err
	}

	host := u.Hostname()
	if host == "" {
		return false, host, nil
	}

	eTLD, icann := publicsuffix.PublicSuffix(host)
	if icann || strings.IndexByte(eTLD, '.') >= 0 {
		return true, host, nil
	}

	return false, host, nil
}

// getListenAddr retrieves the local network address that the HTTP server is
// listening on from the request's context, utilizing a cache to store and
// retrieve this value efficiently.
func (t *Teler) getListenAddr(r *http.Request) string {
	cacheKey := "listen_addr"
	localAddrCtx := r.Context().Value(http.LocalAddrContextKey)

	if listenAddrCache, ok := t.cache.Get(cacheKey); ok {
		return listenAddrCache.(string)
	}

	if conn, ok := localAddrCtx.(net.Addr); ok {
		listenAddr := conn.String()
		t.cache.Set(cacheKey, listenAddr, cache.DefaultExpiration)

		return listenAddr
	}

	return ""
}
