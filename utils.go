package teler

import (
	"errors"
	"fmt"
	"html"
	"strings"

	"net/http"

	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
	"github.com/patrickmn/go-cache"
	"github.com/twharmon/gouid"
	"gitlab.com/golang-commonmark/mdurl"
)

// inThreatIndex checks if the given substring is in specific threat datasets
func (t *Teler) inThreatIndex(kind threat.Threat, substr string) bool {
	if i := strings.Index(t.threat.data[kind], substr); i >= 0 {
		return true
	}

	return false
}

// inWhitelist checks if the given substring is in whitelist patterns
func (t *Teler) inWhitelist(r *http.Request) bool {
	uri := toURLDecode(r.URL.RequestURI())
	headers := headersToRawString(r.Header)
	clientIP := getClientIP(r)

	// Check the request URI, headers, and client IP address against the whitelist
	for _, pattern := range t.whitelistRegexes {
		if pattern.MatchString(uri) || pattern.MatchString(headers) || pattern.MatchString(clientIP) {
			return true
		}
	}

	return false
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
			h.WriteString(
				fmt.Sprintf("%s: %s\n", toURLDecode(key), toURLDecode(value)),
			)
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

// toURLDecode decode URL-decoded characters string using mdurl
func toURLDecode(s string) string {
	return mdurl.Decode(s)
}

// stringDeUnescape to decode URL-decoded characters, and
// unescapes any HTML entities
func stringDeUnescape(s string) string {
	s = toURLDecode(s)
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

// getClientIP to get client IP address from request
func getClientIP(r *http.Request) string {
	// Get the client's IP address from the X-Real-Ip header field
	clientIP := r.Header.Get("X-Real-Ip")

	// If the X-Real-Ip header field is not present, try the X-Forwarded-For header field
	if clientIP == "" {
		clientIP = r.Header.Get("X-Forwarded-For")
	}

	// If the X-Forwarded-For header field is not present, use the RemoteAddr field
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	// Returning client IP address
	return clientIP
}

// setReqIdHeader to set teler request ID header response
func setReqIdHeader(w http.ResponseWriter) string {
	// Generate a unique ID using the gouid package.
	id := gouid.Bytes(10)

	// Set the "X-Teler-Req-Id" header in the response with the unique ID.
	w.Header().Set(xTelerReqId, id.String())

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
