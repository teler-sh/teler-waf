package teler

import (
	"strings"

	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
)

func (t *Teler) inThreatIndex(kind threat.Threat, substr string) bool {
	if i := strings.Index(t.threat.data[kind], substr); i >= 0 {
		return true
	}

	return false
}

func isValidMethod(method request.Method) bool {
	switch method {
	case request.GET, request.HEAD, request.POST, request.PUT, request.PATCH:
	case request.DELETE, request.CONNECT, request.OPTIONS, request.TRACE, request.ALL:
	case "":
		return true
	default:
		return false
	}

	return false
}

func normalizeRawStringReader(raw string) *strings.Reader {
	raw = strings.Trim(raw, `"`)
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	raw = strings.ReplaceAll(raw, "\\r", "\r")
	raw += "\r\n\r\n"

	return strings.NewReader(raw)
}
