package teler

import (
	"fmt"
	"regexp"
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

func (t *Teler) inThreatRegex(kind threat.Threat, substr string) bool {
	pattern := fmt.Sprintf("(?m)^%s$", regexp.QuoteMeta(substr))

	match, err := regexp.MatchString(pattern, t.threat.data[kind])
	if err != nil {
		return false
	}

	return match
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
