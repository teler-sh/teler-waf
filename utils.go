package teler

import (
	"strings"

	"github.com/kitabisa/teler-waf/threat"
)

func (t *Teler) inThreatIndex(kind threat.Threat, substr string) bool {
	if i := strings.Index(t.threat.data[kind], substr); i >= 0 {
		return true
	}

	return false
}
