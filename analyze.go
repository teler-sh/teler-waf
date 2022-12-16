package teler

import (
	"net/http"

	"github.com/kitabisa/teler-waf/threat"
)

// analyzeRequest runs the actual checks on the request and returns an error if the middleware chain should stop.
func (t *Teler) analyzeRequest(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	th := t.threat

	for k, v := range th.excludes {
		if !v {
			continue
		}

		switch k {
		case threat.CommonWebAttack:
			// TODO
		case threat.CVE:
			// TODO
		case threat.BadIPAddress:
			// TODO
		case threat.BadReferrer:
			// TODO
		case threat.BadCrawler:
			// TODO
		case threat.DirectoryBruteforce:
			// TODO
		}
	}

	return r, nil
}
