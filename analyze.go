package teler

import (
	"errors"

	"net/http"
	"net/url"

	"github.com/kitabisa/teler-waf/threat"
	"golang.org/x/net/publicsuffix"
)

/*
analyzeRequest checks an incoming HTTP request for certain types of threats or vulnerabilities.
If a threat is detected, the function returns an error and the request is stopped from continuing through the middleware chain.

The function takes in two arguments: a http.ResponseWriter and an http.Request.
It returns threat type and an error value.

The function first retrieves the threat struct from the Teler struct.
It then iterates over the elements in the excludes map of the threat struct.
For each element in the excludes map, the function checks whether the value is true.
If it is true, the loop continues to the next iteration.
Otherwise, the function performs a check based on the type of threat specified by the key in the excludes map.

The types of threats that are checked for are:

- Common web attacks
- Common Vulnerabilities and Exposures (CVEs)
- Bad IP addresses
- Bad referrers
- Bad crawlers
- Directory bruteforce attacks
*/
func (t *Teler) analyzeRequest(w http.ResponseWriter, r *http.Request) (threat.Threat, error) {
	var err error

	// TODO:
	// - analyze from custom rules
	// - implement whitelisting

	th := t.threat
	for k, v := range th.excludes {
		if v {
			continue
		}

		switch k {
		case threat.CommonWebAttack:
			// TODO
		case threat.CVE:
			// TODO
		case threat.BadIPAddress:
			err = t.checkBadIPAddress(r)
		case threat.BadReferrer:
			err = t.checkBadReferrer(r)
		case threat.BadCrawler:
			err = t.checkBadCrawler(r)
		case threat.DirectoryBruteforce:
			// TODO
		}

		if err != nil {
			t.handler.ServeHTTP(w, r)
			return k, err
		}
	}

	return threat.Undefined, nil
}

func (t *Teler) checkBadIPAddress(r *http.Request) error {
	if t.inThreatIndex(threat.BadIPAddress, r.RemoteAddr) {
		return errors.New("bad IP address")
	}

	return nil
}

func (t *Teler) checkBadReferrer(r *http.Request) error {
	ref, err := url.Parse(r.Referer())
	if err != nil {
		// TODO: What should we do so as not to stop the
		// threat analysis chain from analyzeRequest?
		return nil
	}

	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(ref.Hostname())
	if err != nil {
		// TODO: What should we do so as not to stop the
		// threat analysis chain from analyzeRequest?
		return nil
	}

	if t.inThreatIndex(threat.BadReferrer, eTLD1) {
		return errors.New("bad HTTP referer")
	}

	return nil
}

func (t *Teler) checkBadCrawler(r *http.Request) error {
	ua := r.UserAgent()
	// Do not proccess the check if User-Agent is empty
	if ua == "" {
		return nil
	}

	// Iterate over BadCrawler compiled patterns and do the check
	for _, pattern := range t.threat.pattern[threat.BadCrawler] {
		if pattern != nil && pattern.MatchString(ua) {
			return errors.New("bad crawler")
		}
	}

	return nil
}
