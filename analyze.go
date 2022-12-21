package teler

import (
	"fmt"

	"net/http"
	"net/url"

	"github.com/kitabisa/teler-waf/threat"
	"golang.org/x/net/publicsuffix"
)

/*
analyzeRequest checks an incoming HTTP request for certain types of threats or vulnerabilities.
If a threat is detected, the function returns an error and the request is stopped from continuing through the middleware chain.

The function takes in two arguments: a http.ResponseWriter and an http.Request.
It returns an error value.

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
func (t *Teler) analyzeRequest(w http.ResponseWriter, r *http.Request) error {
	var err error

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
			if err != nil {
				break
			}
		case threat.BadReferrer:
			err = t.checkBadReferrer(r)
			if err != nil {
				break
			}
		case threat.BadCrawler:
			// TODO
		case threat.DirectoryBruteforce:
			// TODO
		}
	}

	return err
}

func (t *Teler) checkBadIPAddress(r *http.Request) error {
	if t.inThreatIndex(threat.BadIPAddress, r.RemoteAddr) {
		return fmt.Errorf(errThreatDetected, "bad IP address", r.RemoteAddr)
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
		return fmt.Errorf(errThreatDetected, "bad HTTP referrer", r.Referer())
	}

	return nil
}
