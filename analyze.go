package teler

import (
	"net/http"

	"github.com/kitabisa/teler-waf/threat"
)

/*
analyzeRequest checks an incoming HTTP request for certain types of threats or vulnerabilities.
If a threat is detected, the function returns an error and the request is stopped from continuing through the middleware chain.

The function takes in two arguments: a http.ResponseWriter and an http.Request.
It returns a modified http.Request and an error value.

The function first retrieves the threat struct from the Teler struct.
It then iterates over the elements in the excludes map of the threat struct.
For each element in the excludes map, the function checks whether the value is true.
If it is not true, the loop continues to the next iteration.
Otherwise, the function performs a check based on the type of threat specified by the key in the excludes map.

The types of threats that are checked for are:

- Common web attacks
- Common Vulnerabilities and Exposures (CVEs)
- Bad IP addresses
- Bad referrers
- Bad crawlers
- Directory bruteforce attacks
*/
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
