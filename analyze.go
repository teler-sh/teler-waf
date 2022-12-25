package teler

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"net/http"
	"net/url"
	"path/filepath"

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
			err = t.checkCommonWebAttack(r)
		case threat.CVE:
			// TODO
		case threat.BadIPAddress:
			err = t.checkBadIPAddress(r)
		case threat.BadReferrer:
			err = t.checkBadReferrer(r)
		case threat.BadCrawler:
			err = t.checkBadCrawler(r)
		case threat.DirectoryBruteforce:
			err = t.checkDirectoryBruteforce(r)
		}

		if err != nil {
			t.handler.ServeHTTP(w, r)
			return k, err
		}
	}

	return threat.Undefined, nil
}

// checkCommonWebAttack checks if the request contains any patterns that match the common web attacks data.
// If a match is found, it returns an error indicating a common web attack has been detected.
// If no match is found, it returns nil.
func (t *Teler) checkCommonWebAttack(r *http.Request) error {
	// Convert the request to a RAW HTTP request string
	raw := toRaw(r)

	// Iterate over the filters in the CommonWebAttack data
	for _, filter := range t.threat.cwa.Filters {
		// Get the compiled regex pattern for the current filter
		pattern := filter.pattern

		// Check if the pattern matches the RAW HTTP request using regexp.MatchString
		if pattern != nil && pattern.MatchString(raw) {
			// If the pattern matches, return an error indicating a common web attack has been detected
			return errors.New(filter.Description)
		}
	}

	// Return nil if no match is found
	return nil
}

// checkBadIPAddress checks if the request remote address is in the BadIPAddress index.
// It returns an error if the remote address is found in the index, indicating a bad IP address.
// Otherwise, it returns nil.
func (t *Teler) checkBadIPAddress(r *http.Request) error {
	// Check if the request remote address is in BadIPAddress index
	if t.inThreatIndex(threat.BadIPAddress, r.RemoteAddr) {
		// Return an error indicating a bad IP address has been detected
		return errors.New("bad IP address")
	}

	// Return nil if the remote address is not found in the index
	return nil
}

// checkBadReferrer checks if the request referer header is from a known bad referer.
// It does this by parsing the referer URL, extracting the hostname, and then finding the effective top-level domain plus one.
// The resulting domain is then checked against the BadReferrer index in the threat struct.
// If the domain is found in the index, an error indicating a bad HTTP referer is returned.
// Otherwise, nil is returned.
func (t *Teler) checkBadReferrer(r *http.Request) error {
	// Parse the request referer URL
	ref, err := url.Parse(r.Referer())
	if err != nil {
		// If there is an error parsing the URL, return nil
		// TODO: What should we do so as not to stop the threat analysis chain from analyzeRequest?
		return nil
	}

	// Extract the effective top-level domain plus one from the hostname of the referer URL
	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(ref.Hostname())
	if err != nil {
		// If there is an error extracting the effective top-level domain plus one, return nil
		// TODO: What should we do so as not to stop the threat analysis chain from analyzeRequest?
		return nil
	}

	// Check if the root domain of request referer header is in the BadReferrer index
	if t.inThreatIndex(threat.BadReferrer, eTLD1) {
		// If the domain is found in the index, return an error indicating a bad HTTP referer
		return errors.New("bad HTTP referer")
	}

	// Return nil if no match is found in the BadReferrer index
	return nil
}

// checkBadCrawler checks the request for bad crawler activity.
// It retrieves the User-Agent from the request and iterates over
// the compiled regular expressions in the badCrawler field of the threat struct.
// If any of the regular expressions match the User-Agent,
// it returns an error with the message "bad crawler".
// If the User-Agent is empty or no regular expressions match,
// it returns nil.
func (t *Teler) checkBadCrawler(r *http.Request) error {
	// Retrieve the User-Agent from the request
	ua := r.UserAgent()

	// Do not proccess the check if User-Agent is empty
	if ua == "" {
		return nil
	}

	// Iterate over BadCrawler compiled patterns and do the check
	for _, pattern := range t.threat.badCrawler {
		// Check if the pattern is not nil and matches the User-Agent
		if pattern != nil && pattern.MatchString(ua) {
			return errors.New("bad crawler")
		}
	}

	return nil
}

// checkDirectoryBruteforce checks the request for a directory bruteforce attack.
// It extracts the file extension from the request path, creates a regex pattern
// that matches the entire request path, and replaces any instances of .%EXT% in
// the directory bruteforce data with the file extension. It then checks if the
// pattern matches the data using regexp.MatchString. If a match is found, it
// returns an error indicating a directory bruteforce attack has been detected.
// If no match is found or there was an error during the regex matching process,
// it returns nil.
func (t *Teler) checkDirectoryBruteforce(r *http.Request) error {
	// Extract the file extension from the request path
	ext := filepath.Ext(r.URL.Path)

	// Trim the leading slash from the request path, and if path
	// is empty string after the trim, do not process the check
	path := strings.TrimLeft(r.URL.Path, "/")
	if path == "" {
		return nil
	}

	// Create a regex pattern that matches the entire request path
	pattern := fmt.Sprintf("(?m)^%s$", regexp.QuoteMeta(path))

	// Replace any instances of .%EXT% in the directory bruteforce data with the file extension
	data := strings.ReplaceAll(t.threat.data[threat.DirectoryBruteforce], ".%EXT%", ext)

	// Check if the pattern matches the data using regexp.MatchString
	match, err := regexp.MatchString(pattern, data)
	if err != nil {
		// Return nil if there was an error during the regex matching process
		return nil
	}

	// If the pattern matches the data, return an error indicating a directory bruteforce attack has been detected
	if match {
		return errors.New("directory bruteforce")
	}

	// Return nil if no match is found
	return nil
}
