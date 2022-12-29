package teler

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"net/http"
	"net/url"
	"path/filepath"

	"github.com/kitabisa/teler-waf/threat"
	"gitlab.com/golang-commonmark/mdurl"
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
			err = t.checkCVE(r)
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
			return k, err
		}
	}

	return threat.Undefined, nil
}

// checkCommonWebAttack checks if the request contains any patterns that match the common web attacks data.
// If a match is found, it returns an error indicating a common web attack has been detected.
// If no match is found, it returns nil.
func (t *Teler) checkCommonWebAttack(r *http.Request) error {
	// Declare byte slice for request body
	var b []byte

	// Decode the raw query string of the URL using the mdurl.Decode() method
	query := mdurl.Decode(r.URL.RawQuery)

	// Read the entire request body into a byte slice using io.ReadAll()
	b, err := io.ReadAll(r.Body)
	if err == nil {
		// If the read not fails, replace the request body with a new io.ReadCloser that reads from the byte slice
		r.Body = io.NopCloser(bytes.NewReader(b))
	}

	// Decode the byte slice using mdurl.Decode() and convert it to a string
	body := mdurl.Decode(string(b))

	// Iterate over the filters in the CommonWebAttack data stored in the t.threat.cwa.Filters field
	for _, filter := range t.threat.cwa.Filters {
		// Get the compiled regex pattern for the current filter
		pattern := filter.pattern

		// Do not process the check if pattern is nil
		if pattern == nil {
			continue
		}

		// If the pattern matches the query, or body, return an error indicating a common web attack has been detected
		if pattern.MatchString(query) || pattern.MatchString(body) {
			return errors.New(filter.Description)
		}
	}

	// Return nil if no match is found
	return nil
}

// checkCVE checks the request against a set of templates to see if it matches a known
// Common Vulnerabilities and Exposures (CVE) threat.
// It takes a pointer to an HTTP request as an input and returns an error if the request
// matches a known threat. Otherwise, it returns nil.
func (t *Teler) checkCVE(r *http.Request) error {
	// data is the set of templates to check against.
	data := t.threat.cve

	// kind is the type of template to check (either "path" or "raw").
	// err is used to store any error that occurs during the parsing of the request URI or the raw string.
	var kind string
	var err error

	// requestParams is a map that stores the query parameters of the request URI and
	// iterate over the query parameters of the request URI and add them to the map.
	requestParams := make(map[string]string)
	for q, v := range r.URL.Query() {
		requestParams[q] = v[0]
	}

	// Iterate over the templates in the data set.
	for _, tpl := range data.GetArray("templates") {
		// Iterate over the requests in the template.
		for _, req := range tpl.GetArray("requests") {
			// diff is a pointer to a URL that represents the difference between the request URI and the URI in the template.
			var diff *url.URL

			// Determine the kind of template (either "path" or "raw").
			switch {
			case len(req.GetArray("path")) > 0:
				kind = "path"
			case len(req.GetArray("raw")) > 0:
				kind = "raw"
			}

			// If the template is a "path" type and the request method doesn't match, skip this template.
			if kind == "path" && string(req.GetStringBytes("method")) != r.Method {
				continue
			}

			// Iterate over the paths or raw strings in the template.
			for _, p := range req.GetArray(kind) {
				// Parse the request URI or the raw string based on the kind of template.
				switch kind {
				case "path":
					diff, err = url.ParseRequestURI(
						strings.TrimPrefix(
							strings.Trim(p.String(), `"`),
							"{{BaseURL}}",
						),
					)

					// If an error occurs during the parsing, skip this path.
					if err != nil {
						continue
					}
				case "raw":
					// TODO: avoid parsing the request URI and normalizing the raw
					// string multiple times by storing the result in a variable and reusing it
					// by using a prefix tree (also known as a trie) data structure
					rawHTTP := normalizeRawStringReader(p.String())

					raw, err := http.ReadRequest(bufio.NewReader(rawHTTP))
					// If an error occurs during the parsing, skip this raw string.
					if err != nil {
						continue
					}

					// If the request method doesn't match, skip this raw string.
					if raw.Method != r.Method {
						continue
					}

					diff = raw.URL
				}

				// If the diff path is empty or contains only a single character, skip this path or raw string.
				if len(diff.Path) <= 1 {
					continue
				}

				// If the request path doesn't match the diff path, break out of the innermost loop.
				if r.URL.Path != diff.Path {
					break
				}

				// diffParams is a map that stores the query parameters of the diff URI and iterate over the
				// query parameters of the diff URI and add them to the diffParams map.
				diffParams := make(map[string]string)
				for q, v := range diff.Query() {
					diffParams[q] = v[0]
				}

				// allParamsMatch is a flag that indicates whether all the query parameters in the diff URI are
				// present in the request URI and iterate over the query parameters of the diff URI.
				allParamsMatch := true
				for q, v := range diffParams {
					// If a query parameter in the diff URI is not present in the request URI,
					// set allParamsMatch to false and break out of the loop.
					if requestParams[q] != v {
						allParamsMatch = false
						break
					}
				}

				// If all the query parameters in the diff URI are present in the request URI, return an error of CVE ID.
				if allParamsMatch {
					return errors.New(string(tpl.GetStringBytes("id")))
				}
			}
		}
	}

	// Return nil if the request doesn't match any known threat.
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
	// Extract the file extension from the request path and if
	// file extension is empty string, do not process the check
	ext := filepath.Ext(r.URL.Path)
	if ext == "" {
		return nil
	}

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
