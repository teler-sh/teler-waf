package teler

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"net/http"
	"net/url"
	"path/filepath"

	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
	"github.com/scorpionknifes/go-pcre"
	"golang.org/x/net/publicsuffix"
)

// Analyze runs the actual checks.
func (t *Teler) Analyze(w http.ResponseWriter, r *http.Request) error {
	_, err := t.analyzeRequest(w, r)

	return err
}

/*
analyzeRequest checks an incoming HTTP request for certain types of threats or vulnerabilities.
If a threat is detected, the function returns an error and the request is stopped from continuing through the middleware chain.

The function takes in two arguments: a http.ResponseWriter and an http.Request.
It returns a threat type and an error value.

The function first checks the request against any custom rules defined in the Teler struct.
If a custom rule is violated, the function returns an error with the name of the violated rule as the message.
If no custom rules are violated, the function continues processing.

The function then checks whether the request URI, headers, or client IP address are included
in a whitelist of patterns. If any of those values are in the whitelist, the function returns early.

The function then retrieves the threat struct from the Teler struct.
It iterates over the elements in the excludes map of the threat struct.
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

	// Check the request against custom rules
	if err = t.checkCustomRules(r); err != nil {
		return threat.Custom, err
	}

	// Check the request against the whitelists
	if t.inWhitelist(r) {
		return threat.Undefined, nil
	}

	// Retrieve the threat struct from the Teler struct
	th := t.threat

	// Iterate over the excludes map in the threat struct
	for k, v := range th.excludes {
		// If the value in the excludes map is true, skip to the next iteration
		if v {
			continue
		}

		// Check for the threat type specified by the key in the excludes map
		switch k {
		case threat.CommonWebAttack:
			err = t.checkCommonWebAttack(r) // Check for common web attacks
		case threat.CVE:
			err = t.checkCVE(r) // Check for Common Vulnerabilities and Exposures (CVEs)
		case threat.BadIPAddress:
			err = t.checkBadIPAddress(r) // Check for bad IP addresses
		case threat.BadReferrer:
			err = t.checkBadReferrer(r) // Check for bad referrers
		case threat.BadCrawler:
			err = t.checkBadCrawler(r) // Check for bad crawlers
		case threat.DirectoryBruteforce:
			err = t.checkDirectoryBruteforce(r) // Check for directory bruteforce attacks
		}

		// If a threat is detected, return the threat type and an error
		if err != nil {
			return k, err
		}
	}

	// If no threats are detected, return Undefined and a nil error
	return threat.Undefined, nil
}

// checkCustomRules checks the given http.Request against a set of custom rules defined in the Teler struct.
// If any of the custom rules are violated, the function returns an error with the name of the violated rule as the message.
// If no custom rules are violated, the function returns nil.
func (t *Teler) checkCustomRules(r *http.Request) error {
	// Converts map of headers to RAW string
	headers := headersToRawString(r.Header)

	// Decode the URL-encoded and unescape HTML entities request URI of the URL
	uri := stringDeUnescape(r.URL.RequestURI())

	// Declare byte slice for request body.
	var body string

	// Initialize buffer to hold request body.
	buf := &bytes.Buffer{}

	// Use io.Copy to copy the request body to the buffer.
	_, err := io.Copy(buf, r.Body)
	if err == nil {
		// If the read not fails, replace the request body
		// with a new io.ReadCloser that reads from the buffer.
		r.Body = io.NopCloser(buf)

		// Convert the buffer to a string.
		body = buf.String()
	}

	// Decode the URL-encoded and unescape HTML entities of body
	body = stringDeUnescape(body)

	// Iterate over the Customs field of the Teler struct, which is a slice of custom rules
	for _, rule := range t.opt.Customs {
		// Initialize the found match counter to zero
		f := 0

		// Iterate over the Rules field of the current custom rule, which is a slice of rule conditions
		for _, cond := range rule.Rules {
			ok := false

			// Check if the Method field of the current rule condition matches the request method
			// If the Method field is ALL, match any request method
			switch {
			case cond.Method == request.ALL:
			case string(cond.Method) == r.Method:
				ok = true
			}

			// If the request method doesn't match, skip the current rule condition
			if !ok {
				break
			}

			ok = false

			// Get the compiled regex pattern for the current rule condition
			pattern := cond.patternRegex

			// Check if the Element field of the current rule condition matches the request URI, headers, body, or any of them
			// If it matches, set ok to true
			switch cond.Element {
			case request.URI:
				ok = pattern.MatchString(uri)
			case request.Headers:
				ok = pattern.MatchString(headers)
			case request.Body:
				ok = pattern.MatchString(body)
			case request.Any:
				ok = (pattern.MatchString(uri) || pattern.MatchString(headers) || pattern.MatchString(body))
			}

			// If the rule condition is satisfied, increment the found match counter
			if ok {
				// If the rule condition "or", return an error with the Name field of the custom rule as the message
				// If the rule condition is "and", increment the found match counter
				switch rule.Condition {
				case "or":
					return errors.New(rule.Name)
				case "and":
					f++
				}
			}
		}

		// If the rule condition is "and", and number of found matches is equal to the number of rule conditions,
		// return an error with the Name field of the custom rule as the message
		if rule.Condition == "and" && f >= len(rule.Rules) {
			return errors.New(rule.Name)
		}
	}

	// If no custom rules were violated, return nil
	return nil
}

// checkCommonWebAttack checks if the request contains any patterns that match the common web attacks data.
// If a match is found, it returns an error indicating a common web attack has been detected.
// If no match is found, it returns nil.
func (t *Teler) checkCommonWebAttack(r *http.Request) error {
	// Decode the URL-encoded and unescape HTML entities request URI of the URL
	uri := stringDeUnescape(r.URL.RequestURI())

	// Declare byte slice for request body.
	var body string

	// Initialize buffer to hold request body.
	buf := &bytes.Buffer{}

	// Use io.Copy to copy the request body to the buffer.
	_, err := io.Copy(buf, r.Body)
	if err == nil {
		// If the read not fails, replace the request body
		// with a new io.ReadCloser that reads from the buffer.
		r.Body = io.NopCloser(buf)

		// Convert the buffer to a string.
		body = buf.String()
	}

	// Decode the URL-encoded and unescape HTML entities of body
	body = stringDeUnescape(body)

	// Iterate over the filters in the CommonWebAttack data stored in the t.threat.cwa.Filters field
	for _, filter := range t.threat.cwa.Filters {
		// Initialize a variable to track whether a match is found
		var match bool

		// Check the type of the filter's pattern
		switch pattern := filter.pattern.(type) {
		case *regexp.Regexp: // If the pattern is a regex
			match = pattern.MatchString(uri) || pattern.MatchString(body)
		case *pcre.Matcher: // If the pattern is a PCRE expr
			match = pattern.MatchString(uri, 0) || pattern.MatchString(body, 0)
		default: // If the pattern is of an unknown type, skip to the next iteration
			continue
		}

		// If the pattern matches the request URI or body, return an error indicating a common web attack has been detected
		if match {
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
	cveData := t.threat.cve

	// kind is the type of template to check (either "path" or "raw").
	var kind string

	// requestParams is a map that stores the query parameters of the request URI and
	// iterate over the query parameters of the request URI and add them to the map.
	requestParams := make(map[string]string)
	for q, v := range r.URL.Query() {
		requestParams[q] = v[0]
	}

	// Iterate over the templates in the data set.
	for _, cveTemplate := range cveData.GetArray("templates") {
		// ID is the current CVE ID of the templates
		cveID := string(cveTemplate.GetStringBytes("id"))

		// Iterate over the requests in the template.
		for _, request := range cveTemplate.GetArray("requests") {
			// Determine the kind of template (either "path" or "raw").
			switch {
			case len(request.GetArray("path")) > 0:
				kind = "path"
			case len(request.GetArray("raw")) > 0:
				kind = "raw"
			}

			// If the template is a "path" type and the request method doesn't match, skip this template.
			if kind == "path" && string(request.GetStringBytes("method")) != r.Method {
				continue
			}

			// Iterate over the CVE URLs
			for _, cve := range cveURL[cveID] {
				// If the CVE path is empty or contains only a single character, skip this CVE URL.
				if len(cve.Path) <= 1 {
					continue
				}

				// If the request path doesn't match the CVE path, skip this CVE URL.
				if r.URL.Path != cve.Path {
					continue
				}

				// diffParams is a map that stores the query parameters of the CVE URI and iterate over the
				// query parameters of the CVE URI and add them to the diffParams map.
				diffParams := make(map[string]string)
				for q, v := range cve.Query() {
					diffParams[q] = v[0]
				}

				// allParamsMatch is a flag that indicates whether all the query parameters in the CVE URI are
				// present in the request URI and iterate over the query parameters of the CVE URI.
				allParamsMatch := true
				for q, v := range diffParams {
					// If a query parameter in the CVE URI is not present in the request URI,
					// set allParamsMatch to false and break out of the loop.
					if requestParams[q] != v {
						allParamsMatch = false
						break
					}
				}

				// If all the query parameters in the CVE URI are present in the request URI, return an error of CVE ID.
				if allParamsMatch {
					return errors.New(cveID)
				}
			}
		}
	}

	// Return nil if the request doesn't match any known threat.
	return nil
}

// checkBadIPAddress checks if the client IP address is in the BadIPAddress index.
// It returns an error if the client IP address is found in the index, indicating a bad IP address.
// Otherwise, it returns nil.
func (t *Teler) checkBadIPAddress(r *http.Request) error {
	// Get the client's IP address
	clientIP := getClientIP(r)

	// Check if the client IP address is in BadIPAddress index
	if t.inThreatIndex(threat.BadIPAddress, clientIP) {
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

	// Do not process the check if User-Agent is empty
	if ua == "" {
		return nil
	}

	// Iterate over BadCrawler compiled patterns and do the check
	for _, pattern := range t.threat.badCrawler {
		// Initialize a variable to track whether a match is found
		var match bool

		// Check the type of the pattern
		switch p := pattern.(type) {
		case *regexp.Regexp: // If the pattern is a regex
			match = p.MatchString(ua)
		case *pcre.Matcher: // If the pattern is a PCRE expr
			match = p.MatchString(ua, 0)
		default: // If the pattern is of an unknown type, skip to the next iteration
			continue
		}

		// Check if the pattern is not nil and matches the User-Agent
		if match {
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
