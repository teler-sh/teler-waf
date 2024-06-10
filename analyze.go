// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"errors"
	"strings"

	"net/http"

	"github.com/teler-sh/teler-waf/request"
	"github.com/teler-sh/teler-waf/threat"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
)

// Analyze runs the actual checks.
func (t *Teler) Analyze(w http.ResponseWriter, r *http.Request) error {
	_, err := t.analyzeRequest(w, r)

	// If threat detected, set teler request ID to the header
	if err != nil {
		setCustomHeader(w, xTelerReqId, getUID())
	}

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

	// Initialize DSL requests environment
	t.setDSLRequestEnv(r)

	// Check the request against custom rules
	if err = t.checkCustomRules(r); err != nil {
		return threat.Custom, err
	}

	// Retrieve the threat struct from the Teler struct
	th := t.threat

	// Iterate over the excludes map in the threat struct
	for k, v := range th.excludes {
		// If the value in the excludes map is true, skip to the next iteration
		if v {
			continue
		}

		// Set DSL threat environment
		t.env.Threat = k

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
	// Declare headers, URI, and body of a request.
	headers := t.env.GetRequestValue("Headers")
	uri := t.env.GetRequestValue("URI")
	body := t.env.GetRequestValue("Body")

	// Check if the request is in cache
	key := headers + uri + body
	if err, ok := t.getCache(key); ok {
		return err
	}

	// Iterate over the Customs field of the Teler struct, which is a slice of custom rules
	for _, rule := range t.opt.Customs {
		// Initialize the found match counter to zero
		f := 0

		// Iterate over the Rules field of the current custom rule, which is a slice of rule conditions
		for _, cond := range rule.Rules {
			ok := false

			// Check if DSL expression is not empty, then evaluate the program
			if cond.DSL != "" {
				ok = t.isDSLProgramTrue(cond.dslProgram)
			}

			// Returns early if the DSL expression above is match.
			if ok {
				t.setCache(key, rule.Name)
				return errors.New(rule.Name)
			}

			// Check if the Method field of the current rule condition matches the request method
			// If the Method field is ALL, match any request method
			switch {
			case cond.Method == request.ALL:
				ok = true
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
				// If the rule condition "or", cache the request and return an error with
				// the Name field of the custom rule as the message.
				// If the rule condition is "and", increment the found match counter
				switch rule.Condition {
				case "or":
					t.setCache(key, rule.Name)
					return errors.New(rule.Name)
				case "and":
					f++
				}
			}
		}

		// If the rule condition is "and", and number of found matches is equal to the number of rule conditions,
		// cache the request and return an error with the Name field of the custom rule as the message
		if rule.Condition == "and" && f >= len(rule.Rules) {
			t.setCache(key, rule.Name)
			return errors.New(rule.Name)
		}
	}

	// Cache the request
	t.setCache(key, "")

	// If no custom rules were violated, return nil
	return nil
}

// checkCommonWebAttack checks if the request contains any patterns that match the common web attacks data.
// If a match is found, it returns an error indicating a common web attack has been detected.
// If no match is found, it returns nil.
func (t *Teler) checkCommonWebAttack(r *http.Request) error {
	// Decode the URL-encoded and unescape HTML entities in the
	// request URI of the URL then remove all special characters
	uri := removeSpecialChars(stringDeUnescape(r.URL.RequestURI()))

	// Declare body of request then remove all special characters
	body := removeSpecialChars(t.env.GetRequestValue("Body"))

	// Check if the request is in cache
	key := uri + body
	if err, ok := t.getCache(key); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Iterate over the filters in the CommonWebAttack data stored in the t.threat.cwa.Filters field
	for _, filter := range t.threat.cwa.Filters {
		// Check if the pattern matches the request URI or request body
		match := filter.pattern.MatchString(uri, 0) || filter.pattern.MatchString(body, 0)

		// If matched, set cache for the request and return an
		// error indicating a common web attack has been detected
		if match {
			t.setCache(key, filter.Description)
			return errors.New(filter.Description)
		}
	}

	// Cache the request
	t.setCache(key, "")

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

	// Initialize key cache
	var key strings.Builder

	// Initialize query map
	qMap := r.URL.Query()

	// Initialize a map to store the query parameters
	requestParams := make(map[string]string)

	i := 0
	for q, v := range qMap {
		requestParams[q] = v[0]

		key.WriteString(q)
		key.WriteString(":")
		key.WriteString(v[0])

		if i < len(qMap)-1 {
			key.WriteString("|")
		}
	}

	if err, ok := t.getCache(key.String()); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
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

			// TODO(dwisiswant0): Add HTTP raw request CVEs here

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

				// If all the query parameters in the CVE URI are present in the request URI,
				// cache the request and return an error of CVE ID.
				if allParamsMatch {
					t.setCache(key.String(), cveID)
					return errors.New(cveID)
				}
			}
		}
	}

	// Cache the request
	t.setCache(key.String(), "")

	// Return nil if the request doesn't match any known threat.
	return nil
}

// checkBadIPAddress checks if the client IP address is in the BadIPAddress index.
// It returns an error if the client IP address is found in the index, indicating a bad IP address.
// Otherwise, it returns nil.
func (t *Teler) checkBadIPAddress(r *http.Request) error {
	// Get the client's IP address
	clientIP := t.env.GetRequestValue("IP")

	// Check if the client's IP address is in the cache
	if err, ok := t.getCache(clientIP); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Check if the client IP address is in BadIPAddress threat data
	match, err := t.inThreatRegexp(threat.BadIPAddress, clientIP)
	if err != nil {
		// Logs and return nil if there was an error during the regex matching process
		t.error(zapcore.ErrorLevel, err.Error())
		return nil
	}

	if match {
		// Cache the client's IP address and return an error
		// indicating a bad IP address has been detected
		t.setCache(clientIP, errBadIPAddress)
		return errors.New(errBadIPAddress)
	}

	// Cache the client's IP address
	t.setCache(clientIP, "")

	// Return nil if the remote address is not found in the index
	return nil
}

// checkBadReferrer checks if the request referer header is from a known bad referer.
// It does this by parsing and validate the referer URL, and then finding the effective
// top-level domain plus one. The resulting domain is then checked against the BadReferrer
// index in the threat struct. If the domain is found in the index, an error indicating a
// bad HTTP referer is returned. Otherwise, nil is returned.
func (t *Teler) checkBadReferrer(r *http.Request) error {
	// Parse the request referer URL
	valid, ref, err := isValidReferrer(r.Referer())
	if err != nil {
		t.error(zapcore.ErrorLevel, err.Error())
		return nil
	}

	// Return early if TLD hostname is invalid
	if !valid {
		return nil
	}

	// Extract the effective top-level domain plus one from the hostname of the referer URL
	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(ref)
	if err != nil {
		t.error(zapcore.ErrorLevel, err.Error())
		return nil
	}

	// Check if the referrer request is in cache
	if err, ok := t.getCache(eTLD1); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Check if the root domain of request referer header is in the BadReferrer index
	if t.inThreatIndex(threat.BadReferrer, eTLD1) {
		// If the domain is found in the index, cache the referrer
		// request and return an error indicating a bad HTTP referer
		t.setCache(eTLD1, errBadIPAddress)
		return errors.New(errBadReferer)
	}

	// Cache the referrer of the request
	t.setCache(eTLD1, "")

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

	// Check if the referrer request is in cache
	if err, ok := t.getCache(ua); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Iterate over BadCrawler compiled patterns and do the check
	for _, pattern := range t.threat.badCrawler {
		// Check if the pattern is not nil and matches the User-Agent,
		// then cache the User-Agent if it matched
		if pattern.MatchString(ua, 0) {
			t.setCache(ua, errBadCrawler)
			return errors.New(errBadCrawler)
		}
	}

	// Cache the User-Agent of the request
	t.setCache(ua, "")

	return nil
}

// checkDirectoryBruteforce checks the request for a directory bruteforce attack.
// It checks if the pattern matches the data using inThreatRegexp. If a match
// is found, it returns an error indicating a directory bruteforce attack has been
// detected. If no match is found or there was an error during the regex matching
// process, it returns nil.
func (t *Teler) checkDirectoryBruteforce(r *http.Request) error {
	// Trim the leading slash from the request path, and if path
	// is empty string after the trim, do not process the check
	path := strings.TrimLeft(r.URL.Path, "/")
	if path == "" {
		return nil
	}

	// Check if the request path is in cache
	if err, ok := t.getCache(path); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Check if the pattern matches the data using inThreatRegexp
	match, err := t.inThreatRegexp(threat.DirectoryBruteforce, path)
	if err != nil {
		// Logs and return nil if there was an error during the regex matching process
		t.error(zapcore.ErrorLevel, err.Error())
		return nil
	}

	// If the pattern matches the data, cache the request path and
	// return an error indicating a directory bruteforce attack has been detected
	if match {
		t.setCache(path, errDirectoryBruteforce)
		return errors.New(errDirectoryBruteforce)
	}

	// Cache the request path
	t.setCache(path, "")

	// Return nil if no match is found
	return nil
}
