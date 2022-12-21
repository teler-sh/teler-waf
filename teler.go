package teler

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"io/ioutil"
	"net/http"
	"path/filepath"

	"github.com/kitabisa/teler-waf/threat"
)

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Bad Request", http.StatusBadRequest)
}

// Threat defines what threat category should be excluded
// and what is the corresponding data.
type Threat struct {
	// excludes specifies which threat categories should be excluded.
	// The keys in the map are of type threat.Threat, and the values are
	// boolean flags indicating whether the corresponding threat category
	// should be excluded.
	excludes map[threat.Threat]bool

	// data contains the data for each threat category.
	// The keys in the map are of type threat.Threat, and the values are
	// strings containing the data for the corresponding threat category.
	data map[threat.Threat]string
}

// Teler is a middleware that helps setup a few basic security features
type Teler struct {
	// opt is a struct that contains options for the Teler middleware.
	opt Options

	// log is a file descriptor for the log file.
	log *os.File

	// threat is a Threat struct.
	threat *Threat

	// handler is the http.Handler that the Teler middleware wraps.
	handler http.Handler

	// whitelistRegexes is a slice of regular expression pointers
	// that are used to check whether a request should be whitelisted.
	whitelistRegexes []*regexp.Regexp
}

// New constructs a new Teler instance with the supplied options.
func New(opts ...Options) *Teler {
	var o Options

	// Set default options if none are provided
	if len(opts) == 0 {
		o = Options{}
	} else {
		o = opts[0]
	}

	// Create a new Teler struct and initialize its handler and threat fields
	t := &Teler{
		handler: http.HandlerFunc(defaultHandler),
		threat:  &Threat{},
	}

	// Retrieve the data for each threat category
	err := t.getResources()
	if err != nil {
		panic(fmt.Sprintf(errResources, err))
	}

	// If the LogFile option is set, open the log file and
	// set the log field of the Teler struct to the file descriptor
	if o.LogFile != "" {
		t.log, err = os.OpenFile(o.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(fmt.Sprintf(errLogFile, err))
		}
		defer t.log.Close()
	}

	// Initialize the excludes field of the Threat struct to a new map and
	// set the boolean flag for each threat category specified in the Excludes option to true
	t.threat.excludes = make(map[threat.Threat]bool)
	for _, ex := range o.Excludes {
		t.threat.excludes[ex] = true
	}

	// For each entry in the Whitelists option, compile a regular expression and
	// add it to the whitelistRegexes slice of the Teler struct
	for _, wl := range o.Whitelists {
		regex, err := regexp.Compile(wl)
		if err != nil {
			panic(fmt.Sprintf(errWhitelist, wl, err))
		}
		t.whitelistRegexes = append(t.whitelistRegexes, regex)
	}

	// Iterate over the Customs option and verify that each custom rule has a non-empty name and a valid condition
	// Compile the regular expression pattern for each rule and add it to the patternRegex field of the Rule struct
	for _, rule := range o.Customs {
		if rule.Name == "" {
			panic(errInvalidRuleName)
		}

		// Convert the condition to lowercase, if empty string then defaulting to "or"
		rule.Condition = strings.ToLower(rule.Condition)
		if rule.Condition == "" {
			rule.Condition = "or"
		}

		// Check the condition is either "or" or "and"
		if rule.Condition != "or" && rule.Condition != "and" {
			panic(fmt.Sprintf(errInvalidRuleCond, rule.Name, rule.Condition))
		}

		// Iterate over the rules in the custom rule and compile the regular expression pattern
		for _, cond := range rule.Rules {
			if cond.Pattern == "" {
				panic(fmt.Sprintf(errPattern, rule.Name, "pattern can't be blank"))
			}

			regex, err := regexp.Compile(cond.Pattern)
			if err != nil {
				panic(fmt.Sprintf(errPattern, rule.Name, err))
			}

			cond.patternRegex = regex
		}
	}

	// Set the opt field of the Teler struct to the options
	t.opt = o

	return t
}

// Handler implements the http.HandlerFunc for integration with the standard net/http library.
func (t *Teler) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: analyze from custom rules

		// Let teler analyze the request. If it returns an error,
		// that indicates the request should not continue.
		if err := t.analyzeRequest(w, r); err != nil {
			return
		}

		h.ServeHTTP(w, r)
	})
}

// SetHandler sets the handler to call when the teler rejects a request.
func (t *Teler) SetHandler(handler http.Handler) {
	t.handler = handler
}

// getResources to download datasets of threat ruleset from teler-resources
func (t *Teler) getResources() error {
	// Download the datasets of threat ruleset from teler-resources
	if err := threat.Get(); err != nil {
		return err
	}

	// Create a map with the names of the data files for each
	// threat category as the keys and the corresponding threat category as the values
	files := map[threat.Threat]string{
		threat.CommonWebAttack:     commonWebAttack,
		threat.CVE:                 cve,
		threat.BadIPAddress:        badIPAddress,
		threat.BadReferrer:         badReferrer,
		threat.BadCrawler:          badCrawler,
		threat.DirectoryBruteforce: directoryBruteforce,
	}

	// Initialize the data field of the Threat struct to a new map
	t.threat.data = make(map[threat.Threat]string)

	for k, v := range files {
		// Get the location of the downloaded datasets
		c, err := threat.Location()
		if err != nil {
			return err
		}

		// Read the contents of the data file and store it
		// as a string in the data field of the Threat struct
		b, err := ioutil.ReadFile(filepath.Join(c, v))
		if err != nil {
			return err
		}

		t.threat.data[k] = string(b)
	}

	return nil
}
