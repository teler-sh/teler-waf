package teler

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Forbidden", http.StatusForbidden)
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

	// badCrawler contains the compiled slices of pointers to regexp.Regexp
	// objects of BadCrawler threat data.
	badCrawler []*regexp.Regexp

	// cve is a struct of CVEs threat data
	cve *cve

	// cwa is a struct of CommonWebAttack threat data
	cwa *cwa
}

// Teler is a middleware that helps setup a few basic security features
type Teler struct {
	// opt is a struct that contains options for the Teler middleware.
	opt Options

	// out is a file descriptor for the log file.
	out *os.File

	// log is a logger descriptor for the log.
	log *zap.Logger

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

	// Initialize writer for logging
	ws := []zapcore.WriteSyncer{os.Stderr}

	// If the LogFile option is set, open the log file and
	// set the log field of the Teler struct to the file descriptor
	if o.LogFile != "" {
		t.out, err = os.OpenFile(o.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(fmt.Sprintf(errLogFile, err))
		}

		ws = append(ws, t.out)
	}

	// Create a new logger with the multiwriter as the output destination
	mw := zapcore.NewMultiWriteSyncer(ws...)
	t.log = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), // Use JSON encoding
		mw,            // Use the multiwriter
		zap.WarnLevel, // Set the logging level to debug
	))
	defer t.log.Sync() // Flush any buffered writes before exiting

	// Initialize the excludes field of the Threat struct to a new map and
	// set the boolean flag for each threat category specified in the Excludes option to true
	t.threat.excludes = map[threat.Threat]bool{
		threat.CommonWebAttack:     false,
		threat.CVE:                 false,
		threat.BadIPAddress:        false,
		threat.BadReferrer:         false,
		threat.BadCrawler:          false,
		threat.DirectoryBruteforce: false,
	}
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

		// Iterate over the rules in the custom rules
		for _, cond := range rule.Rules {
			// Check if the method rule condition is valid, and
			// set to UNDEFINED if it isn't.
			if !isValidMethod(cond.Method) {
				cond.Method = request.UNDEFINED
			}

			// Defaulting method rule condition to GET if empty or undefined
			if cond.Method == request.UNDEFINED {
				cond.Method = request.GET
			}

			// Empty pattern cannot be process
			if cond.Pattern == "" {
				panic(fmt.Sprintf(errPattern, rule.Name, "pattern can't be blank"))
			}

			// Compile the regular expression pattern
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
		// Let teler analyze the request. If it returns an error,
		// that indicates the request should not continue.
		k, err := t.analyzeRequest(w, r)
		if err != nil {
			// Convert the error from analyzeRequest as string message
			msg := err.Error()

			// Read the request body and initialize empty byte if returns an error
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				body = []byte{}
			}
			r.Body = ioutil.NopCloser(bytes.NewReader(body))

			// Log the detected threats
			t.log.With(
				zap.String("category", k.String()),
				zap.Namespace("request"),
				zap.String("method", r.Method),
				zap.String("URL", r.URL.String()),
				zap.String("remote_addr", r.RemoteAddr),
				zap.Any("headers", r.Header),
				zap.ByteString("body", body),
			).Warn(msg)

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

	// Initialize the data field of the Threat struct to a new map
	t.threat.data = make(map[threat.Threat]string)

	for _, k := range threat.List() {
		// Skip if it is undefined
		if k == threat.Undefined {
			continue
		}

		// Get the location of respective threat type
		path, err := k.Filepath()
		if err != nil {
			return err
		}

		// Read the contents of the data file and store it
		// as a string in the data field of the Threat struct
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		t.threat.data[k] = string(b)

		err = t.processResource(k)
		if err != nil {
			return err
		}

	}

	return nil
}

// processResource processes the resource data for the given threat type.
// It initializes and unmarshals the data into the corresponding field in the threat struct.
func (t *Teler) processResource(k threat.Threat) error {
	var err error

	switch k {
	case threat.CommonWebAttack:
		// Initialize the cwa field of the threat struct.
		t.threat.cwa = &cwa{}

		// Unmarshal the data into the cwa field.
		err = json.Unmarshal([]byte(t.threat.data[k]), &t.threat.cwa)
		if err != nil {
			return err
		}

		// Compile the Rule field of each filter in the Filters slice
		// and save it in the pattern field of the filter.
		for i, filter := range t.threat.cwa.Filters {
			t.threat.cwa.Filters[i].pattern, err = regexp.Compile(filter.Rule)
			if err != nil {
				continue
			}
		}
	case threat.CVE:
		// Initialize the cve field of the threat struct.
		t.threat.cve = &cve{}

		// Unmarshal the data into the cve field.
		err = json.Unmarshal([]byte(t.threat.data[k]), &t.threat.cve)
		if err != nil {
			return err
		}
	case threat.BadCrawler:
		// Split the data into a slice of strings, compile each string
		// into a regexp, and save it in the badCrawler field.
		patterns := strings.Split(t.threat.data[k], "\n")
		t.threat.badCrawler = make([]*regexp.Regexp, len(patterns))

		for i, pattern := range patterns {
			t.threat.badCrawler[i], err = regexp.Compile(pattern)
			if err != nil {
				continue
			}
		}
	}

	return nil
}
