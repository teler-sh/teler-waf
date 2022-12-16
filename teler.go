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

// Threat defines what threat category should be excluded,
// what is the corresponding file, and what is the data.
type Threat struct {
	excludes map[threat.Exclude]bool
	data     map[threat.Exclude]string
}

// Teler is a middleware that helps setup a few basic security features
type Teler struct {
	opt              Options
	log              *os.File
	threat           *Threat
	handler          http.Handler
	whitelistRegexes []*regexp.Regexp
}

// New constructs a new Teler instance with the supplied options.
func New(opts ...Options) *Teler {
	var o Options

	if len(opts) == 0 {
		o = Options{}
	} else {
		o = opts[0]
	}

	t := &Teler{
		handler: http.HandlerFunc(defaultHandler),
		threat:  &Threat{},
	}

	err := t.getResources()
	if err != nil {
		panic(fmt.Sprintf(errResources, err))
	}

	if o.LogFile != "" {
		t.log, err = os.OpenFile(o.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(fmt.Sprintf(errLogFile, err))
		}
		defer t.log.Close()
	}

	t.threat.excludes = make(map[threat.Exclude]bool)
	for _, ex := range o.Excludes {
		t.threat.excludes[ex] = true
	}

	for _, wl := range o.Whitelists {
		regex, err := regexp.Compile(wl)
		if err != nil {
			panic(fmt.Sprintf(errWhitelist, wl, err))
		}
		t.whitelistRegexes = append(t.whitelistRegexes, regex)
	}

	for _, rule := range o.Customs {
		if rule.Name == "" {
			panic(errInvalidRuleName)
		}

		rule.Condition = strings.ToLower(rule.Condition)
		if rule.Condition != "or" && rule.Condition != "and" {
			panic(fmt.Sprintf(errInvalidRuleCond, rule.Name, rule.Condition))
		}

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

	t.opt = o

	return t
}

// Handler implements the http.HandlerFunc for integration with the standard net/http library.
func (t *Teler) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let teler analyze the request. If it returns an error,
		// that indicates the request should not continue.
		r, err := t.analyzeRequest(w, r)

		// If there was an error, do not continue.
		if err != nil {
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
	if err := threat.Get(); err != nil {
		return err
	}

	files := map[threat.Exclude]string{
		threat.CommonWebAttack:     commonWebAttack,
		threat.CVE:                 cve,
		threat.BadIPAddress:        badIPAddress,
		threat.BadReferrer:         badReferrer,
		threat.BadCrawler:          badCrawler,
		threat.DirectoryBruteforce: directoryBruteforce,
	}

	t.threat.data = make(map[threat.Exclude]string)

	for k, v := range files {
		c, err := threat.Location()
		if err != nil {
			return err
		}

		b, err := ioutil.ReadFile(filepath.Join(c, v))
		if err != nil {
			return err
		}

		t.threat.data[k] = string(b)
	}

	return nil
}
