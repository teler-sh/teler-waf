package teler

import (
	"fmt"
	"regexp"

	"net/http"
)

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Bad Request", http.StatusBadRequest)
}

// Teler is a middleware that helps setup a few basic security features. A single secure.Options struct can be
// provided to configure which features should be enabled, and the ability to override a few of the default values.
type Teler struct {
	opt Options

	whitelistRegexes []*regexp.Regexp

	handler http.Handler
}

// New constructs a new Teler instance with the supplied options.
func New(opts ...Options) *Teler {
	var o Options

	if len(options) == 0 {
		o = Options{}
	} else {
		o = opts[0]
	}

	err := getResources()
	if err != nil {
		panic(fmt.Sprintf(errResources, err))
	}

	t := &Teler{handler: http.HandlerFunc(defaultHandler)}

	for _, wl := range o.Whitelists {
		regex, err := regexp.Compile(wl)
		if err != nil {
			panic(fmt.Sprintf(errParsing, "Whitelist(s)", err))
		}
		t.whitelistRegexes = append(t.whitelistRegexes, regex)
	}

	for _, rule := range o.Customs {
		for _, cond := range rule.Rules {
			regex, err := regexp.Compile(cond.Pattern)
			if err != nil {
				panic(fmt.Sprintf(errParsing, "Pattern", err))
			}
			cond.patternRegex = regex
		}
	}

	// t.options = o

	// TODO
}

// SetHandler sets the handler to call when the teler rejects a request.
func (s *Secure) SetHandler(handler http.Handler) {
	s.handler = handler
}

// addResponseHeaders Adds the headers from 'responseHeader' to the response.
func addResponseHeaders(responseHeader http.Header, w http.ResponseWriter) {
	for key, values := range responseHeader {
		for _, value := range values {
			w.Header().Set(key, value)
		}
	}
}

// getResources to download the selected datasets of threat ruleset from teler-resources
func getResources() error {
	// TODO
}

// analyzeRequest runs the actual checks on the request and returns an error if the middleware chain should stop.
func (t *Teler) analyzeRequest(w http.ResponseWriter, r *http.Request) (http.Header, *http.Request, error) {
	// TODO
}
