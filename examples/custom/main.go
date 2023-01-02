package main

import (
	"net/http"

	"github.com/kitabisa/teler-waf"
	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello world"))
})

func main() {
	telerMiddleware := teler.New(teler.Options{
		Excludes: []threat.Threat{
			threat.BadReferrer,
			threat.BadCrawler,
		},
		Whitelists: []string{
			`(curl|Go-http-client|okhttp)/*`,
			`^/wp-login\.php`,
			`(?i)Referer: https?:\/\/www\.facebook\.com`,
			`192\.168\.0\.1`,
		},
		Customs: []teler.Rule{
			{
				Name:      "Log4j Attack",
				Condition: "or",
				Rules: []teler.Condition{
					{
						Method: request.GET,
						// if Method is not set or invalid, defaulting to request.GET.
						Element: request.URI,
						// you can use request.Any: it useful when you want to
						// match against multiple elements of the request at once,
						// rather than just a single element.
						Pattern: `\$\{.*:\/\/.*\/?\w+?\}`,
					},
				},
			},
		},
		LogFile: "/tmp/teler.log",
	})

	app := telerMiddleware.Handler(myHandler)
	http.ListenAndServe("127.0.0.1:3000", app)
}
