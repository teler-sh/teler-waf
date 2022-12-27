package teler

import (
	"testing"

	"net/http"
	"net/http/httptest"

	"github.com/kitabisa/teler-waf/threat"
)

func TestNew(t *testing.T) {
	// Initialize teler
	telerMiddleware := New()

	// Create a custom handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a client to send requests to the test server
	client := &http.Client{}

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

func BenchmarkTelerDefaultOptions(b *testing.B) {
	// Initialize teler
	telerMiddleware := New(Options{NoStderr: true})

	// Create a custom handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a client to send requests to the test server
	client := &http.Client{}

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Set the custom User-Agent so that the operation does
	// not stop at the BadCrawler check
	req.Header.Set("User-Agent", "awikwok")

	// Run the benchmark
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Send the request to the test server and discard the response
		_, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTelerCommonWebAttackOnly(b *testing.B) {
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

	// Create a custom handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a client to send requests to the test server
	client := &http.Client{}

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Run the benchmark
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Send the request to the test server and discard the response
		_, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// func BenchmarkTelerCVEOnly(b *testing.B) {
// 	// Initialize teler
// 	telerMiddleware := New(Options{
// 		Excludes: []threat.Threat{
// 			threat.CommonWebAttack,
// 			threat.BadIPAddress,
// 			threat.BadReferrer,
// 			threat.BadCrawler,
// 			threat.DirectoryBruteforce,
// 		},
// 		NoStderr: true,
// 	})

// 	// Create a custom handler
// 	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 	})
// 	wrappedHandler := telerMiddleware.Handler(handler)

// 	// Create a test server with the wrapped handler
// 	ts := httptest.NewServer(wrappedHandler)
// 	defer ts.Close()

// 	// Create a client to send requests to the test server
// 	client := &http.Client{}

// 	// Create a request to send to the test server
// 	req, err := http.NewRequest("GET", ts.URL, nil)
// 	if err != nil {
// 		b.Fatal(err)
// 	}

// 	// Run the benchmark
// 	b.ReportAllocs()
// 	for i := 0; i < b.N; i++ {
// 		// Send the request to the test server and discard the response
// 		_, err := client.Do(req)
// 		if err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }

func BenchmarkTelerBadIPAddressOnly(b *testing.B) {
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

	// Create a custom handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a client to send requests to the test server
	client := &http.Client{}

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Run the benchmark
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Send the request to the test server and discard the response
		_, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTelerBadReferrerOnly(b *testing.B) {
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

	// Create a custom handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a client to send requests to the test server
	client := &http.Client{}

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Run the benchmark
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Send the request to the test server and discard the response
		_, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTelerBadCrawlerOnly(b *testing.B) {
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

	// Create a custom handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a client to send requests to the test server
	client := &http.Client{}

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Run the benchmark
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Send the request to the test server and discard the response
		_, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTelerDirectoryBruteforceOnly(b *testing.B) {
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

	// Create a custom handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := telerMiddleware.Handler(handler)

	// Create a test server with the wrapped handler
	ts := httptest.NewServer(wrappedHandler)
	defer ts.Close()

	// Create a client to send requests to the test server
	client := &http.Client{}

	// Create a request to send to the test server
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Run the benchmark
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Send the request to the test server and discard the response
		_, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}
