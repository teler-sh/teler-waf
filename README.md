# teler-waf

<!-- [![GoDoc](https://pkg.go.dev/static/frontend/badge/badge.svg)](http://pkg.go.dev/github.com/kitabisa/teler-waf) [![Test](https://github.com/kitabisa/teler-waf/workflows/tests/badge.svg] -->

<img src="https://user-images.githubusercontent.com/25837540/97091757-7200d880-1668-11eb-82c4-e5c4971d2bc8.png" align="right" width="250px"/>

**teler-waf** is a comprehensive security solution for Go-based web applications. It acts as an HTTP middleware, providing an easy-to-use interface for integrating IDS functionality into existing Go applications. By using teler-waf, you can help protect against a variety of web-based attacks, such as cross-site scripting (XSS) and SQL injection by facilitates [teler IDS](https://github.com/kitabisa/teler-waf).

The package comes with a standard [`net/http.Handler`](https://pkg.go.dev/net/http#Handler), making it easy to integrate into your application's routing. When a client makes a request to a route protected by teler-waf, the request is first checked against the teler IDS to detect known malicious patterns. If no malicious patterns are detected, the request is then passed through for further processing.

In addition to providing protection against web-based attacks, teler-waf can also help improve the overall security and integrity of your application. It is highly configurable, allowing you to tailor it to fit the specific needs of your application.

**See also:**

- [kitabisa/teler](https://github.com/kitabisa/teler): Real-time HTTP intrusion detection.
- [dwisiswant0/cox](https://github.com/dwisiswant0/cox): Cox is [bluemonday](https://github.com/microcosm-cc/bluemonday)-wrapper to perform a deep-clean and/or sanitization of <i>(nested-)</i>interfaces from HTML to prevent XSS payloads.

## Features

Some core features of teler-waf include:

- **HTTP middleware** for Go web applications.
- Integration of **teler IDS** functionality.
- **Detection of known malicious patterns** using the teler IDS.
  - Common web attacks, such as cross-site scripting (XSS) and SQL injection, etc.
  - CVEs, covers known vulnerabilities and exploits.
  - Bad IP addresses, such as those associated with known malicious actors or botnets.
  - Bad HTTP referers, such as those that are not expected based on the application's URL structure or are known to be associated with malicious actors.
  - Bad crawlers, covers requests from known bad crawlers or scrapers, such as those that are known to cause performance issues or attempt to extract sensitive information from the application.
  - Directory bruteforce attacks, such as by trying common directory names or using dictionary attacks.
- Configuration options to **whitelist specific types of requests** based on their URL or headers.
- **Easy integration** with many frameworks.
- **High configurability** to fit the specific needs of your application.

Overall, teler-waf provides a comprehensive security solution for Go-based web applications, helping to protect against web-based attacks and improve the overall security and integrity of your application.

## Install

To install teler-waf in your Go application, run the following command to download and install the teler-waf package:

```console
go get github.com/kitabisa/teler-waf
```

## Usage

Here is an example of how to use teler-waf in a Go application:

1. Import the teler-waf package in your Go code:

```go
import "github.com/kitabisa/teler-waf"
```

2. Use the `New` function to create a new instance of the `Teler` type. This function takes a variety of optional parameters that can be used to configure teler-waf to suit the specific needs of your application.

```go
waf := teler.New()
```

3. Use the `Handler` method of the `Teler` instance to create a `net/http.Handler`. This handler can then be used in your application's HTTP routing to apply teler-waf's security measures to specific routes.

```go
handler := waf.Handler(http.HandlerFunc(yourHandlerFunc))
```

4. Use the `handler` in your application's HTTP routing to apply teler-waf's security measures to specific routes.

```go
http.Handle("/path", handler)
```

That's it! You have configured teler-waf in your Go application.

**Options:**

For a list of the options available to customize teler-waf, see the [`teler.Options`](https://pkg.go.dev/github.com/kitabisa/teler-waf#Options) struct.

### Examples

Here is an example of how to customize the options and rules for teler-waf:

```go
// main.go
package main

import (
	"net/http"

	"github.com/kitabisa/teler-waf"
	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// this is the handler function for the route that we want to protect
	// with teler-waf's security measures
	w.Write([]byte("hello world"))
})

func main() {
	// create a new instance of the Teler type using the New function
	// and configure it using the Options struct
	telerMiddleware := teler.New(teler.Options{
		// exclude specific threats from being checked by the teler IDS
		Excludes: []threat.Threat{
			threat.BadReferrer,
			threat.BadCrawler,
		},
		// specify whitelisted paths or headers that will always be allowed
		// by the teler IDS
		Whitelists: []string{
			`(curl|Go-http-client|okhttp)/*`,
			`^/wp-login\.php`,
			`https?:\/\/www\.facebook\.com`,
			`192\.168\.0\.1`,
		},
		// specify custom rules for the teler IDS to follow
		Customs: []teler.Rule{
			{
				// give the rule a name for easy identification
				Name:      "Log4j Attack",
				// specify the logical operator to use when evaluating the rule's conditions
				Condition: "or",
				// specify the conditions that must be met for the rule to trigger
				Rules: []teler.Condition{
					{
						// specify the HTTP method that the rule applies to
						Method: request.GET,
						// specify the element of the request that the rule applies to
						// (e.g. path, headers, etc.)
						Element: request.Path,
						// specify the pattern to match against the element of the request
						Pattern: `\$\{.*:\/\/.*\/?\w+?\}`,
					},
				},
			},
		},
		// specify the file path to use for logging
		LogFile: "/tmp/teler.log",
	})

	// create a new handler using the handler method of the Teler instance
	// and pass in the handler function for the route we want to protect
	app := telerMiddleware.Handler(myHandler)
	// use the handler as the handler for the route in the http package's ListenAndServe function
	http.ListenAndServe("127.0.0.1:3000", app)
}
```

For more examples of how to use teler-waf, check out the [examples/](https://github.com/kitabisa/teler-waf/tree/master/examples) directory.

#### Logs

Here is an example of what the log lines would look like if teler-waf detects a threat on a request:

```json
{"level":"warn","ts":1672261174.5995026,"msg":"bad crawler","id":"654b85325e1b2911258a","category":"BadCrawler","request":{"method":"GET","path":"/","remote_addr":"127.0.0.1:37702","headers":{"Accept":["*/*"],"User-Agent":["curl/7.81.0"]},"body":""}}
{"level":"warn","ts":1672261175.9567692,"msg":"directory bruteforce","id":"b29546945276ed6b1fba","category":"DirectoryBruteforce","request":{"method":"GET","path":"/.git","remote_addr":"127.0.0.1:37716","headers":{"Accept":["*/*"],"User-Agent":["X"]},"body":""}}
{"level":"warn","ts":1672261177.1487508,"msg":"Detects common comment types","id":"75412f2cc0ec1cf79efd","category":"CommonWebAttack","request":{"method":"GET","path":"/?id=1%27%20or%201%3D1%23","remote_addr":"127.0.0.1:37728","headers":{"Accept":["*/*"],"User-Agent":["X"]},"body":""}}
```

The **id** is a unique identifier that is generated when a request is rejected by teler-waf. It is included in the HTTP response headers of the request (`X-Teler-Req-Id`), and can be used to troubleshoot issues with requests that are being made to the website.

For example, if a request to a website returns an HTTP error status code, such as a 403 Forbidden, the teler request ID can be used to identify the specific request that caused the error and help troubleshoot the issue.

Teler request IDs are used by teler-waf to track requests made to its web application and can be useful for debugging and analyzing traffic patterns on a website.

#### Demo

You are free to use the following site for testing, https://waf.teler.app.

## Limitations

Here are some limitations of using teler-waf:

- **Performance overhead**: teler-waf may introduce some performance overhead, as the application firewall and teler IDS will need to process each incoming request. This can potentially slow down the overall performance of your application, especially if you have a high volume of traffic. Benchmark:

```console
$ go test -bench . -cpu=4
goos: linux
goarch: amd64
pkg: github.com/kitabisa/teler-waf
cpu: 11th Gen Intel(R) Core(TM) i9-11900H @ 2.50GHz
BenchmarkTelerDefaultOptions-4               	     392	   2930161 ns/op	 6131716 B/op	   14885 allocs/op
BenchmarkTelerCommonWebAttackOnly-4          	   54973	     21006 ns/op	    4485 B/op	      50 allocs/op
BenchmarkTelerCVEOnly-4                      	     414	   2752341 ns/op	 6107559 B/op	   14866 allocs/op
BenchmarkTelerBadIPAddressOnly-4             	   22608	     52756 ns/op	    4315 B/op	      49 allocs/op
BenchmarkTelerBadReferrerOnly-4              	   53136	     21410 ns/op	    4127 B/op	      50 allocs/op
BenchmarkTelerBadCrawlerOnly-4               	    9387	    120534 ns/op	   29265 B/op	     168 allocs/op
BenchmarkTelerDirectoryBruteforceOnly-4      	   53097	     22979 ns/op	    3917 B/op	      47 allocs/op
BenchmarkTelerWithoutCommonWebAttack-4       	     482	   2138415 ns/op	 3850371 B/op	    9443 allocs/op
BenchmarkTelerWithoutCVE-4                   	    8017	    149552 ns/op	   29429 B/op	     173 allocs/op
BenchmarkTelerWithoutBadIPAddress-4          	     535	   2017782 ns/op	 3811759 B/op	    9348 allocs/op
BenchmarkTelerWithoutBadReferrer-4           	     598	   2148427 ns/op	 3910542 B/op	    9582 allocs/op
BenchmarkTelerWithoutBadCrawler-4            	     385	   3202302 ns/op	 6108932 B/op	   14873 allocs/op
BenchmarkTelerWithoutDirectoryBruteforce-4   	     553	   2164306 ns/op	 3952144 B/op	    9687 allocs/op
PASS
ok  	github.com/kitabisa/teler-waf	23.131s
```

> **Note**: It's important to note that the benchmarking results for execution time, byte allocation, and heap allocation may vary and may not be consistent. Those results were obtained when there were **1545** CVE templates and the [teler-resources](https://github.com/kitabisa/teler-resources) dataset may have increased since then, which may impact the results.

- **Configuration complexity**: Configuring teler-waf to suit the specific needs of your application can be complex, and may require a certain level of expertise in web security. This can make it difficult for those who are not familiar with application firewalls and IDS systems to properly set up and use teler-waf.
- **Limited protection**: teler-waf is not a perfect security solution, and it may not be able to protect against all possible types of attacks. As with any security system, it is important to regularly monitor and maintain teler-waf to ensure that it is providing the desired level of protection.

#### Known Issues

To view a list of known issues with teler-waf, please filter the issues by the ["known-issue" label](https://github.com/kitabisa/teler-waf/issues?q=is%3Aopen+is%3Aissue+label%3Aknown-issue).

## License

This program is developed and maintained by members of Kitabisa Security Team, and this is not an officially supported Kitabisa product. This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](/LICENSE). Kitabisa teler-waf and any contributions are copyright © by Dwi Siswanto 2022-2023.