# teler-waf

[![Kitabisa Security](https://img.shields.io/badge/kitabisa-security%20project-blue)](#)
[![GoDoc](https://pkg.go.dev/static/frontend/badge/badge.svg)](http://pkg.go.dev/github.com/kitabisa/teler-waf)
[![tests](https://github.com/kitabisa/teler-waf/actions/workflows/test.yaml/badge.svg)](https://github.com/kitabisa/teler-waf/actions/workflows/test.yaml)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

<img src="https://user-images.githubusercontent.com/25837540/97091757-7200d880-1668-11eb-82c4-e5c4971d2bc8.png" align="right" width="250px"/>

**teler-waf** is a comprehensive security solution for Go-based web applications. It acts as an HTTP middleware, providing an easy-to-use interface for integrating IDS functionality with [teler IDS](https://github.com/kitabisa/teler-waf) into existing Go applications. By using teler-waf, you can help protect against a variety of web-based attacks, such as cross-site scripting (XSS) and SQL injection.

The package comes with a standard [`net/http.Handler`](https://pkg.go.dev/net/http#Handler), making it easy to integrate into your application's routing. When a client makes a request to a route protected by teler-waf, the request is first checked against the teler IDS to detect known malicious patterns. If no malicious patterns are detected, the request is then passed through for further processing.

In addition to providing protection against web-based attacks, teler-waf can also help improve the overall security and integrity of your application. It is highly configurable, allowing you to tailor it to fit the specific needs of your application.

**See also:**

- [kitabisa/teler](https://github.com/kitabisa/teler): Real-time HTTP intrusion detection.
- [dwisiswant0/cox](https://github.com/dwisiswant0/cox): Cox is [bluemonday](https://github.com/microcosm-cc/bluemonday)-wrapper to perform a deep-clean and/or sanitization of <i>(nested-)</i>interfaces from HTML to prevent XSS payloads.

## Features

teler-waf offers a range of powerful features designed to enhance the security of your Go web applications:

- **HTTP middleware** for Go web applications.
- Integration of **teler IDS** functionality.
- **Detection of known malicious patterns** using the teler IDS.
  - Common web attacks, such as cross-site scripting (XSS) and SQL injection, etc.
  - CVEs, covers known vulnerabilities and exploits.
  - Bad IP addresses, such as those associated with known malicious actors or botnets.
  - Bad HTTP referers, such as those that are not expected based on the application's URL structure or are known to be associated with malicious actors.
  - Bad crawlers, covers requests from known bad crawlers or scrapers, such as those that are known to cause performance issues or attempt to extract sensitive information from the application.
  - Directory bruteforce attacks, such as by trying common directory names or using dictionary attacks.
- Providing increased flexibility for creating your own **custom rules**.
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
	// This is the handler function for the route that we want to protect
	// with teler-waf's security measures.
	w.Write([]byte("hello world"))
})

var rejectHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// This is the handler function for the route that we want to be rejected
	// if the teler-waf's security measures are triggered.
	http.Error(w, "Sorry, your request has been denied for security reasons.", http.StatusForbidden)
})

func main() {
	// Create a new instance of the Teler type using the New function
	// and configure it using the Options struct.
	telerMiddleware := teler.New(teler.Options{
		// Exclude specific threats from being checked by the teler-waf.
		Excludes: []threat.Threat{
			threat.BadReferrer,
			threat.BadCrawler,
		},
		// Specify whitelisted URIs (path & query parameters), headers,
		// or IP addresses that will always be allowed by the teler-waf.
		Whitelists: []string{
			`(curl|Go-http-client|okhttp)/*`,
			`^/wp-login\.php`,
			`(?i)Referer: https?:\/\/www\.facebook\.com`,
			`192\.168\.0\.1`,
		},
		// Specify file path or glob pattern of custom rule files.
		CustomsFromRule: "/path/to/custom/rules/**/*.yaml",
		// Specify custom rules for the teler-waf to follow.
		Customs: []teler.Rule{
			{
				// Give the rule a name for easy identification.
				Name:      "Log4j Attack",
				// Specify the logical operator to use when evaluating the rule's conditions.
				Condition: "or",
				// Specify the conditions that must be met for the rule to trigger.
				Rules: []teler.Condition{
					{
						// Specify the HTTP method that the rule applies to.
						Method: request.GET,
						// Specify the element of the request that the rule applies to
						// (e.g. URI, headers, body).
						Element: request.URI,
						// Specify the pattern to match against the element of the request.
						Pattern: `\$\{.*:\/\/.*\/?\w+?\}`,
					},
				},
			},
			{
				// Give the rule a name for easy identification.
				Name: `Headers Contains "curl" String`,
				// Specify the conditions that must be met for the rule to trigger.
				Rules: []teler.Condition{
					{
						// Specify the DSL expression that the rule applies to.
						DSL: `request.Headers contains "curl"`,
					},
				},
			},
		},
		// Specify the file path to use for logging.
		LogFile: "/tmp/teler.log",
	})

	// Set the rejectHandler as the handler for the telerMiddleware.
	telerMiddleware.SetHandler(rejectHandler)

	// Create a new handler using the handler method of the Teler instance
	// and pass in the myHandler function for the route we want to protect.
	app := telerMiddleware.Handler(myHandler)

	// Use the app handler as the handler for the route.
	http.ListenAndServe("127.0.0.1:3000", app)
}
```

> **Warning**: When using a whitelist, any request that matches it - regardless of the type of threat it poses, it will be returned without further analysis.
>
> To illustrate, suppose you set up a whitelist to permit requests containing a certain string. In the event that a request contains that string, but _/also/_ includes a payload such as an SQL injection or cross-site scripting ("XSS") attack, the request may not be thoroughly analyzed for common web attack threats and will be swiftly returned. See issue [#25](https://github.com/kitabisa/teler-waf/issues/25).

For more examples of how to use teler-waf or integrate it with any framework, take a look at [examples/](https://github.com/kitabisa/teler-waf/tree/master/examples) directory.

### Custom Rules

To integrate custom rules into the teler-waf middleware, you have two choices: `Customs` and `CustomsFromFile`. These options offer flexibility to create your own security checks or override the default checks provided by teler-waf.

- **`Customs` option**

You can define custom rules directly using the `Customs` option, as shown in the [example](https://github.com/kitabisa/teler-waf#examples) above.

In the `Customs` option, you provide an array of `teler.Rule` structures. Each `teler.Rule` represents a custom rule with a unique name and a condition that specifies how the individual conditions within the rule are evaluated (`or` or `and`). The rule consists of one or more `teler.Condition` structures, each defining a specific condition to check. Conditions can be based on the [HTTP method](https://pkg.go.dev/github.com/kitabisa/teler-waf/request#pkg-constants), [element](https://pkg.go.dev/github.com/kitabisa/teler-waf/request#Element) (headers, body, URI, or any), and a regex pattern or a [DSL expression](https://pkg.go.dev/github.com/kitabisa/teler-waf/dsl) to match against.

- **`CustomsFromFile` option**

Alternatively, the `CustomsFromFile` option allows you to load custom rules from external files, offering even greater flexibility and manageability. These rules can be defined in YAML format, with each file containing one or more rules. Here is an example YAML structure representing a custom rule:

```yaml
- name: <name>
  condition: <condition> # Valid values are: "or" or "and", in lowercase or uppercase.
  rules:
    - method: <method> # Valid methods are: "ALL", "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", and "TRACE". Please refer to https://pkg.go.dev/github.com/kitabisa/teler-waf/request for further details.
      element: <element> # Valid elements are: "headers", "body", "uri", and "any", in lowercase, uppercase, or title case (except for "uri").
      pattern: "<pattern>" # Regular expression pattern
    - dsl: "<expression>" # DSL expression
```

> **Note**: Please note that the `condition`, `method`, and `element` are optional parameters. The default values assigned to them are as follows: `condition` is set to **or**, `method` is set to **ALL**, and `element` is set to **ANY**. Therefore, if desired, you can leave those parameters empty. The `pattern` parameter is mandatory, unless you specify a `dsl` expression. In such cases, when a `dsl` expression is provided, teler-waf will disregard any values assigned to `method` and `element`, even if they are defined. To see some examples, you can refer to the [`tests/rules/`](https://github.com/kitabisa/teler-waf/tree/master/tests/rules/valid) directory.

You can specify the `CustomsFromFile` option with the actual file path or glob pattern pointing to the location of your custom rule files. For example:

```go
// Create a new instance of the Teler middleware and
// specify custom rules with the CustomsFromFile option.
telerMiddleware := teler.New(teler.Options{
    CustomsFromFile: "/path/to/custom/rules/**/*.yaml",
})
```

With `CustomsFromFile`, you provide the file path or glob pattern where your custom rule files are located. The pattern can include wildcards to match multiple files or a directory and its subdirectories. Each file should contain one or more custom rules defined in the proper YAML format.

By utilizing either the `Customs`, `CustomsFromFile`, or both option, you can seamlessly integrate your custom rules into the teler-waf middleware, enhancing its security capabilities to meet your specific requirements.

### DSL Expression

DSL (Domain Specific Language) expressions that can be used to define conditions for evaluating incoming requests in custom rules<!-- or whitelists-->. Here are some examples of DSL expression code:

#### Examples of DSL expression code:

Check if the incoming request headers contains "curl":

```sql
request.Headers contains "curl"
```

Check if the incoming request method is "GET":

```sql
request.Method == "GET"
```

Check if the incoming request method is "GET" or "POST" using regular expression [operator] matching:

```sql
request.Method matches "^(POS|GE)T$"
```

Check if the incoming request IP address is from localhost:

```sql
request.IP in ["127.0.0.1", "::1", "0.0.0.0"]
```

Check if the any element in request contains the string "foo":

```console
one(request.ALL, # contains "foo")
```

Check if the incoming request body contains "foo":

```sql
request.Body contains "foo"
```

Check whether the current threat category being analyzed is bad crawler or directory bruteforce:

```sql
threat in [BadCrawler, DirectoryBruteforce]
```

#### Available variables

- **Threat category**

All constant identifiers of the `threat.Threat` type are valid variables.

- **`request`**

	* `request` represents the incoming request fields (URI, Headers, Body, etc.) and its values.
	* `request.URI` represents the incoming request URI (path, queries, parameters, and a fragments).
	* `request.Headers` represents the incoming request headers in multiple lines.
	* `request.Body` represents the incoming request body.
	* `request.Method` represents the incoming request method.
	* `request.IP` represents the client IP address of the incoming request.
	* `request.ALL` represents all the string values from the request fields above in slice.

- **`threat`**

	* `threat` represents the threat category being analyzed (type of `threat.Threat`).

**Available functions**

The functions available in this package include both [built-in functions from the expr package](https://expr.medv.io/docs/Language-Definition#built-in-functions) and those specifically defined by DSL package. The following is a list of the functions provided by, which utilize the functionalities offered by the built-in `strings` Go package.

* `clone`
* `containsAny`
* `equalFold`
* `hasPrefix`
* `hasSuffix`
* `join`
* `repeat`
* `replace`
* `replaceAll`
* `request`
* `threat`
* `title`
* `toLower`
* `toTitle`
* `toUpper`
* `toValidUTF8`
* `trim`
* `trimLeft`
* `trimPrefix`
* `trimRight`
* `trimSpace`
* `trimSuffix`

For more information on operators and built-in functions, please refer to the [Expr](https://expr.medv.io/docs/Getting-Started) documentation.

### Development

By default, teler-waf caches all incoming requests for 15 minutes & clear them every 20 minutes to improve the performance. However, if you're still customizing the settings to match the requirements of your application, you can disable caching during development by setting the development mode option to `true`. This will prevent incoming requests from being cached and can be helpful for debugging purposes.

```go
// Create a new instance of the Teler type using
// the New function & enable development mode option.
telerMiddleware := teler.New(teler.Options{
	Development: true,
})
```

### Logs

Here is an example of what the log lines would look like if teler-waf detects a threat on a request:

```json
{"level":"warn","ts":1672261174.5995026,"msg":"bad crawler","id":"654b85325e1b2911258a","category":"BadCrawler","request":{"method":"GET","path":"/","ip_addr":"127.0.0.1:37702","headers":{"Accept":["*/*"],"User-Agent":["curl/7.81.0"]},"body":""}}
{"level":"warn","ts":1672261175.9567692,"msg":"directory bruteforce","id":"b29546945276ed6b1fba","category":"DirectoryBruteforce","request":{"method":"GET","path":"/.git","ip_addr":"127.0.0.1:37716","headers":{"Accept":["*/*"],"User-Agent":["X"]},"body":""}}
{"level":"warn","ts":1672261177.1487508,"msg":"Detects common comment types","id":"75412f2cc0ec1cf79efd","category":"CommonWebAttack","request":{"method":"GET","path":"/?id=1%27%20or%201%3D1%23","ip_addr":"127.0.0.1:37728","headers":{"Accept":["*/*"],"User-Agent":["X"]},"body":""}}
```

The **id** is a unique identifier that is generated when a request is rejected by teler-waf. It is included in the HTTP response headers of the request (`X-Teler-Req-Id`), and can be used to troubleshoot issues with requests that are being made to the website.

For example, if a request to a website returns an HTTP error status code, such as a 403 Forbidden, the teler request ID can be used to identify the specific request that caused the error and help troubleshoot the issue.

Teler request IDs are used by teler-waf to track requests made to its web application and can be useful for debugging and analyzing traffic patterns on a website.

### Falco Sidekick

[Falco Sidekick](https://github.com/falcosecurity/falcosidekick) is a tool that receives events from Falco, an open-source cloud-native runtime security project, and sends them to different output channels. It allows you to forward security alerts to various third-party systems such as Slack, Elasticsearch, Loki, Grafana, Datadog and [more](https://github.com/falcosecurity/falcosidekick#outputs). This enables security teams to efficiently monitor and respond to security threats and events in real-time.

Integrating Falco Sidekick with teler-waf is also possible. By using the `FalcoSidekickURL` option, you can configure teler-waf to send events to Falco Sidekick, which will receive and process them for you. To do this, simply create a new instance of the `Teler` type using the `New` function and provide the `FalcoSidekickURL` option with the URL of your Falco Sidekick instance. For example:

```go
// Create a new instance of the Teler type using
// the New function & integrate Falco Sidekick.
telerMiddleware := teler.New(teler.Options{
	FalcoSidekickURL: "http://localhost:2801",
})
```

Once you have set up this integration, any threats detected by teler-waf will be sent to Falco Sidekick, which can then take appropriate actions based on the configuration you have set up. For instance, you can set up Falco Sidekick to automatically send alerts to your incident response team.

<a href="#"><img src="https://user-images.githubusercontent.com/25837540/235839471-a9d0b35d-4ff8-4c7f-bed2-fcfc4afa4a1e.png" alt="teler-waf's Falco Sidekick event" width="400px"></a>

Overall, Falco Sidekick is a versatile tool that can help you automate your security response process and improve your overall security posture. By leveraging its capabilities, you can ensure that your cloud-native applications are secure and protected against potential threats.

### Datasets

The teler-waf package utilizes a dataset of threats to identify and analyze each incoming request for potential security threats. This dataset is updated daily, which means that you will always have the latest resource. The dataset is initially stored in the user-level cache directory _(on Unix systems, it returns `$XDG_CACHE_HOME/teler-waf` as specified by [XDG Base Directory Specification
](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) if non-empty, else `$HOME/.cache/teler-waf`. On Darwin, it returns `$HOME/Library/Caches/teler-waf`. On Windows, it returns `%LocalAppData%/teler-waf`. On Plan 9, it returns `$home/lib/cache/teler-waf`)_ on your first launch. Subsequent launch will utilize the cached dataset, rather than downloading it again.

> **Note**: The threat datasets are obtained from the [kitabisa/teler-resources](https://github.com/kitabisa/teler-resources) repository.

However, there may be situations where you want to disable automatic updates to the threat dataset. For example, you may have a slow or limited internet connection, or you may be using a machine with restricted file access. In these cases, you can set an option called **NoUpdateCheck** to `true`, which will prevent the teler-waf from automatically updating the dataset.

```go
// Create a new instance of the Teler type using the New
// function & disable automatic updates to the threat dataset.
telerMiddleware := teler.New(teler.Options{
	NoUpdateCheck: true,
})
```

Finally, there may be cases where it's necessary to load the threat dataset into memory rather than saving it to a user-level cache directory. This can be particularly useful if you're running the application or service on a distroless or runtime image, where file access may be limited or slow. In this scenario, you can set an option called **InMemory** to `true`, which will load the threat dataset into memory for faster access.

```go
// Create a new instance of the Teler type using the
// New function & enable in-memory threat datasets store.
telerMiddleware := teler.New(teler.Options{
	InMemory: true,
})
```
> **Warning**: This may also consume more system resources, so it's worth considering the trade-offs before making this decision.

## Resources

- **teler WAF tester!** — You are free to use the following site for testing, https://waf.teler.app.

## Security

If you discover a security issue, please bring it to their attention right away, we take security seriously!

### Reporting a Vulnerability

If you have information about a security issue, or vulnerability in this teler-waf package, and/or you are able to successfully execute such as cross-site scripting (XSS) and pop-up an alert in our [demo site](https://waf.teler.app) (see [resources](#resources)), please do **NOT** file a public issue — instead, kindly send your report privately via the [vulnerability report form](https://github.com/kitabisa/teler-waf/security/advisories/new) or to our [official channels](https://security.kitabisa.com/#official-channels) as per our [security policy](https://security.kitabisa.com/).

## Limitations

Here are some limitations of using teler-waf:

- **Performance overhead**: teler-waf may introduce some performance overhead, as the teler-waf will need to process each incoming request. If you have a high volume of traffic, this can potentially slow down the overall performance of your application significantly, _especially_ if you enable the CVEs threat detection. See benchmark below:

```console
$ go test -bench . -cpu=4
goos: linux
goarch: amd64
pkg: github.com/kitabisa/teler-waf
cpu: 11th Gen Intel(R) Core(TM) i9-11900H @ 2.50GHz
BenchmarkTelerDefaultOptions-4               	   42649	     24923 ns/op	    6206 B/op	      97 allocs/op
BenchmarkTelerCommonWebAttackOnly-4          	   48589	     23069 ns/op	    5560 B/op	      89 allocs/op
BenchmarkTelerCVEOnly-4                      	   48103	     23909 ns/op	    5587 B/op	      90 allocs/op
BenchmarkTelerBadIPAddressOnly-4             	   47871	     22846 ns/op	    5470 B/op	      87 allocs/op
BenchmarkTelerBadReferrerOnly-4              	   47558	     23917 ns/op	    5649 B/op	      89 allocs/op
BenchmarkTelerBadCrawlerOnly-4               	   42138	     24010 ns/op	    5694 B/op	      86 allocs/op
BenchmarkTelerDirectoryBruteforceOnly-4      	   45274	     23523 ns/op	    5657 B/op	      86 allocs/op
BenchmarkTelerCustomRule-4                   	   48193	     22821 ns/op	    5434 B/op	      86 allocs/op
BenchmarkTelerWithoutCommonWebAttack-4       	   44524	     24822 ns/op	    6054 B/op	      94 allocs/op
BenchmarkTelerWithoutCVE-4                   	   46023	     25732 ns/op	    6018 B/op	      93 allocs/op
BenchmarkTelerWithoutBadIPAddress-4          	   39205	     25927 ns/op	    6220 B/op	      96 allocs/op
BenchmarkTelerWithoutBadReferrer-4           	   45228	     24806 ns/op	    5967 B/op	      94 allocs/op
BenchmarkTelerWithoutBadCrawler-4            	   45806	     26114 ns/op	    5980 B/op	      97 allocs/op
BenchmarkTelerWithoutDirectoryBruteforce-4   	   44432	     25636 ns/op	    6185 B/op	      97 allocs/op
PASS
ok  	github.com/kitabisa/teler-waf	25.759s
```

> **Note**: Benchmarking results may vary and may not be consistent. Those results were obtained when there were **>1.5k** CVE templates and the [teler-resources](https://github.com/kitabisa/teler-resources) dataset may have increased since then, which may impact the results.

- **Configuration complexity**: Configuring teler-waf to suit the specific needs of your application can be complex, and may require a certain level of expertise in web security. This can make it difficult for those who are not familiar with application firewalls and IDS systems to properly set up and use teler-waf.
- **Limited protection**: teler-waf is not a perfect security solution, and it may not be able to protect against all possible types of attacks. As with any security system, it is important to regularly monitor and maintain teler-waf to ensure that it is providing the desired level of protection.

#### Known Issues

To view a list of known issues with teler-waf, please filter the issues by the ["known-issue" label](https://github.com/kitabisa/teler-waf/issues?q=is%3Aopen+is%3Aissue+label%3Aknown-issue).

## License

This program is developed and maintained by members of Kitabisa Security Team, and this is not an officially supported Kitabisa product. This program is free software: you can redistribute it and/or modify it under the terms of the [Apache license](/LICENSE). Kitabisa teler-waf and any contributions are copyright © by Dwi Siswanto 2022-2023.