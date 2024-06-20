# teler-waf

[![GoDoc](https://pkg.go.dev/static/frontend/badge/badge.svg)](http://pkg.go.dev/github.com/teler-sh/teler-waf)
[![codecov](https://codecov.io/gh/teler-sh/teler-waf/graph/badge.svg?token=RTIZW58NWK)](https://codecov.io/gh/teler-sh/teler-waf)
[![tests](https://github.com/teler-sh/teler-waf/actions/workflows/tests.yaml/badge.svg)](https://github.com/teler-sh/teler-waf/actions/workflows/tests.yaml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/teler-sh/teler-waf/badge)](https://securityscorecards.dev/viewer/?uri=github.com/teler-sh/teler-waf)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

<img src="https://user-images.githubusercontent.com/25837540/97091757-7200d880-1668-11eb-82c4-e5c4971d2bc8.png" align="right" width="250px"/>

**teler-waf** is a comprehensive security solution for Go-based web applications. It acts as an HTTP middleware, providing an easy-to-use interface for integrating IDS functionality with [teler IDS](https://github.com/teler-sh/teler-waf) into existing Go applications. By using teler-waf, you can help protect against a variety of web-based attacks, such as cross-site scripting (XSS) and SQL injection.

The package comes with a standard [`net/http.Handler`](https://pkg.go.dev/net/http#Handler), making it easy to integrate into your application's routing. When a client makes a request to a route protected by teler-waf, the request is first checked against the teler IDS to detect known malicious patterns. If no malicious patterns are detected, the request is then passed through for further processing.

In addition to providing protection against web-based attacks, teler-waf can also help improve the overall security and integrity of your application. It is highly configurable, allowing you to tailor it to fit the specific needs of your application.

**See also:**

- [teler-sh/teler](https://github.com/teler-sh/teler): Real-time HTTP intrusion detection.
- [teler-sh/teler-proxy](https://github.com/teler-sh/teler-proxy): teler Proxy enabling seamless integration with teler WAF.
- [teler-sh/teler-caddy](https://github.com/teler-sh/teler-caddy): teler Caddy integrates the powerful security features of teler WAF into the Caddy web server

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

**Dependencies**:

* **gcc** (GNU Compiler Collection) should be installed & configured to compile teler-waf.

To install teler-waf in your Go application, run the following command to download and install the teler-waf package:

```console
go get github.com/teler-sh/teler-waf
```

## Usage

> [!WARNING]
> **Deprecation notice**: Threat exclusions (`Excludes`) will be deprecated in the upcoming release (**v2**). See [#73](https://github.com/teler-sh/teler-waf/discussions/73) & [#64](https://github.com/teler-sh/teler-waf/issues/64).

Here is an example of how to use teler-waf in a Go application:

1. Import the teler-waf package in your Go code:

```go
import "github.com/teler-sh/teler-waf"
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

For a list of the options available to customize teler-waf, see the [`teler.Options`](https://pkg.go.dev/github.com/teler-sh/teler-waf#Options) struct.

### Examples

Here is an example of how to customize the options and rules for teler-waf:

```go
// main.go
package main

import (
	"net/http"

	"github.com/teler-sh/teler-waf"
	"github.com/teler-sh/teler-waf/request"
	"github.com/teler-sh/teler-waf/threat"
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
		// or IP addresses that will always be allowed by the teler-waf
		// with DSL expressions.
		Whitelists: []string{
			`request.Headers matches "(curl|Go-http-client|okhttp)/*" && threat == BadCrawler`,
			`request.URI startsWith "/wp-login.php"`,
			`request.IP in ["127.0.0.1", "::1", "0.0.0.0"]`,
			`request.Headers contains "authorization" && request.Method == "POST"`
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

For more examples of how to use teler-waf or integrate it with any framework, take a look at [examples/](https://github.com/teler-sh/teler-waf/tree/master/examples) directory.

### Custom Rules

> [!TIP]
> If you want to explore configurations, delve into crafting custom rules and composing DSL expressions, you can practice and gain hands-on experience by using this [teler WAF playground](https://play.teler.sh/). Here, you can also simulate requests customized to fulfill the specific needs of your application.

To integrate custom rules into the teler-waf middleware, you have two choices: `Customs` and `CustomsFromFile`. These options offer flexibility to create your own security checks or override the default checks provided by teler-waf.

- **`Customs` option**

You can define custom rules directly using the `Customs` option, as shown in the [example](https://github.com/teler-sh/teler-waf#examples) above.

In the `Customs` option, you provide an array of `teler.Rule` structures. Each `teler.Rule` represents a custom rule with a unique name and a condition that specifies how the individual conditions within the rule are evaluated (`or` or `and`). The rule consists of one or more `teler.Condition` structures, each defining a specific condition to check. Conditions can be based on the [HTTP method](https://pkg.go.dev/github.com/teler-sh/teler-waf/request#pkg-constants), [element](https://pkg.go.dev/github.com/teler-sh/teler-waf/request#Element) (headers, body, URI, or any), and a regex pattern or a [DSL expression](https://pkg.go.dev/github.com/teler-sh/teler-waf/dsl) to match against.

- **`CustomsFromFile` option**

Alternatively, the `CustomsFromFile` option allows you to load custom rules from external files, offering even greater flexibility and manageability. These rules can be defined in YAML format, with each file containing one or more rules. Here is an example YAML structure representing a custom rule:

```yaml
- name: <name>
  condition: <condition> # Valid values are: "or" or "and", in lowercase or uppercase.
  rules:
    - method: <method> # Valid methods are: "ALL", "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", and "TRACE". Please refer to https://pkg.go.dev/github.com/teler-sh/teler-waf/request for further details.
      element: <element> # Valid elements are: "headers", "body", "uri", and "any", in lowercase, uppercase, or title case (except for "uri").
      pattern: "<pattern>" # Regular expression pattern
    - dsl: "<expression>" # DSL expression
```

> [!IMPORTANT]
> Please note that the `condition`, `method`, and `element` are optional parameters. The default values assigned to them are as follows: `condition` is set to **or**, `method` is set to **ALL**, and `element` is set to **ANY**. Therefore, if desired, you can leave those parameters empty. The `pattern` parameter is mandatory, unless you specify a `dsl` expression. In such cases, when a `dsl` expression is provided, teler-waf will disregard any values assigned to `method` and `element`, even if they are defined. To see some examples, you can refer to the [`tests/rules/`](https://github.com/teler-sh/teler-waf/tree/master/tests/rules/valid) directory.

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

DSL (Domain-Specific Language) expressions provide a powerful means of defining conditions that are used to evaluate incoming requests within the context of custom rules or whitelists. With DSL expressions, you can create sophisticated and targeted conditions based on different attributes of the incoming requests. Here are some illustrative examples of DSL expression code:

#### Examples of DSL expression code:

Check if the incoming request headers contains "curl":

```sql
request.Headers contains "curl"
```

Check if the incoming request method is "GET":

```sql
request.Method == "GET"
```

Check if the incoming request method is "GET" or "POST" using regular expression, `matches` operator:

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

Those examples provide a glimpse into the expressive capabilities of DSL expressions, allowing you to define intricate conditions based on various request attributes. By leveraging these expressions, you can effectively define the criteria for evaluating incoming requests and tailor your custom rules or whitelists accordingly, enabling fine-grained control over your application's behavior.

#### Available variables

When working with DSL expressions, you have access to various variables that provide valuable information about the incoming requests and the threat category being analyzed. Here is a detailed description of the available variables:

- **Threat category**

	All constant identifiers of the `threat.Threat` type can be used as valid variables. These identifiers represent different threat categories that are relevant to your analysis.

- **`request`**

	The `request` variable represents the incoming request and provides access to its fields and corresponding values. The following sub-variables are available within the `request` variable:

  - `request.URI`: Represents the URI of the incoming request, including the path, queries, parameters, and fragments.
  - `request.Headers`: Represents the headers of the incoming request, presented in multiple lines.
  - `request.Body`: Represents the body of the incoming request.
  - `request.Method`: Represents the method of the incoming request.
  - `request.IP`: Represents the client IP address associated with the incoming request.
  - `request.ALL`: Represents all the string values from the request fields mentioned above in a slice.

- **`threat`**

	The `threat` variable represents the threat category being analyzed. It is of the `threat.Threat` type and allows you to evaluate and make decisions based on the specific threat category associated with the request.

By utilizing those variables within your DSL expressions, you can effectively access and manipulate the attributes of the incoming requests and assess the relevant threat categories. This enables you to create custom rule conditions<!-- and whitelists--> that tailored to your specific use case.

#### Available functions

Also, you have access to a variety of functions. These functions encompass both the [built-in functions](https://expr.medv.io/docs/Language-Definition#built-in-functions) provided by the expr package and those specifically defined within the DSL package. The functions utilize the functionalities offered by the built-in `strings` Go package. Here is a detailed list of the functions available:

- `cidr`: Get all IP addresses in range with given CIDR.
- `clone`: Create a copy of a string.
- `containsAny`: Check if a string contains any of the specified substrings.
- `equalFold`: Compare two strings in a case-insensitive manner.
- `hasPrefix`: Check if a string has a specified prefix.
- `hasSuffix`: Check if a string has a specified suffix.
- `join`: Concatenate multiple strings using a specified separator.
- `repeat`: Repeat a string a specified number of times.
- `replace`: Replace occurrences of a substring within a string.
- `replaceAll`: Replace all occurrences of a substring within a string.
- `request`: Access request-specific information within the DSL expression.
- `threat`: Access information related to the threat category being analyzed.
- `title`: Convert a string to title case.
- `toLower`: Convert a string to lowercase.
- `toTitle`: Convert a string to title case.
- `toUpper`: Convert a string to uppercase.
- `toValidUTF8`: Convert a string to a valid UTF-8 encoded string.
- `trim`: Remove leading and trailing whitespace from a string.
- `trimLeft`: Remove leading whitespace from a string.
- `trimPrefix`: Remove a specified prefix from a string.
- `trimRight`: Remove trailing whitespace from a string.
- `trimSpace`: Remove leading and trailing whitespace and collapse consecutive whitespace within a string.
- `trimSuffix`: Remove a specified suffix from a string.

For more comprehensive details on operators and built-in functions, please refer to the [Expr documentation](https://expr.medv.io/docs/Getting-Started). It provides a comprehensive guide to utilizing operators and exploring the available built-in functions in your DSL expressions.

### Streamlined Configuration Management

For effective configuration, it's essential to define a range of settings, including whitelists, custom rule definitions, logging preferences, and other parameters. The [`option`](https://pkg.go.dev/github.com/teler-sh/teler-waf/option) package streamlines this configuration workflow by enabling you to efficiently unmarshal or load configuration data from JSON and YAML formats into a format that teler-waf can readily comprehend and implement.

```go
// Load configuration from a YAML file.
opt, err := option.LoadFromYAMLFile("/path/to/teler-waf.conf.yaml")
if err != nil {
    panic(err)
}

// Create a new instance of the Teler type with
// the loaded options.
telerMiddleware := teler.New(opt)
```

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
{"level":"warn","ts":1672261174.5995026,"msg":"bad crawler","id":"654b85325e1b2911258a","category":"BadCrawler","caller":"teler-waf","listen_addr":"127.0.0.1:36267","request":{"method":"GET","path":"/","ip_addr":"127.0.0.1:37702","headers":{"Accept":["*/*"],"User-Agent":["curl/7.81.0"]},"body":""}}
{"level":"warn","ts":1672261175.9567692,"msg":"directory bruteforce","id":"b29546945276ed6b1fba","category":"DirectoryBruteforce","caller":"teler-waf","listen_addr":"127.0.0.1:36267","request":{"method":"GET","path":"/.git","ip_addr":"127.0.0.1:37716","headers":{"Accept":["*/*"],"User-Agent":["X"]},"body":""}}
{"level":"warn","ts":1672261177.1487508,"msg":"Detects common comment types","id":"75412f2cc0ec1cf79efd","category":"CommonWebAttack","caller":"teler-waf","listen_addr":"127.0.0.1:36267","request":{"method":"GET","path":"/?id=1%27%20or%201%3D1%23","ip_addr":"127.0.0.1:37728","headers":{"Accept":["*/*"],"User-Agent":["X"]},"body":""}}
```

The **id** is a unique identifier that is generated when a request is rejected by teler-waf. It is included in the HTTP response headers of the request (`X-Teler-Req-Id`), and can be used to troubleshoot issues with requests that are being made to the website.

For example, if a request to a website returns an HTTP error status code, such as a 403 Forbidden, the teler request ID can be used to identify the specific request that caused the error and help troubleshoot the issue.

Teler request IDs are used by teler-waf to track requests made to its web application and can be useful for debugging and analyzing traffic patterns on a website.

### Custom Response

By default, teler-waf employs the [`DefaultHTMLResponse`](https://pkg.go.dev/github.com/teler-sh/teler-waf#DefaultHTMLResponse) as the standard response when a request is rejected or blocked. However, teler-waf offers a high degree of customization, empowering you to tailor the response to your specific requirements. The customization can be achieved using the `Status`, `HTML`, or `HTMLFile` options, all of which are part of the [`Response`](https://pkg.go.dev/github.com/teler-sh/teler-waf#Response) interface.

Here's how you can make use of these options in your code:

```go
// Create a new instance of the Teler middleware
telerMiddleware := teler.New(teler.Options{
	// Customize the response for rejected requests
	Response: teler.Response{
		Status: 403,
		HTML: "Your request has been denied for security reasons. Ref ID: {{ID}}.",
		// Alternatively, you can use HTMLFile to point to a custom HTML file
		HTMLFile: "/path/to/custom-403.html",
	},
})
```

With this level of customization, you can construct personalized and informative responses to be shown when teler-waf blocks or rejects a request. The `HTML` option permits you to directly specify the desired HTML content as a string, whereas the `HTMLFile` option enables you to reference an external file containing the custom HTML response.

Moreover, to enhance the user experience, you can leverage placeholders in your HTML content to generate dynamic elements. During runtime, these placeholders will be substituted with actual values, resulting in more contextually relevant responses. The available and supported placeholders include:

* `{{ID}}`: Request IDs, allowing for unique identification of each rejected request.
* `{{message}}`: Rejected messages conveying the reason for request blocking.
* `{{threat}}`: Threat categories, providing insights into the detected security threat.

By incorporating these placeholders, you can create detailed and comprehensive responses that effectively communicate the rationale behind request rejections or blocks.

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

#### **Event**

The event forwarded to Falco Sidekick instance includes the following information:

* **`output`**: Represents the alert message.
* **`priority`**: The priority is consistently denoted as **warning**, a nod to the urgency associated with security-related events.
* **`rule`**: Indicates the specific rule _(message)_ that matched the associated request.
* **`time`**: Event's generation timestamp.
* Output fields:
	* **`teler.caller`**: Identifies the application source that invoked teler-waf.
	* **`teler.id`**: Represents a unique identifier for the rejected request.
	* **`teler.threat`**: Specifies the category of the threat.
  * **`teler.listen_addr`**: Denotes the network address on which teler-waf is listening for incoming requests.
	* **`request.body`**: Contains the body of the associated request.
	* **`request.headers`**: Lists the headers from the associated request.
	* **`request.ip_addr`**: Discloses the IP address of the associated request.
	* **`request.method`**: States the HTTP method employed in the associated request.
	* **`request.path`**: Refers to the path of the associated request.

Overall, Falco Sidekick is a versatile tool that can help you automate your security response process and improve your overall security posture. By leveraging its capabilities, you can ensure that your cloud-native applications are secure and protected against potential threats.

### Wazuh

You can enhance your security monitoring by integrating teler WAF logs into Wazuh. To do this, use [custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) available in the [`extras/`](/extras) directory.

Add the `localfile` element block below inside `ossec_config` element in the [local configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html) file:

```xml
<ossec_config>
  <!-- ... -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/path/to/your/teler.log</location>
  </localfile>
</ossec_config>
```

> [!NOTE]
> The value of `location` should be the teler WAF log file path you specified in [`Options.LogFile`](https://pkg.go.dev/github.com/teler-sh/teler-waf#Options.LogFile).

By doing this, Wazuh will be able to read and analyze the teler WAF logs, enhancing your network protection and providing better insights.

### Datasets

The teler-waf package utilizes a dataset of threats to identify and analyze each incoming request for potential security threats. This dataset is updated daily, which means that you will always have the latest resource. The dataset is initially stored in the user-level cache directory _(on Unix systems, it returns `$XDG_CACHE_HOME/teler-waf` as specified by [XDG Base Directory Specification
](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) if non-empty, else `$HOME/.cache/teler-waf`. On Darwin, it returns `$HOME/Library/Caches/teler-waf`. On Windows, it returns `%LocalAppData%/teler-waf`. On Plan 9, it returns `$home/lib/cache/teler-waf`)_ on your first launch. Subsequent launch will utilize the cached dataset, rather than downloading it again.

> [!NOTE]
> The threat datasets are obtained from the [teler-sh/teler-resources](https://github.com/teler-sh/teler-resources) repository.

However, there may be situations where you want to disable automatic updates to the threat dataset. For example, you may have a slow or limited internet connection, or you may be using a machine with restricted file access. In these cases, you can set an option called **NoUpdateCheck** to `true`, which will prevent the teler-waf from automatically updating the dataset.

> [!CAUTION]
> Enabling the `InMemory` takes precedence and ensures that automatic updates remain enabled.

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

> [!CAUTION]
> This may also consume more system resources, so it's worth considering the trade-offs before making this decision.

## Resources

- **teler WAF tester!** — You are free to use the following site for testing, https://test.teler.sh.
- **teler WAF playground** — Simulate your requests tailored to meet the specific needs of your app, https://play.teler.sh.

## Security

If you discover a security issue, please bring it to their attention right away, we take security seriously!

### Reporting a Vulnerability

If you have information about a security issue, or vulnerability in this teler-waf package, and/or you are able to successfully execute such as cross-site scripting (XSS) and pop-up an alert in our [demo site](https://test.teler.sh) (see [resources](#resources)), please do **NOT** file a public issue — instead, kindly send your report privately via the [vulnerability report form](https://github.com/teler-sh/teler-waf/security/advisories/new).

## Limitations

Here are some limitations of using teler-waf:

- **Performance overhead**: teler-waf may introduce some performance overhead, as the teler-waf will need to process each incoming request. If you have a high volume of traffic, this can potentially slow down the overall performance of your application significantly. See benchmark below:

```console
$ go test -bench "^BenchmarkAnalyze" -cpu=4 
goos: linux
goarch: amd64
pkg: github.com/teler-sh/teler-waf
cpu: 11th Gen Intel(R) Core(TM) i9-11900H @ 2.50GHz
BenchmarkAnalyzeDefault-4                      	  266018	      4018 ns/op	    2682 B/op	      74 allocs/op
BenchmarkAnalyzeCommonWebAttack-4              	  374410	      3126 ns/op	    2090 B/op	      68 allocs/op
BenchmarkAnalyzeCVE-4                          	  351668	      3296 ns/op	    2402 B/op	      68 allocs/op
BenchmarkAnalyzeBadIPAddress-4                 	  416152	      2967 ns/op	    1954 B/op	      63 allocs/op
BenchmarkAnalyzeBadReferrer-4                  	  410858	      3033 ns/op	    2098 B/op	      64 allocs/op
BenchmarkAnalyzeBadCrawler-4                   	  346707	      2964 ns/op	    1953 B/op	      63 allocs/op
BenchmarkAnalyzeDirectoryBruteforce-4          	  377634	      3062 ns/op	    1953 B/op	      63 allocs/op
BenchmarkAnalyzeCustomRule-4                   	  432568	      2594 ns/op	    1954 B/op	      63 allocs/op
BenchmarkAnalyzeWithoutCommonWebAttack-4       	  354930	      3460 ns/op	    2546 B/op	      69 allocs/op
BenchmarkAnalyzeWithoutCVE-4                   	  304500	      3491 ns/op	    2234 B/op	      69 allocs/op
BenchmarkAnalyzeWithoutBadIPAddress-4          	  288517	      3924 ns/op	    2682 B/op	      74 allocs/op
BenchmarkAnalyzeWithoutBadReferrer-4           	  298168	      3667 ns/op	    2538 B/op	      73 allocs/op
BenchmarkAnalyzeWithoutBadCrawler-4            	  276108	      4023 ns/op	    2682 B/op	      74 allocs/op
BenchmarkAnalyzeWithoutDirectoryBruteforce-4   	  276699	      3627 ns/op	    2682 B/op	      74 allocs/op
PASS
ok  	github.com/teler-sh/teler-waf	32.093s
```

> [!NOTE]
> Benchmarking results may vary and may not be consistent. The [teler-resources](https://github.com/teler-sh/teler-resources) dataset may have increased since then, which may impact the results.

- **Configuration complexity**: Configuring teler-waf to suit the specific needs of your application can be complex, and may require a certain level of expertise in web security. This can make it difficult for those who are not familiar with application firewalls and IDS systems to properly set up and use teler-waf.
- **Limited protection**: teler-waf is not a perfect security solution, and it may not be able to protect against all possible types of attacks. As with any security system, it is important to regularly monitor and maintain teler-waf to ensure that it is providing the desired level of protection.

#### Known Issues

To view a list of known issues with teler-waf, please filter the issues by the ["known-issue" label](https://github.com/teler-sh/teler-waf/issues?q=is%3Aopen+is%3Aissue+label%3Aknown-issue).

## Community

We use the Google Groups as our dedicated mailing list. Subscribe to [teler-announce](https://groups.google.com/g/teler-announce) via [teler-announce+subscribe@googlegroups.com](mailto:teler-announce+subscribe@googlegroups.com) for important announcements, such as the availability of new releases. This subscription will keep you informed about significant developments related to [teler IDS](https://github.com/teler-sh/teler), [teler WAF](https://github.com/teler-sh/teler-waf), [teler Proxy](https://github.com/teler-sh/teler-proxy), [teler Caddy](https://github.com/teler-sh/teler-caddy), and [teler Resources](https://github.com/teler-sh/teler-resources).

For any [inquiries](https://github.com/teler-sh/teler-waf/discussions/categories/q-a), [discussions](https://github.com/teler-sh/teler-waf/discussions), or [issues](https://github.com/teler-sh/teler-waf/issues) are being tracked here on GitHub. This is where we actively manage and address these aspects of our community engagement.

## License

This package is made available under a dual license: the [Apache License 2.0](/LICENSE-APACHE) and the [Elastic License 2.0 (ELv2)](/LICENSE-ELASTIC) (for the main package, **teler**).

You can use it freely inside your organization to protect your applications. However, you cannot use the main package to create a cloud, hosted, or managed service, or for any commercial purposes, as you would need a commercial license for that – though this option is not currently available. If you are interested in obtaining this commercial license for uses not authorized by [ELv2](/LICENSE-ELASTIC), please reach out to **@dwisiswant0**.

teler-waf and any contributions are copyright © by Dwi Siswanto 2022-2024.