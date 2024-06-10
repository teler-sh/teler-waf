// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

/*
Package teler provides implementations of teler IDS middleware.

teler IDS is a web application firewall that protects against a
variety of web-based attacks. The middleware implementations in
this package can be used to protect Go-based web applications
from these attacks.

To use the middleware implementations in this package, simply
import the package and then use the appropriate middleware
function to create a new middleware instance. The middleware
instance can then be used to wrap an existing HTTP handler.
*/
package teler

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"archive/tar"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/expr-lang/expr/vm"
	"github.com/teler-sh/teler-waf/request"
	"github.com/teler-sh/teler-waf/threat"
	"github.com/klauspost/compress/zstd"
	"github.com/patrickmn/go-cache"
	"github.com/scorpionknifes/go-pcre"
	"github.com/teler-sh/dsl"
	"github.com/valyala/fastjson"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"tlog.app/go/loc"
)

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

	// badCrawler contains the compiled slices of pcre.Matcher pointers
	// objects of BadCrawler threat data.
	badCrawler []*pcre.Matcher

	// cve contains the compiled JSON CVEs data of pointers to fastjson.Value
	cve *fastjson.Value

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

	// wlPrograms is a slice of compiled DSL expression as a program pointers
	// that are used to check whether a request should be whitelisted.
	wlPrograms []*vm.Program

	// cache is an in-memory cache used by Teler middleware to
	// store data for a short period of time.
	cache *cache.Cache

	// caller is the name of the package that called the Teler middleware.
	caller string

	// env is environment for DSL.
	env *dsl.Env

	// falcoSidekick is Falco Sidekick instance that holds events.
	falcoSidekick falcoSidekick
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
		handler: http.HandlerFunc(rejectHandler),
		threat:  &Threat{},
	}

	// Get the package name of the calling package
	if pc := loc.Caller(1); pc != 0 {
		_, file, _ := pc.NameFileLine()
		t.caller = path.Base(path.Dir(file))
	}

	// Initialize writer for logging
	ws := []zapcore.WriteSyncer{}

	// Add standard error (stderr)
	// as writer if NoStderr is false
	if !o.NoStderr {
		ws = append(ws, os.Stderr)
	}

	// Add LogWriter to writer if its non-nil
	if o.LogWriter != nil {
		ws = append(ws, zapcore.AddSync(o.LogWriter))
	}

	var err error

	// If the LogFile option is set, open the log file and
	// set the log field of the Teler struct to the file descriptor
	if o.LogFile != "" {
		t.out, err = os.OpenFile(o.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) // nosemgrep: trailofbits.go.questionable-assignment.questionable-assignment
		if err != nil {
			panic(fmt.Sprintf(errLogFile, err))
		}

		ws = append(ws, t.out)
	}

	// Define log level
	logLevel := zap.WarnLevel
	if o.Verbose {
		logLevel = zap.DebugLevel
	}

	// Create a new logger with the multiwriter as the output destination
	mw := zapcore.NewMultiWriteSyncer(ws...)
	t.log = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), // Use JSON encoding
		mw,       // Use the multiwriter
		logLevel, // Set the logging level
	))

	// Logs the options
	t.log.Info("teler WAF options", zap.Any("options", o))

	// The defer statement is used to ensure that the Sync function is called before the function exits.
	// This is used to flush any buffered writes to the output stream.
	defer func() {
		_ = t.log.Sync()
	}()

	// Initialize the excludes field of the Threat struct to a new map
	t.threat.excludes = map[threat.Threat]bool{
		threat.CommonWebAttack:     false,
		threat.CVE:                 false,
		threat.BadIPAddress:        false,
		threat.BadReferrer:         false,
		threat.BadCrawler:          false,
		threat.DirectoryBruteforce: false,
	}

	// Deprecation notice for Excludes options
	if len(o.Excludes) > 0 {
		deprecatedExcludesMsg := "threat exclusions (Excludes) will be " +
			"deprecated in the upcoming release (v2), use Whitelists instead. " +
			"See teler-waf#73 & teler-waf#64."
		t.log.Warn(deprecatedExcludesMsg)
	}

	// set the boolean flag for each threat category specified in the Excludes
	// option to true
	for _, ex := range o.Excludes {
		t.threat.excludes[ex] = true
	}

	// Initialize DSL environments
	t.env = dsl.New()

	// For each entry in the Whitelists option, compile a DSL expression and
	// add it to the wlPrograms slice of the Teler struct
	for _, wl := range o.Whitelists {
		t.log.Debug("compiling whitelist", zap.String("pattern", wl))
		program, err := t.env.Compile(wl)
		if err != nil {
			t.error(zapcore.PanicLevel, fmt.Sprintf(errCompileDSLExpr, wl, err.Error()))
			continue
		}
		t.wlPrograms = append(t.wlPrograms, program)
	}

	if o.CustomsFromFile != "" {
		// Find files matching the pattern specified in o.CustomsFromFile
		rules, err := filepath.Glob(o.CustomsFromFile)
		if err != nil {
			t.error(zapcore.PanicLevel, fmt.Sprintf(errFindFile, o.CustomsFromFile, err.Error()))
		}

		// Iterate over the found files
		for _, rule := range rules {
			// Open the file
			t.log.Debug("load CustomsFromFile", zap.String("file", rule), zap.String("pattern", o.CustomsFromFile))

			file, err := os.Open(rule)
			if err != nil {
				t.error(zapcore.PanicLevel, fmt.Sprintf(errOpenFile, rule, err.Error()))
			}

			// Convert the YAML file to a Rule
			r, err := yamlToRule(file)
			if err != nil {
				t.error(zapcore.PanicLevel, fmt.Sprintf(errConvYAML, rule, err.Error()))
			}

			// Append the converted Rule to the o.Customs slice
			o.Customs = append(o.Customs, r)
		}
	}

	// Iterate over the Customs option and verify that each custom rule has a non-empty name and a valid condition
	// Compile the regular expression pattern for each rule and add it to the patternRegex field of the Rule struct
	for _, rule := range o.Customs {
		if rule.Name == "" {
			t.error(zapcore.PanicLevel, errInvalidRuleName)
		}

		// Logs the rule
		t.log.Debug("load Customs", zap.Any("rule", rule))

		// Convert the condition to lowercase, if empty string then defaulting to "or"
		rule.Condition = strings.ToLower(rule.Condition)
		if rule.Condition == "" {
			rule.Condition = "or"
		}

		// Check the condition is either "or" or "and"
		if rule.Condition != "or" && rule.Condition != "and" {
			t.error(zapcore.PanicLevel, fmt.Sprintf(errInvalidRuleCond, rule.Name, rule.Condition))
		}

		// Iterate over the rules in the custom rules
		for i, cond := range rule.Rules {
			// If DSL expression is not empty, then compile as a program.
			if cond.DSL != "" {
				program, err := t.env.Compile(cond.DSL)
				if err != nil {
					t.error(zapcore.PanicLevel, fmt.Sprintf(errCompileDSLExpr, cond.DSL, err.Error()))
					continue
				}

				// Stores compiled DSL program
				rule.Rules[i].dslProgram = program
				continue
			}

			// Check if the DSL expression or pattern is empty string
			if cond.DSL == "" && cond.Pattern == "" {
				t.error(zapcore.PanicLevel, fmt.Sprintf(errPattern, rule.Name, "DSL or pattern cannot be empty"))
			}

			// Check if the method rule condition is valid, and
			// set to UNDEFINED if it isn't.
			if !isValidMethod(cond.Method) {
				cond.Method = request.UNDEFINED
			}

			// Defaulting method rule condition to ALL if empty or undefined
			if cond.Method == request.UNDEFINED {
				cond.Method = request.ALL
			}

			// Empty pattern cannot be process
			if cond.Pattern == "" {
				t.error(zapcore.PanicLevel, fmt.Sprintf(errPattern, rule.Name, "pattern cannot be empty"))
			}

			// Compile the regular expression pattern
			regex, err := regexp.Compile(cond.Pattern)
			if err != nil {
				t.error(zapcore.PanicLevel, fmt.Sprintf(errPattern, rule.Name, err.Error()))
			}

			rule.Rules[i].patternRegex = regex
		}
	}

	// Initialize cache with a default expiration time of 15 minutes and cleanup
	// interval of 20 minutes.
	t.cache = cache.New(15*time.Minute, 20*time.Minute)

	// If custom response status is set, overwrite default response status.
	if o.Response.Status != 0 {
		respStatus = o.Response.Status
	}

	// If HTMLFile option is not empty, read the contents of the
	// specified file into customResponseHTML variable. This file is used
	// as a custom HTML response page for rendering in request rejection.
	if o.Response.HTMLFile != "" {
		f, err := os.ReadFile(o.Response.HTMLFile)
		if err != nil {
			t.error(zapcore.PanicLevel, err.Error())
		}

		customHTMLResponse = string(f)
	}

	// If customHTMLResponse is still empty (no custom HTML response was provided),
	// and HTML option is not empty, set the customResponseHTML variable
	// to the value of HTML option.
	if customHTMLResponse == "" && o.Response.HTML != "" {
		customHTMLResponse = o.Response.HTML
	}

	// Set the opt field of the Teler struct to the options
	t.opt = o

	// Retrieve the data for each threat category
	err = t.getResources()
	if err != nil {
		t.error(zapcore.PanicLevel, fmt.Sprintf(errResources, err))
	}

	// Run checks Falco events
	go t.checkFalcoEvents()

	return t
}

// postAnalyze is a function that processes the HTTP response after
// an error is returned from the analyzeRequest function.
func (t *Teler) postAnalyze(w http.ResponseWriter, r *http.Request, k threat.Threat, err error) {
	// If there is no error, return early.
	if err == nil {
		return
	}

	// Get unique ID
	id := getUID()

	// Get the error message & convert to string as a message
	msg := err.Error()

	// Set custom headers ("X-Teler-Msg", "X-Teler-Threat", "X-Teler-Req-Id")
	setCustomHeader(w, xTelerMsg, msg)
	setCustomHeader(w, xTelerThreat, k.String())
	setCustomHeader(w, xTelerReqId, id)

	// Send the logs
	t.sendLogs(r, k, id, msg)

	// Serve the reject handler
	t.handler.ServeHTTP(w, r)
}

func (t *Teler) sendLogs(r *http.Request, k threat.Threat, id string, msg string) {
	// Declare request body, threat category, URL path, and remote IP address.
	body := t.env.GetRequestValue("Body")
	cat := k.String()
	path := r.URL.String()
	ipAddr := t.env.GetRequestValue("IP")
	listenAddr := t.getListenAddr(r)

	// Log the detected threat, request details and the error message.
	t.log.With(
		zap.String("id", id),
		zap.String("category", cat),
		zap.String("caller", t.caller),
		zap.String("listen_addr", listenAddr),
		zap.Namespace("request"),
		zap.String("method", r.Method),
		zap.String("path", path),
		zap.String("ip_addr", ipAddr),
		zap.Any("headers", r.Header),
		zap.String("body", body),
	).Warn(msg)

	if t.opt.FalcoSidekickURL == "" {
		return
	}

	// Forward the detected threat to FalcoSidekick instance
	jsonHeaders, err := json.Marshal(r.Header)
	if err != nil {
		t.error(zapcore.PanicLevel, err.Error())
	}

	// Initialize time
	now := time.Now()

	// Build FalcoSidekick event payload
	event := new(falcoEvent)
	event.Output = fmt.Sprintf(
		"%s: %s at %s by %s (caller=%s threat=%s id=%s)",
		now.Format("15:04:05.000000000"), msg, r.URL.Path, ipAddr, t.caller, cat, id,
	)
	event.Priority = "Warning"
	event.Rule = msg
	event.Time = now.Format("2006-01-02T15:04:05.999999999Z")
	event.OutputFields.Caller = t.caller
	event.OutputFields.ID = id
	event.OutputFields.Threat = cat
	event.OutputFields.ListenAddr = listenAddr
	event.OutputFields.RequestBody = string(body)
	event.OutputFields.RequestHeaders = string(jsonHeaders)
	event.OutputFields.RequestIPAddr = ipAddr
	event.OutputFields.RequestMethod = r.Method
	event.OutputFields.RequestPath = path

	// Append event to falcoSidekick instance
	t.falcoSidekick.sl.Lock()
	t.falcoSidekick.events = append(t.falcoSidekick.events, event)
	t.falcoSidekick.sl.Unlock()
}

// getResources to download datasets of threat ruleset from teler-resources
func (t *Teler) getResources() error {
	// Initialize updated
	var updated bool

	// Check if threat datasets is updated
	updated, err := threat.IsUpdated() // nosemgrep: trailofbits.go.invalid-usage-of-modified-variable.invalid-usage-of-modified-variable
	if err != nil {
		updated = false
	}

	// Do checksum for threat datasets
	if updated {
		t.log.Debug("verifying datasets")
		verify, err := threat.Verify()
		if err != nil {
			// Got something error while verifying
			updated = false
		}

		// Checks if datasets is malformed/corrupted
		//
		// If not verified, err is defintely not nil.
		if !verify {
			t.log.Debug(err.Error())
			updated = false
		}
	}

	// Download the datasets of threat ruleset from teler-resources
	// if threat datasets is not up-to-date, update check is disabled
	// and in-memory option is true
	if !updated && !t.opt.NoUpdateCheck && !t.opt.InMemory {
		t.log.Debug("downloading datasets")
		if err := threat.Get(); err != nil {
			return err
		}
	}

	// Initialize files for in-memory threat datasets
	files := make(map[string][]byte, 0)

	// If the Threat struct was configured to load data into memory, retrieve the threat data
	// from the DB URL and uncompress it from Zstandard format, then extract the contents of
	// each file from the tar archive and store them in a map indexed by their file name
	if t.opt.InMemory {
		t.log.Debug("downloading datasets")
		resp, err := http.Get(threat.DbURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		zstdReader, err := zstd.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer zstdReader.Close()

		tarReader := tar.NewReader(zstdReader)

		for {
			// Read the next header from the tar archive
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}

			if err != nil {
				return err
			}

			// Skip non-regular files
			if header.Typeflag != tar.TypeReg {
				continue
			}

			// Read the contents of the file
			fileContent, err := io.ReadAll(tarReader)
			if err != nil {
				return err
			}

			// Store the file content in the map indexed by the file name
			files[header.Name] = fileContent
		}
	}

	// Initialize the data field of the Threat struct to a new map
	// that will be used to store the threat data
	t.threat.data = make(map[threat.Threat]string)

	for _, k := range threat.List() {
		// Initialize error & threat dataset content variables
		var err error
		var b []byte

		// Get the file name and the path of respective threat type
		path, err := k.Filename(!t.opt.InMemory)
		if err != nil {
			return err
		}

		// If the data is loaded in memory, retrieve it from the files map. Otherwise,
		// read the contents of the data file at the specified path and store it as a
		// string in the data field of the Threat struct. If the file is not found,
		// the function will attempt to retrieve the threat from an external source
		// using the `Get()` method on the `threat` object. If the threat retrieval
		// fails, an error will be returned. Otherwise, the function will retry reading
		// the file as usual. If any other error occurs while reading the file, it will
		// be returned immediately.
		if t.opt.InMemory {
			b = files[path]
		} else {
			b, err = os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					// If the error is a file not found error, attempt to retrieve the
					// threat from an external source using the `Get()` method on the
					// `threat` object.
					if err := threat.Get(); err != nil {
						return err
					}

					// Retry reading the file after retrieving the threat.
					b, err = os.ReadFile(path)
					if err != nil {
						return err
					}
				} else {
					// If the error is not a file not found error, return it immediately.
					return err
				}
			}
		}

		// Store the threat dataset contents in Threat struct as a string
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

	if t.opt.Verbose {
		cat := k.String()
		count, err := k.Count()
		if err != nil {
			return err
		}

		path, err := k.Filename(false)
		if err != nil {
			return err
		}

		t.log.Debug("load datasets",
			zap.String("category", cat),
			zap.Int("count", count),
			zap.String("file", path),
		)
	}

	switch k {
	case threat.CommonWebAttack:
		// Initialize the cwa field of the threat struct.
		t.threat.cwa = &cwa{}

		// Unmarshal the data into the cwa field.
		err = json.Unmarshal([]byte(t.threat.data[k]), &t.threat.cwa)
		if err != nil {
			return err
		}

		// Compile the regular expression patterns from the filter rules
		for i, filter := range t.threat.cwa.Filters {
			// Compile the filter rule as a perl-compatible regular expression
			cpcre, err := pcre.Compile(filter.Rule, pcre.MULTILINE)
			if err != nil {
				return err
			}

			t.threat.cwa.Filters[i].pattern = cpcre.NewMatcher()
		}
	case threat.CVE:
		// Initialize the cve field of the threat struct.
		t.threat.cve, err = fastjson.Parse(t.threat.data[k]) // nosemgrep: trailofbits.go.questionable-assignment.questionable-assignment
		if err != nil {
			return err
		}

		if !t.threat.cve.Exists("templates") {
			return errors.New("the CVE templates didn't exist")
		}

		// Initialize the CVE URLs map
		cveURL = make(map[string][]*url.URL)

		// Iterate over the templates in the data set.
		for _, tpl := range t.threat.cve.GetArray("templates") {
			// kind is the type of template to check (either "path" or "raw").
			var kind string

			// Iterate over the requests in the template.
			for _, req := range tpl.GetArray("requests") {
				// Determine CVE ID of current requests.
				id := string(tpl.GetStringBytes("id"))

				// Determine the kind of template (either "path" or "raw").
				switch {
				case len(req.GetArray("path")) > 0:
					kind = "path"
				case len(req.GetArray("raw")) > 0:
					kind = "raw"
				}

				// Iterate over the paths or raw strings in the template.
				for _, p := range req.GetArray(kind) {
					// Parse the request URI or the raw string based on the kind of template.
					switch kind {
					case "path":
						parsedURL, err := url.ParseRequestURI(
							strings.TrimPrefix(
								strings.Trim(p.String(), `"`),
								"{{BaseURL}}",
							),
						)

						// If an error occurs during the parsing, skip this path.
						if err != nil {
							continue
						}

						cveURL[id] = append(cveURL[id], parsedURL)
					case "raw":
						raw := bufio.NewReader(normalizeRawStringReader(p.String()))
						parsedReq, err := http.ReadRequest(raw)

						// If an error occurs during the parsing, skip this raw string.
						if err != nil {
							continue
						}

						cveURL[id] = append(cveURL[id], parsedReq.URL)
					}
				}
			}
		}
	case threat.BadCrawler:
		// Split the data into a slice of strings, compile each string
		// into a regex or pcre expr, and save it in the badCrawler field.
		patterns := strings.Split(t.threat.data[k], "\n")
		t.threat.badCrawler = make([]*pcre.Matcher, len(patterns))

		for i, pattern := range patterns {
			cpcre, err := pcre.Compile(pattern, pcre.MULTILINE)
			if err != nil {
				return err
			}

			t.threat.badCrawler[i] = cpcre.NewMatcher()
		}
	}

	return nil
}
