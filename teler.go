package teler

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"

	"archive/tar"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/kitabisa/teler-waf/dsl"
	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
	"github.com/klauspost/compress/zstd"
	"github.com/patrickmn/go-cache"
	"github.com/scorpionknifes/go-pcre"
	"github.com/valyala/fastjson"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

	// badCrawler contains the compiled slices of pointers to regexp.Regexp
	// and pcre.Matcher objects of BadCrawler threat data as interface.
	badCrawler []interface{}

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

	// whitelistRegexes is a slice of regular expression pointers
	// that are used to check whether a request should be whitelisted.
	whitelistRegexes []*regexp.Regexp

	// cache is an in-memory cache used by Teler middleware to
	// store data for a short period of time.
	cache *cache.Cache

	// caller is the name of the package that called the Teler middleware.
	caller string

	// env is environment for DSL.
	env *dsl.Env
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

	// Get the package name of the calling package
	_, file, _, ok := runtime.Caller(1)
	if ok {
		t.caller = path.Base(path.Dir(file))
	}

	// Initialize writer for logging and add standard error (stderr)
	// as writer if NoStderr is false
	ws := []zapcore.WriteSyncer{}
	if !o.NoStderr {
		ws = append(ws, os.Stderr)
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

	// Create a new logger with the multiwriter as the output destination
	mw := zapcore.NewMultiWriteSyncer(ws...)
	t.log = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), // Use JSON encoding
		mw,            // Use the multiwriter
		zap.WarnLevel, // Set the logging level to debug
	))

	// The defer statement is used to ensure that the Sync function is called before the function exits.
	// This is used to flush any buffered writes to the output stream.
	defer func() {
		_ = t.log.Sync()
	}()

	// Retrieve the data for each threat category
	err = t.getResources()
	if err != nil {
		t.error(zapcore.PanicLevel, fmt.Sprintf(errResources, err))
	}

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

	// Initialize DSL environments
	t.env = dsl.New()

	// For each entry in the Whitelists option, compile a regular expression and
	// add it to the whitelistRegexes slice of the Teler struct
	for _, wl := range o.Whitelists {
		regex, err := regexp.Compile(wl)
		if err != nil {
			t.error(zapcore.PanicLevel, fmt.Sprintf(errWhitelist, wl, err))
		}
		t.whitelistRegexes = append(t.whitelistRegexes, regex)
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
					t.error(zapcore.PanicLevel, fmt.Sprintf(errCompileDSLExpr, rule.Name, err.Error()))
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

	// If development mode is enabled, create a new cache with a default
	// expiration time of 15 minutes and cleanup interval of 20 minutes.
	if !o.Development {
		t.cache = cache.New(15*time.Minute, 20*time.Minute)
	}

	// Set the opt field of the Teler struct to the options
	t.opt = o

	return t
}

// postAnalyze is a function that processes the HTTP response after
// an error is returned from the analyzeRequest function.
func (t *Teler) postAnalyze(w http.ResponseWriter, r *http.Request, k threat.Threat, err error) {
	// If there is no error, return early.
	if err == nil {
		return
	}

	// Set teler request ID to the header
	id := setReqIdHeader(w)

	// Get the error message & convert to string as a message
	msg := err.Error()

	// Send the logs
	t.sendLogs(r, k, id, msg)

	// Serve the reject handler
	t.handler.ServeHTTP(w, r)
}

func (t *Teler) sendLogs(r *http.Request, k threat.Threat, id string, msg string) {
	// Declare request body, threat category, URL path, and remote IP address.
	body := t.env.Requests["Body"].(string)
	cat := k.String()
	path := r.URL.String()
	ipAddr := t.env.Requests["IP"].(string)

	// Log the detected threat, request details and the error message.
	t.log.With(
		zap.String("id", id),
		zap.String("category", cat),
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
	data := map[string]interface{}{
		"output": fmt.Sprintf(
			"%s: %s at %s by %s (caller=%s threat=%s id=%s)",
			now.Format("15:04:05.000000000"), msg, r.URL.Path, ipAddr, t.caller, cat, id),
		"priority": "Warning",
		"rule":     msg,
		"time":     now.Format("2006-01-02T15:04:05.999999999Z"),
		"output_fields": map[string]interface{}{
			"teler.caller":    t.caller,
			"teler.id":        id,
			"teler.threat":    cat,
			"request.method":  r.Method,
			"request.path":    path,
			"request.ip_addr": ipAddr,
			"request.headers": string(jsonHeaders),
			"request.body":    string(body),
		},
	}
	payload, err := json.Marshal(data)
	if err != nil {
		t.error(zapcore.ErrorLevel, err.Error())
	}

	// Send the POST request to FalcoSidekick instance
	req, err := http.NewRequest("POST", t.opt.FalcoSidekickURL, bytes.NewBuffer(payload))
	if err != nil {
		t.error(zapcore.ErrorLevel, err.Error())
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.error(zapcore.ErrorLevel, err.Error())
	} else {
		defer resp.Body.Close()
	}
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

	// Download the datasets of threat ruleset from teler-resources
	// if threat datasets is not up-to-date, update check is disabled
	// and in-memory option is true
	if !updated && !t.opt.NoUpdateCheck && !t.opt.InMemory {
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
			// Compile the filter rule as a regular expression
			t.threat.cwa.Filters[i].pattern, err = regexp.Compile(filter.Rule) // nosemgrep: trailofbits.go.questionable-assignment.questionable-assignment
			if err != nil {
				// If the regular expression cannot be compiled,
				// try to compile it as a PCRE pattern
				cpcre, err := pcre.Compile(filter.Rule, pcre.MULTILINE)
				if err == nil {
					// If the PCRE pattern is successfully compiled,
					// create a new Matcher and assign it to the pattern field
					t.threat.cwa.Filters[i].pattern = cpcre.NewMatcher()
				}
			}
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
		t.threat.badCrawler = make([]interface{}, len(patterns))

		for i, pattern := range patterns {
			t.threat.badCrawler[i], err = regexp.Compile(pattern)
			if err != nil {
				// If the regular expression cannot be compiled,
				// try to compile it as a PCRE pattern
				cpcre, err := pcre.Compile(pattern, pcre.MULTILINE)
				if err == nil {
					// If the PCRE pattern is successfully compiled,
					// create a new Matcher and assign it to the pattern field
					t.threat.badCrawler[i] = cpcre.NewMatcher()
				}
			}
		}
	}

	return nil
}
