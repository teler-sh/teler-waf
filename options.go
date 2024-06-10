// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"io"

	"github.com/teler-sh/teler-waf/threat"
)

// Options is a struct for specifying configuration options for the teler.Teler middleware.
type Options struct {
	// Excludes is a list of threat types to exclude from the security checks.
	// These threat types are defined in the threat.Threat type.
	//
	// When you specify the definition using JSON or YAML, the value
	// is an `int` that corresponds to the following representations:
	// - `0` represents [Threat.Custom]
	// - `1` represents [Threat.CommonWebAttack]
	// - `2` represents [Threat.CVE]
	// - `3` represents [Threat.BadIPAddress]
	// - `4` represents [Threat.BadReferrer]
	// - `5` represents [Threat.BadCrawler]
	// - `6` represents [Threat.DirectoryBruteforce]
	Excludes []threat.Threat `json:"excludes" yaml:"excludes"`

	// Whitelists is a list of DSL expressions that match request elements
	// that should be excluded from the security checks.
	Whitelists []string `json:"whitelists" yaml:"whitelists"`

	// Customs is a list of custom security rules to apply to incoming requests.
	//
	// These rules can be used to create custom security checks or to override
	// the default security checks provided by teler-waf.
	Customs []Rule `json:"customs" yaml:"customs"`

	// CustomsFromFile specifies the file path or glob pattern for loading custom
	// security rules. These rules can be used to create custom security checks
	// or to override the default security checks provided by teler IDS.
	//
	// The glob pattern supports wildcards, allowing you to specify multiple files
	// or a directory with matching files. For example, "/path/to/custom/rules/**/*.yaml"
	// will load all YAML files in the "rules" directory and its subdirectories.
	CustomsFromFile string `json:"customs_from_file" yaml:"customs_from_file"`

	// Response is the configuration for custom error response pages when a request
	// is blocked or rejected.
	Response Response `json:"response" yaml:"response"`

	// LogFile is the file path for the log file to store the security logs.
	//
	// If LogFile is specified, log messages will be written to the specified
	// file in addition to stderr (if NoStderr is false).
	LogFile string `json:"log_file" yaml:"log_file"`

	// LogWriter is an io.Writer interface used for custom log message output.
	//
	// By default, log messages are written to the standard error (stderr) if
	// NoStderr is set to false. However, you can customize the output destination
	// for log messages by providing your own implementation of io.Writer to this
	// field. When a custom LogWriter is assigned, log messages will be written to
	// it in addition to LogFile and stderr (if NoStderr is false). This allows you
	// to capture and handle log messages in a custom way, such as sending them to
	// a remote logging service, storing them in a database, or handling them in a
	// specialized manner.
	LogWriter io.Writer `json:"-" yaml:"-"`

	// TODO:
	// LogRotate specifies whether to rotate the log file when it reaches a new day.
	// LogRotate bool

	// NoStderr is a boolean flag indicating whether or not to suppress log messages
	// from being printed to the standard error (stderr) stream.
	//
	// When set to true, log messages will not be printed to stderr. If set to false,
	// log messages will be printed to stderr. By default, log messages are printed
	// to stderr (false).
	NoStderr bool `json:"no_stderr" yaml:"no_stderr"`

	// NoUpdateCheck is a boolean flag indicating whether or not to disable automatic threat
	// dataset updates.
	//
	// When set to true, automatic updates will be disabled. If set to false, automatic
	// updates will be enabled. By default, automatic updates are enabled (false).
	//
	// If the InMemory is set to true, the NoUpdateCheck value will not have any effect
	// or automatic updates will always be enabled.
	NoUpdateCheck bool `json:"no_update_check" yaml:"no_update_check"`

	// Development is a boolean flag that determines whether the request is cached or not.
	//
	// By default, development mode is disabled (false) or requests will cached.
	Development bool `json:"development" yaml:"development"`

	// InMemory is a boolean flag that specifies whether or not to load the threat dataset
	// into memory on initialization.
	//
	// When set to true, the threat dataset will be loaded into memory, which can be useful
	// when running your service or application on a distroless or runtime image, where file
	// access may be limited or slow. If InMemory is set to false, the threat dataset will
	// be downloaded and stored under the user-level cache directory on the first startup.
	// Subsequent startups will use the cached dataset.
	InMemory bool `json:"in_memory" yaml:"in_memory"`

	// FalcoSidekickURL is the URL of the FalcoSidekick endpoint to which teler-waf's events
	// will be forwarded.
	//
	// This field should be set to the URL of your FalcoSidekick instance, including the
	// protocol & port (e.g. "http://localhost:2801").
	FalcoSidekickURL string `json:"falcosidekick_url" yaml:"falcosidekick_url"`

	// Verbose is a boolean flag that controls whether verbose logging is enabled.
	// When set to true, it enables detailed and informative logging messages.
	Verbose bool `json:"verbose" yaml:"verbose"`
}
