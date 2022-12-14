package teler

import "github.com/kitabisa/teler-waf/threat"

type Options struct {
	// Excludes is a list of threat types to exclude from the security checks.
	// These threat types are defined in the threat.Exclude type.
	Excludes []threat.Exclude

	// Whitelists is a list of regular expressions that match request elements
	// that should be excluded from the security checks. The request elements
	// that can be matched are user-agent, request path, HTTP referrer,
	// IP address, and request query values.
	Whitelists []string

	// Customs is a list of custom security rules to apply to incoming requests.
	// These rules can be used to create custom security checks or to override
	// the default security checks provided by teler-waf.
	Customs []Rule

	// LogFile is the file path for the log file to store the security logs.
	LogFile string

	// LogRotate specifies whether to rotate the log file when it reaches a
	// certain size or at a specified time interval.
	LogRotate bool
}
