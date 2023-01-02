package teler

const (
	errResources = "error while getting teler resources: %s"
	errLogFile   = "error opening log file: %s"
	errPattern   = "error while compile custom rule for \"%s\": %s"
	errWhitelist = "error parsing whitelist pattern \"%s\": %s"

	errInvalidRuleName = "error while compile custom rule: missing rule name"
	errInvalidRuleCond = "invalid logical operator for \"%s\" rule condition, valid values are \"and\" or \"or\", given: \"%s\""
)
