package teler

const (
	errResources = "error while getting teler resources: %s"
	errLogFile   = "error opening log file: %s"
	errPattern   = "error while compile custom rule for \"%s\": %s"
	errWhitelist = "error parsing whitelist pattern \"%s\": %s"

	errInvalidRuleName = "error while compile custom rule: missing rule name"
	errInvalidRuleCond = "invalid logical operator for \"%s\" rule condition, valid values are \"and\" or \"or\", given: \"%s\""

	errBadIPAddress        = "bad IP address"
	errBadReferer          = "bad HTTP referer"
	errBadCrawler          = "bad crawler"
	errDirectoryBruteforce = "directory bruteforce"

	errConvYAML      = "failed to convert YAML file \"%s\" to teler rule: %s"
	errFindFile      = "failed to find files matching pattern \"%s\": %s"
	errOpenFile      = "error while open file \"%s\": %s"
	errReadFile      = "error while read YAML file: %s"
	errUnmarshalYAML = "cannot unmarshal YAML: %s"
	errInvalidYAML   = "invalid YAML rule: %s"
	errConvValRule   = "invalid \"%s\" %s value for \"%s\" rule"
)
